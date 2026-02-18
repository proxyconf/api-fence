// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! ModSecurity observability
//!
//! This module provides metrics and dynamic metadata integration
//! for ModSecurity scanning results.
//!
//! # Dynamic Metadata
//!
//! The following metadata keys are set in the `api_fence` namespace:
//!
//! | Key | Type | Description |
//! |-----|------|-------------|
//! | `modsec.request.verdict` | string | `"blocked"`, `"allowed"`, `"alert"` |
//! | `modsec.request.ruleset` | string | Ruleset name used for enforcement |
//! | `modsec.request.matched_rules` | string | JSON array of matched rule IDs |
//! | `modsec.request.matched_messages` | string | Pipe-delimited rule messages |
//! | `modsec.request.scan_time_ms` | number | Scan duration |
//! | `modsec.request.timed_out` | bool | Whether scan timed out |
//! | `modsec.response.*` | ... | Same keys for response scanning |

use crate::modsec::config::ScanAction;
use crate::modsec::scanner::DualScanResult;
use std::sync::atomic::{AtomicU64, Ordering};

/// Metadata namespace for api_fence
pub const METADATA_NAMESPACE: &str = "api_fence";

/// Metrics for ModSecurity scanning
///
/// Thread-safe counters and statistics for observability.
#[derive(Debug, Default)]
pub struct ModSecMetrics {
    // Request scanning metrics
    /// Total request scans performed
    pub request_scans: AtomicU64,
    /// Requests blocked by ModSecurity
    pub request_blocked: AtomicU64,
    /// Requests with alerts (matched but not blocked)
    pub request_alerts: AtomicU64,
    /// Request scan timeouts
    pub request_timeouts: AtomicU64,
    /// Total request scan time in milliseconds
    pub request_scan_time_total_ms: AtomicU64,

    // Response scanning metrics
    /// Total response scans performed
    pub response_scans: AtomicU64,
    /// Responses blocked by ModSecurity
    pub response_blocked: AtomicU64,
    /// Responses with alerts
    pub response_alerts: AtomicU64,
    /// Response scan timeouts
    pub response_timeouts: AtomicU64,
    /// Total response scan time in milliseconds
    pub response_scan_time_total_ms: AtomicU64,

    // String extraction metrics
    /// Total strings extracted from JSON payloads
    pub strings_extracted: AtomicU64,
    /// Base64 strings skipped
    pub base64_skipped: AtomicU64,
    /// Times string extraction limit was reached
    pub string_limit_reached: AtomicU64,
}

impl ModSecMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request scan
    pub fn record_request_scan(&self, result: &DualScanResult, action: &ScanAction) {
        self.request_scans.fetch_add(1, Ordering::Relaxed);
        self.request_scan_time_total_ms
            .fetch_add(result.total_scan_time_ms(), Ordering::Relaxed);

        if result.any_timeout() {
            self.request_timeouts.fetch_add(1, Ordering::Relaxed);
        }

        let effective = result.effective_result();
        if effective.blocked {
            match action {
                ScanAction::Block => {
                    self.request_blocked.fetch_add(1, Ordering::Relaxed);
                }
                ScanAction::Alert => {
                    self.request_alerts.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Record a response scan
    pub fn record_response_scan(&self, result: &DualScanResult, action: &ScanAction) {
        self.response_scans.fetch_add(1, Ordering::Relaxed);
        self.response_scan_time_total_ms
            .fetch_add(result.total_scan_time_ms(), Ordering::Relaxed);

        if result.any_timeout() {
            self.response_timeouts.fetch_add(1, Ordering::Relaxed);
        }

        let effective = result.effective_result();
        if effective.blocked {
            match action {
                ScanAction::Block => {
                    self.response_blocked.fetch_add(1, Ordering::Relaxed);
                }
                ScanAction::Alert => {
                    self.response_alerts.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Record string extraction statistics
    pub fn record_string_extraction(
        &self,
        strings_count: u64,
        base64_skipped: u64,
        limit_reached: bool,
    ) {
        self.strings_extracted
            .fetch_add(strings_count, Ordering::Relaxed);
        self.base64_skipped
            .fetch_add(base64_skipped, Ordering::Relaxed);
        if limit_reached {
            self.string_limit_reached.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get average request scan time in milliseconds
    pub fn avg_request_scan_time_ms(&self) -> f64 {
        let total = self.request_scan_time_total_ms.load(Ordering::Relaxed);
        let count = self.request_scans.load(Ordering::Relaxed);
        if count == 0 {
            0.0
        } else {
            total as f64 / count as f64
        }
    }

    /// Get average response scan time in milliseconds
    pub fn avg_response_scan_time_ms(&self) -> f64 {
        let total = self.response_scan_time_total_ms.load(Ordering::Relaxed);
        let count = self.response_scans.load(Ordering::Relaxed);
        if count == 0 {
            0.0
        } else {
            total as f64 / count as f64
        }
    }

    /// Get request block rate (0.0 to 1.0)
    pub fn request_block_rate(&self) -> f64 {
        let blocked = self.request_blocked.load(Ordering::Relaxed);
        let total = self.request_scans.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            blocked as f64 / total as f64
        }
    }

    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.request_scans.store(0, Ordering::Relaxed);
        self.request_blocked.store(0, Ordering::Relaxed);
        self.request_alerts.store(0, Ordering::Relaxed);
        self.request_timeouts.store(0, Ordering::Relaxed);
        self.request_scan_time_total_ms.store(0, Ordering::Relaxed);
        self.response_scans.store(0, Ordering::Relaxed);
        self.response_blocked.store(0, Ordering::Relaxed);
        self.response_alerts.store(0, Ordering::Relaxed);
        self.response_timeouts.store(0, Ordering::Relaxed);
        self.response_scan_time_total_ms.store(0, Ordering::Relaxed);
        self.strings_extracted.store(0, Ordering::Relaxed);
        self.base64_skipped.store(0, Ordering::Relaxed);
        self.string_limit_reached.store(0, Ordering::Relaxed);
    }
}

/// Metadata values for request scanning
pub struct RequestMetadata {
    /// Verdict: "blocked", "allowed", or "alert"
    pub verdict: String,
    /// Name of ruleset used
    pub ruleset: String,
    /// JSON array of matched rule IDs
    pub matched_rules: String,
    /// Pipe-delimited matched rule messages
    pub matched_messages: String,
    /// Scan duration in milliseconds
    pub scan_time_ms: u64,
    /// Whether scan timed out
    pub timed_out: bool,
}

/// Metadata values for response scanning
pub struct ResponseMetadata {
    /// Verdict: "blocked", "allowed", or "alert"
    pub verdict: String,
    /// Name of ruleset used
    pub ruleset: String,
    /// JSON array of matched rule IDs
    pub matched_rules: String,
    /// Pipe-delimited matched rule messages
    pub matched_messages: String,
    /// Scan duration in milliseconds
    pub scan_time_ms: u64,
    /// Whether scan timed out
    pub timed_out: bool,
}

/// Build metadata for a request scan result
///
/// # Arguments
///
/// * `result` - The dual scan result
/// * `action` - The configured action
///
/// # Returns
///
/// Metadata values ready to be set on the filter.
pub fn build_request_metadata(result: &DualScanResult, action: &ScanAction) -> RequestMetadata {
    let effective = result.effective_result();

    let verdict = match (action, effective.blocked) {
        (ScanAction::Block, true) => "blocked",
        (ScanAction::Alert, true) => "alert",
        (_, false) if !effective.matched_rules.is_empty() => "alert",
        _ => "allowed",
    };

    let rule_ids: Vec<u32> = effective.matched_rules.iter().map(|r| r.rule_id).collect();

    let matched_rules = serde_json::to_string(&rule_ids).unwrap_or_else(|_| "[]".to_string());

    let matched_messages: String = effective
        .matched_rules
        .iter()
        .map(|r| r.message.as_str())
        .collect::<Vec<_>>()
        .join(" | ");

    RequestMetadata {
        verdict: verdict.to_string(),
        ruleset: effective.ruleset_name.clone(),
        matched_rules,
        matched_messages,
        scan_time_ms: effective.scan_duration_ms,
        timed_out: effective.timed_out,
    }
}

/// Build metadata for a response scan result
///
/// # Arguments
///
/// * `result` - The dual scan result
/// * `action` - The configured action
///
/// # Returns
///
/// Metadata values ready to be set on the filter.
pub fn build_response_metadata(result: &DualScanResult, action: &ScanAction) -> ResponseMetadata {
    let effective = result.effective_result();

    let verdict = match (action, effective.blocked) {
        (ScanAction::Block, true) => "blocked",
        (ScanAction::Alert, true) => "alert",
        (_, false) if !effective.matched_rules.is_empty() => "alert",
        _ => "allowed",
    };

    let rule_ids: Vec<u32> = effective.matched_rules.iter().map(|r| r.rule_id).collect();

    let matched_rules = serde_json::to_string(&rule_ids).unwrap_or_else(|_| "[]".to_string());

    let matched_messages: String = effective
        .matched_rules
        .iter()
        .map(|r| r.message.as_str())
        .collect::<Vec<_>>()
        .join(" | ");

    ResponseMetadata {
        verdict: verdict.to_string(),
        ruleset: effective.ruleset_name.clone(),
        matched_rules,
        matched_messages,
        scan_time_ms: effective.scan_duration_ms,
        timed_out: effective.timed_out,
    }
}

/// Set ModSecurity request metadata on an Envoy filter
///
/// This is a helper that sets all request-related metadata keys.
/// The actual implementation depends on the Envoy SDK traits.
///
/// # Type Parameters
///
/// * `F` - The Envoy HTTP filter type
///
/// # Arguments
///
/// * `filter` - Mutable reference to the filter
/// * `result` - The dual scan result
/// * `action` - The configured action
#[inline]
pub fn set_modsec_request_metadata<F: MetadataSetter>(
    filter: &mut F,
    result: &DualScanResult,
    action: &ScanAction,
) {
    let metadata = build_request_metadata(result, action);

    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.request.verdict",
        &metadata.verdict,
    );
    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.request.ruleset",
        &metadata.ruleset,
    );
    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.request.matched_rules",
        &metadata.matched_rules,
    );
    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.request.matched_messages",
        &metadata.matched_messages,
    );
    filter.set_metadata_number(
        METADATA_NAMESPACE,
        "modsec.request.scan_time_ms",
        metadata.scan_time_ms as f64,
    );
    filter.set_metadata_bool(
        METADATA_NAMESPACE,
        "modsec.request.timed_out",
        metadata.timed_out,
    );
}

/// Set ModSecurity response metadata on an Envoy filter
///
/// This is a helper that sets all response-related metadata keys.
///
/// # Type Parameters
///
/// * `F` - The Envoy HTTP filter type
///
/// # Arguments
///
/// * `filter` - Mutable reference to the filter
/// * `result` - The dual scan result
/// * `action` - The configured action
#[inline]
pub fn set_modsec_response_metadata<F: MetadataSetter>(
    filter: &mut F,
    result: &DualScanResult,
    action: &ScanAction,
) {
    let metadata = build_response_metadata(result, action);

    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.response.verdict",
        &metadata.verdict,
    );
    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.response.ruleset",
        &metadata.ruleset,
    );
    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.response.matched_rules",
        &metadata.matched_rules,
    );
    filter.set_metadata_string(
        METADATA_NAMESPACE,
        "modsec.response.matched_messages",
        &metadata.matched_messages,
    );
    filter.set_metadata_number(
        METADATA_NAMESPACE,
        "modsec.response.scan_time_ms",
        metadata.scan_time_ms as f64,
    );
    filter.set_metadata_bool(
        METADATA_NAMESPACE,
        "modsec.response.timed_out",
        metadata.timed_out,
    );
}

/// Trait for setting dynamic metadata
///
/// This abstracts over the Envoy SDK's metadata setting methods,
/// allowing the observability functions to be tested independently.
pub trait MetadataSetter {
    /// Set a string metadata value
    fn set_metadata_string(&mut self, namespace: &str, key: &str, value: &str);

    /// Set a numeric metadata value
    fn set_metadata_number(&mut self, namespace: &str, key: &str, value: f64);

    /// Set a boolean metadata value
    fn set_metadata_bool(&mut self, namespace: &str, key: &str, value: bool);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modsec::intervention::MatchedRule;
    use crate::modsec::pool::ScanResult;
    use std::collections::HashMap;

    /// Mock metadata setter for testing
    struct MockFilter {
        strings: HashMap<String, String>,
        numbers: HashMap<String, f64>,
        bools: HashMap<String, bool>,
    }

    impl MockFilter {
        fn new() -> Self {
            Self {
                strings: HashMap::new(),
                numbers: HashMap::new(),
                bools: HashMap::new(),
            }
        }

        fn get_string(&self, key: &str) -> Option<&String> {
            self.strings.get(key)
        }

        fn get_number(&self, key: &str) -> Option<f64> {
            self.numbers.get(key).copied()
        }

        fn get_bool(&self, key: &str) -> Option<bool> {
            self.bools.get(key).copied()
        }
    }

    impl MetadataSetter for MockFilter {
        fn set_metadata_string(&mut self, _namespace: &str, key: &str, value: &str) {
            self.strings.insert(key.to_string(), value.to_string());
        }

        fn set_metadata_number(&mut self, _namespace: &str, key: &str, value: f64) {
            self.numbers.insert(key.to_string(), value);
        }

        fn set_metadata_bool(&mut self, _namespace: &str, key: &str, value: bool) {
            self.bools.insert(key.to_string(), value);
        }
    }

    fn make_scan_result(blocked: bool, rules: Vec<(u32, &str)>, ruleset: &str) -> ScanResult {
        ScanResult {
            blocked,
            matched_rules: rules
                .into_iter()
                .map(|(id, msg)| MatchedRule::new(id, msg.to_string()))
                .collect(),
            intervention: None,
            scan_duration_ms: 42,
            ruleset_name: ruleset.to_string(),
            timed_out: false,
        }
    }

    #[test]
    fn test_request_metadata_blocked() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![(942100, "SQL injection")], "crs"),
            secondary: None,
        };

        let metadata = build_request_metadata(&result, &ScanAction::Block);

        assert_eq!(metadata.verdict, "blocked");
        assert_eq!(metadata.ruleset, "crs");
        assert!(metadata.matched_rules.contains("942100"));
        assert!(metadata.matched_messages.contains("SQL injection"));
        assert_eq!(metadata.scan_time_ms, 42);
        assert!(!metadata.timed_out);
    }

    #[test]
    fn test_request_metadata_alert() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![(942100, "SQL injection")], "crs"),
            secondary: None,
        };

        let metadata = build_request_metadata(&result, &ScanAction::Alert);

        assert_eq!(metadata.verdict, "alert");
    }

    #[test]
    fn test_request_metadata_allowed() {
        let result = DualScanResult {
            primary: make_scan_result(false, vec![], "crs"),
            secondary: None,
        };

        let metadata = build_request_metadata(&result, &ScanAction::Block);

        assert_eq!(metadata.verdict, "allowed");
        assert_eq!(metadata.matched_rules, "[]");
        assert!(metadata.matched_messages.is_empty());
    }

    #[test]
    fn test_set_request_metadata() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![(942100, "SQL injection")], "crs"),
            secondary: None,
        };

        let mut filter = MockFilter::new();
        set_modsec_request_metadata(&mut filter, &result, &ScanAction::Block);

        assert_eq!(
            filter.get_string("modsec.request.verdict"),
            Some(&"blocked".to_string())
        );
        assert_eq!(
            filter.get_string("modsec.request.ruleset"),
            Some(&"crs".to_string())
        );
        assert_eq!(filter.get_number("modsec.request.scan_time_ms"), Some(42.0));
        assert_eq!(filter.get_bool("modsec.request.timed_out"), Some(false));
    }

    #[test]
    fn test_set_response_metadata() {
        let result = DualScanResult {
            primary: make_scan_result(false, vec![], "crs"),
            secondary: None,
        };

        let mut filter = MockFilter::new();
        set_modsec_response_metadata(&mut filter, &result, &ScanAction::Alert);

        assert_eq!(
            filter.get_string("modsec.response.verdict"),
            Some(&"allowed".to_string())
        );
    }

    #[test]
    fn test_metrics_record_request() {
        let metrics = ModSecMetrics::new();

        let result = DualScanResult {
            primary: make_scan_result(true, vec![(942100, "test")], "crs"),
            secondary: None,
        };

        metrics.record_request_scan(&result, &ScanAction::Block);

        assert_eq!(metrics.request_scans.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.request_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.request_alerts.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_record_alert() {
        let metrics = ModSecMetrics::new();

        let result = DualScanResult {
            primary: make_scan_result(true, vec![(942100, "test")], "crs"),
            secondary: None,
        };

        metrics.record_request_scan(&result, &ScanAction::Alert);

        assert_eq!(metrics.request_blocked.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.request_alerts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_metrics_average_scan_time() {
        let metrics = ModSecMetrics::new();

        metrics.request_scans.store(10, Ordering::Relaxed);
        metrics
            .request_scan_time_total_ms
            .store(500, Ordering::Relaxed);

        assert!((metrics.avg_request_scan_time_ms() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_metrics_block_rate() {
        let metrics = ModSecMetrics::new();

        metrics.request_scans.store(100, Ordering::Relaxed);
        metrics.request_blocked.store(25, Ordering::Relaxed);

        assert!((metrics.request_block_rate() - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = ModSecMetrics::new();

        metrics.request_scans.store(100, Ordering::Relaxed);
        metrics.request_blocked.store(50, Ordering::Relaxed);

        metrics.reset();

        assert_eq!(metrics.request_scans.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.request_blocked.load(Ordering::Relaxed), 0);
    }
}
