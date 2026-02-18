// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Dual ruleset scanner
//!
//! This module provides support for running two rulesets (OLD/NEW)
//! simultaneously, enabling seamless migration between CRS versions.
//!
//! # Use Case
//!
//! When upgrading from CRS 3.x to CRS 4.x, you can:
//! 1. Set CRS 3.x as the primary (OLD) ruleset
//! 2. Set CRS 4.x as the secondary (NEW) ruleset
//! 3. Both are evaluated for every request
//! 4. When both match, the NEW result is used for enforcement
//!
//! This allows testing new rules in production without breaking
//! existing functionality.

use crate::modsec::config::{RulesetConfig, ScanAction};
use crate::modsec::error::ModSecResult;
use crate::modsec::global;
use crate::modsec::pool::{ScanPayload, ScanResult, ScanType};
use crate::modsec::rules::RulesSet;
use std::sync::Arc;

/// Result of scanning with dual rulesets
#[derive(Debug, Clone)]
pub struct DualScanResult {
    /// Result from primary (OLD) ruleset
    pub primary: ScanResult,

    /// Result from secondary (NEW) ruleset, if configured
    pub secondary: Option<ScanResult>,
}

impl DualScanResult {
    /// Get the effective result for enforcement
    ///
    /// Per design: when both rulesets match, use the secondary (NEW) result.
    /// This allows the NEW ruleset to take precedence for migration testing.
    ///
    /// # Returns
    ///
    /// Reference to the result that should be used for enforcement.
    pub fn effective_result(&self) -> &ScanResult {
        match &self.secondary {
            // If secondary matched (blocked or has matched rules), use it
            Some(secondary) if secondary.blocked || !secondary.matched_rules.is_empty() => {
                secondary
            }
            // Otherwise use primary
            _ => &self.primary,
        }
    }

    /// Check if the request should be blocked based on action config
    ///
    /// # Arguments
    ///
    /// * `action` - The configured action (Block or Alert)
    ///
    /// # Returns
    ///
    /// `true` if the request should be blocked.
    pub fn should_block(&self, action: &ScanAction) -> bool {
        match action {
            ScanAction::Block => self.effective_result().blocked,
            ScanAction::Alert => false,
        }
    }

    /// Check if either ruleset timed out
    pub fn any_timeout(&self) -> bool {
        self.primary.timed_out || self.secondary.as_ref().is_some_and(|s| s.timed_out)
    }

    /// Get total scan time (max of both rulesets since they run in parallel)
    pub fn total_scan_time_ms(&self) -> u64 {
        let primary_time = self.primary.scan_duration_ms;
        let secondary_time = self
            .secondary
            .as_ref()
            .map(|s| s.scan_duration_ms)
            .unwrap_or(0);
        std::cmp::max(primary_time, secondary_time)
    }

    /// Check if any ruleset had matches
    pub fn has_matches(&self) -> bool {
        !self.primary.matched_rules.is_empty()
            || self
                .secondary
                .as_ref()
                .is_some_and(|s| !s.matched_rules.is_empty())
    }
}

/// Scanner that evaluates requests against two rulesets
///
/// This is the main entry point for ModSecurity scanning in api_fence.
/// It holds shared references to compiled rulesets and delegates scanning
/// to the global scanner thread pool.
///
/// # Example
///
/// ```ignore
/// use api_fence::modsec::{DualRulesetScanner, ScanPayload, ScanType, RulesetConfig};
///
/// let scanner = DualRulesetScanner::new(
///     &RulesetConfig { name: "crs_3.3".into(), rules_path: vec!["/etc/crs/*.conf".into()], ..Default::default() },
///     Some(&RulesetConfig { name: "crs_4.0".into(), rules_path: vec!["/etc/crs4/*.conf".into()], ..Default::default() }),
///     100,
/// )?;
///
/// let payload = ScanPayload::request("POST", "/api/users", vec![], Some(body));
/// let result = scanner.scan_blocking("req-123", ScanType::Request, payload);
///
/// if result.should_block(&ScanAction::Block) {
///     // Block the request
/// }
/// ```
pub struct DualRulesetScanner {
    /// Primary (OLD) ruleset (shared reference from rules registry)
    primary_rules: Arc<RulesSet>,

    /// Name of the primary ruleset
    primary_name: String,

    /// Secondary (NEW) ruleset (optional, shared reference from rules registry)
    secondary_rules: Option<Arc<RulesSet>>,

    /// Name of the secondary ruleset
    secondary_name: Option<String>,

    /// Per-API timeout in milliseconds for scan blocking
    timeout_ms: u64,
}

impl DualRulesetScanner {
    /// Create a new dual ruleset scanner
    ///
    /// Rulesets are compiled (or retrieved from the global registry) on creation.
    /// Scanning is performed by the global scanner thread pool.
    ///
    /// # Arguments
    ///
    /// * `primary_config` - Primary ruleset configuration (required)
    /// * `secondary_config` - Secondary ruleset configuration (optional)
    /// * `timeout_ms` - Per-API timeout for scan blocking
    ///
    /// # Errors
    ///
    /// Returns an error if ruleset compilation fails.
    pub fn new(
        primary_config: &RulesetConfig,
        secondary_config: Option<&RulesetConfig>,
        timeout_ms: u64,
    ) -> ModSecResult<Self> {
        let primary_rules = global::get_or_compile_ruleset(primary_config)?;
        let primary_name = primary_config.name.clone();

        let (secondary_rules, secondary_name) = match secondary_config {
            Some(config) => {
                let rules = global::get_or_compile_ruleset(config)?;
                (Some(rules), Some(config.name.clone()))
            }
            None => (None, None),
        };

        Ok(Self {
            primary_rules,
            primary_name,
            secondary_rules,
            secondary_name,
            timeout_ms,
        })
    }

    /// Scan a payload with both rulesets (blocking)
    ///
    /// This method blocks until both scans complete or timeout.
    ///
    /// # Arguments
    ///
    /// * `request_id` - Unique identifier for this request
    /// * `scan_type` - Type of scan to perform
    /// * `payload` - The payload to scan
    ///
    /// # Returns
    ///
    /// Combined result from both rulesets.
    pub fn scan_blocking(
        &self,
        request_id: &str,
        scan_type: ScanType,
        payload: ScanPayload,
    ) -> DualScanResult {
        let pool = global::global_scanner_pool();

        // Always scan with primary
        let primary = pool.scan_blocking(
            request_id.to_string(),
            scan_type,
            payload.clone(),
            &self.primary_rules,
            &self.primary_name,
            self.timeout_ms,
        );

        // Optionally scan with secondary
        let secondary = self.secondary_rules.as_ref().map(|rules| {
            let name = self.secondary_name.as_deref().unwrap_or("secondary");
            pool.scan_blocking(
                request_id.to_string(),
                scan_type,
                payload,
                rules,
                name,
                self.timeout_ms,
            )
        });

        DualScanResult { primary, secondary }
    }

    /// Submit scans to both rulesets (non-blocking)
    ///
    /// Returns receivers for both results. The caller is responsible
    /// for waiting on both receivers.
    ///
    /// # Arguments
    ///
    /// * `request_id` - Unique identifier for this request
    /// * `scan_type` - Type of scan to perform
    /// * `payload` - The payload to scan
    ///
    /// # Returns
    ///
    /// Tuple of (primary_receiver, optional_secondary_receiver)
    ///
    /// # Errors
    ///
    /// Returns an error if job submission fails.
    pub fn submit(
        &self,
        request_id: &str,
        scan_type: ScanType,
        payload: ScanPayload,
    ) -> ModSecResult<(
        std::sync::mpsc::Receiver<ScanResult>,
        Option<std::sync::mpsc::Receiver<ScanResult>>,
    )> {
        let pool = global::global_scanner_pool();

        let primary_rx = pool.submit(
            request_id.to_string(),
            scan_type,
            payload.clone(),
            &self.primary_rules,
            &self.primary_name,
        )?;

        let secondary_rx = match &self.secondary_rules {
            Some(rules) => {
                let name = self.secondary_name.as_deref().unwrap_or("secondary");
                Some(pool.submit(request_id.to_string(), scan_type, payload, rules, name)?)
            }
            None => None,
        };

        Ok((primary_rx, secondary_rx))
    }

    /// Get the primary ruleset name
    pub fn primary_ruleset_name(&self) -> &str {
        &self.primary_name
    }

    /// Get the secondary ruleset name, if configured
    pub fn secondary_ruleset_name(&self) -> Option<&str> {
        self.secondary_name.as_deref()
    }

    /// Check if a secondary ruleset is configured
    pub fn has_secondary(&self) -> bool {
        self.secondary_rules.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modsec::intervention::MatchedRule;

    fn make_scan_result(blocked: bool, rules: Vec<u32>, ruleset: &str) -> ScanResult {
        ScanResult {
            blocked,
            matched_rules: rules
                .into_iter()
                .map(|id| MatchedRule::new(id, format!("Rule {}", id)))
                .collect(),
            intervention: None,
            scan_duration_ms: 10,
            ruleset_name: ruleset.to_string(),
            timed_out: false,
        }
    }

    #[test]
    fn test_effective_result_primary_only() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![942100], "primary"),
            secondary: None,
        };

        assert_eq!(result.effective_result().ruleset_name, "primary");
        assert!(result.effective_result().blocked);
    }

    #[test]
    fn test_effective_result_secondary_matches() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![942100], "primary"),
            secondary: Some(make_scan_result(true, vec![942101], "secondary")),
        };

        // Secondary matched, so it takes precedence
        assert_eq!(result.effective_result().ruleset_name, "secondary");
        assert_eq!(result.effective_result().matched_rules[0].rule_id, 942101);
    }

    #[test]
    fn test_effective_result_only_primary_matches() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![942100], "primary"),
            secondary: Some(make_scan_result(false, vec![], "secondary")),
        };

        // Secondary didn't match, so primary is used
        assert_eq!(result.effective_result().ruleset_name, "primary");
    }

    #[test]
    fn test_effective_result_neither_matches() {
        let result = DualScanResult {
            primary: make_scan_result(false, vec![], "primary"),
            secondary: Some(make_scan_result(false, vec![], "secondary")),
        };

        // Neither matched, primary is default
        assert_eq!(result.effective_result().ruleset_name, "primary");
    }

    #[test]
    fn test_should_block_with_block_action() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![942100], "primary"),
            secondary: None,
        };

        assert!(result.should_block(&ScanAction::Block));
    }

    #[test]
    fn test_should_block_with_alert_action() {
        let result = DualScanResult {
            primary: make_scan_result(true, vec![942100], "primary"),
            secondary: None,
        };

        // Alert action never blocks
        assert!(!result.should_block(&ScanAction::Alert));
    }

    #[test]
    fn test_any_timeout() {
        let mut result = DualScanResult {
            primary: make_scan_result(false, vec![], "primary"),
            secondary: Some(make_scan_result(false, vec![], "secondary")),
        };

        assert!(!result.any_timeout());

        result.primary.timed_out = true;
        assert!(result.any_timeout());
    }

    #[test]
    fn test_total_scan_time() {
        let mut result = DualScanResult {
            primary: make_scan_result(false, vec![], "primary"),
            secondary: Some(make_scan_result(false, vec![], "secondary")),
        };

        result.primary.scan_duration_ms = 50;
        result.secondary.as_mut().unwrap().scan_duration_ms = 75;

        assert_eq!(result.total_scan_time_ms(), 75);
    }

    #[test]
    fn test_has_matches() {
        let result_no_matches = DualScanResult {
            primary: make_scan_result(false, vec![], "primary"),
            secondary: Some(make_scan_result(false, vec![], "secondary")),
        };
        assert!(!result_no_matches.has_matches());

        let result_primary_matches = DualScanResult {
            primary: make_scan_result(true, vec![942100], "primary"),
            secondary: Some(make_scan_result(false, vec![], "secondary")),
        };
        assert!(result_primary_matches.has_matches());

        let result_secondary_matches = DualScanResult {
            primary: make_scan_result(false, vec![], "primary"),
            secondary: Some(make_scan_result(true, vec![942100], "secondary")),
        };
        assert!(result_secondary_matches.has_matches());
    }
}
