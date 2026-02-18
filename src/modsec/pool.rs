// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Thread pool for ModSecurity scanning
//!
//! This module provides a thread pool for executing ModSecurity scans
//! without blocking Envoy worker threads. Each worker thread owns its
//! own ModSecurity engine and can process scans independently.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      ScannerPool                             │
//! │  ┌───────────┐    ┌──────────────────────────────────────┐  │
//! │  │ Job Queue │───>│ Worker Threads                        │  │
//! │  │ (mpsc)    │    │  ┌─────────┐ ┌─────────┐ ┌─────────┐ │  │
//! │  └───────────┘    │  │Worker 1 │ │Worker 2 │ │Worker N │ │  │
//! │                   │  │(Engine) │ │(Engine) │ │(Engine) │ │  │
//! │                   │  └─────────┘ └─────────┘ └─────────┘ │  │
//! │                   └──────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! - `ScannerPool` is `Send + Sync` and can be shared via `Arc`
//! - Jobs are submitted via channel and processed by worker threads
//! - Results are returned via oneshot channels

use crate::modsec::error::{ModSecError, ModSecResult};
use crate::modsec::intervention::{Intervention, MatchedRule};
use crate::modsec::rules::RulesSet;
use crate::modsec::transaction::Transaction;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Type of scan to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    /// Scan as an HTTP request
    Request,
    /// Scan as an HTTP response
    Response,
    /// Scan response body using request scanning API
    ///
    /// This allows using request-oriented rules (which are typically
    /// more comprehensive) to scan response content.
    ResponseAsRequest,
}

/// Payload for a scan job
#[derive(Debug, Clone)]
pub struct ScanPayload {
    /// HTTP method (e.g., "GET", "POST")
    pub method: String,

    /// Request URI (e.g., "/api/users?id=1")
    pub uri: String,

    /// HTTP version (e.g., "HTTP/1.1")
    pub http_version: String,

    /// Request headers as key-value pairs
    pub headers: Vec<(String, String)>,

    /// Request or response body
    pub body: Option<Vec<u8>>,

    /// Pre-extracted strings from JSON (for optimization)
    ///
    /// If provided, these strings are used instead of the raw body
    /// for scanning, reducing false positives from base64 data.
    pub extracted_strings: Option<Vec<String>>,

    /// Response status code (for response scanning)
    pub response_status: Option<u16>,

    /// Response headers (for response scanning)
    pub response_headers: Option<Vec<(String, String)>>,
}

impl ScanPayload {
    /// Create a new request scan payload
    pub fn request(
        method: impl Into<String>,
        uri: impl Into<String>,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            http_version: "1.1".to_string(),
            headers,
            body,
            extracted_strings: None,
            response_status: None,
            response_headers: None,
        }
    }

    /// Create a new response scan payload
    pub fn response(
        method: impl Into<String>,
        uri: impl Into<String>,
        request_headers: Vec<(String, String)>,
        response_status: u16,
        response_headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Self {
        Self {
            method: method.into(),
            uri: uri.into(),
            http_version: "1.1".to_string(),
            headers: request_headers,
            body,
            extracted_strings: None,
            response_status: Some(response_status),
            response_headers: Some(response_headers),
        }
    }

    /// Set extracted strings for optimized scanning
    pub fn with_extracted_strings(mut self, strings: Vec<String>) -> Self {
        self.extracted_strings = Some(strings);
        self
    }
}

/// Result of a scan operation
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Whether the scan resulted in a block
    pub blocked: bool,

    /// Rules that matched during the scan
    pub matched_rules: Vec<MatchedRule>,

    /// Intervention details if disruptive action was triggered
    pub intervention: Option<Intervention>,

    /// Time taken to perform the scan in milliseconds
    pub scan_duration_ms: u64,

    /// Name of the ruleset that was used
    pub ruleset_name: String,

    /// Whether the scan timed out
    pub timed_out: bool,
}

impl ScanResult {
    /// Create a timeout result
    fn timeout(ruleset_name: String, timeout_ms: u64) -> Self {
        Self {
            blocked: false,
            matched_rules: Vec::new(),
            intervention: None,
            scan_duration_ms: timeout_ms,
            ruleset_name,
            timed_out: true,
        }
    }

    /// Create an error result
    fn error(ruleset_name: String) -> Self {
        Self {
            blocked: false,
            matched_rules: Vec::new(),
            intervention: None,
            scan_duration_ms: 0,
            ruleset_name,
            timed_out: false,
        }
    }
}

/// A scan job to be processed by a worker
pub struct ScanJob {
    /// Unique identifier for this scan (e.g., request ID)
    pub request_id: String,

    /// Type of scan to perform
    pub scan_type: ScanType,

    /// Payload to scan
    pub payload: ScanPayload,

    /// Rules to use for this scan (shared reference)
    pub rules: Arc<RulesSet>,

    /// Name of the ruleset (for result tagging)
    pub ruleset_name: String,

    /// Channel to send the result back
    pub result_sender: std::sync::mpsc::SyncSender<ScanResult>,
}

/// Message sent to worker threads
enum WorkerMessage {
    /// A job to process
    Job(Box<ScanJob>),
    /// Shutdown signal
    Shutdown,
}

/// Thread pool for ModSecurity scanning
///
/// The pool manages worker threads that process scan jobs. Each job
/// carries its own `Arc<RulesSet>`, allowing the pool to be shared
/// across APIs with different rulesets.
pub struct ScannerPool {
    /// Sender for submitting jobs
    job_sender: Sender<WorkerMessage>,

    /// Worker thread handles
    workers: Vec<JoinHandle<()>>,
}

// Safety: ScannerPool can be sent between threads
unsafe impl Send for ScannerPool {}
// Safety: ScannerPool can be shared between threads (uses channels)
unsafe impl Sync for ScannerPool {}

impl ScannerPool {
    /// Create a new scanner pool with the specified number of worker threads.
    ///
    /// The pool does not own any engine or ruleset; each scan job carries
    /// its own `Arc<RulesSet>` reference.
    ///
    /// # Arguments
    ///
    /// * `thread_count` - Number of worker threads to spawn
    ///
    /// # Errors
    ///
    /// Returns an error if workers cannot be started.
    pub fn new(thread_count: usize) -> ModSecResult<Self> {
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));

        // Start worker threads
        let mut workers = Vec::with_capacity(thread_count);

        for worker_id in 0..thread_count {
            let receiver = Arc::clone(&receiver);

            let handle = thread::Builder::new()
                .name(format!("modsec-worker-{}", worker_id))
                .spawn(move || {
                    worker_loop(receiver);
                })
                .map_err(|e| ModSecError::PoolError {
                    message: format!("failed to spawn worker thread: {}", e),
                })?;

            workers.push(handle);
        }

        Ok(Self {
            job_sender: sender,
            workers,
        })
    }

    /// Submit a scan job to the pool
    ///
    /// This is non-blocking - the job is queued and a receiver
    /// is returned for getting the result.
    ///
    /// # Arguments
    ///
    /// * `request_id` - Unique identifier for this request
    /// * `scan_type` - Type of scan to perform
    /// * `payload` - The payload to scan
    /// * `rules` - Ruleset to use for scanning
    /// * `ruleset_name` - Name of the ruleset (for result tagging)
    ///
    /// # Returns
    ///
    /// A receiver for the scan result.
    ///
    /// # Errors
    ///
    /// Returns an error if the pool has been shut down.
    pub fn submit(
        &self,
        request_id: String,
        scan_type: ScanType,
        payload: ScanPayload,
        rules: &Arc<RulesSet>,
        ruleset_name: &str,
    ) -> ModSecResult<mpsc::Receiver<ScanResult>> {
        let (result_sender, result_receiver) = mpsc::sync_channel(1);

        let job = ScanJob {
            request_id,
            scan_type,
            payload,
            rules: Arc::clone(rules),
            ruleset_name: ruleset_name.to_string(),
            result_sender,
        };

        self.job_sender
            .send(WorkerMessage::Job(Box::new(job)))
            .map_err(|_| ModSecError::PoolError {
                message: "pool has been shut down".to_string(),
            })?;

        Ok(result_receiver)
    }

    /// Submit a scan job and block until completion or timeout
    ///
    /// # Arguments
    ///
    /// * `request_id` - Unique identifier for this request
    /// * `scan_type` - Type of scan to perform
    /// * `payload` - The payload to scan
    /// * `rules` - Ruleset to use for scanning
    /// * `ruleset_name` - Name of the ruleset (for result tagging)
    /// * `timeout_ms` - Maximum time to wait for scan completion
    ///
    /// # Returns
    ///
    /// The scan result.
    pub fn scan_blocking(
        &self,
        request_id: String,
        scan_type: ScanType,
        payload: ScanPayload,
        rules: &Arc<RulesSet>,
        ruleset_name: &str,
        timeout_ms: u64,
    ) -> ScanResult {
        match self.submit(request_id, scan_type, payload, rules, ruleset_name) {
            Ok(receiver) => {
                let timeout = Duration::from_millis(timeout_ms);
                match receiver.recv_timeout(timeout) {
                    Ok(result) => result,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        ScanResult::timeout(ruleset_name.to_string(), timeout_ms)
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        ScanResult::error(ruleset_name.to_string())
                    }
                }
            }
            Err(_) => ScanResult::error(ruleset_name.to_string()),
        }
    }

    /// Shut down the pool and wait for workers to finish
    pub fn shutdown(self) {
        // Send shutdown signal to all workers
        for _ in 0..self.workers.len() {
            let _ = self.job_sender.send(WorkerMessage::Shutdown);
        }

        // Wait for workers to finish
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

/// Worker loop - processes jobs until shutdown
fn worker_loop(receiver: Arc<Mutex<Receiver<WorkerMessage>>>) {
    loop {
        // Get next job from the queue
        let message = {
            let rx = match receiver.lock() {
                Ok(rx) => rx,
                Err(_) => return, // Mutex poisoned, exit
            };
            rx.recv()
        };

        match message {
            Ok(WorkerMessage::Job(job)) => {
                let result = process_scan_job(&job, &job.rules, &job.ruleset_name);

                // Send result back (ignore send errors - receiver may have dropped)
                let _ = job.result_sender.send(result);
            }
            Ok(WorkerMessage::Shutdown) | Err(_) => {
                // Shutdown or channel closed
                return;
            }
        }
    }
}

/// Process a single scan job
fn process_scan_job(job: &ScanJob, rules: &RulesSet, ruleset_name: &str) -> ScanResult {
    let start = Instant::now();

    // Create a new transaction for this scan
    let transaction = match Transaction::new(rules, &job.request_id) {
        Ok(t) => t,
        Err(_) => return ScanResult::error(ruleset_name.to_string()),
    };

    // Process based on scan type
    let scan_result = match job.scan_type {
        ScanType::Request => process_request_scan(&transaction, &job.payload),
        ScanType::Response => process_response_scan(&transaction, &job.payload),
        ScanType::ResponseAsRequest => process_response_as_request_scan(&transaction, &job.payload),
    };

    let duration = start.elapsed();

    match scan_result {
        Ok((blocked, matched_rules, intervention)) => ScanResult {
            blocked,
            matched_rules,
            intervention,
            scan_duration_ms: duration.as_millis() as u64,
            ruleset_name: ruleset_name.to_string(),
            timed_out: false,
        },
        Err(_) => ScanResult::error(ruleset_name.to_string()),
    }
}

/// Process a request scan
fn process_request_scan(
    transaction: &Transaction,
    payload: &ScanPayload,
) -> ModSecResult<(bool, Vec<MatchedRule>, Option<Intervention>)> {
    // Process URI (phase 1)
    transaction.process_uri(&payload.uri, &payload.method, &payload.http_version)?;

    // Process headers (phase 1)
    transaction.process_request_headers(&payload.headers)?;

    // Process body (phase 2)
    // IMPORTANT: We MUST always call finalize_request_body (msc_process_request_body)
    // even for bodyless requests (GET, DELETE, etc.). CRS detection rules like
    // 942xxx (SQLi), 941xxx (XSS), 932xxx (RCE) all run in phase 2.
    // Without triggering phase 2, query parameter attacks go undetected.
    if let Some(ref body) = payload.body {
        // Use extracted strings if available, otherwise use raw body
        let scan_body = if let Some(ref strings) = payload.extracted_strings {
            crate::modsec::string_extractor::build_scan_payload(strings)
        } else {
            body.clone()
        };
        transaction.process_request_body(&scan_body)?;
    } else {
        // No body, but still need to trigger phase 2 rule evaluation
        transaction.finalize_request_body()?;
    }

    // Get intervention - this is the primary way to detect blocking in CRS anomaly mode
    let intervention = transaction.intervention();

    // Determine blocking based on intervention (disruptive action triggered)
    // The log callback may not fire for all rules, but intervention is reliable
    let blocked_by_intervention = intervention.as_ref().map(|i| i.disruptive).unwrap_or(false);

    // Also check log-based rule matching as a fallback
    let blocked_by_logs = transaction.has_rule_matches();

    let blocked = blocked_by_intervention || blocked_by_logs;

    // Collect matched rules from both sources
    let mut matched_rules = transaction.matched_rules();

    // Parse additional rule info from intervention log if present
    if let Some(ref interv) = intervention {
        if let Some(ref log) = interv.log {
            if let Some(rule) = parse_rule_from_intervention_log(log) {
                // Only add if not already present
                if !matched_rules.iter().any(|r| r.rule_id == rule.rule_id) {
                    matched_rules.push(rule);
                }
            }
        }
    }

    Ok((blocked, matched_rules, intervention))
}

/// Parse a MatchedRule from an intervention log message
fn parse_rule_from_intervention_log(log: &str) -> Option<MatchedRule> {
    // Extract rule ID: [id "NNNNN"]
    let rule_id = log.find("[id \"").and_then(|start| {
        let rest = &log[start + 5..];
        rest.find("\"]")
            .and_then(|end| rest[..end].parse::<u32>().ok())
    })?;

    // Extract message: [msg "..."]
    let message = log
        .find("[msg \"")
        .and_then(|start| {
            let rest = &log[start + 6..];
            rest.find("\"]").map(|end| rest[..end].to_string())
        })
        .unwrap_or_else(|| "Rule matched".to_string());

    Some(MatchedRule::new(rule_id, message))
}

/// Process a response scan
fn process_response_scan(
    transaction: &Transaction,
    payload: &ScanPayload,
) -> ModSecResult<(bool, Vec<MatchedRule>, Option<Intervention>)> {
    // First process request context (required for response scanning)
    transaction.process_uri(&payload.uri, &payload.method, &payload.http_version)?;
    transaction.process_request_headers(&payload.headers)?;
    // Finalize request body to trigger phase 2 (even though we're scanning response)
    transaction.finalize_request_body()?;

    // Process response headers (phase 3)
    let status = payload.response_status.unwrap_or(200);
    let response_headers = payload.response_headers.as_deref().unwrap_or(&[]);
    transaction.process_response_headers(status, response_headers)?;

    // Process response body if present (phase 4)
    if let Some(ref body) = payload.body {
        let scan_body = if let Some(ref strings) = payload.extracted_strings {
            crate::modsec::string_extractor::build_scan_payload(strings)
        } else {
            body.clone()
        };
        transaction.process_response_body(&scan_body)?;
    } else {
        // Still need to trigger phase 4 rule evaluation
        transaction.finalize_response_body()?;
    }

    // Get intervention - this is the primary way to detect blocking
    let intervention = transaction.intervention();

    // Determine blocking based on intervention (disruptive action triggered)
    let blocked_by_intervention = intervention.as_ref().map(|i| i.disruptive).unwrap_or(false);

    // Also check log-based rule matching as a fallback
    let blocked_by_logs = transaction.has_rule_matches();

    let blocked = blocked_by_intervention || blocked_by_logs;

    // Collect matched rules from both sources
    let mut matched_rules = transaction.matched_rules();

    // Parse additional rule info from intervention log if present
    if let Some(ref interv) = intervention {
        if let Some(ref log) = interv.log {
            if let Some(rule) = parse_rule_from_intervention_log(log) {
                if !matched_rules.iter().any(|r| r.rule_id == rule.rule_id) {
                    matched_rules.push(rule);
                }
            }
        }
    }

    Ok((blocked, matched_rules, intervention))
}

/// Process a response body using request scanning API
///
/// This allows using request-oriented rules to scan response content,
/// which is useful because CRS REQUEST-* rules are typically more
/// comprehensive than RESPONSE-* rules.
fn process_response_as_request_scan(
    transaction: &Transaction,
    payload: &ScanPayload,
) -> ModSecResult<(bool, Vec<MatchedRule>, Option<Intervention>)> {
    // Set up a synthetic request context
    transaction.process_uri("/response-scan", "POST", "1.1")?;

    transaction.process_request_headers(&[(
        "Content-Type".to_string(),
        "application/octet-stream".to_string(),
    )])?;

    // Process response body as if it were a request body
    if let Some(ref body) = payload.body {
        let scan_body = if let Some(ref strings) = payload.extracted_strings {
            crate::modsec::string_extractor::build_scan_payload(strings)
        } else {
            body.clone()
        };
        transaction.process_request_body(&scan_body)?;
    } else {
        // Still need to trigger phase 2 rule evaluation
        transaction.finalize_request_body()?;
    }

    // Get intervention - this is the primary way to detect blocking
    let intervention = transaction.intervention();

    // Determine blocking based on intervention (disruptive action triggered)
    let blocked_by_intervention = intervention.as_ref().map(|i| i.disruptive).unwrap_or(false);

    // Also check log-based rule matching as a fallback
    let blocked_by_logs = transaction.has_rule_matches();

    let blocked = blocked_by_intervention || blocked_by_logs;

    // Collect matched rules from both sources
    let mut matched_rules = transaction.matched_rules();

    // Parse additional rule info from intervention log if present
    if let Some(ref interv) = intervention {
        if let Some(ref log) = interv.log {
            if let Some(rule) = parse_rule_from_intervention_log(log) {
                if !matched_rules.iter().any(|r| r.rule_id == rule.rule_id) {
                    matched_rules.push(rule);
                }
            }
        }
    }

    Ok((blocked, matched_rules, intervention))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_payload_request() {
        let payload = ScanPayload::request(
            "POST",
            "/api/users",
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(b"{}".to_vec()),
        );

        assert_eq!(payload.method, "POST");
        assert_eq!(payload.uri, "/api/users");
        assert!(payload.body.is_some());
        assert!(payload.response_status.is_none());
    }

    #[test]
    fn test_scan_payload_response() {
        let payload = ScanPayload::response(
            "GET",
            "/api/users",
            vec![],
            200,
            vec![("Content-Type".to_string(), "application/json".to_string())],
            Some(b"[]".to_vec()),
        );

        assert_eq!(payload.method, "GET");
        assert_eq!(payload.response_status, Some(200));
        assert!(payload.response_headers.is_some());
    }

    #[test]
    fn test_scan_payload_with_extracted_strings() {
        let payload = ScanPayload::request("POST", "/api/data", vec![], Some(b"{}".to_vec()))
            .with_extracted_strings(vec!["test".to_string()]);

        assert!(payload.extracted_strings.is_some());
        assert_eq!(payload.extracted_strings.unwrap().len(), 1);
    }

    #[test]
    fn test_scan_result_timeout() {
        let result = ScanResult::timeout("test".to_string(), 100);

        assert!(result.timed_out);
        assert!(!result.blocked);
        assert_eq!(result.scan_duration_ms, 100);
    }

    #[test]
    fn test_scan_type_variants() {
        assert_eq!(ScanType::Request, ScanType::Request);
        assert_ne!(ScanType::Request, ScanType::Response);
        assert_ne!(ScanType::Response, ScanType::ResponseAsRequest);
    }

    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_scanner_pool_with_bundled_crs() {
        use crate::modsec::config::RulesetConfig;
        use crate::modsec::global::get_or_compile_ruleset;

        // Use full bundled CRS (all rules)
        let ruleset_config = RulesetConfig::bundled_crs("test-crs");
        let rules = get_or_compile_ruleset(&ruleset_config).expect("Failed to compile rules");

        let pool = ScannerPool::new(1).expect("Failed to create scanner pool");

        // Create a payload with an attack pattern
        // This will trigger protocol enforcement rules due to special characters
        let payload = ScanPayload::request(
            "GET",
            "/search?q=' OR '1'='1",
            vec![("Host".to_string(), "example.com".to_string())],
            None,
        );

        let result = pool.scan_blocking(
            "test-req-1".to_string(),
            ScanType::Request,
            payload,
            &rules,
            "test-crs",
            5000,
        );

        pool.shutdown();

        // Test passes if any rule matched - proves WAF integration works
        // In practice with Envoy, SQLi rules will fire due to proper request processing
        assert!(
            result.blocked,
            "Expected attack to be blocked. Matched rules: {:?}, Intervention: {:?}",
            result.matched_rules, result.intervention
        );
        assert!(
            !result.matched_rules.is_empty(),
            "Expected at least one rule to match"
        );
    }
}
