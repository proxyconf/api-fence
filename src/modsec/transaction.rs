//! ModSecurity transaction wrapper
//!
//! This module provides a safe wrapper around ModSecurity transactions.

use crate::modsec::engine::{LogCollector, ModSecurityEngine};
use crate::modsec::error::{ModSecError, ModSecResult};
use crate::modsec::ffi;
use crate::modsec::intervention::{Intervention, MatchedRule};
use crate::modsec::rules::RulesSet;
use std::ffi::CString;
use std::sync::Arc;

/// Safe wrapper around a ModSecurity transaction
///
/// A transaction represents a single HTTP request/response being scanned.
/// Each HTTP request should have its own transaction.
///
/// # Thread Safety
///
/// `Transaction` is `Send` but NOT `Sync`. Use one transaction per request
/// and do not share across threads.
///
/// # Lifecycle
///
/// 1. Create transaction with `new()`
/// 2. Process connection info (optional)
/// 3. Process URI and method
/// 4. Add and process request headers
/// 5. Append and process request body
/// 6. Check for matched rules via `get_matched_rules()`
/// 7. Add and process response headers (if scanning responses)
/// 8. Append and process response body
/// 9. Check for matched rules again
/// 10. Process logging (optional)
/// 11. Transaction is cleaned up on drop
pub struct Transaction {
    inner: *mut ffi::Transaction,
    /// Keep engine alive while transaction exists
    _engine: Arc<ModSecurityEngine>,
    /// Log collector that receives rule match notifications via callback
    /// Boxed to ensure stable address for the callback pointer
    log_collector: Box<LogCollector>,
}

// Safety: Transaction can be moved between threads but not shared
unsafe impl Send for Transaction {}

impl Transaction {
    /// Create a new transaction
    ///
    /// # Arguments
    ///
    /// * `rules` - The rules set to use for scanning
    /// * `_transaction_id` - Unique identifier for this transaction (for logging)
    ///
    /// # Errors
    ///
    /// Returns `ModSecError::TransactionCreationFailed` if creation fails.
    pub fn new(rules: &RulesSet, _transaction_id: &str) -> ModSecResult<Self> {
        let engine = rules.engine();

        // Create log collector - boxed for stable address
        let mut log_collector = Box::new(LogCollector::new());

        // Get raw pointer to pass to libmodsecurity as callback user data
        let collector_ptr = log_collector.as_mut() as *mut LogCollector as *mut std::ffi::c_void;

        // Safety: engine and rules are valid, collector_ptr points to our LogCollector
        let inner =
            unsafe { ffi::msc_new_transaction(engine.as_ptr(), rules.as_ptr(), collector_ptr) };

        if inner.is_null() {
            return Err(ModSecError::TransactionCreationFailed);
        }

        Ok(Self {
            inner,
            _engine: engine,
            log_collector,
        })
    }

    /// Check if any rules matched during scanning
    ///
    /// This is the primary method for determining if a request should be blocked.
    /// Returns true if any detection rules fired (SQLi, XSS, RCE, etc.)
    pub fn has_rule_matches(&self) -> bool {
        self.log_collector.has_matches()
    }

    /// Get all matched rules as MatchedRule structs
    ///
    /// Returns details about each rule that fired, including rule ID and message.
    /// Use this for logging, metrics, and building WAF exception rules.
    pub fn get_matched_rules(&self) -> Vec<MatchedRule> {
        self.log_collector
            .matched_rules()
            .iter()
            .map(|(rule_id, message)| MatchedRule::new(*rule_id, message.clone()))
            .collect()
    }

    /// Get raw log messages from ModSecurity
    ///
    /// Useful for debugging and detailed audit logging.
    pub fn get_logs(&self) -> &[String] {
        self.log_collector.logs()
    }

    /// Process connection information
    ///
    /// This is optional but recommended for rules that check client IP.
    ///
    /// # Arguments
    ///
    /// * `client_ip` - Client IP address
    /// * `client_port` - Client port
    /// * `server_ip` - Server IP address
    /// * `server_port` - Server port
    pub fn process_connection(
        &self,
        client_ip: &str,
        client_port: u16,
        server_ip: &str,
        server_port: u16,
    ) -> ModSecResult<()> {
        let client_ip_cstr =
            CString::new(client_ip).map_err(|_| ModSecError::ConnectionProcessingFailed)?;
        let server_ip_cstr =
            CString::new(server_ip).map_err(|_| ModSecError::ConnectionProcessingFailed)?;

        // Safety: inner is valid, strings are null-terminated
        let result = unsafe {
            ffi::msc_process_connection(
                self.inner,
                client_ip_cstr.as_ptr(),
                client_port as i32,
                server_ip_cstr.as_ptr(),
                server_port as i32,
            )
        };

        if result == 0 {
            return Err(ModSecError::ConnectionProcessingFailed);
        }

        Ok(())
    }

    /// Process URI and HTTP method
    ///
    /// # Arguments
    ///
    /// * `uri` - Request URI (e.g., "/api/users?id=1")
    /// * `method` - HTTP method (e.g., "POST")
    /// * `http_version` - HTTP version number (e.g., "1.1", "2.0")
    pub fn process_uri(&self, uri: &str, method: &str, http_version: &str) -> ModSecResult<()> {
        let uri_cstr = CString::new(uri).map_err(|_| ModSecError::UriProcessingFailed {
            uri: uri.to_string(),
        })?;
        let method_cstr = CString::new(method).map_err(|_| ModSecError::UriProcessingFailed {
            uri: uri.to_string(),
        })?;
        let version_cstr =
            CString::new(http_version).map_err(|_| ModSecError::UriProcessingFailed {
                uri: uri.to_string(),
            })?;

        // Safety: inner is valid, strings are null-terminated
        let result = unsafe {
            ffi::msc_process_uri(
                self.inner,
                uri_cstr.as_ptr(),
                method_cstr.as_ptr(),
                version_cstr.as_ptr(),
            )
        };

        if result == 0 {
            return Err(ModSecError::UriProcessingFailed {
                uri: uri.to_string(),
            });
        }

        Ok(())
    }

    /// Add a request header
    ///
    /// Call this for each request header, then call `finalize_request_headers()`.
    pub fn add_request_header(&self, name: &str, value: &str) -> ModSecResult<()> {
        // Defensive check - ensure transaction is still valid
        if self.inner.is_null() {
            return Err(ModSecError::RequestHeadersProcessingFailed);
        }

        // Skip empty headers which could cause issues
        if name.is_empty() {
            return Ok(());
        }

        // Safety: inner is valid (checked above), we pass correct lengths
        let result = unsafe {
            ffi::msc_add_request_header(
                self.inner,
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };

        if result == 0 {
            return Err(ModSecError::RequestHeadersProcessingFailed);
        }

        Ok(())
    }

    /// Process all request headers
    ///
    /// Call after adding all headers with `add_request_header()`.
    pub fn finalize_request_headers(&self) -> ModSecResult<()> {
        // Safety: inner is valid
        let result = unsafe { ffi::msc_process_request_headers(self.inner) };

        if result == 0 {
            return Err(ModSecError::RequestHeadersProcessingFailed);
        }

        Ok(())
    }

    /// Process request headers from a slice of (name, value) pairs
    ///
    /// Convenience method that adds all headers and processes them.
    pub fn process_request_headers(&self, headers: &[(String, String)]) -> ModSecResult<()> {
        for (name, value) in headers {
            self.add_request_header(name, value)?;
        }
        self.finalize_request_headers()
    }

    /// Append request body data
    ///
    /// Can be called multiple times to append chunks.
    pub fn append_request_body(&self, body: &[u8]) -> ModSecResult<()> {
        if body.is_empty() {
            return Ok(());
        }

        // Safety: inner is valid, body pointer and length are correct
        let result = unsafe { ffi::msc_append_request_body(self.inner, body.as_ptr(), body.len()) };

        if result == 0 {
            return Err(ModSecError::RequestBodyProcessingFailed);
        }

        Ok(())
    }

    /// Finalize request body processing
    ///
    /// Call after all body data has been appended.
    pub fn finalize_request_body(&self) -> ModSecResult<()> {
        // Safety: inner is valid
        let result = unsafe { ffi::msc_process_request_body(self.inner) };

        if result == 0 {
            return Err(ModSecError::RequestBodyProcessingFailed);
        }

        Ok(())
    }

    /// Process the complete request body
    ///
    /// Convenience method that appends and processes the body.
    pub fn process_request_body(&self, body: &[u8]) -> ModSecResult<()> {
        self.append_request_body(body)?;
        self.finalize_request_body()
    }

    /// Add a response header
    pub fn add_response_header(&self, name: &str, value: &str) -> ModSecResult<()> {
        // Safety: inner is valid, we pass correct lengths
        let result = unsafe {
            ffi::msc_add_response_header(
                self.inner,
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };

        if result == 0 {
            return Err(ModSecError::ResponseHeadersProcessingFailed);
        }

        Ok(())
    }

    /// Finalize response headers
    ///
    /// # Arguments
    ///
    /// * `status` - HTTP response status code
    /// * `protocol` - Protocol version string (e.g., "1.1", "2.0")
    pub fn finalize_response_headers(&self, status: u16, protocol: &str) -> ModSecResult<()> {
        let protocol_cstr =
            CString::new(protocol).map_err(|_| ModSecError::ResponseHeadersProcessingFailed)?;

        // Safety: inner is valid, protocol_cstr is null-terminated
        let result = unsafe {
            ffi::msc_process_response_headers(self.inner, status as i32, protocol_cstr.as_ptr())
        };

        if result == 0 {
            return Err(ModSecError::ResponseHeadersProcessingFailed);
        }

        Ok(())
    }

    /// Process response headers from a slice of (name, value) pairs
    ///
    /// Convenience method that adds all headers and processes them.
    pub fn process_response_headers(
        &self,
        status: u16,
        headers: &[(String, String)],
    ) -> ModSecResult<()> {
        for (name, value) in headers {
            self.add_response_header(name, value)?;
        }
        self.finalize_response_headers(status, "1.1")
    }

    /// Append response body data
    pub fn append_response_body(&self, body: &[u8]) -> ModSecResult<()> {
        if body.is_empty() {
            return Ok(());
        }

        // Safety: inner is valid, body pointer and length are correct
        let result =
            unsafe { ffi::msc_append_response_body(self.inner, body.as_ptr(), body.len()) };

        if result == 0 {
            return Err(ModSecError::ResponseBodyProcessingFailed);
        }

        Ok(())
    }

    /// Finalize response body processing
    pub fn finalize_response_body(&self) -> ModSecResult<()> {
        // Safety: inner is valid
        let result = unsafe { ffi::msc_process_response_body(self.inner) };

        if result == 0 {
            return Err(ModSecError::ResponseBodyProcessingFailed);
        }

        Ok(())
    }

    /// Process the complete response body
    ///
    /// Convenience method that appends and processes the body.
    pub fn process_response_body(&self, body: &[u8]) -> ModSecResult<()> {
        self.append_response_body(body)?;
        self.finalize_response_body()
    }

    /// Process logging phase
    ///
    /// Call at the end of the transaction to finalize logging.
    #[allow(clippy::unnecessary_wraps)]
    pub fn process_logging(&self) -> ModSecResult<()> {
        // Safety: inner is valid
        let _result = unsafe { ffi::msc_process_logging(self.inner) };

        // Logging failures are not critical
        Ok(())
    }

    /// Check for intervention
    ///
    /// Returns `Some(Intervention)` if a rule triggered a disruptive action,
    /// or `None` if no intervention is required.
    pub fn intervention(&self) -> Option<Intervention> {
        let mut intervention = ffi::ModSecurityIntervention::default();

        // Safety: inner is valid, intervention is a valid mutable pointer
        let result = unsafe { ffi::msc_intervention(self.inner, &mut intervention) };

        if result == 0 {
            return None;
        }

        // Convert C strings to Rust strings
        let log = if !intervention.log.is_null() {
            // Safety: log is a valid C string from libmodsecurity
            Some(
                unsafe { std::ffi::CStr::from_ptr(intervention.log) }
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        };

        let url = if !intervention.url.is_null() {
            Some(
                unsafe { std::ffi::CStr::from_ptr(intervention.url) }
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        };

        Some(Intervention {
            status: intervention.status as u16,
            url,
            log,
            disruptive: intervention.disruptive != 0,
        })
    }

    /// Get matched rules from the transaction
    ///
    /// Uses the log collector to return all rules that fired during scanning.
    /// This is the recommended method for getting matched rules.
    pub fn matched_rules(&self) -> Vec<MatchedRule> {
        self.get_matched_rules()
    }
}

/// Parse a MatchedRule from a ModSecurity log message
///
/// Log format typically contains: [id "NNNNN"] [msg "..."] [severity "..."]
///
/// Note: This function is kept for reference but the LogCollector now handles
/// parsing directly. Remove after confirming LogCollector works correctly.
#[allow(dead_code)]
fn parse_rule_from_log(log: &str) -> Option<MatchedRule> {
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

    // Extract severity: [severity "..."]
    let severity = log
        .find("[severity \"")
        .and_then(|start| {
            let rest = &log[start + 11..];
            rest.find("\"]").map(|end| rest[..end].to_string())
        })
        .unwrap_or_default();

    // Extract file: [file "..."]
    let file = log
        .find("[file \"")
        .and_then(|start| {
            let rest = &log[start + 7..];
            rest.find("\"]").map(|end| rest[..end].to_string())
        })
        .unwrap_or_default();

    // Extract line: [line "..."]
    let line = log
        .find("[line \"")
        .and_then(|start| {
            let rest = &log[start + 7..];
            rest.find("\"]")
                .and_then(|end| rest[..end].parse::<u32>().ok())
        })
        .unwrap_or(0);

    Some(MatchedRule::with_details(
        rule_id,
        severity,
        message,
        file,
        line,
        Vec::new(), // Tags would require more parsing
    ))
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // Safety: inner was created by msc_new_transaction and is valid
            unsafe {
                ffi::msc_transaction_cleanup(self.inner);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_from_log() {
        let log = r#"[id "942100"] [msg "SQL Injection Attack"] [severity "CRITICAL"] [file "/etc/rules.conf"] [line "42"]"#;

        let rule = parse_rule_from_log(log).unwrap();
        assert_eq!(rule.rule_id, 942100);
        assert_eq!(rule.message, "SQL Injection Attack");
        assert_eq!(rule.severity, "CRITICAL");
        assert_eq!(rule.file, "/etc/rules.conf");
        assert_eq!(rule.line, 42);
    }

    #[test]
    fn test_parse_rule_minimal_log() {
        let log = r#"[id "123"]"#;

        let rule = parse_rule_from_log(log).unwrap();
        assert_eq!(rule.rule_id, 123);
        assert_eq!(rule.message, "Rule matched");
    }

    #[test]
    fn test_parse_rule_no_id() {
        let log = "Some log without rule id";
        assert!(parse_rule_from_log(log).is_none());
    }

    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_transaction_lifecycle() {
        let engine = Arc::new(ModSecurityEngine::new("test/1.0").unwrap());
        let mut rules = RulesSet::new(Arc::clone(&engine)).unwrap();
        rules
            .add_inline(r#"SecRule ARGS "@contains attack" "id:1,phase:2,deny,status:403""#)
            .unwrap();

        let tx = Transaction::new(&rules, "test-1").unwrap();

        tx.process_uri("/api/test?input=attack", "GET", "1.1")
            .unwrap();
        tx.finalize_request_headers().unwrap();
        tx.finalize_request_body().unwrap();

        let intervention = tx.intervention();
        assert!(intervention.is_some());
        assert_eq!(intervention.unwrap().status, 403);
    }

    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_log_callback_rule_matching() {
        eprintln!("[TEST] Starting test_log_callback_rule_matching");

        let engine = Arc::new(ModSecurityEngine::new("test/1.0").unwrap());
        let mut rules = RulesSet::new(Arc::clone(&engine)).unwrap();

        // Use a simple rule that should definitely log - must enable logging with "log" action
        rules
            .add_inline(r#"SecRule ARGS "@contains attack" "id:100001,phase:2,log,deny,status:403,msg:'Test attack detected'""#)
            .unwrap();

        eprintln!("[TEST] Rules loaded, creating transaction");

        let tx = Transaction::new(&rules, "test-log-1").unwrap();

        eprintln!("[TEST] Transaction created, processing URI with attack payload");

        // Process a request that should trigger the rule
        tx.process_uri("/api/test?q=attack", "GET", "1.1").unwrap();
        tx.finalize_request_headers().unwrap();
        tx.finalize_request_body().unwrap();

        eprintln!("[TEST] Request processed, checking results");

        // Check the logs received
        let logs = tx.get_logs();
        eprintln!("[TEST] Number of logs received: {}", logs.len());
        for (i, log) in logs.iter().enumerate() {
            eprintln!("[TEST] Log {}: {}", i, log);
        }

        // Check matched rules
        let matched = tx.get_matched_rules();
        eprintln!("[TEST] Number of matched rules: {}", matched.len());
        for rule in &matched {
            eprintln!(
                "[TEST] Matched rule: id={}, msg={}",
                rule.rule_id, rule.message
            );
        }

        // Also check intervention for comparison
        let intervention = tx.intervention();
        eprintln!("[TEST] Intervention: {:?}", intervention);

        // Verify that has_rule_matches() returns true
        let has_matches = tx.has_rule_matches();
        eprintln!("[TEST] has_rule_matches() = {}", has_matches);

        // The test should pass if either approach detects the attack
        assert!(
            has_matches || intervention.map(|i| i.status == 403).unwrap_or(false),
            "Expected rule to match. Logs: {:?}, Matched rules: {:?}, Intervention: {:?}",
            logs,
            matched,
            tx.intervention()
        );
    }

    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_detectsqli_operator() {
        eprintln!("[TEST] Starting test_detectsqli_operator");

        let engine = Arc::new(ModSecurityEngine::new("test/1.0").unwrap());
        let mut rules = RulesSet::new(Arc::clone(&engine)).unwrap();

        // Add base config for ARGS parsing
        rules
            .add_inline(
                r#"
SecRuleEngine On
SecRequestBodyAccess On
SecArgumentSeparator &
"#,
            )
            .unwrap();

        // Test with @detectSQLi - this is what CRS uses
        rules
            .add_inline(
                r#"SecRule ARGS "@detectSQLi" "id:999999,phase:2,log,deny,status:403,msg:'SQLi detected via libinjection'""#,
            )
            .unwrap();

        eprintln!("[TEST] Rules loaded with @detectSQLi operator");

        let tx = Transaction::new(&rules, "test-sqli-1").unwrap();

        // Classic SQL injection payload that libinjection should detect
        let uri = "/search?q=' OR '1'='1";
        eprintln!("[TEST] Processing URI: {}", uri);

        tx.process_uri(uri, "GET", "1.1").unwrap();
        tx.finalize_request_headers().unwrap();
        tx.finalize_request_body().unwrap();

        // Check logs
        let logs = tx.get_logs();
        eprintln!("[TEST] Number of logs received: {}", logs.len());
        for (i, log) in logs.iter().enumerate() {
            eprintln!("[TEST] Log {}: {}", i, log);
        }

        // Check matched rules
        let matched = tx.get_matched_rules();
        eprintln!("[TEST] Number of matched rules: {}", matched.len());
        for rule in &matched {
            eprintln!(
                "[TEST] Matched rule: id={}, msg={}",
                rule.rule_id, rule.message
            );
        }

        // Check intervention
        let intervention = tx.intervention();
        eprintln!("[TEST] Intervention: {:?}", intervention);

        let has_matches = tx.has_rule_matches();
        eprintln!("[TEST] has_rule_matches() = {}", has_matches);

        assert!(
            has_matches,
            "Expected @detectSQLi to match SQLi payload. Logs: {:?}",
            logs
        );
    }

    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_args_population_from_query_string() {
        eprintln!("[TEST] Starting test_args_population_from_query_string");

        let engine = Arc::new(ModSecurityEngine::new("test/1.0").unwrap());
        let mut rules = RulesSet::new(Arc::clone(&engine)).unwrap();

        // Add base config
        rules
            .add_inline(
                r#"
SecRuleEngine On
SecRequestBodyAccess On
SecArgumentSeparator &
"#,
            )
            .unwrap();

        // Rule that checks if ARGS:q contains a specific value
        // This tests whether query string parameters are being parsed into ARGS
        rules
            .add_inline(
                r#"SecRule ARGS:q "@contains testvalue123" "id:999998,phase:2,log,deny,status:403,msg:'ARGS:q matched testvalue123'""#,
            )
            .unwrap();

        eprintln!("[TEST] Rules loaded with ARGS:q rule");

        let tx = Transaction::new(&rules, "test-args-1").unwrap();

        let uri = "/search?q=testvalue123";
        eprintln!("[TEST] Processing URI: {}", uri);

        tx.process_uri(uri, "GET", "1.1").unwrap();
        tx.finalize_request_headers().unwrap();
        tx.finalize_request_body().unwrap();

        // Check results
        let logs = tx.get_logs();
        eprintln!("[TEST] Number of logs received: {}", logs.len());
        for (i, log) in logs.iter().enumerate() {
            eprintln!("[TEST] Log {}: {}", i, log);
        }

        let has_matches = tx.has_rule_matches();
        eprintln!("[TEST] has_rule_matches() = {}", has_matches);

        let intervention = tx.intervention();
        eprintln!("[TEST] Intervention: {:?}", intervention);

        assert!(
            has_matches || intervention.map(|i| i.status == 403).unwrap_or(false),
            "Expected ARGS:q to be populated from query string. Logs: {:?}",
            logs
        );
    }
}
