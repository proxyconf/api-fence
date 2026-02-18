// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! ModSecurity engine wrapper
//!
//! This module provides a safe wrapper around the libmodsecurity engine.

use crate::modsec::error::{ModSecError, ModSecResult};
use crate::modsec::ffi;
use std::ffi::{c_void, CStr, CString};

/// Log callback that collects rule matches into the transaction's log collector.
///
/// This callback is invoked by libmodsecurity for each log message.
/// The `cb_data` pointer points to a `LogCollector` instance associated with the transaction.
///
/// # Safety
/// - `cb_data` must be a valid pointer to a `LogCollector` (or null)
/// - `data` must be a valid C string pointer
unsafe extern "C" fn modsec_log_callback(cb_data: *mut c_void, data: *const c_void) {
    if cb_data.is_null() || data.is_null() {
        return;
    }

    // Safety: cb_data points to a LogCollector that lives for the transaction duration
    let collector = &mut *(cb_data as *mut LogCollector);

    // Safety: data is a null-terminated C string from libmodsecurity
    let log_cstr = CStr::from_ptr(data as *const i8);
    if let Ok(log_str) = log_cstr.to_str() {
        collector.add_log(log_str);
    }
}

/// Collects log messages from ModSecurity during a transaction.
///
/// This struct is passed as user data to `msc_new_transaction` and receives
/// log messages via the `modsec_log_callback`.
#[derive(Debug, Default)]
pub struct LogCollector {
    /// Raw log messages from ModSecurity
    logs: Vec<String>,
    /// Parsed matched rules (rule_id, message)
    matched_rules: Vec<(u32, String)>,
}

impl LogCollector {
    /// Create a new empty log collector
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a log message and parse rule info if present
    fn add_log(&mut self, log: &str) {
        self.logs.push(log.to_string());

        // Parse rule ID and message from log
        // Format: ... [id "NNNNN"] ... [msg "..."] ...
        if let Some(rule_info) = Self::parse_rule_from_log(log) {
            self.matched_rules.push(rule_info);
        }
    }

    /// Parse rule ID and message from a ModSecurity log line
    fn parse_rule_from_log(log: &str) -> Option<(u32, String)> {
        // Extract rule ID: [id "NNNNN"]
        let rule_id = log.find("[id \"").and_then(|start| {
            let rest = &log[start + 5..];
            rest.find("\"]")
                .and_then(|end| rest[..end].parse::<u32>().ok())
        })?;

        // Skip non-blocking internal rules (901xxx, 949xxx threshold rules without actual detections)
        // We want to capture actual detection rules like 942xxx (SQLi), 941xxx (XSS), etc.
        // Rules in 900000-901999 range are initialization/setup rules
        if (900_000..902_000).contains(&rule_id) {
            return None;
        }

        // Extract message: [msg "..."]
        let message = log
            .find("[msg \"")
            .and_then(|start| {
                let rest = &log[start + 6..];
                rest.find("\"]").map(|end| rest[..end].to_string())
            })
            .unwrap_or_else(|| "Rule matched".to_string());

        Some((rule_id, message))
    }

    /// Check if any rules matched (excluding setup/threshold rules)
    pub fn has_matches(&self) -> bool {
        !self.matched_rules.is_empty()
    }

    /// Get all matched rules as (rule_id, message) pairs
    pub fn matched_rules(&self) -> &[(u32, String)] {
        &self.matched_rules
    }

    /// Get all raw log messages
    pub fn logs(&self) -> &[String] {
        &self.logs
    }
}

/// Safe wrapper around the ModSecurity engine
///
/// The engine is the core of ModSecurity and is initialized once.
/// After initialization, it is immutable and safe to share across threads.
///
/// # Thread Safety
///
/// `ModSecurityEngine` is `Send + Sync`. After construction, the engine
/// state is read-only (used by `msc_create_rules_set` and `msc_new_transaction`).
/// The global singleton wraps it in `Arc` for shared ownership.
///
/// # Example
///
/// ```ignore
/// use api_fence::modsec::ModSecurityEngine;
///
/// let engine = ModSecurityEngine::new("api_fence/1.0")?;
/// // Use engine to create transactions...
/// // Engine is automatically cleaned up when dropped
/// ```
pub struct ModSecurityEngine {
    inner: *mut ffi::ModSecurity,
}

// Safety: ModSecurity engine can be moved between threads.
unsafe impl Send for ModSecurityEngine {}

// Safety: After initialization (msc_init + msc_set_connector_info + msc_set_log_cb),
// the engine is only accessed via msc_create_rules_set() and msc_new_transaction(),
// which read but do not mutate the engine state. This makes sharing via
// Arc<ModSecurityEngine> safe for the global singleton pattern.
unsafe impl Sync for ModSecurityEngine {}

impl ModSecurityEngine {
    /// Create a new ModSecurity engine
    ///
    /// # Arguments
    ///
    /// * `connector_info` - Identifier for this connector (e.g., "api_fence/1.0")
    ///
    /// # Errors
    ///
    /// Returns `ModSecError::InitializationFailed` if engine creation fails.
    pub fn new(connector_info: &str) -> ModSecResult<Self> {
        // Safety: msc_init returns NULL on failure, we check for that
        let inner = unsafe { ffi::msc_init() };

        if inner.is_null() {
            return Err(ModSecError::InitializationFailed);
        }

        // Set connector info
        if let Ok(connector_cstr) = CString::new(connector_info) {
            // Safety: inner is valid (checked above), connector_cstr is null-terminated
            unsafe {
                ffi::msc_set_connector_info(inner, connector_cstr.as_ptr());
            }
        }

        // Set up the log callback to collect matched rules
        // Safety: inner is valid, callback is a valid function pointer
        unsafe {
            ffi::msc_set_log_cb(inner, Some(modsec_log_callback));
        }

        Ok(Self { inner })
    }

    /// Get the raw pointer to the engine
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid for the lifetime of this engine.
    /// Do not store or use after the engine is dropped.
    pub(crate) fn as_ptr(&self) -> *mut ffi::ModSecurity {
        self.inner
    }
}

impl Drop for ModSecurityEngine {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // Safety: inner was created by msc_init and is valid
            unsafe {
                ffi::msc_cleanup(self.inner);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_engine_creation() {
        use super::*;
        let engine = ModSecurityEngine::new("test/1.0");
        assert!(engine.is_ok());
    }

    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_engine_drop() {
        use super::*;
        {
            let _engine = ModSecurityEngine::new("test/1.0").unwrap();
            // Engine should be valid here
        }
        // Engine should be cleaned up after scope exit
    }
}
