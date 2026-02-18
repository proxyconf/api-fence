// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! ModSecurity rules set wrapper
//!
//! This module provides a safe wrapper around ModSecurity rule sets.

use crate::modsec::engine::ModSecurityEngine;
use crate::modsec::error::{ModSecError, ModSecResult};
use crate::modsec::ffi;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::sync::Arc;

/// Safe wrapper around a ModSecurity rules set
///
/// A rules set contains compiled ModSecurity rules loaded from files
/// or remote URLs. Once compiled, it can be shared across threads.
///
/// # Thread Safety
///
/// `RulesSet` is `Send + Sync` after rules are loaded. It can be wrapped
/// in `Arc` and shared across threads for creating transactions.
///
/// # Example
///
/// ```ignore
/// use api_fence::modsec::{ModSecurityEngine, RulesSet};
/// use std::sync::Arc;
///
/// let engine = Arc::new(ModSecurityEngine::new("api_fence/1.0")?);
/// let mut rules = RulesSet::new(engine)?;
/// rules.add_file("/etc/modsecurity/crs/crs-setup.conf")?;
/// rules.add_file("/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf")?;
///
/// let rules = Arc::new(rules);
/// // Now rules can be shared across threads
/// ```
pub struct RulesSet {
    inner: *mut ffi::RulesSet,
    /// Keep engine alive while rules exist
    _engine: Arc<ModSecurityEngine>,
    /// Number of rules loaded
    rules_count: i32,
}

// Safety: RulesSet is immutable after loading and can be shared
unsafe impl Send for RulesSet {}
unsafe impl Sync for RulesSet {}

impl RulesSet {
    /// Create a new empty rules set
    ///
    /// # Arguments
    ///
    /// * `engine` - The ModSecurity engine to use
    ///
    /// # Errors
    ///
    /// Returns `ModSecError::RulesSetCreationFailed` if creation fails.
    pub fn new(engine: Arc<ModSecurityEngine>) -> ModSecResult<Self> {
        // Safety: msc_create_rules_set returns NULL on failure
        let inner = unsafe { ffi::msc_create_rules_set() };

        if inner.is_null() {
            return Err(ModSecError::RulesSetCreationFailed);
        }

        Ok(Self {
            inner,
            _engine: engine,
            rules_count: 0,
        })
    }

    /// Add rules from a file
    ///
    /// Supports glob patterns (e.g., `/path/to/rules/*.conf`).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the rules file (can be a glob pattern)
    ///
    /// # Returns
    ///
    /// Number of rules loaded from this file.
    ///
    /// # Errors
    ///
    /// Returns `ModSecError::RulesLoadError` if loading fails.
    pub fn add_file<P: AsRef<Path>>(&mut self, path: P) -> ModSecResult<i32> {
        let path_str = path.as_ref().to_string_lossy();

        // Check if this is a glob pattern
        if path_str.contains('*') || path_str.contains('?') {
            return self.add_files_glob(&path_str);
        }

        let path_cstr =
            CString::new(path_str.as_bytes()).map_err(|_| ModSecError::RulesLoadError {
                path: path_str.to_string(),
                message: "path contains null byte".to_string(),
            })?;

        let mut error: *const std::os::raw::c_char = std::ptr::null();

        // Safety: inner is valid, path_cstr is null-terminated, error is valid pointer
        let result = unsafe { ffi::msc_rules_add_file(self.inner, path_cstr.as_ptr(), &mut error) };

        if result < 0 {
            let error_msg = if !error.is_null() {
                // Safety: error points to a C string from libmodsecurity
                let msg = unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .to_string();
                // Note: we don't free error here as libmodsecurity manages it
                msg
            } else {
                "unknown error".to_string()
            };

            return Err(ModSecError::RulesLoadError {
                path: path_str.to_string(),
                message: error_msg,
            });
        }

        self.rules_count += result;
        Ok(result)
    }

    /// Add rules from files matching a glob pattern
    fn add_files_glob(&mut self, pattern: &str) -> ModSecResult<i32> {
        let paths = glob::glob(pattern).map_err(|e| ModSecError::GlobPatternError {
            pattern: pattern.to_string(),
            message: e.to_string(),
        })?;

        let mut total = 0;
        for entry in paths {
            let path = entry.map_err(|e| ModSecError::GlobPatternError {
                pattern: pattern.to_string(),
                message: e.to_string(),
            })?;

            // Recursively add (but won't be a glob since we resolved it)
            let path_str = path.to_string_lossy();
            let path_cstr =
                CString::new(path_str.as_bytes()).map_err(|_| ModSecError::RulesLoadError {
                    path: path_str.to_string(),
                    message: "path contains null byte".to_string(),
                })?;

            let mut error: *const std::os::raw::c_char = std::ptr::null();
            let result =
                unsafe { ffi::msc_rules_add_file(self.inner, path_cstr.as_ptr(), &mut error) };

            if result < 0 {
                let error_msg = if !error.is_null() {
                    unsafe { CStr::from_ptr(error) }
                        .to_string_lossy()
                        .to_string()
                } else {
                    "unknown error".to_string()
                };

                return Err(ModSecError::RulesLoadError {
                    path: path_str.to_string(),
                    message: error_msg,
                });
            }

            total += result;
        }

        self.rules_count += total;
        Ok(total)
    }

    /// Add rules from a remote URL
    ///
    /// # Arguments
    ///
    /// * `uri` - URL to fetch rules from
    /// * `key` - Optional API key for authentication
    ///
    /// # Returns
    ///
    /// Number of rules loaded.
    ///
    /// # Errors
    ///
    /// Returns `ModSecError::RemoteRulesLoadError` if loading fails.
    pub fn add_remote(&mut self, uri: &str, key: Option<&str>) -> ModSecResult<i32> {
        let uri_cstr = CString::new(uri).map_err(|_| ModSecError::RemoteRulesLoadError {
            uri: uri.to_string(),
            message: "URI contains null byte".to_string(),
        })?;

        let key_cstr = match key {
            Some(k) => Some(
                CString::new(k).map_err(|_| ModSecError::RemoteRulesLoadError {
                    uri: uri.to_string(),
                    message: "key contains null byte".to_string(),
                })?,
            ),
            None => None,
        };

        let key_ptr = key_cstr
            .as_ref()
            .map(|k| k.as_ptr())
            .unwrap_or(std::ptr::null());

        let mut error: *const std::os::raw::c_char = std::ptr::null();

        // Safety: inner is valid, uri_cstr and key_ptr are null-terminated or null
        let result = unsafe {
            ffi::msc_rules_add_remote(self.inner, key_ptr, uri_cstr.as_ptr(), &mut error)
        };

        if result < 0 {
            let error_msg = if !error.is_null() {
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .to_string()
            } else {
                "unknown error".to_string()
            };

            return Err(ModSecError::RemoteRulesLoadError {
                uri: uri.to_string(),
                message: error_msg,
            });
        }

        self.rules_count += result;
        Ok(result)
    }

    /// Add rules from a string
    ///
    /// # Arguments
    ///
    /// * `rules` - ModSecurity rules as a string
    ///
    /// # Returns
    ///
    /// Number of rules loaded.
    ///
    /// # Errors
    ///
    /// Returns `ModSecError::InlineRulesParseError` if parsing fails.
    pub fn add_inline(&mut self, rules: &str) -> ModSecResult<i32> {
        let rules_cstr = CString::new(rules).map_err(|_| ModSecError::InlineRulesParseError {
            message: "rules contain null byte".to_string(),
        })?;

        let mut error: *const std::os::raw::c_char = std::ptr::null();

        // Safety: inner is valid, rules_cstr is null-terminated
        let result = unsafe { ffi::msc_rules_add(self.inner, rules_cstr.as_ptr(), &mut error) };

        if result < 0 {
            let error_msg = if !error.is_null() {
                unsafe { CStr::from_ptr(error) }
                    .to_string_lossy()
                    .to_string()
            } else {
                "unknown error".to_string()
            };

            return Err(ModSecError::InlineRulesParseError { message: error_msg });
        }

        self.rules_count += result;
        Ok(result)
    }

    /// Get the total number of rules loaded
    pub fn rules_count(&self) -> i32 {
        self.rules_count
    }

    /// Get a reference to the engine
    pub(crate) fn engine(&self) -> Arc<ModSecurityEngine> {
        Arc::clone(&self._engine)
    }

    /// Get the raw pointer to the rules set
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid for the lifetime of this rules set.
    pub(crate) fn as_ptr(&self) -> *mut ffi::RulesSet {
        self.inner
    }
}

impl Drop for RulesSet {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // Safety: inner was created by msc_create_rules_set and is valid
            unsafe {
                ffi::msc_rules_cleanup(self.inner);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "requires libmodsecurity installed"]
    fn test_rules_set_creation() {
        use super::*;
        let engine = Arc::new(ModSecurityEngine::new("test/1.0").unwrap());
        let rules = RulesSet::new(engine);
        assert!(rules.is_ok());
    }

    #[test]
    #[ignore = "requires libmodsecurity and CRS installed"]
    fn test_rules_add_inline() {
        use super::*;
        let engine = Arc::new(ModSecurityEngine::new("test/1.0").unwrap());
        let mut rules = RulesSet::new(engine).unwrap();

        let result = rules.add_inline(
            r#"
            SecRule ARGS "@contains test" "id:1,phase:2,deny,status:403"
            "#,
        );
        assert!(result.is_ok());
        assert!(rules.rules_count() > 0);
    }
}
