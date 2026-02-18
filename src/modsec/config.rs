// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! ModSecurity configuration types
//!
//! This module defines configuration types for ModSecurity integration.

use schemars::JsonSchema;
use serde::Deserialize;

/// Main ModSecurity configuration
///
/// This configures all aspects of WAF scanning including request/response
/// scanning, thread pool settings, and ruleset configuration.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(title = "ModSecurity Configuration")]
pub struct ModSecurityConfig {
    /// Enable request body scanning (default: false)
    pub scan_request: bool,

    /// Enable response body scanning (default: false)
    pub scan_response: bool,

    /// Use request scanning API for response body (default: false)
    ///
    /// When true, response body is passed through `processRequestBody()`
    /// instead of `processResponseBody()` for more thorough scanning
    /// with request-oriented rules (CRS REQUEST-* rules are more comprehensive).
    pub scan_response_as_request: bool,

    /// Action to take when request scan matches (default: Block)
    pub request_action: ScanAction,

    /// Action to take when response scan matches (default: Alert)
    pub response_action: ScanAction,

    /// Thread pool configuration
    pub pool: ScannerPoolConfig,

    /// String extraction configuration for JSON optimization
    pub string_extraction: StringExtractorConfig,

    /// Primary ruleset configuration (OLD rules for migration)
    ///
    /// This ruleset is always evaluated. If no secondary ruleset is configured,
    /// this is the only ruleset used for enforcement.
    pub primary_ruleset: Option<RulesetConfig>,

    /// Secondary ruleset for testing (NEW rules for migration)
    ///
    /// When configured, both rulesets are evaluated. If both match,
    /// the secondary (NEW) result is used for enforcement, allowing
    /// seamless migration to new CRS versions.
    pub secondary_ruleset: Option<RulesetConfig>,
}

impl Default for ModSecurityConfig {
    fn default() -> Self {
        Self {
            scan_request: false,
            scan_response: false,
            scan_response_as_request: false,
            request_action: ScanAction::Block,
            response_action: ScanAction::Alert,
            pool: ScannerPoolConfig::default(),
            string_extraction: StringExtractorConfig::default(),
            primary_ruleset: None,
            secondary_ruleset: None,
        }
    }
}

impl ModSecurityConfig {
    /// Check if ModSecurity scanning is enabled
    pub fn is_enabled(&self) -> bool {
        (self.scan_request || self.scan_response) && self.primary_ruleset.is_some()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if (self.scan_request || self.scan_response) && self.primary_ruleset.is_none() {
            return Err(
                "modsecurity scanning is enabled but no primary_ruleset is configured".to_string(),
            );
        }

        if let Some(ref ruleset) = self.primary_ruleset {
            ruleset.validate()?;
        }

        if let Some(ref ruleset) = self.secondary_ruleset {
            ruleset.validate()?;
        }

        self.pool.validate()?;
        self.string_extraction.validate()?;

        Ok(())
    }
}

/// Action to take when ModSecurity rules match
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ScanAction {
    /// Block the request/response (return error to client)
    #[default]
    Block,
    /// Alert only (log and set metadata, but allow through)
    Alert,
}

/// Per-API pool behavior configuration for ModSecurity scanning
///
/// Thread count is no longer per-API; it is controlled globally via
/// the `API_FENCE_MODSEC_THREADS` environment variable or defaults
/// to the number of available CPUs. This struct retains per-API
/// timeout and queue settings.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(title = "Scanner Pool Configuration")]
pub struct ScannerPoolConfig {
    /// Maximum scan timeout in milliseconds (default: 100)
    pub timeout_ms: u64,

    /// Action to take when scan times out (default: Allow)
    pub timeout_action: TimeoutAction,

    /// Maximum queue depth for pending scan jobs (default: 1000)
    pub queue_capacity: usize,
}

impl Default for ScannerPoolConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 100,
            timeout_action: TimeoutAction::Allow,
            queue_capacity: 1000,
        }
    }
}

impl ScannerPoolConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be greater than 0".to_string());
        }

        if self.queue_capacity == 0 {
            return Err("queue_capacity must be greater than 0".to_string());
        }

        Ok(())
    }
}

/// Action to take when scan timeout is exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TimeoutAction {
    /// Allow the request/response through (fail open)
    #[default]
    Allow,
    /// Block the request/response (fail closed)
    Block,
}

/// Configuration for a ModSecurity ruleset
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[schemars(title = "Ruleset Configuration")]
pub struct RulesetConfig {
    /// Unique name for this ruleset (used in metrics and metadata)
    pub name: String,

    /// Use bundled CoreRuleSet (CRS) rules (default: false)
    ///
    /// When true, the bundled CRS v4.0.0 rules are automatically loaded.
    /// This provides zero-configuration WAF protection with essential rules:
    /// - SQL Injection (942)
    /// - Cross-Site Scripting (941)
    /// - Remote Code Execution (932)
    /// - Local/Remote File Inclusion (930, 931)
    /// - Protocol Enforcement (920, 921)
    #[serde(default)]
    pub use_bundled_crs: bool,

    /// Bundled CRS rule profile (default: "full")
    ///
    /// Options:
    /// - "full": All bundled CRS rules (request + response)
    /// - "request": Request rules only (faster, no response scanning)
    /// - "minimal": SQLi, XSS, RCE only (fastest, most critical attacks)
    #[serde(default = "default_crs_profile")]
    pub bundled_crs_profile: String,

    /// Paths to rule files (can use glob patterns like `/path/*.conf`)
    #[serde(default)]
    pub rules_path: Vec<String>,

    /// Remote rules configuration (alternative to rules_path)
    #[serde(default)]
    pub rules_remote: Option<RemoteRulesConfig>,

    /// Inline rules as a string (for simple configurations)
    #[serde(default)]
    pub rules_inline: Option<String>,
}

fn default_crs_profile() -> String {
    "full".to_string()
}

impl RulesetConfig {
    /// Create a new RulesetConfig with bundled CRS enabled
    pub fn bundled_crs(name: &str) -> Self {
        Self {
            name: name.to_string(),
            use_bundled_crs: true,
            bundled_crs_profile: "full".to_string(),
            rules_path: Vec::new(),
            rules_remote: None,
            rules_inline: None,
        }
    }

    /// Create a new RulesetConfig with bundled CRS and a specific profile
    pub fn bundled_crs_with_profile(name: &str, profile: &str) -> Self {
        Self {
            name: name.to_string(),
            use_bundled_crs: true,
            bundled_crs_profile: profile.to_string(),
            rules_path: Vec::new(),
            rules_remote: None,
            rules_inline: None,
        }
    }

    /// Get the bundled CRS rules based on the configured profile
    pub fn get_bundled_rules(&self) -> Option<&'static str> {
        if !self.use_bundled_crs {
            return None;
        }

        use super::bundled_crs;

        let rules = match self.bundled_crs_profile.as_str() {
            "minimal" => bundled_crs::minimal_rules(),
            "request" => bundled_crs::request_rules_only(),
            _ => bundled_crs::all_rules(), // "full" or any unrecognized profile
        };

        Some(rules)
    }

    /// Check if this ruleset has any rules configured
    pub fn has_rules(&self) -> bool {
        self.use_bundled_crs
            || !self.rules_path.is_empty()
            || self.rules_remote.is_some()
            || self.rules_inline.is_some()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("ruleset name cannot be empty".to_string());
        }

        if !self.has_rules() {
            return Err(format!(
                "ruleset '{}' has no rules configured (need use_bundled_crs, rules_path, rules_remote, or rules_inline)",
                self.name
            ));
        }

        // Validate bundled CRS profile
        if self.use_bundled_crs {
            let valid_profiles = ["full", "request", "minimal"];
            if !valid_profiles.contains(&self.bundled_crs_profile.as_str()) {
                return Err(format!(
                    "invalid bundled_crs_profile '{}', must be one of: full, request, minimal",
                    self.bundled_crs_profile
                ));
            }
        }

        Ok(())
    }
}

/// Configuration for loading rules from a remote URL
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[schemars(title = "Remote Rules Configuration")]
pub struct RemoteRulesConfig {
    /// URL to fetch rules from
    pub url: String,

    /// Optional API key for authentication
    #[serde(default)]
    pub key: Option<String>,
}

/// Configuration for JSON string extraction optimization
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(default)]
#[schemars(title = "String Extractor Configuration")]
pub struct StringExtractorConfig {
    /// Maximum number of unique strings to extract (default: 1000)
    pub max_unique_strings: usize,

    /// Minimum string length to include (default: 1)
    pub min_string_length: usize,

    /// Maximum string length to include (default: 10000)
    pub max_string_length: usize,

    /// Whether to skip base64-encoded strings (default: true)
    pub skip_base64: bool,
}

impl Default for StringExtractorConfig {
    fn default() -> Self {
        Self {
            max_unique_strings: 1000,
            min_string_length: 1,
            max_string_length: 10000,
            skip_base64: true,
        }
    }
}

impl StringExtractorConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.max_unique_strings == 0 {
            return Err("max_unique_strings must be greater than 0".to_string());
        }

        if self.min_string_length > self.max_string_length {
            return Err("min_string_length cannot be greater than max_string_length".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ModSecurityConfig::default();
        assert!(!config.scan_request);
        assert!(!config.scan_response);
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_config_validation_no_ruleset() {
        let config = ModSecurityConfig {
            scan_request: true,
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("primary_ruleset"));
    }

    #[test]
    fn test_config_validation_with_ruleset() {
        let config = ModSecurityConfig {
            scan_request: true,
            primary_ruleset: Some(RulesetConfig {
                name: "crs".to_string(),
                use_bundled_crs: false,
                bundled_crs_profile: "full".to_string(),
                rules_path: vec!["/etc/modsecurity/crs/*.conf".to_string()],
                rules_remote: None,
                rules_inline: None,
            }),
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_pool_config_validation() {
        let config = ScannerPoolConfig::default();
        assert!(config.validate().is_ok());

        let config = ScannerPoolConfig {
            timeout_ms: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_string_extractor_config_validation() {
        let mut config = StringExtractorConfig::default();
        assert!(config.validate().is_ok());

        config.min_string_length = 100;
        config.max_string_length = 50;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ruleset_config_validation() {
        let config = RulesetConfig {
            name: "".to_string(),
            use_bundled_crs: false,
            bundled_crs_profile: "full".to_string(),
            rules_path: vec![],
            rules_remote: None,
            rules_inline: None,
        };
        assert!(config.validate().is_err());

        let config = RulesetConfig {
            name: "test".to_string(),
            use_bundled_crs: false,
            bundled_crs_profile: "full".to_string(),
            rules_path: vec![],
            rules_remote: None,
            rules_inline: None,
        };
        assert!(config.validate().is_err());

        let config = RulesetConfig {
            name: "test".to_string(),
            use_bundled_crs: false,
            bundled_crs_profile: "full".to_string(),
            rules_path: vec!["/path/to/rules.conf".to_string()],
            rules_remote: None,
            rules_inline: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_deserialize_config() {
        let json = r#"{
            "scan_request": true,
            "scan_response": true,
            "request_action": "block",
            "response_action": "alert",
            "pool": {
                "timeout_ms": 200,
                "timeout_action": "block"
            },
            "primary_ruleset": {
                "name": "crs_3.3",
                "rules_path": ["/etc/modsecurity/crs/*.conf"]
            }
        }"#;

        let config: ModSecurityConfig = serde_json::from_str(json).unwrap();
        assert!(config.scan_request);
        assert!(config.scan_response);
        assert_eq!(config.request_action, ScanAction::Block);
        assert_eq!(config.response_action, ScanAction::Alert);
        assert_eq!(config.pool.timeout_ms, 200);
        assert_eq!(config.pool.timeout_action, TimeoutAction::Block);
        assert!(config.primary_ruleset.is_some());
    }

    #[test]
    fn test_bundled_crs_config() {
        let config = RulesetConfig::bundled_crs("crs");
        assert!(config.validate().is_ok());
        assert!(config.use_bundled_crs);
        assert_eq!(config.bundled_crs_profile, "full");
        assert!(config.has_rules());
    }

    #[test]
    fn test_bundled_crs_profiles() {
        let config = RulesetConfig::bundled_crs_with_profile("crs", "minimal");
        assert!(config.validate().is_ok());
        assert_eq!(config.bundled_crs_profile, "minimal");

        let config = RulesetConfig::bundled_crs_with_profile("crs", "request");
        assert!(config.validate().is_ok());

        let config = RulesetConfig::bundled_crs_with_profile("crs", "invalid");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_bundled_rules_content() {
        let config = RulesetConfig::bundled_crs("crs");
        let rules = config.get_bundled_rules();
        assert!(rules.is_some());
        let rules = rules.unwrap();
        assert!(rules.contains("SecRule"));
        assert!(rules.contains("942")); // SQLi rules
    }

    #[test]
    fn test_config_with_bundled_crs_json() {
        let json = r#"{
            "scan_request": true,
            "primary_ruleset": {
                "name": "crs",
                "use_bundled_crs": true,
                "bundled_crs_profile": "minimal"
            }
        }"#;

        let config: ModSecurityConfig = serde_json::from_str(json).unwrap();
        assert!(config.scan_request);
        let ruleset = config.primary_ruleset.as_ref().unwrap();
        assert!(ruleset.use_bundled_crs);
        assert_eq!(ruleset.bundled_crs_profile, "minimal");
        assert!(config.validate().is_ok());
    }
}
