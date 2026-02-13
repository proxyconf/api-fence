//! Bundled CoreRuleSet (CRS) rules
//!
//! This module provides OWASP CoreRuleSet v4.0.0 rules that are
//! downloaded during build time and embedded into the binary.
//!
//! # Included Rules
//!
//! - Protocol Enforcement (920, 921)
//! - SQL Injection (942)
//! - Cross-Site Scripting (941)
//! - Remote Code Execution (932)
//! - Local File Inclusion (930)
//! - Remote File Inclusion (931)
//! - Data Leakage Detection (950, 951)
//!
//! # Rule Profiles
//!
//! Three profiles are available:
//!
//! - **full**: All essential CRS rules (request + response scanning)
//! - **request**: Request rules only (faster, no response inspection)
//! - **minimal**: SQLi, XSS, RCE only (fastest, most critical attacks)
//!
//! # Usage
//!
//! ```ignore
//! use api_fence::modsec::bundled_crs;
//!
//! // Get all bundled rules
//! let rules = bundled_crs::all_rules();
//!
//! // Or get a specific profile
//! let minimal = bundled_crs::minimal_rules();
//! ```

// Include the generated rules from build.rs
include!(concat!(env!("OUT_DIR"), "/bundled_crs_generated.rs"));

/// Rule categories that can be selectively enabled
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleCategory {
    /// CRS setup and initialization (required)
    Setup,
    /// Protocol enforcement (920, 921)
    Protocol,
    /// SQL Injection (942)
    SqlInjection,
    /// Cross-Site Scripting (941)
    Xss,
    /// Remote Code Execution (932)
    Rce,
    /// Local File Inclusion (930)
    Lfi,
    /// Remote File Inclusion (931)
    Rfi,
    /// Data leakage detection (950, 951)
    DataLeakage,
}

impl RuleCategory {
    /// Get all available categories
    pub fn all() -> &'static [RuleCategory] {
        &[
            RuleCategory::Setup,
            RuleCategory::Protocol,
            RuleCategory::SqlInjection,
            RuleCategory::Xss,
            RuleCategory::Rce,
            RuleCategory::Lfi,
            RuleCategory::Rfi,
            RuleCategory::DataLeakage,
        ]
    }
}

/// Get all bundled CRS rules (full profile)
///
/// This returns all essential CRS rules ready to be loaded by ModSecurity.
/// Rules are ordered according to CRS conventions (setup first, then
/// request rules by ID, then response rules).
#[inline]
pub fn all_rules() -> &'static str {
    FULL_RULES
}

/// Get request-only rules (no response scanning)
///
/// Use this for faster scanning when you only need to protect
/// against malicious requests but don't need response inspection.
#[inline]
pub fn request_rules_only() -> &'static str {
    REQUEST_RULES
}

/// Get a minimal rule set for high-performance scenarios
///
/// Includes only the most critical attack detection:
/// - SQL Injection
/// - Cross-Site Scripting
/// - Remote Code Execution
#[inline]
pub fn minimal_rules() -> &'static str {
    MINIMAL_RULES
}

/// Get the CRS version
#[inline]
pub fn version() -> &'static str {
    CRS_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_rules_not_empty() {
        let rules = all_rules();
        assert!(!rules.is_empty());
        // Should contain SecRule directives
        assert!(rules.contains("SecRule"));
    }

    #[test]
    fn test_request_rules_not_empty() {
        let rules = request_rules_only();
        assert!(!rules.is_empty());
        assert!(rules.contains("SecRule"));
    }

    #[test]
    fn test_minimal_rules_not_empty() {
        let rules = minimal_rules();
        assert!(!rules.is_empty());
        assert!(rules.contains("SecRule"));
    }

    #[test]
    fn test_sqli_rules_present() {
        assert!(all_rules().contains("942"));
    }

    #[test]
    fn test_xss_rules_present() {
        assert!(all_rules().contains("941"));
    }

    #[test]
    fn test_version() {
        assert!(version().starts_with("v4"));
    }
}
