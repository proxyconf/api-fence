// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! ModSecurity intervention types
//!
//! When ModSecurity rules match and trigger disruptive actions,
//! the intervention details are captured in these types.

/// Intervention result from ModSecurity
///
/// Represents a disruptive action triggered by a rule match.
#[derive(Debug, Clone)]
pub struct Intervention {
    /// HTTP status code to return (e.g., 403)
    pub status: u16,

    /// Redirect URL (for 3xx responses)
    pub url: Option<String>,

    /// Log message from the triggered rule
    pub log: Option<String>,

    /// Whether this intervention is disruptive (blocks the request)
    pub disruptive: bool,
}

impl Intervention {
    /// Create a new intervention
    pub fn new(status: u16, disruptive: bool) -> Self {
        Self {
            status,
            url: None,
            log: None,
            disruptive,
        }
    }

    /// Create an intervention with a log message
    pub fn with_log(status: u16, log: String, disruptive: bool) -> Self {
        Self {
            status,
            url: None,
            log: Some(log),
            disruptive,
        }
    }
}

/// Information about a matched ModSecurity rule
#[derive(Debug, Clone)]
pub struct MatchedRule {
    /// Rule ID (e.g., 942100 for SQL injection)
    pub rule_id: u32,

    /// Severity level (e.g., "CRITICAL", "WARNING")
    pub severity: String,

    /// Human-readable message describing the match
    pub message: String,

    /// Source file containing the rule
    pub file: String,

    /// Line number in the source file
    pub line: u32,

    /// Rule tags (e.g., "OWASP_CRS", "SQL_INJECTION")
    pub tags: Vec<String>,
}

impl MatchedRule {
    /// Create a new matched rule
    pub fn new(rule_id: u32, message: String) -> Self {
        Self {
            rule_id,
            severity: String::new(),
            message,
            file: String::new(),
            line: 0,
            tags: Vec::new(),
        }
    }

    /// Create a matched rule with full details
    pub fn with_details(
        rule_id: u32,
        severity: String,
        message: String,
        file: String,
        line: u32,
        tags: Vec<String>,
    ) -> Self {
        Self {
            rule_id,
            severity,
            message,
            file,
            line,
            tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intervention_new() {
        let intervention = Intervention::new(403, true);
        assert_eq!(intervention.status, 403);
        assert!(intervention.disruptive);
        assert!(intervention.url.is_none());
        assert!(intervention.log.is_none());
    }

    #[test]
    fn test_intervention_with_log() {
        let intervention = Intervention::with_log(403, "SQL injection detected".to_string(), true);
        assert_eq!(intervention.status, 403);
        assert!(intervention.disruptive);
        assert_eq!(intervention.log, Some("SQL injection detected".to_string()));
    }

    #[test]
    fn test_matched_rule_new() {
        let rule = MatchedRule::new(942100, "SQL injection attack detected".to_string());
        assert_eq!(rule.rule_id, 942100);
        assert_eq!(rule.message, "SQL injection attack detected");
        assert!(rule.severity.is_empty());
    }

    #[test]
    fn test_matched_rule_with_details() {
        let rule = MatchedRule::with_details(
            942100,
            "CRITICAL".to_string(),
            "SQL injection attack detected".to_string(),
            "/etc/modsecurity/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf".to_string(),
            42,
            vec!["OWASP_CRS".to_string(), "SQL_INJECTION".to_string()],
        );
        assert_eq!(rule.rule_id, 942100);
        assert_eq!(rule.severity, "CRITICAL");
        assert_eq!(rule.tags.len(), 2);
    }
}
