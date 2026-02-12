//! Security controls for the OpenAPI filter
//!
//! This module provides security hardening features including:
//! - Input length limits to prevent resource exhaustion
//! - JSON depth limits to prevent stack overflow
//! - Regex safety controls
//! - Schema complexity limits
//! - Error message sanitization
//!
//! ## Threat Model
//!
//! This module protects against:
//! - **Resource exhaustion attacks**: Oversized paths, headers, bodies
//! - **ReDoS attacks**: Malicious regex patterns or inputs
//! - **Stack overflow**: Deeply nested JSON or schemas
//! - **Information disclosure**: Internal paths in error messages
//!
//! ## Configuration
//!
//! All limits are configurable via the `security` section in filter config:
//!
//! ```json
//! {
//!   "security": {
//!     "max_path_length": 2048,
//!     "max_header_value_length": 8192,
//!     "max_json_depth": 32
//!   }
//! }
//! ```

use serde::Deserialize;
use thiserror::Error;

/// Maximum length of error detail messages (prevents information leakage)
const MAX_ERROR_DETAIL_LENGTH: usize = 1024;

/// Maximum length of regex input to prevent CPU exhaustion
const MAX_REGEX_INPUT_LENGTH: usize = 65536; // 64KB

/// Security limits for input validation
///
/// All limits have sensible defaults suitable for most API use cases.
/// Adjust these based on your specific requirements and threat model.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityLimits {
    /// Maximum URL path length in bytes (default: 2048)
    ///
    /// Paths longer than this are rejected with 414 URI Too Long.
    /// Most browsers support up to 2048 characters.
    #[serde(default = "default_max_path_length")]
    pub max_path_length: usize,

    /// Maximum header value length in bytes (default: 8192)
    ///
    /// Individual header values longer than this are rejected.
    /// Standard recommendation is 8KB per header.
    #[serde(default = "default_max_header_value_length")]
    pub max_header_value_length: usize,

    /// Maximum query string length in bytes (default: 8192)
    ///
    /// Query strings longer than this are rejected.
    #[serde(default = "default_max_query_string_length")]
    pub max_query_string_length: usize,

    /// Maximum request body size in bytes (default: 10MB)
    ///
    /// Bodies larger than this are rejected with 413 Payload Too Large.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Maximum JSON nesting depth (default: 32)
    ///
    /// JSON documents with deeper nesting are rejected.
    /// Prevents stack overflow during parsing.
    #[serde(default = "default_max_json_depth")]
    pub max_json_depth: usize,

    /// Maximum number of array items to validate (default: 1000)
    ///
    /// Arrays with more items are truncated for validation.
    /// Prevents CPU exhaustion on large arrays.
    #[serde(default = "default_max_array_items")]
    pub max_array_items: usize,

    /// Maximum number of object properties to validate (default: 100)
    ///
    /// Objects with more properties are truncated for validation.
    #[serde(default = "default_max_object_properties")]
    pub max_object_properties: usize,

    /// Maximum schema nesting depth (default: 32)
    ///
    /// Schemas deeper than this are rejected during compilation.
    #[serde(default = "default_max_schema_depth")]
    pub max_schema_depth: usize,

    /// Maximum regex pattern length (default: 1024)
    ///
    /// Regex patterns longer than this in OpenAPI schemas are rejected.
    #[serde(default = "default_max_regex_pattern_length")]
    pub max_regex_pattern_length: usize,
}

// Default value functions for serde
fn default_max_path_length() -> usize {
    2048
}
fn default_max_header_value_length() -> usize {
    8192
}
fn default_max_query_string_length() -> usize {
    8192
}
fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}
fn default_max_json_depth() -> usize {
    32
}
fn default_max_array_items() -> usize {
    1000
}
fn default_max_object_properties() -> usize {
    100
}
fn default_max_schema_depth() -> usize {
    32
}
fn default_max_regex_pattern_length() -> usize {
    1024
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self {
            max_path_length: default_max_path_length(),
            max_header_value_length: default_max_header_value_length(),
            max_query_string_length: default_max_query_string_length(),
            max_body_size: default_max_body_size(),
            max_json_depth: default_max_json_depth(),
            max_array_items: default_max_array_items(),
            max_object_properties: default_max_object_properties(),
            max_schema_depth: default_max_schema_depth(),
            max_regex_pattern_length: default_max_regex_pattern_length(),
        }
    }
}

impl SecurityLimits {
    /// Validate security limits configuration
    ///
    /// Ensures limits are within reasonable bounds and not set to dangerous values.
    pub fn validate(&self) -> Result<(), SecurityError> {
        // Minimum limits to prevent misconfiguration
        if self.max_path_length < 64 {
            return Err(SecurityError::InvalidLimit {
                name: "max_path_length".to_string(),
                value: self.max_path_length,
                reason: "must be at least 64 bytes".to_string(),
            });
        }

        if self.max_json_depth < 2 {
            return Err(SecurityError::InvalidLimit {
                name: "max_json_depth".to_string(),
                value: self.max_json_depth,
                reason: "must be at least 2".to_string(),
            });
        }

        if self.max_schema_depth < 2 {
            return Err(SecurityError::InvalidLimit {
                name: "max_schema_depth".to_string(),
                value: self.max_schema_depth,
                reason: "must be at least 2".to_string(),
            });
        }

        Ok(())
    }
}

/// Security-related errors
#[derive(Error, Debug, Clone)]
pub enum SecurityError {
    /// Input exceeds maximum allowed length
    #[error("{input_type} too long: {length} bytes exceeds limit of {limit} bytes")]
    InputTooLong {
        input_type: InputType,
        length: usize,
        limit: usize,
    },

    /// JSON nesting too deep
    #[error("JSON nesting too deep: depth {depth} exceeds limit of {limit}")]
    JsonTooDeep { depth: usize, limit: usize },

    /// Schema too complex
    #[error("Schema too complex: {metric} {value} exceeds limit of {limit}")]
    SchemaTooComplex {
        metric: String,
        value: usize,
        limit: usize,
    },

    /// Regex pattern too long
    #[error("Regex pattern too long: {length} bytes exceeds limit of {limit} bytes")]
    RegexPatternTooLong { length: usize, limit: usize },

    /// Invalid security limit configuration
    #[error("Invalid security limit '{name}' = {value}: {reason}")]
    InvalidLimit {
        name: String,
        value: usize,
        reason: String,
    },
}

impl SecurityError {
    /// Get the HTTP status code for this security error
    pub fn status_code(&self) -> u16 {
        match self {
            SecurityError::InputTooLong { input_type, .. } => match input_type {
                InputType::Path => 414, // URI Too Long
                InputType::Body => 413, // Payload Too Large
                _ => 400,               // Bad Request
            },
            SecurityError::JsonTooDeep { .. } => 400,
            SecurityError::SchemaTooComplex { .. } => 500, // Internal - schema issue
            SecurityError::RegexPatternTooLong { .. } => 500, // Internal - schema issue
            SecurityError::InvalidLimit { .. } => 500,     // Internal - config issue
        }
    }
}

/// Type of input being validated (for error messages)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputType {
    Path,
    Header,
    QueryString,
    Body,
    RegexInput,
}

impl std::fmt::Display for InputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InputType::Path => write!(f, "Path"),
            InputType::Header => write!(f, "Header"),
            InputType::QueryString => write!(f, "Query string"),
            InputType::Body => write!(f, "Request body"),
            InputType::RegexInput => write!(f, "Regex input"),
        }
    }
}

/// Check if an input exceeds the maximum length
pub fn check_input_length(
    input: &[u8],
    input_type: InputType,
    max_length: usize,
) -> Result<(), SecurityError> {
    if input.len() > max_length {
        return Err(SecurityError::InputTooLong {
            input_type,
            length: input.len(),
            limit: max_length,
        });
    }
    Ok(())
}

/// Check if a string input exceeds the maximum length
pub fn check_string_length(
    input: &str,
    input_type: InputType,
    max_length: usize,
) -> Result<(), SecurityError> {
    if input.len() > max_length {
        return Err(SecurityError::InputTooLong {
            input_type,
            length: input.len(),
            limit: max_length,
        });
    }
    Ok(())
}

/// Check if regex input is safe to process
pub fn check_regex_input_length(input: &str) -> Result<(), SecurityError> {
    if input.len() > MAX_REGEX_INPUT_LENGTH {
        return Err(SecurityError::InputTooLong {
            input_type: InputType::RegexInput,
            length: input.len(),
            limit: MAX_REGEX_INPUT_LENGTH,
        });
    }
    Ok(())
}

/// Sanitize error messages to remove sensitive information
///
/// Removes:
/// - Internal file paths
/// - Stack traces
/// - Truncates overly long messages
pub fn sanitize_error_message(message: &str) -> String {
    let mut result = message.to_string();

    // Remove absolute file paths (Unix style)
    // Pattern: /path/to/file.ext or /path/to/directory
    let unix_path_pattern =
        regex::Regex::new(r"/[a-zA-Z0-9_/.-]+\.(rs|yaml|yml|json|toml)").expect("valid regex");
    result = unix_path_pattern.replace_all(&result, "[path]").to_string();

    // Remove absolute file paths (Windows style)
    let windows_path_pattern =
        regex::Regex::new(r"[A-Za-z]:\\[a-zA-Z0-9_\\.-]+").expect("valid regex");
    result = windows_path_pattern
        .replace_all(&result, "[path]")
        .to_string();

    // Remove common stack trace patterns
    let stack_trace_pattern = regex::Regex::new(r"at [a-zA-Z0-9_:<>]+::\w+").expect("valid regex");
    result = stack_trace_pattern.replace_all(&result, "").to_string();

    // Remove line:column patterns often found in errors
    let line_col_pattern = regex::Regex::new(r":\d+:\d+").expect("valid regex");
    result = line_col_pattern.replace_all(&result, "").to_string();

    // Truncate if too long
    if result.len() > MAX_ERROR_DETAIL_LENGTH {
        result.truncate(MAX_ERROR_DETAIL_LENGTH - 3);
        result.push_str("...");
    }

    // Clean up multiple spaces
    let multi_space = regex::Regex::new(r"\s+").expect("valid regex");
    result = multi_space.replace_all(&result, " ").to_string();

    result.trim().to_string()
}

/// Parse JSON with depth limiting
///
/// Returns an error if the JSON exceeds the maximum nesting depth.
pub fn parse_json_with_depth_limit(
    data: &[u8],
    max_depth: usize,
) -> Result<serde_json::Value, SecurityError> {
    // First, check the depth by scanning the bytes
    let depth = estimate_json_depth(data);
    if depth > max_depth {
        return Err(SecurityError::JsonTooDeep {
            depth,
            limit: max_depth,
        });
    }

    // Now parse normally - serde_json has its own recursion limit (128 by default)
    serde_json::from_slice(data).map_err(|_| SecurityError::JsonTooDeep {
        depth,
        limit: max_depth,
    })
}

/// Estimate JSON nesting depth by scanning for brackets
///
/// This is a fast heuristic that may slightly overcount depth
/// (e.g., brackets in strings), but is safe for security purposes.
fn estimate_json_depth(data: &[u8]) -> usize {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for &byte in data {
        if escape_next {
            escape_next = false;
            continue;
        }

        match byte {
            b'\\' if in_string => {
                escape_next = true;
            }
            b'"' => {
                in_string = !in_string;
            }
            b'[' | b'{' if !in_string => {
                current_depth += 1;
                if current_depth > max_depth {
                    max_depth = current_depth;
                }
            }
            b']' | b'}' if !in_string => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

/// Estimate schema complexity by counting nodes
///
/// Returns the total number of nodes in the schema tree.
pub fn estimate_schema_complexity(schema: &openapiv3::Schema, max_depth: usize) -> usize {
    count_schema_nodes(schema, 0, max_depth)
}

fn count_schema_nodes(schema: &openapiv3::Schema, current_depth: usize, max_depth: usize) -> usize {
    if current_depth >= max_depth {
        return 1; // Count this node but don't recurse
    }

    let mut count = 1; // Count this node

    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(type_schema) => match type_schema {
            openapiv3::Type::Object(obj) => {
                for (_name, prop) in &obj.properties {
                    if let openapiv3::ReferenceOr::Item(prop_schema) = prop {
                        count += count_schema_nodes(prop_schema, current_depth + 1, max_depth);
                    } else {
                        count += 1; // Count reference as one node
                    }
                }
                if let Some(openapiv3::AdditionalProperties::Schema(additional)) =
                    &obj.additional_properties
                {
                    if let openapiv3::ReferenceOr::Item(additional_schema) = additional.as_ref() {
                        count +=
                            count_schema_nodes(additional_schema, current_depth + 1, max_depth);
                    }
                }
            }
            openapiv3::Type::Array(arr) => {
                if let Some(openapiv3::ReferenceOr::Item(items_schema)) = &arr.items {
                    count += count_schema_nodes(items_schema, current_depth + 1, max_depth);
                }
            }
            _ => {} // String, Number, Integer, Boolean have no children
        },
        openapiv3::SchemaKind::OneOf { one_of } => {
            for variant in one_of {
                if let openapiv3::ReferenceOr::Item(variant_schema) = variant {
                    count += count_schema_nodes(variant_schema, current_depth + 1, max_depth);
                } else {
                    count += 1;
                }
            }
        }
        openapiv3::SchemaKind::AnyOf { any_of } => {
            for variant in any_of {
                if let openapiv3::ReferenceOr::Item(variant_schema) = variant {
                    count += count_schema_nodes(variant_schema, current_depth + 1, max_depth);
                } else {
                    count += 1;
                }
            }
        }
        openapiv3::SchemaKind::AllOf { all_of } => {
            for variant in all_of {
                if let openapiv3::ReferenceOr::Item(variant_schema) = variant {
                    count += count_schema_nodes(variant_schema, current_depth + 1, max_depth);
                } else {
                    count += 1;
                }
            }
        }
        openapiv3::SchemaKind::Not { not } => {
            if let openapiv3::ReferenceOr::Item(not_schema) = not.as_ref() {
                count += count_schema_nodes(not_schema, current_depth + 1, max_depth);
            } else {
                count += 1;
            }
        }
        openapiv3::SchemaKind::Any(_) => {} // Any schema has no children
    }

    count
}

/// Check if a regex pattern is safe to compile
pub fn check_regex_pattern_length(pattern: &str, max_length: usize) -> Result<(), SecurityError> {
    if pattern.len() > max_length {
        return Err(SecurityError::RegexPatternTooLong {
            length: pattern.len(),
            limit: max_length,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_limits_default() {
        let limits = SecurityLimits::default();
        assert_eq!(limits.max_path_length, 2048);
        assert_eq!(limits.max_header_value_length, 8192);
        assert_eq!(limits.max_query_string_length, 8192);
        assert_eq!(limits.max_body_size, 10 * 1024 * 1024);
        assert_eq!(limits.max_json_depth, 32);
        assert_eq!(limits.max_array_items, 1000);
        assert_eq!(limits.max_object_properties, 100);
        assert_eq!(limits.max_schema_depth, 32);
        assert_eq!(limits.max_regex_pattern_length, 1024);
    }

    #[test]
    fn test_security_limits_validate_success() {
        let limits = SecurityLimits::default();
        assert!(limits.validate().is_ok());
    }

    #[test]
    fn test_security_limits_validate_path_too_small() {
        let mut limits = SecurityLimits::default();
        limits.max_path_length = 10;
        let result = limits.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_path_length"));
    }

    #[test]
    fn test_security_limits_validate_json_depth_too_small() {
        let mut limits = SecurityLimits::default();
        limits.max_json_depth = 1;
        let result = limits.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("max_json_depth"));
    }

    #[test]
    fn test_check_input_length_ok() {
        let input = b"short input";
        assert!(check_input_length(input, InputType::Path, 100).is_ok());
    }

    #[test]
    fn test_check_input_length_exceeded() {
        let input = b"this is a long input";
        let result = check_input_length(input, InputType::Path, 10);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SecurityError::InputTooLong { .. }));
        assert_eq!(err.status_code(), 414); // URI Too Long for path
    }

    #[test]
    fn test_check_string_length_ok() {
        let input = "short";
        assert!(check_string_length(input, InputType::Header, 100).is_ok());
    }

    #[test]
    fn test_check_string_length_exceeded() {
        let input = "this is a very long header value";
        let result = check_string_length(input, InputType::Header, 10);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SecurityError::InputTooLong { .. }));
        assert_eq!(err.status_code(), 400); // Bad Request for header
    }

    #[test]
    fn test_body_too_large_status_code() {
        let err = SecurityError::InputTooLong {
            input_type: InputType::Body,
            length: 1000,
            limit: 100,
        };
        assert_eq!(err.status_code(), 413); // Payload Too Large
    }

    #[test]
    fn test_sanitize_error_message_removes_unix_paths() {
        let msg = "Failed to load /home/user/config/schema.yaml";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains("/home/user"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_message_removes_windows_paths() {
        let msg = "Failed to load C:\\Users\\admin\\schema.json";
        let sanitized = sanitize_error_message(msg);
        assert!(!sanitized.contains("C:\\Users"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_error_message_truncates_long_messages() {
        let msg = "a".repeat(2000);
        let sanitized = sanitize_error_message(&msg);
        assert!(sanitized.len() <= MAX_ERROR_DETAIL_LENGTH);
        assert!(sanitized.ends_with("..."));
    }

    #[test]
    fn test_sanitize_error_message_preserves_short_messages() {
        let msg = "Simple error message";
        let sanitized = sanitize_error_message(msg);
        assert_eq!(sanitized, msg);
    }

    #[test]
    fn test_estimate_json_depth_flat() {
        let json = br#"{"a": 1, "b": 2}"#;
        assert_eq!(estimate_json_depth(json), 1);
    }

    #[test]
    fn test_estimate_json_depth_nested() {
        let json = br#"{"a": {"b": {"c": 1}}}"#;
        assert_eq!(estimate_json_depth(json), 3);
    }

    #[test]
    fn test_estimate_json_depth_array() {
        let json = br#"[[[1, 2], [3, 4]]]"#;
        assert_eq!(estimate_json_depth(json), 3);
    }

    #[test]
    fn test_estimate_json_depth_ignores_brackets_in_strings() {
        let json = br#"{"a": "[[[not nested]]]"}"#;
        assert_eq!(estimate_json_depth(json), 1);
    }

    #[test]
    fn test_parse_json_with_depth_limit_ok() {
        let json = br#"{"a": {"b": 1}}"#;
        let result = parse_json_with_depth_limit(json, 10);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_json_with_depth_limit_exceeded() {
        let json = br#"{"a": {"b": {"c": {"d": {"e": 1}}}}}"#;
        let result = parse_json_with_depth_limit(json, 3);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SecurityError::JsonTooDeep { .. }));
    }

    #[test]
    fn test_check_regex_pattern_length_ok() {
        let pattern = "^[a-z]+$";
        assert!(check_regex_pattern_length(pattern, 100).is_ok());
    }

    #[test]
    fn test_check_regex_pattern_length_exceeded() {
        let pattern = "a".repeat(2000);
        let result = check_regex_pattern_length(&pattern, 1024);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, SecurityError::RegexPatternTooLong { .. }));
    }

    #[test]
    fn test_check_regex_input_length_ok() {
        let input = "short input";
        assert!(check_regex_input_length(input).is_ok());
    }

    #[test]
    fn test_check_regex_input_length_exceeded() {
        let input = "a".repeat(100_000);
        let result = check_regex_input_length(&input);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_error_display() {
        let err = SecurityError::InputTooLong {
            input_type: InputType::Path,
            length: 5000,
            limit: 2048,
        };
        let msg = err.to_string();
        assert!(msg.contains("Path"));
        assert!(msg.contains("5000"));
        assert!(msg.contains("2048"));
    }

    #[test]
    fn test_input_type_display() {
        assert_eq!(InputType::Path.to_string(), "Path");
        assert_eq!(InputType::Header.to_string(), "Header");
        assert_eq!(InputType::QueryString.to_string(), "Query string");
        assert_eq!(InputType::Body.to_string(), "Request body");
        assert_eq!(InputType::RegexInput.to_string(), "Regex input");
    }

    #[test]
    fn test_deserialize_security_limits() {
        let json = r#"{
            "max_path_length": 4096,
            "max_json_depth": 16
        }"#;
        let limits: SecurityLimits = serde_json::from_str(json).expect("valid json");
        assert_eq!(limits.max_path_length, 4096);
        assert_eq!(limits.max_json_depth, 16);
        // Defaults should be applied for non-specified fields
        assert_eq!(limits.max_header_value_length, 8192);
    }
}
