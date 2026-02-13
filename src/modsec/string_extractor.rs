//! JSON string extraction optimization
//!
//! This module extracts unique string values from JSON payloads
//! for more efficient ModSecurity scanning. Instead of scanning
//! the entire nested JSON structure, we extract unique strings
//! and scan them as a flat array.
//!
//! # Benefits
//!
//! - Reduces duplicate scanning (same string value in multiple fields)
//! - Allows skipping base64-encoded strings that cause false positives
//! - Provides metrics on extraction for observability
//!
//! # Example
//!
//! ```
//! use api_fence::modsec::{extract_strings, StringExtractorConfig};
//!
//! let json = br#"{"name": "Alice", "items": ["SELECT", "Alice"]}"#;
//! let config = StringExtractorConfig::default();
//! let result = extract_strings(json, &config);
//!
//! // "Alice" appears twice but is only extracted once
//! assert!(result.strings.contains(&"Alice".to_string()));
//! assert!(result.strings.contains(&"SELECT".to_string()));
//! ```

use crate::modsec::base64_detector::is_likely_base64;
use crate::modsec::config::StringExtractorConfig;
use std::collections::HashSet;

/// Result of string extraction from JSON
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    /// Unique strings extracted from the JSON
    pub strings: Vec<String>,

    /// Number of base64 strings that were skipped
    pub base64_skipped: usize,

    /// Whether the max_unique_strings limit was reached
    pub limit_reached: bool,

    /// Total number of strings encountered (before deduplication)
    pub total_encountered: usize,

    /// Number of strings filtered due to length constraints
    pub length_filtered: usize,
}

impl ExtractionResult {
    /// Create an empty result
    fn empty() -> Self {
        Self {
            strings: Vec::new(),
            base64_skipped: 0,
            limit_reached: false,
            total_encountered: 0,
            length_filtered: 0,
        }
    }
}

/// Extract unique string values from JSON bytes
///
/// Uses a simple state machine to find JSON string boundaries
/// without fully parsing the JSON. This is more efficient for
/// large payloads where we only need the string values.
///
/// # Arguments
///
/// * `json_bytes` - The JSON payload as bytes
/// * `config` - Configuration for extraction limits
///
/// # Returns
///
/// An `ExtractionResult` containing the unique strings and metrics.
///
/// # Example
///
/// ```
/// use api_fence::modsec::{extract_strings, StringExtractorConfig};
///
/// let json = br#"{"query": "SELECT * FROM users"}"#;
/// let config = StringExtractorConfig::default();
/// let result = extract_strings(json, &config);
///
/// assert!(result.strings.iter().any(|s| s.contains("SELECT")));
/// ```
pub fn extract_strings(json_bytes: &[u8], config: &StringExtractorConfig) -> ExtractionResult {
    let mut result = ExtractionResult::empty();
    let mut seen: HashSet<String> = HashSet::new();

    let mut i = 0;
    let len = json_bytes.len();

    while i < len {
        // Look for the start of a string (unescaped quote)
        if json_bytes[i] == b'"' {
            i += 1;
            let start = i;

            // Find the end of the string
            let mut escaped = false;
            while i < len {
                let b = json_bytes[i];
                if escaped {
                    escaped = false;
                } else if b == b'\\' {
                    escaped = true;
                } else if b == b'"' {
                    break;
                }
                i += 1;
            }

            // Extract the string content
            if i < len && json_bytes[i] == b'"' {
                let raw = &json_bytes[start..i];
                result.total_encountered += 1;

                // Try to decode as UTF-8 and process
                if let Ok(s) = std::str::from_utf8(raw) {
                    // Unescape the string
                    let unescaped = unescape_json_string(s);

                    // Check length constraints
                    if unescaped.len() < config.min_string_length
                        || unescaped.len() > config.max_string_length
                    {
                        result.length_filtered += 1;
                    } else if config.skip_base64 && is_likely_base64(&unescaped) {
                        // Skip base64 strings
                        result.base64_skipped += 1;
                    } else if !seen.contains(&unescaped) {
                        // New unique string
                        if seen.len() >= config.max_unique_strings {
                            result.limit_reached = true;
                            break;
                        }
                        seen.insert(unescaped.clone());
                        result.strings.push(unescaped);
                    }
                }
            }
        }

        i += 1;
    }

    result
}

/// Unescape a JSON string
///
/// Handles standard JSON escape sequences:
/// - `\"` -> `"`
/// - `\\` -> `\`
/// - `\/` -> `/`
/// - `\b` -> backspace
/// - `\f` -> form feed
/// - `\n` -> newline
/// - `\r` -> carriage return
/// - `\t` -> tab
/// - `\uXXXX` -> Unicode character
fn unescape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('b') => result.push('\x08'),
                Some('f') => result.push('\x0C'),
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('u') => {
                    // Unicode escape sequence
                    let hex: String = chars.by_ref().take(4).collect();
                    if hex.len() == 4 {
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(ch) = char::from_u32(code) {
                                result.push(ch);
                            }
                        }
                    }
                }
                Some(other) => {
                    // Unknown escape, keep as-is
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Build a JSON array from extracted strings for ModSecurity scanning
///
/// # Arguments
///
/// * `strings` - The extracted strings
///
/// # Returns
///
/// A JSON array as bytes, e.g., `["string1", "string2"]`
pub fn build_scan_payload(strings: &[String]) -> Vec<u8> {
    // Use serde_json for proper escaping
    match serde_json::to_vec(strings) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Fallback: empty array
            b"[]".to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> StringExtractorConfig {
        StringExtractorConfig::default()
    }

    #[test]
    fn test_simple_json() {
        let json = br#"{"name": "Alice", "city": "Boston"}"#;
        let result = extract_strings(json, &default_config());

        // Extractor gets ALL strings: keys ("name", "city") and values ("Alice", "Boston")
        assert_eq!(result.strings.len(), 4);
        assert!(result.strings.contains(&"Alice".to_string()));
        assert!(result.strings.contains(&"Boston".to_string()));
        assert!(result.strings.contains(&"name".to_string()));
        assert!(result.strings.contains(&"city".to_string()));
        assert_eq!(result.total_encountered, 4);
    }

    #[test]
    fn test_deduplication() {
        let json = br#"{"a": "same", "b": "same", "c": "same"}"#;
        let result = extract_strings(json, &default_config());

        // "same" should only appear once
        let same_count = result.strings.iter().filter(|s| *s == "same").count();
        assert_eq!(same_count, 1);
    }

    #[test]
    fn test_nested_json() {
        let json = br#"{"user": {"name": "Bob", "address": {"city": "NYC"}}}"#;
        let result = extract_strings(json, &default_config());

        assert!(result.strings.contains(&"Bob".to_string()));
        assert!(result.strings.contains(&"NYC".to_string()));
    }

    #[test]
    fn test_array() {
        let json = br#"["apple", "banana", "cherry"]"#;
        let result = extract_strings(json, &default_config());

        assert_eq!(result.strings.len(), 3);
        assert!(result.strings.contains(&"apple".to_string()));
        assert!(result.strings.contains(&"banana".to_string()));
        assert!(result.strings.contains(&"cherry".to_string()));
    }

    #[test]
    fn test_escape_sequences() {
        let json = br#"{"msg": "Hello\nWorld", "path": "C:\\Users"}"#;
        let result = extract_strings(json, &default_config());

        assert!(result.strings.contains(&"Hello\nWorld".to_string()));
        assert!(result.strings.contains(&"C:\\Users".to_string()));
    }

    #[test]
    fn test_unicode_escape() {
        let json = br#"{"emoji": "\u0048\u0065\u006c\u006c\u006f"}"#;
        let result = extract_strings(json, &default_config());

        assert!(result.strings.contains(&"Hello".to_string()));
    }

    #[test]
    fn test_skip_base64() {
        let json = br#"{"data": "SGVsbG8sIFdvcmxkIQ==", "name": "test"}"#;
        let mut config = default_config();
        config.skip_base64 = true;

        let result = extract_strings(json, &config);

        assert!(result.base64_skipped > 0);
        assert!(!result.strings.iter().any(|s| s.contains("SGVsbG8")));
        assert!(result.strings.contains(&"test".to_string()));
    }

    #[test]
    fn test_dont_skip_base64() {
        let json = br#"{"data": "SGVsbG8sIFdvcmxkIQ==", "name": "test"}"#;
        let mut config = default_config();
        config.skip_base64 = false;

        let result = extract_strings(json, &config);

        assert_eq!(result.base64_skipped, 0);
        assert!(result.strings.iter().any(|s| s.contains("SGVsbG8")));
    }

    #[test]
    fn test_length_filter() {
        let json = br#"{"short": "ab", "ok": "hello", "long": "this is a very long string"}"#;
        let mut config = default_config();
        config.min_string_length = 3;
        config.max_string_length = 10;

        let result = extract_strings(json, &config);

        // "ab" is too short, "this is a very long string" is too long
        assert!(result.length_filtered >= 2);
        assert!(result.strings.contains(&"hello".to_string()));
    }

    #[test]
    fn test_max_unique_strings() {
        // Create JSON with many unique strings
        let mut json = String::from("[");
        for i in 0..100 {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("\"string{}\"", i));
        }
        json.push(']');

        let mut config = default_config();
        config.max_unique_strings = 10;

        let result = extract_strings(json.as_bytes(), &config);

        assert!(result.limit_reached);
        assert_eq!(result.strings.len(), 10);
    }

    #[test]
    fn test_empty_json() {
        let json = b"{}";
        let result = extract_strings(json, &default_config());
        assert_eq!(result.strings.len(), 0);
    }

    #[test]
    fn test_empty_strings() {
        let json = br#"{"empty": ""}"#;
        let mut config = default_config();
        config.min_string_length = 0;

        let result = extract_strings(json, &config);
        assert!(result.strings.contains(&String::new()));
    }

    #[test]
    fn test_malformed_json() {
        // Missing closing quote
        let json = br#"{"name": "Alice}"#;
        let result = extract_strings(json, &default_config());
        // Should still extract what it can
        assert!(result.total_encountered > 0);
    }

    #[test]
    fn test_build_scan_payload() {
        let strings = vec!["hello".to_string(), "world".to_string()];
        let payload = build_scan_payload(&strings);
        let expected = br#"["hello","world"]"#;
        assert_eq!(payload, expected);
    }

    #[test]
    fn test_build_scan_payload_empty() {
        let strings: Vec<String> = vec![];
        let payload = build_scan_payload(&strings);
        assert_eq!(payload, b"[]");
    }

    #[test]
    fn test_build_scan_payload_with_special_chars() {
        let strings = vec!["hello\nworld".to_string(), "quote\"here".to_string()];
        let payload = build_scan_payload(&strings);
        // serde_json will escape these properly
        let parsed: Vec<String> = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed, strings);
    }

    #[test]
    fn test_unescape_json_string() {
        assert_eq!(unescape_json_string(r#"hello"#), "hello");
        assert_eq!(unescape_json_string(r#"hello\nworld"#), "hello\nworld");
        assert_eq!(unescape_json_string(r#"hello\\world"#), "hello\\world");
        assert_eq!(unescape_json_string(r#"hello\"world"#), "hello\"world");
        assert_eq!(unescape_json_string(r#"hello\tworld"#), "hello\tworld");
    }
}
