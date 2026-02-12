//! Utility functions for the API Fence filter
//!
//! This module contains pure utility functions that are shared across the filter.
//! All functions here are stateless and have no side effects.

use std::collections::HashMap;

/// Check if a media type represents JSON (including vendored JSON types)
///
/// # Examples
///
/// ```
/// use api_fence::util::is_json_media_type;
///
/// assert!(is_json_media_type("application/json"));
/// assert!(is_json_media_type("application/vnd.api+json"));
/// assert!(is_json_media_type("application/problem+json"));
/// assert!(!is_json_media_type("text/plain"));
/// ```
pub fn is_json_media_type(media_type: &str) -> bool {
    // Try to parse as MIME type
    if let Ok(mime_type) = media_type.parse::<mime::Mime>() {
        // Check if it's application/json or has +json suffix
        if mime_type.type_() == mime::APPLICATION {
            let subtype = mime_type.subtype().as_str();
            // Check for exact "json" subtype or +json suffix
            if subtype == "json" {
                return true;
            }
            // Check for +json suffix (e.g., application/vnd.api+json)
            if let Some(suffix) = mime_type.suffix() {
                return suffix.as_str() == "json";
            }
        }
    }

    // Fallback: simple string check for malformed media types
    media_type.contains("json")
}

/// Find JSON media type in content map
///
/// Returns the first JSON-compatible media type and its content.
/// Tries exact "application/json" first, then any JSON-compatible type.
pub fn find_json_content<T>(content_map: &indexmap::IndexMap<String, T>) -> Option<(&str, &T)> {
    // First try exact match on application/json
    if let Some(content) = content_map.get("application/json") {
        return Some(("application/json", content));
    }

    // Then look for any JSON-compatible media type
    content_map
        .iter()
        .find(|(media_type, _)| is_json_media_type(media_type))
        .map(|(k, v)| (k.as_str(), v))
}

/// Parse query string into key-value map
///
/// Handles URL-encoded values and empty values.
///
/// # Examples
///
/// ```
/// use api_fence::util::parse_query_string;
///
/// let params = parse_query_string("foo=bar&baz=qux");
/// assert_eq!(params.get("foo"), Some(&"bar".to_string()));
/// assert_eq!(params.get("baz"), Some(&"qux".to_string()));
///
/// // Handles empty values
/// let params = parse_query_string("flag&key=value");
/// assert_eq!(params.get("flag"), Some(&"".to_string()));
/// ```
pub fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            params.insert(
                urlencoding::decode(key).unwrap_or_default().to_string(),
                urlencoding::decode(value).unwrap_or_default().to_string(),
            );
        } else if !pair.is_empty() {
            params.insert(
                urlencoding::decode(pair).unwrap_or_default().to_string(),
                String::new(),
            );
        }
    }
    params
}

/// Check if a request media type matches a spec media type (with wildcard support)
///
/// Supports wildcards like `*/*` and `application/*`.
///
/// # Examples
///
/// ```
/// use api_fence::util::media_type_matches;
///
/// assert!(media_type_matches("application/json", "*/*"));
/// assert!(media_type_matches("application/json", "application/*"));
/// assert!(media_type_matches("application/json", "application/json"));
/// assert!(!media_type_matches("text/plain", "application/json"));
/// ```
pub fn media_type_matches(request_media: &str, spec_media: &str) -> bool {
    if spec_media == "*/*" {
        return true;
    }

    let request_parts: Vec<&str> = request_media.split('/').collect();
    let spec_parts: Vec<&str> = spec_media.split('/').collect();

    if request_parts.len() != 2 || spec_parts.len() != 2 {
        return false;
    }

    // Check type
    if spec_parts[0] != "*" && spec_parts[0] != request_parts[0] {
        return false;
    }

    // Check subtype
    if spec_parts[1] != "*" && spec_parts[1] != request_parts[1] {
        return false;
    }

    true
}

/// Extract the base media type from a content-type header value
///
/// Strips parameters like charset from the content-type.
///
/// # Examples
///
/// ```
/// use api_fence::util::extract_media_type;
///
/// assert_eq!(
///     extract_media_type("application/json; charset=utf-8"),
///     Some("application/json".to_string())
/// );
/// assert_eq!(
///     extract_media_type("text/plain"),
///     Some("text/plain".to_string())
/// );
/// ```
pub fn extract_media_type(content_type: &str) -> Option<String> {
    content_type
        .parse::<mime::Mime>()
        .ok()
        .map(|mime_type| format!("{}/{}", mime_type.type_(), mime_type.subtype()))
}

/// Extract boundary parameter from multipart content-type
///
/// # Examples
///
/// ```
/// use api_fence::util::extract_multipart_boundary;
///
/// let boundary = extract_multipart_boundary(
///     "multipart/form-data; boundary=----WebKitFormBoundary"
/// );
/// assert_eq!(boundary, Some("----WebKitFormBoundary".to_string()));
/// ```
pub fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    content_type
        .parse::<mime::Mime>()
        .ok()
        .and_then(|mime_type| {
            mime_type
                .get_param("boundary")
                .map(|b| b.as_str().to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_json_media_type_standard() {
        assert!(is_json_media_type("application/json"));
    }

    #[test]
    fn test_is_json_media_type_vendored() {
        assert!(is_json_media_type("application/vnd.api+json"));
        assert!(is_json_media_type("application/problem+json"));
        assert!(is_json_media_type("application/hal+json"));
    }

    #[test]
    fn test_is_json_media_type_with_params() {
        assert!(is_json_media_type("application/json; charset=utf-8"));
    }

    #[test]
    fn test_is_json_media_type_non_json() {
        assert!(!is_json_media_type("text/plain"));
        assert!(!is_json_media_type("application/xml"));
        assert!(!is_json_media_type("text/html"));
    }

    #[test]
    fn test_parse_query_string_basic() {
        let params = parse_query_string("foo=bar&baz=qux");
        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
    }

    #[test]
    fn test_parse_query_string_empty_value() {
        let params = parse_query_string("flag&key=value");
        assert_eq!(params.get("flag"), Some(&"".to_string()));
        assert_eq!(params.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_parse_query_string_encoded() {
        let params = parse_query_string("name=John%20Doe&email=test%40example.com");
        assert_eq!(params.get("name"), Some(&"John Doe".to_string()));
        assert_eq!(params.get("email"), Some(&"test@example.com".to_string()));
    }

    #[test]
    fn test_parse_query_string_empty() {
        let params = parse_query_string("");
        assert!(params.is_empty());
    }

    #[test]
    fn test_media_type_matches_exact() {
        assert!(media_type_matches("application/json", "application/json"));
        assert!(!media_type_matches("text/plain", "application/json"));
    }

    #[test]
    fn test_media_type_matches_wildcard_all() {
        assert!(media_type_matches("application/json", "*/*"));
        assert!(media_type_matches("text/plain", "*/*"));
    }

    #[test]
    fn test_media_type_matches_wildcard_subtype() {
        assert!(media_type_matches("application/json", "application/*"));
        assert!(media_type_matches("application/xml", "application/*"));
        assert!(!media_type_matches("text/plain", "application/*"));
    }

    #[test]
    fn test_extract_media_type() {
        assert_eq!(
            extract_media_type("application/json; charset=utf-8"),
            Some("application/json".to_string())
        );
        assert_eq!(
            extract_media_type("text/plain"),
            Some("text/plain".to_string())
        );
    }

    #[test]
    fn test_extract_multipart_boundary() {
        assert_eq!(
            extract_multipart_boundary("multipart/form-data; boundary=----WebKitFormBoundary"),
            Some("----WebKitFormBoundary".to_string())
        );
        assert_eq!(extract_multipart_boundary("application/json"), None);
    }

    #[test]
    fn test_find_json_content_exact() {
        let mut map = indexmap::IndexMap::new();
        map.insert("application/json".to_string(), "json-content");
        map.insert("text/plain".to_string(), "text-content");

        let result = find_json_content(&map);
        assert!(result.is_some());
        let (media_type, content) = result.unwrap();
        assert_eq!(media_type, "application/json");
        assert_eq!(*content, "json-content");
    }

    #[test]
    fn test_find_json_content_vendored() {
        let mut map = indexmap::IndexMap::new();
        map.insert("application/vnd.api+json".to_string(), "api-json");

        let result = find_json_content(&map);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "application/vnd.api+json");
    }

    #[test]
    fn test_find_json_content_not_found() {
        let mut map = indexmap::IndexMap::new();
        map.insert("text/plain".to_string(), "text");

        let result = find_json_content(&map);
        assert!(result.is_none());
    }
}
