// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Body validation
//!
//! This module handles validation of HTTP request and response bodies,
//! including parsing of JSON, form-urlencoded, multipart, and XML content.

use crate::error::ValidationError;
use crate::security::{self, SecurityLimits};
use crate::util::{
    extract_media_type, extract_multipart_boundary, is_json_media_type, media_type_matches,
};

/// Parse application/x-www-form-urlencoded to JSON
pub fn parse_form_urlencoded_to_json(body: &[u8]) -> Result<serde_json::Value, String> {
    let body_str =
        std::str::from_utf8(body).map_err(|e| format!("Invalid UTF-8 in form data: {}", e))?;

    let mut map = serde_json::Map::new();

    for (key, value) in form_urlencoded::parse(body_str.as_bytes()) {
        let key = key.into_owned();
        let value = value.into_owned();

        // Check if key already exists (array handling)
        if let Some(existing) = map.get_mut(&key) {
            // Convert to array if not already
            match existing {
                serde_json::Value::Array(arr) => {
                    arr.push(serde_json::Value::String(value));
                }
                _ => {
                    let old_value = existing.clone();
                    *existing =
                        serde_json::Value::Array(vec![old_value, serde_json::Value::String(value)]);
                }
            }
        } else {
            map.insert(key, serde_json::Value::String(value));
        }
    }

    Ok(serde_json::Value::Object(map))
}

/// Coerce form data values to their expected types based on schema
///
/// Form data comes in as strings, but the schema may expect integers, booleans, etc.
/// This function recursively coerces string values to match the schema's expected types.
pub fn coerce_form_data_to_schema(
    value: &serde_json::Value,
    schema: &openapiv3::Schema,
) -> Result<serde_json::Value, String> {
    use openapiv3::{SchemaKind, Type};

    match &schema.schema_kind {
        SchemaKind::Type(Type::Object(obj)) => {
            // Coerce each property of the object
            if let serde_json::Value::Object(map) = value {
                let mut coerced = serde_json::Map::new();
                for (key, val) in map {
                    let coerced_val = if let Some(prop_schema_ref) = obj.properties.get(key) {
                        // Get the schema (handling ReferenceOr::Item)
                        if let openapiv3::ReferenceOr::Item(prop_schema) = prop_schema_ref {
                            coerce_form_data_to_schema(val, prop_schema.as_ref())?
                        } else {
                            // Reference - can't resolve here, keep as is
                            val.clone()
                        }
                    } else if let Some(openapiv3::AdditionalProperties::Schema(schema_ref)) =
                        &obj.additional_properties
                    {
                        // Try additional properties schema
                        if let openapiv3::ReferenceOr::Item(add_schema) = schema_ref.as_ref() {
                            coerce_form_data_to_schema(val, add_schema)?
                        } else {
                            val.clone()
                        }
                    } else {
                        val.clone()
                    };
                    coerced.insert(key.clone(), coerced_val);
                }
                Ok(serde_json::Value::Object(coerced))
            } else {
                Ok(value.clone())
            }
        }
        SchemaKind::Type(Type::Integer(_)) => {
            if let serde_json::Value::String(s) = value {
                s.parse::<i64>()
                    .map(serde_json::Value::from)
                    .map_err(|_| format!("Cannot coerce '{}' to integer", s))
            } else {
                Ok(value.clone())
            }
        }
        SchemaKind::Type(Type::Number(_)) => {
            if let serde_json::Value::String(s) = value {
                s.parse::<f64>()
                    .map(serde_json::Value::from)
                    .map_err(|_| format!("Cannot coerce '{}' to number", s))
            } else {
                Ok(value.clone())
            }
        }
        SchemaKind::Type(Type::Boolean(_)) => {
            if let serde_json::Value::String(s) = value {
                match s.to_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => Ok(serde_json::Value::Bool(true)),
                    "false" | "0" | "no" | "off" => Ok(serde_json::Value::Bool(false)),
                    _ => Err(format!("Cannot coerce '{}' to boolean", s)),
                }
            } else {
                Ok(value.clone())
            }
        }
        SchemaKind::Type(Type::Array(arr)) => {
            if let serde_json::Value::Array(items) = value {
                let item_schema = arr.items.as_ref().and_then(|items_ref| {
                    if let openapiv3::ReferenceOr::Item(s) = items_ref {
                        Some(s.as_ref())
                    } else {
                        None
                    }
                });

                let coerced: Result<Vec<_>, _> = items
                    .iter()
                    .map(|item| {
                        if let Some(schema) = item_schema {
                            coerce_form_data_to_schema(item, schema)
                        } else {
                            Ok(item.clone())
                        }
                    })
                    .collect();
                coerced.map(serde_json::Value::Array)
            } else {
                Ok(value.clone())
            }
        }
        _ => Ok(value.clone()),
    }
}

/// Parse multipart/form-data to JSON
///
/// Note: This is a synchronous operation that blocks on async
pub fn parse_multipart_to_json(body: &[u8], boundary: &str) -> Result<serde_json::Value, String> {
    use bytes::Bytes;
    use futures::executor::block_on;
    use multer::Multipart;

    // Convert to Bytes for cheap cloning and 'static lifetime
    let body_bytes = Bytes::copy_from_slice(body);
    let boundary = boundary.to_string();

    // Create a multipart parser
    let multipart = Multipart::new(
        futures::stream::once(async move { Ok::<_, std::io::Error>(body_bytes) }),
        boundary,
    );

    // Parse fields synchronously (blocking on async)
    block_on(async {
        let mut map = serde_json::Map::new();
        let mut multipart = multipart;

        while let Some(field) = multipart
            .next_field()
            .await
            .map_err(|e| format!("Multipart parsing error: {}", e))?
        {
            let name = field
                .name()
                .ok_or_else(|| "Field without name".to_string())?
                .to_string();

            // Get field info before consuming field
            let filename_opt = field.file_name().map(|s| s.to_string());
            let content_type = field
                .content_type()
                .map(|ct| ct.to_string())
                .unwrap_or_else(|| "application/octet-stream".to_string());

            // Check if this is a file field
            if let Some(filename) = filename_opt {
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| format!("Error reading file field: {}", e))?;

                let mut file_obj = serde_json::Map::new();
                file_obj.insert("filename".to_string(), serde_json::Value::String(filename));
                file_obj.insert(
                    "content_type".to_string(),
                    serde_json::Value::String(content_type),
                );
                file_obj.insert(
                    "size".to_string(),
                    serde_json::Value::Number(data.len().into()),
                );
                // Optionally include base64 data for validation
                file_obj.insert(
                    "data".to_string(),
                    serde_json::Value::String(base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        &data,
                    )),
                );

                map.insert(name, serde_json::Value::Object(file_obj));
            } else {
                // Regular field
                let value = field
                    .text()
                    .await
                    .map_err(|e| format!("Error reading field: {}", e))?;

                // Handle array fields (same key multiple times)
                if let Some(existing) = map.get_mut(&name) {
                    match existing {
                        serde_json::Value::Array(arr) => {
                            arr.push(serde_json::Value::String(value));
                        }
                        _ => {
                            let old_value = existing.clone();
                            *existing = serde_json::Value::Array(vec![
                                old_value,
                                serde_json::Value::String(value),
                            ]);
                        }
                    }
                } else {
                    map.insert(name, serde_json::Value::String(value));
                }
            }
        }

        Ok(serde_json::Value::Object(map))
    })
}

/// Parse XML to JSON using serde-xml-rs
pub fn parse_xml_to_json(body: &[u8]) -> Result<serde_json::Value, String> {
    let body_str = std::str::from_utf8(body).map_err(|e| format!("Invalid UTF-8 in XML: {}", e))?;

    // Parse XML to serde_json::Value
    let xml_value: serde_json::Value =
        serde_xml_rs::from_str(body_str).map_err(|e| format!("Invalid XML: {}", e))?;

    Ok(xml_value)
}

/// Convert body to JSON based on content type
pub fn body_to_json(body: &[u8], content_type: &str) -> Result<serde_json::Value, String> {
    // Parse the content type to extract media type and parameters
    let mime_type = content_type
        .parse::<mime::Mime>()
        .map_err(|e| format!("Invalid content-type: {}", e))?;

    let media_type = format!("{}/{}", mime_type.type_(), mime_type.subtype());

    // Check for JSON first using the original content_type to preserve +json suffix
    if is_json_media_type(content_type) {
        return serde_json::from_slice(body).map_err(|e| format!("Invalid JSON: {}", e));
    }

    match media_type.as_str() {
        "application/x-www-form-urlencoded" => parse_form_urlencoded_to_json(body),
        "multipart/form-data" => {
            // Extract boundary from content-type parameters
            let boundary = extract_multipart_boundary(content_type)
                .ok_or_else(|| "Missing boundary in multipart/form-data".to_string())?;

            parse_multipart_to_json(body, &boundary)
        }
        "application/xml" | "text/xml" => parse_xml_to_json(body),
        _ => Err(format!(
            "Unsupported content type for validation: {}",
            media_type
        )),
    }
}

/// Convert body to JSON with security limits applied
///
/// This version applies JSON depth limiting for security.
pub fn body_to_json_secure(
    body: &[u8],
    content_type: &str,
    security_limits: &SecurityLimits,
) -> Result<serde_json::Value, String> {
    // Parse the content type to extract media type and parameters
    let mime_type = content_type
        .parse::<mime::Mime>()
        .map_err(|e| format!("Invalid content-type: {}", e))?;

    let media_type = format!("{}/{}", mime_type.type_(), mime_type.subtype());

    // Check for JSON first using the original content_type to preserve +json suffix
    if is_json_media_type(content_type) {
        // Use depth-limited JSON parsing for security
        return security::parse_json_with_depth_limit(body, security_limits.max_json_depth)
            .map_err(|e| format!("JSON parsing error: {}", e));
    }

    match media_type.as_str() {
        "application/x-www-form-urlencoded" => parse_form_urlencoded_to_json(body),
        "multipart/form-data" => {
            // Extract boundary from content-type parameters
            let boundary = extract_multipart_boundary(content_type)
                .ok_or_else(|| "Missing boundary in multipart/form-data".to_string())?;

            parse_multipart_to_json(body, &boundary)
        }
        "application/xml" | "text/xml" => parse_xml_to_json(body),
        _ => Err(format!(
            "Unsupported content type for validation: {}",
            media_type
        )),
    }
}

/// Find matching content type in OpenAPI spec content map
///
/// Returns the spec media type and its content definition
pub fn find_matching_content_type<'a, T>(
    content_map: &'a indexmap::IndexMap<String, T>,
    request_content_type: &str,
) -> Result<(&'a str, &'a T), ValidationError> {
    // Parse request content type
    let request_media =
        extract_media_type(request_content_type).ok_or_else(|| ValidationError::InvalidBody {
            content_type: request_content_type.to_string(),
            message: "Invalid content-type format".to_string(),
        })?;

    // First try exact match in content map keys
    for (spec_media, content) in content_map.iter() {
        if spec_media == &request_media {
            return Ok((spec_media.as_str(), content));
        }
    }

    // Try wildcard matches (e.g., "application/*", "*/*")
    for (spec_media, content) in content_map.iter() {
        if spec_media.contains('*') && media_type_matches(&request_media, spec_media) {
            return Ok((spec_media.as_str(), content));
        }
    }

    // If no match, return error
    Err(ValidationError::UnsupportedContentType {
        content_type: request_content_type.to_string(),
        supported: content_map.keys().cloned().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_form_urlencoded() {
        let body = b"name=John&age=30";
        let result = parse_form_urlencoded_to_json(body);
        assert!(result.is_ok());

        let json = result.unwrap();
        assert_eq!(json["name"], "John");
        assert_eq!(json["age"], "30");
    }

    #[test]
    fn test_parse_form_urlencoded_array() {
        let body = b"tags=a&tags=b&tags=c";
        let result = parse_form_urlencoded_to_json(body);
        assert!(result.is_ok());

        let json = result.unwrap();
        assert!(json["tags"].is_array());
        assert_eq!(json["tags"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_parse_form_urlencoded_empty() {
        let body = b"";
        let result = parse_form_urlencoded_to_json(body);
        assert!(result.is_ok());

        let json = result.unwrap();
        assert!(json.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_parse_xml_valid() {
        let body = b"<root><name>John</name><age>30</age></root>";
        let result = parse_xml_to_json(body);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_xml_invalid() {
        let body = b"<invalid xml";
        let result = parse_xml_to_json(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_body_to_json_json() {
        let body = br#"{"name": "John"}"#;
        let result = body_to_json(body, "application/json");
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["name"], "John");
    }

    #[test]
    fn test_body_to_json_json_with_charset() {
        let body = br#"{"name": "John"}"#;
        let result = body_to_json(body, "application/json; charset=utf-8");
        assert!(result.is_ok());
    }

    #[test]
    fn test_body_to_json_form() {
        let body = b"name=John";
        let result = body_to_json(body, "application/x-www-form-urlencoded");
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["name"], "John");
    }

    #[test]
    fn test_body_to_json_xml() {
        let body = b"<root><name>John</name></root>";
        let result = body_to_json(body, "application/xml");
        assert!(result.is_ok());
    }

    #[test]
    fn test_body_to_json_unsupported() {
        let body = b"some data";
        let result = body_to_json(body, "text/plain");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_matching_content_type_exact() {
        let mut map = indexmap::IndexMap::new();
        map.insert("application/json".to_string(), "json");
        map.insert("text/plain".to_string(), "text");

        let result = find_matching_content_type(&map, "application/json");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "application/json");
    }

    #[test]
    fn test_find_matching_content_type_with_charset() {
        let mut map = indexmap::IndexMap::new();
        map.insert("application/json".to_string(), "json");

        let result = find_matching_content_type(&map, "application/json; charset=utf-8");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "application/json");
    }

    #[test]
    fn test_find_matching_content_type_wildcard() {
        let mut map = indexmap::IndexMap::new();
        map.insert("*/*".to_string(), "any");

        let result = find_matching_content_type(&map, "application/json");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_matching_content_type_not_found() {
        let mut map = indexmap::IndexMap::new();
        map.insert("application/json".to_string(), "json");

        let result = find_matching_content_type(&map, "text/plain");
        assert!(result.is_err());
    }

    #[test]
    fn test_json_invalid_syntax() {
        // Test various invalid JSON syntaxes
        let invalid_jsons = [
            br#"{"name": "John""#.as_slice(), // Missing closing brace
            br#"{"name": }"#.as_slice(),      // Missing value
            br#"name: "John"}"#.as_slice(),   // Not JSON (YAML-like)
            br#"["a", "b",]"#.as_slice(),     // Trailing comma
            br#"undefined"#.as_slice(),       // JavaScript undefined
        ];

        for invalid_json in invalid_jsons {
            let result = body_to_json(invalid_json, "application/json");
            assert!(
                result.is_err(),
                "Should fail for: {:?}",
                std::str::from_utf8(invalid_json)
            );
            let err_msg = result.unwrap_err();
            assert!(
                err_msg.contains("Invalid JSON"),
                "Error should mention JSON: {}",
                err_msg
            );
        }
    }

    #[test]
    fn test_multipart_simple() {
        // Simple multipart form with text fields
        let boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        let body = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
             Content-Disposition: form-data; name=\"field1\"\r\n\r\n\
             value1\r\n\
             ------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n\
             Content-Disposition: form-data; name=\"field2\"\r\n\r\n\
             value2\r\n\
             ------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
            .to_string();

        let result = parse_multipart_to_json(body.as_bytes(), boundary);
        assert!(
            result.is_ok(),
            "Multipart parsing failed: {:?}",
            result.err()
        );

        let json = result.unwrap();
        assert_eq!(json["field1"], "value1");
        assert_eq!(json["field2"], "value2");
    }

    #[test]
    fn test_empty_body_json_parsing() {
        // Empty body should fail JSON parsing
        let body = b"";
        let result = body_to_json(body, "application/json");
        assert!(result.is_err());

        // Whitespace-only body should also fail
        let body = b"   ";
        let result = body_to_json(body, "application/json");
        assert!(result.is_err());
    }

    #[test]
    fn test_vendored_json_content_type() {
        // Test that vendored JSON content types work (e.g., application/vnd.api+json)
        let body = br#"{"data": {"type": "user", "id": "1"}}"#;

        // application/vnd.api+json (JSON:API spec)
        let result = body_to_json(body, "application/vnd.api+json");
        assert!(result.is_ok(), "Should accept application/vnd.api+json");
        assert_eq!(result.unwrap()["data"]["type"], "user");

        // application/hal+json
        let result = body_to_json(body, "application/hal+json");
        assert!(result.is_ok(), "Should accept application/hal+json");

        // application/ld+json (JSON-LD)
        let result = body_to_json(body, "application/ld+json");
        assert!(result.is_ok(), "Should accept application/ld+json");

        // application/problem+json (RFC 7807)
        let body = br#"{"type": "about:blank", "title": "Error"}"#;
        let result = body_to_json(body, "application/problem+json");
        assert!(result.is_ok(), "Should accept application/problem+json");
    }
}
