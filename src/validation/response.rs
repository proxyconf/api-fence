// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Response validation
//!
//! This module handles validation of HTTP response headers and body.

use crate::error::{ValidationError, ValidationResult};
use crate::util::find_json_content;
use openapiv3::{Operation, ReferenceOr, Schema, StatusCode};

/// Get the response definition for a specific status code
///
/// Tries exact match first, then range match (2XX), then default
pub fn get_response_for_status(
    operation: &Operation,
    status_code: u16,
) -> Option<&openapiv3::Response> {
    // Try exact match
    if let Some(ReferenceOr::Item(response)) = operation
        .responses
        .responses
        .get(&StatusCode::Code(status_code))
    {
        return Some(response);
    }

    // Try range match (e.g., 2XX for 200)
    let range = status_code / 100;
    if let Some(ReferenceOr::Item(response)) =
        operation.responses.responses.get(&StatusCode::Range(range))
    {
        return Some(response);
    }

    // Try default
    if let Some(ReferenceOr::Item(response)) = &operation.responses.default {
        return Some(response);
    }

    None
}

/// Validate response body against OpenAPI spec
///
/// # Arguments
///
/// * `body` - The response body bytes
/// * `operation` - The OpenAPI operation definition
/// * `status_code` - The HTTP status code (as string)
/// * `validate_with_schema` - Callback to validate JSON against a schema
///
/// # Returns
///
/// * `Ok(())` if valid
/// * `Err(ValidationError)` if invalid
pub fn validate_response_body<F>(
    body: &[u8],
    operation: &Operation,
    status_code: u16,
    validate_with_schema: F,
) -> ValidationResult<()>
where
    F: Fn(&serde_json::Value, &Schema) -> ValidationResult<()>,
{
    let response = match get_response_for_status(operation, status_code) {
        Some(r) => r,
        None => return Ok(()), // No response spec, skip validation
    };

    // Validate JSON body - look for any JSON-compatible media type
    if body.is_empty() {
        return Ok(());
    }

    if let Some((media_type, content)) = find_json_content(&response.content) {
        // Parse the body as JSON
        let body_json: serde_json::Value =
            serde_json::from_slice(body).map_err(|e| ValidationError::InvalidBody {
                content_type: media_type.to_string(),
                message: format!("Invalid JSON: {}", e),
            })?;

        // Validate against schema if present
        if let Some(ReferenceOr::Item(schema)) = &content.schema {
            validate_with_schema(&body_json, schema)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapiv3::MediaType;

    fn make_json_response() -> openapiv3::Response {
        let mut response = openapiv3::Response::default();
        response
            .content
            .insert("application/json".to_string(), MediaType::default());
        response
    }

    fn noop_validator(_json: &serde_json::Value, _schema: &Schema) -> ValidationResult<()> {
        Ok(())
    }

    #[test]
    fn test_get_response_for_status_exact() {
        let mut operation = Operation::default();
        operation.responses.responses.insert(
            StatusCode::Code(200),
            ReferenceOr::Item(make_json_response()),
        );

        let result = get_response_for_status(&operation, 200);
        assert!(result.is_some());
    }

    #[test]
    fn test_get_response_for_status_range() {
        let mut operation = Operation::default();
        operation.responses.responses.insert(
            StatusCode::Range(2),
            ReferenceOr::Item(make_json_response()),
        );

        let result = get_response_for_status(&operation, 201);
        assert!(result.is_some());
    }

    #[test]
    fn test_get_response_for_status_default() {
        let mut operation = Operation::default();
        operation.responses.default = Some(ReferenceOr::Item(make_json_response()));

        let result = get_response_for_status(&operation, 404);
        assert!(result.is_some());
    }

    #[test]
    fn test_get_response_for_status_not_found() {
        let operation = Operation::default();
        let result = get_response_for_status(&operation, 200);
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_response_body_empty() {
        let operation = Operation::default();
        let result = validate_response_body(b"", &operation, 200, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_response_body_no_spec() {
        let operation = Operation::default();
        let result = validate_response_body(br#"{"valid": true}"#, &operation, 200, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_response_body_valid_json() {
        let mut operation = Operation::default();
        operation.responses.responses.insert(
            StatusCode::Code(200),
            ReferenceOr::Item(make_json_response()),
        );

        let result = validate_response_body(br#"{"valid": true}"#, &operation, 200, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_response_body_invalid_json() {
        let mut operation = Operation::default();
        operation.responses.responses.insert(
            StatusCode::Code(200),
            ReferenceOr::Item(make_json_response()),
        );

        let result = validate_response_body(b"not json", &operation, 200, noop_validator);
        assert!(result.is_err());
    }
}
