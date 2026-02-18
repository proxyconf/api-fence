// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Header validation
//!
//! This module handles validation of HTTP request and response headers.

use crate::error::{ParameterLocation, ValidationError, ValidationResult};
use openapiv3::{Operation, Parameter, ParameterSchemaOrContent, ReferenceOr, Schema};

/// Validate request headers against OpenAPI spec
///
/// # Arguments
///
/// * `operation` - The OpenAPI operation to validate against
/// * `get_header` - Function to retrieve header value by name (case-insensitive)
/// * `validate_value` - Callback function to validate parameter values against their schemas
///
/// # Returns
///
/// * `Ok(())` if all headers are valid
/// * `Err(ValidationError)` with details about the first invalid header
pub fn validate_request_headers<F, G>(
    operation: &Operation,
    get_header: F,
    mut validate_value: G,
) -> ValidationResult<()>
where
    F: Fn(&str) -> Option<String>,
    G: FnMut(&str, &Schema, &str) -> ValidationResult<()>,
{
    for param in &operation.parameters {
        if let ReferenceOr::Item(Parameter::Header { parameter_data, .. }) = param {
            // Get header value (case-insensitive lookup via provided function)
            let header_value = get_header(&parameter_data.name);

            // Check if required
            if parameter_data.required && header_value.is_none() {
                return Err(ValidationError::MissingParameter {
                    location: ParameterLocation::Header,
                    name: parameter_data.name.clone(),
                });
            }

            // Validate parameter value if present
            if let Some(value) = header_value {
                if let ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)) =
                    &parameter_data.format
                {
                    validate_value(&value, schema, &parameter_data.name)?;
                }
            }
        }
    }
    Ok(())
}

/// Validate response headers against OpenAPI spec
///
/// # Arguments
///
/// * `response` - The OpenAPI response definition
/// * `get_header` - Function to retrieve header value by name (case-insensitive)
/// * `validate_value` - Callback function to validate parameter values against their schemas
///
/// # Returns
///
/// * `Ok(())` if all headers are valid
/// * `Err(ValidationError)` with details about the first invalid header
pub fn validate_response_headers<F, G>(
    response: &openapiv3::Response,
    get_header: F,
    mut validate_value: G,
) -> ValidationResult<()>
where
    F: Fn(&str) -> Option<String>,
    G: FnMut(&str, &Schema, &str) -> ValidationResult<()>,
{
    for (header_name, header_ref) in &response.headers {
        if let ReferenceOr::Item(header) = header_ref {
            // Get header value (case-insensitive)
            let header_value = get_header(header_name);

            // Check if required
            if header.required && header_value.is_none() {
                return Err(ValidationError::MissingParameter {
                    location: ParameterLocation::Header,
                    name: header_name.clone(),
                });
            }

            // Validate parameter value if present
            if let Some(value) = header_value {
                if let ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)) = &header.format
                {
                    validate_value(&value, schema, header_name)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapiv3::{
        Header, ParameterData, ParameterSchemaOrContent, SchemaKind, StringType, Type,
    };
    use std::collections::HashMap;

    fn make_header_param(name: &str, required: bool) -> ReferenceOr<Parameter> {
        ReferenceOr::Item(Parameter::Header {
            parameter_data: ParameterData {
                name: name.to_string(),
                description: None,
                required,
                deprecated: None,
                format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(Schema {
                    schema_data: Default::default(),
                    schema_kind: SchemaKind::Type(Type::String(Default::default())),
                })),
                example: None,
                examples: Default::default(),
                explode: None,
                extensions: Default::default(),
            },
            style: Default::default(),
        })
    }

    fn make_header_param_with_schema(
        name: &str,
        required: bool,
        schema: Schema,
    ) -> ReferenceOr<Parameter> {
        ReferenceOr::Item(Parameter::Header {
            parameter_data: ParameterData {
                name: name.to_string(),
                description: None,
                required,
                deprecated: None,
                format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)),
                example: None,
                examples: Default::default(),
                explode: None,
                extensions: Default::default(),
            },
            style: Default::default(),
        })
    }

    fn noop_validator(_value: &str, _schema: &Schema, _name: &str) -> ValidationResult<()> {
        Ok(())
    }

    #[test]
    fn test_validate_required_header_present() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param("X-Request-Id", true));

        let headers: HashMap<String, String> = [("x-request-id".to_string(), "abc123".to_string())]
            .into_iter()
            .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        let result = validate_request_headers(&operation, get_header, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_required_header_missing() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param("X-Request-Id", true));

        let headers: HashMap<String, String> = HashMap::new();
        let get_header = |_name: &str| headers.get("").cloned();

        let result = validate_request_headers(&operation, get_header, noop_validator);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingParameter {
                location: ParameterLocation::Header,
                ..
            }
        ));
    }

    #[test]
    fn test_validate_optional_header_missing() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param("X-Optional", false));

        let get_header = |_name: &str| None;

        let result = validate_request_headers(&operation, get_header, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_header_case_insensitive() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param("X-Request-Id", true));

        let headers: HashMap<String, String> = [("X-REQUEST-ID".to_string(), "abc123".to_string())]
            .into_iter()
            .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        let result = validate_request_headers(&operation, get_header, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_response_header_required() {
        let mut response = openapiv3::Response::default();
        response.headers.insert(
            "X-Rate-Limit".to_string(),
            ReferenceOr::Item(Header {
                description: None,
                style: Default::default(),
                required: true,
                deprecated: None,
                format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(Schema {
                    schema_data: Default::default(),
                    schema_kind: SchemaKind::Type(Type::String(Default::default())),
                })),
                example: None,
                examples: Default::default(),
                extensions: Default::default(),
            }),
        );

        // Missing required header
        let get_header = |_name: &str| None;
        let result = validate_response_headers(&response, get_header, noop_validator);
        assert!(result.is_err());

        // Present required header
        let get_header = |_name: &str| Some("100".to_string());
        let result = validate_response_headers(&response, get_header, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_pattern_valid() {
        // Create a header with pattern constraint (UUID format)
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                pattern: Some(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$".to_string(),
                ),
                ..Default::default()
            })),
        };

        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param_with_schema("X-Request-Id", true, schema));

        let headers: HashMap<String, String> = [(
            "x-request-id".to_string(),
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
        )]
        .into_iter()
        .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        // Validator that checks pattern
        let pattern_validator =
            |value: &str, schema: &Schema, name: &str| -> ValidationResult<()> {
                if let SchemaKind::Type(Type::String(string_type)) = &schema.schema_kind {
                    if let Some(pattern) = &string_type.pattern {
                        let re = regex::Regex::new(pattern).map_err(|_| {
                            ValidationError::PatternMismatch {
                                location: ParameterLocation::Header,
                                name: name.to_string(),
                                pattern: pattern.clone(),
                                value: value.to_string(),
                            }
                        })?;
                        if !re.is_match(value) {
                            return Err(ValidationError::PatternMismatch {
                                location: ParameterLocation::Header,
                                name: name.to_string(),
                                pattern: pattern.clone(),
                                value: value.to_string(),
                            });
                        }
                    }
                }
                Ok(())
            };

        let result = validate_request_headers(&operation, get_header, pattern_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_pattern_invalid() {
        // Create a header with pattern constraint (UUID format)
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                pattern: Some(
                    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$".to_string(),
                ),
                ..Default::default()
            })),
        };

        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param_with_schema("X-Request-Id", true, schema));

        let headers: HashMap<String, String> = [(
            "x-request-id".to_string(),
            "not-a-valid-uuid".to_string(), // Invalid UUID format
        )]
        .into_iter()
        .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        // Validator that checks pattern
        let pattern_validator =
            |value: &str, schema: &Schema, name: &str| -> ValidationResult<()> {
                if let SchemaKind::Type(Type::String(string_type)) = &schema.schema_kind {
                    if let Some(pattern) = &string_type.pattern {
                        let re = regex::Regex::new(pattern).map_err(|_| {
                            ValidationError::PatternMismatch {
                                location: ParameterLocation::Header,
                                name: name.to_string(),
                                pattern: pattern.clone(),
                                value: value.to_string(),
                            }
                        })?;
                        if !re.is_match(value) {
                            return Err(ValidationError::PatternMismatch {
                                location: ParameterLocation::Header,
                                name: name.to_string(),
                                pattern: pattern.clone(),
                                value: value.to_string(),
                            });
                        }
                    }
                }
                Ok(())
            };

        let result = validate_request_headers(&operation, get_header, pattern_validator);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::PatternMismatch { name, value, .. } => {
                assert_eq!(name, "X-Request-Id");
                assert_eq!(value, "not-a-valid-uuid");
            }
            _ => panic!("Expected PatternMismatch error"),
        }
    }

    #[test]
    fn test_header_enum_valid() {
        // Create a header with enum constraint
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                enumeration: vec![
                    Some("json".to_string()),
                    Some("xml".to_string()),
                    Some("csv".to_string()),
                ],
                ..Default::default()
            })),
        };

        let mut operation = Operation::default();
        operation.parameters.push(make_header_param_with_schema(
            "X-Output-Format",
            true,
            schema,
        ));

        let headers: HashMap<String, String> =
            [("x-output-format".to_string(), "json".to_string())]
                .into_iter()
                .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        // Validator that checks enum values
        let enum_validator = |value: &str, schema: &Schema, name: &str| -> ValidationResult<()> {
            if let SchemaKind::Type(Type::String(string_type)) = &schema.schema_kind {
                if !string_type.enumeration.is_empty() {
                    let valid_values: Vec<String> = string_type
                        .enumeration
                        .iter()
                        .filter_map(|v| v.clone())
                        .collect();
                    let valid_refs: Vec<&str> = valid_values.iter().map(|s| s.as_str()).collect();
                    if !valid_refs.contains(&value) {
                        return Err(ValidationError::enum_mismatch(
                            ParameterLocation::Header,
                            name.to_string(),
                            valid_values,
                            value.to_string(),
                        ));
                    }
                }
            }
            Ok(())
        };

        let result = validate_request_headers(&operation, get_header, enum_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_header_enum_invalid() {
        // Create a header with enum constraint
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                enumeration: vec![
                    Some("json".to_string()),
                    Some("xml".to_string()),
                    Some("csv".to_string()),
                ],
                ..Default::default()
            })),
        };

        let mut operation = Operation::default();
        operation.parameters.push(make_header_param_with_schema(
            "X-Output-Format",
            true,
            schema,
        ));

        let headers: HashMap<String, String> = [(
            "x-output-format".to_string(),
            "yaml".to_string(), // Not in enum
        )]
        .into_iter()
        .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        // Validator that checks enum values
        let enum_validator = |value: &str, schema: &Schema, name: &str| -> ValidationResult<()> {
            if let SchemaKind::Type(Type::String(string_type)) = &schema.schema_kind {
                if !string_type.enumeration.is_empty() {
                    let valid_values: Vec<String> = string_type
                        .enumeration
                        .iter()
                        .filter_map(|v| v.clone())
                        .collect();
                    let valid_refs: Vec<&str> = valid_values.iter().map(|s| s.as_str()).collect();
                    if !valid_refs.contains(&value) {
                        return Err(ValidationError::enum_mismatch(
                            ParameterLocation::Header,
                            name.to_string(),
                            valid_values,
                            value.to_string(),
                        ));
                    }
                }
            }
            Ok(())
        };

        let result = validate_request_headers(&operation, get_header, enum_validator);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::EnumMismatch { name, actual, .. } => {
                assert_eq!(name, "X-Output-Format");
                assert_eq!(actual, "yaml");
            }
            _ => panic!("Expected EnumMismatch error"),
        }
    }

    #[test]
    fn test_standard_headers_content_type_accept() {
        // Test Content-Type and Accept headers
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_header_param("Content-Type", true));
        operation.parameters.push(make_header_param("Accept", true));

        let headers: HashMap<String, String> = [
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/json, text/plain".to_string(),
            ),
        ]
        .into_iter()
        .collect();

        let get_header = |name: &str| {
            let name_lower = name.to_lowercase();
            headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == name_lower)
                .map(|(_, v)| v.clone())
        };

        let result = validate_request_headers(&operation, get_header, noop_validator);
        assert!(result.is_ok());
    }
}
