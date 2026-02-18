// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Path parameter validation
//!
//! This module handles validation of path parameters extracted from the URL.

use crate::error::{ParameterLocation, ValidationError, ValidationResult};
use crate::security;
use openapiv3::Schema;
use std::collections::HashMap;
use std::sync::Arc;

/// Schema information for a path parameter
#[derive(Clone, Debug)]
pub struct ParamSchema {
    /// Parameter name
    pub name: String,
    /// The JSON Schema for validation
    pub schema: Arc<Schema>,
    /// Whether the parameter is required
    pub required: bool,
}

/// Validate path parameter types against their schemas (early type checking)
///
/// This is called immediately after path matching to reject invalid types early.
/// It performs basic type validation without full JSON Schema validation.
///
/// # Arguments
///
/// * `path_params` - Map of parameter names to values extracted from the path
/// * `param_schemas` - Map of parameter names to their schema definitions
///
/// # Returns
///
/// * `Ok(())` if all parameters are valid
/// * `Err(ValidationError)` with details about the first invalid parameter
pub fn validate_path_param_types(
    path_params: &HashMap<String, String>,
    param_schemas: &HashMap<String, ParamSchema>,
) -> ValidationResult<()> {
    for (name, value) in path_params {
        if let Some(param_schema) = param_schemas.get(name) {
            validate_single_path_param(name, value, &param_schema.schema)?;
        }
    }
    Ok(())
}

/// Validate a single path parameter value against its schema
fn validate_single_path_param(name: &str, value: &str, schema: &Schema) -> ValidationResult<()> {
    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(schema_type) => match schema_type {
            openapiv3::Type::Integer(_) => {
                value
                    .parse::<i64>()
                    .map_err(|_| ValidationError::TypeMismatch {
                        location: ParameterLocation::Path,
                        name: name.to_string(),
                        expected: "an integer".to_string(),
                        actual: value.to_string(),
                    })?;
            }
            openapiv3::Type::Number(_) => {
                value
                    .parse::<f64>()
                    .map_err(|_| ValidationError::TypeMismatch {
                        location: ParameterLocation::Path,
                        name: name.to_string(),
                        expected: "a number".to_string(),
                        actual: value.to_string(),
                    })?;
            }
            openapiv3::Type::String(string_type) => {
                validate_string_type(name, value, string_type)?;
            }
            openapiv3::Type::Boolean(_) => {
                if value != "true" && value != "false" {
                    return Err(ValidationError::TypeMismatch {
                        location: ParameterLocation::Path,
                        name: name.to_string(),
                        expected: "'true' or 'false'".to_string(),
                        actual: value.to_string(),
                    });
                }
            }
            _ => {
                // Array, Object not typical for path params, skip validation
            }
        },
        _ => {
            // OneOf, AllOf, AnyOf - complex, skip for now
        }
    }
    Ok(())
}

/// Validate string type constraints (enum, pattern, length)
fn validate_string_type(
    name: &str,
    value: &str,
    string_type: &openapiv3::StringType,
) -> ValidationResult<()> {
    // Validate string enum if specified
    if !string_type.enumeration.is_empty() {
        let valid_values: Vec<String> = string_type
            .enumeration
            .iter()
            .filter_map(|v| v.clone())
            .collect();
        if !valid_values.iter().any(|v| v == value) {
            return Err(ValidationError::enum_mismatch(
                ParameterLocation::Path,
                name.to_string(),
                valid_values,
                value.to_string(),
            ));
        }
    }

    // Validate string pattern if specified
    if let Some(pattern) = &string_type.pattern {
        // Security check: limit input length for regex matching
        // Rust's regex crate is already ReDoS-safe (O(n) time),
        // but we limit input size to prevent excessive CPU usage
        if let Err(e) = security::check_regex_input_length(value) {
            return Err(ValidationError::InvalidParameter {
                location: ParameterLocation::Path,
                name: name.to_string(),
                message: e.to_string(),
            });
        }
        if let Ok(regex) = regex::Regex::new(pattern) {
            if !regex.is_match(value) {
                return Err(ValidationError::PatternMismatch {
                    location: ParameterLocation::Path,
                    name: name.to_string(),
                    pattern: pattern.clone(),
                    value: value.to_string(),
                });
            }
        }
    }

    // Validate min/max length if specified
    if let Some(min_length) = string_type.min_length {
        if value.len() < min_length {
            return Err(ValidationError::length_error(
                ParameterLocation::Path,
                name.to_string(),
                Some(min_length),
                string_type.max_length,
                value.len(),
            ));
        }
    }
    if let Some(max_length) = string_type.max_length {
        if value.len() > max_length {
            return Err(ValidationError::length_error(
                ParameterLocation::Path,
                name.to_string(),
                string_type.min_length,
                Some(max_length),
                value.len(),
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapiv3::{SchemaKind, StringType, Type};

    fn make_integer_schema() -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::Integer(Default::default())),
        }
    }

    fn make_string_schema() -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(Default::default())),
        }
    }

    fn make_enum_schema(values: Vec<&str>) -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                enumeration: values.into_iter().map(|v| Some(v.to_string())).collect(),
                ..Default::default()
            })),
        }
    }

    fn make_pattern_schema(pattern: &str) -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                pattern: Some(pattern.to_string()),
                ..Default::default()
            })),
        }
    }

    #[test]
    fn test_validate_integer_param_valid() {
        let mut path_params = HashMap::new();
        path_params.insert("id".to_string(), "123".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "id".to_string(),
            ParamSchema {
                name: "id".to_string(),
                schema: Arc::new(make_integer_schema()),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_integer_param_invalid() {
        let mut path_params = HashMap::new();
        path_params.insert("id".to_string(), "abc".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "id".to_string(),
            ParamSchema {
                name: "id".to_string(),
                schema: Arc::new(make_integer_schema()),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::TypeMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_enum_param_valid() {
        let mut path_params = HashMap::new();
        path_params.insert("status".to_string(), "active".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "status".to_string(),
            ParamSchema {
                name: "status".to_string(),
                schema: Arc::new(make_enum_schema(vec!["active", "inactive"])),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_enum_param_invalid() {
        let mut path_params = HashMap::new();
        path_params.insert("status".to_string(), "unknown".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "status".to_string(),
            ParamSchema {
                name: "status".to_string(),
                schema: Arc::new(make_enum_schema(vec!["active", "inactive"])),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::EnumMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_pattern_param_valid() {
        let mut path_params = HashMap::new();
        path_params.insert("code".to_string(), "ABC123".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "code".to_string(),
            ParamSchema {
                name: "code".to_string(),
                schema: Arc::new(make_pattern_schema(r"^[A-Z]+[0-9]+$")),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_pattern_param_invalid() {
        let mut path_params = HashMap::new();
        path_params.insert("code".to_string(), "abc123".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "code".to_string(),
            ParamSchema {
                name: "code".to_string(),
                schema: Arc::new(make_pattern_schema(r"^[A-Z]+[0-9]+$")),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::PatternMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_string_param() {
        let mut path_params = HashMap::new();
        path_params.insert("name".to_string(), "test".to_string());

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "name".to_string(),
            ParamSchema {
                name: "name".to_string(),
                schema: Arc::new(make_string_schema()),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_no_schema_param() {
        let mut path_params = HashMap::new();
        path_params.insert("unknown".to_string(), "value".to_string());

        let param_schemas = HashMap::new();

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok()); // No schema means no validation
    }

    #[test]
    fn test_string_min_length_valid() {
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                min_length: Some(3),
                max_length: None,
                ..Default::default()
            })),
        };

        let mut path_params = HashMap::new();
        path_params.insert("code".to_string(), "abc".to_string()); // Exactly 3 chars

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "code".to_string(),
            ParamSchema {
                name: "code".to_string(),
                schema: Arc::new(schema),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());

        // Also test with longer string
        path_params.insert("code".to_string(), "abcdef".to_string()); // 6 chars
        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_string_min_length_invalid() {
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                min_length: Some(5),
                max_length: None,
                ..Default::default()
            })),
        };

        let mut path_params = HashMap::new();
        path_params.insert("code".to_string(), "ab".to_string()); // Only 2 chars, min is 5

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "code".to_string(),
            ParamSchema {
                name: "code".to_string(),
                schema: Arc::new(schema),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::LengthError {
                name, min, actual, ..
            } => {
                assert_eq!(name, "code");
                assert_eq!(min, Some(5));
                assert_eq!(actual, 2);
            }
            _ => panic!("Expected LengthError"),
        }
    }

    #[test]
    fn test_string_max_length_valid() {
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                min_length: None,
                max_length: Some(10),
                ..Default::default()
            })),
        };

        let mut path_params = HashMap::new();
        path_params.insert("code".to_string(), "abcdefgh".to_string()); // 8 chars, max is 10

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "code".to_string(),
            ParamSchema {
                name: "code".to_string(),
                schema: Arc::new(schema),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_ok());
    }

    #[test]
    fn test_string_max_length_invalid() {
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType {
                min_length: None,
                max_length: Some(5),
                ..Default::default()
            })),
        };

        let mut path_params = HashMap::new();
        path_params.insert("code".to_string(), "abcdefghij".to_string()); // 10 chars, max is 5

        let mut param_schemas = HashMap::new();
        param_schemas.insert(
            "code".to_string(),
            ParamSchema {
                name: "code".to_string(),
                schema: Arc::new(schema),
                required: true,
            },
        );

        let result = validate_path_param_types(&path_params, &param_schemas);
        assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::LengthError {
                name, max, actual, ..
            } => {
                assert_eq!(name, "code");
                assert_eq!(max, Some(5));
                assert_eq!(actual, 10);
            }
            _ => panic!("Expected LengthError"),
        }
    }
}
