//! Query parameter validation
//!
//! This module handles validation of query string parameters.

use crate::error::{ParameterLocation, ValidationError, ValidationResult};
use crate::util::parse_query_string;
use openapiv3::{Operation, Parameter, ParameterSchemaOrContent, ReferenceOr, Schema};

/// Validate query parameters against OpenAPI spec
///
/// # Arguments
///
/// * `query_string` - The raw query string from the URL (without the leading '?')
/// * `operation` - The OpenAPI operation to validate against
/// * `validate_value` - Callback function to validate parameter values against their schemas
///
/// # Returns
///
/// * `Ok(())` if all parameters are valid
/// * `Err(ValidationError)` with details about the first invalid parameter
pub fn validate_query_params<F>(
    query_string: &str,
    operation: &Operation,
    mut validate_value: F,
) -> ValidationResult<()>
where
    F: FnMut(&str, &Schema, &str) -> ValidationResult<()>,
{
    let query_params = parse_query_string(query_string);

    for param in &operation.parameters {
        if let ReferenceOr::Item(Parameter::Query { parameter_data, .. }) = param {
            // Check required parameters
            if parameter_data.required && !query_params.contains_key(&parameter_data.name) {
                return Err(ValidationError::MissingParameter {
                    location: ParameterLocation::Query,
                    name: parameter_data.name.clone(),
                });
            }

            // Validate parameter values if present using JSON Schema
            if let Some(value) = query_params.get(&parameter_data.name) {
                if let ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)) =
                    &parameter_data.format
                {
                    validate_value(value, schema, &parameter_data.name)?;
                }
            }
        }
    }

    Ok(())
}

/// Convert a parameter string value to JSON value based on schema type
pub fn convert_param_to_json(value: &str, schema: &Schema) -> Result<serde_json::Value, String> {
    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(openapiv3::Type::Integer(_)) => value
            .parse::<i64>()
            .map(serde_json::Value::from)
            .map_err(|_| format!("Expected integer value, got '{}'", value)),
        openapiv3::SchemaKind::Type(openapiv3::Type::Number(_)) => value
            .parse::<f64>()
            .map(serde_json::Value::from)
            .map_err(|_| format!("Expected number value, got '{}'", value)),
        openapiv3::SchemaKind::Type(openapiv3::Type::Boolean(_)) => value
            .parse::<bool>()
            .map(serde_json::Value::from)
            .map_err(|_| format!("Expected boolean value, got '{}'", value)),
        openapiv3::SchemaKind::Type(openapiv3::Type::String(_)) => {
            Ok(serde_json::Value::String(value.to_string()))
        }
        openapiv3::SchemaKind::Type(openapiv3::Type::Array(array_type)) => {
            // First try to parse as JSON array (for explicit JSON input like ["a","b","c"])
            if let Ok(json_arr) = serde_json::from_str::<serde_json::Value>(value) {
                if json_arr.is_array() {
                    return Ok(json_arr);
                }
            }

            // Otherwise, treat as comma-separated values (OpenAPI form-style with explode=false)
            // e.g., ids=1,2,3 should become [1, 2, 3]
            let items_schema = array_type.items.as_ref().and_then(|items| {
                if let ReferenceOr::Item(boxed_schema) = items {
                    Some(boxed_schema.as_ref())
                } else {
                    None
                }
            });

            // Split by comma and convert each item based on the items schema
            let items: Result<Vec<serde_json::Value>, String> = value
                .split(',')
                .map(|item| {
                    let trimmed = item.trim();
                    if let Some(item_schema) = items_schema {
                        // Recursively convert each item
                        convert_param_to_json(trimmed, item_schema)
                    } else {
                        // Default to string if no items schema
                        Ok(serde_json::Value::String(trimmed.to_string()))
                    }
                })
                .collect();

            items.map(serde_json::Value::Array)
        }
        _ => Ok(serde_json::Value::String(value.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapiv3::{ParameterData, ParameterSchemaOrContent, SchemaKind, Type};

    fn make_query_param(name: &str, required: bool, schema: Schema) -> ReferenceOr<Parameter> {
        ReferenceOr::Item(Parameter::Query {
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
            allow_reserved: false,
            style: Default::default(),
            allow_empty_value: None,
        })
    }

    fn make_string_schema() -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::String(Default::default())),
        }
    }

    fn make_integer_schema() -> Schema {
        Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::Integer(Default::default())),
        }
    }

    fn noop_validator(_value: &str, _schema: &Schema, _name: &str) -> ValidationResult<()> {
        Ok(())
    }

    #[test]
    fn test_validate_required_param_present() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("user_id", true, make_string_schema()));

        let result = validate_query_params("user_id=123", &operation, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_required_param_missing() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("user_id", true, make_string_schema()));

        let result = validate_query_params("other=value", &operation, noop_validator);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingParameter { .. }
        ));
    }

    #[test]
    fn test_validate_optional_param_missing() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("filter", false, make_string_schema()));

        let result = validate_query_params("other=value", &operation, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_multiple_params() {
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("page", true, make_integer_schema()));
        operation
            .parameters
            .push(make_query_param("limit", false, make_integer_schema()));

        let result = validate_query_params("page=1&limit=10", &operation, noop_validator);
        assert!(result.is_ok());
    }

    #[test]
    fn test_convert_param_integer() {
        let schema = make_integer_schema();
        let result = convert_param_to_json("123", &schema);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::from(123i64));
    }

    #[test]
    fn test_convert_param_integer_invalid() {
        let schema = make_integer_schema();
        let result = convert_param_to_json("abc", &schema);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_param_string() {
        let schema = make_string_schema();
        let result = convert_param_to_json("hello", &schema);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            serde_json::Value::String("hello".to_string())
        );
    }

    #[test]
    fn test_convert_param_boolean() {
        let schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::Boolean(Default::default())),
        };

        let result = convert_param_to_json("true", &schema);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::Bool(true));

        let result = convert_param_to_json("false", &schema);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), serde_json::Value::Bool(false));
    }

    #[test]
    fn test_empty_value() {
        // Test that ?param= is handled correctly (empty string value)
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("filter", false, make_string_schema()));

        // Empty value after = should be a valid empty string
        let result = validate_query_params("filter=", &operation, noop_validator);
        assert!(result.is_ok());

        // The validator should receive an empty string
        let mut received_value = String::new();
        let capture_validator =
            |value: &str, _schema: &Schema, _name: &str| -> ValidationResult<()> {
                received_value = value.to_string();
                Ok(())
            };

        let _ = validate_query_params("filter=", &operation, capture_validator);
        assert_eq!(received_value, "");
    }

    #[test]
    fn test_url_encoded_value() {
        // Test that URL-encoded values are properly decoded
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("name", true, make_string_schema()));

        // %20 is a space in URL encoding
        let mut received_value = String::new();
        let capture_validator =
            |value: &str, _schema: &Schema, _name: &str| -> ValidationResult<()> {
                received_value = value.to_string();
                Ok(())
            };

        let result = validate_query_params("name=John%20Doe", &operation, capture_validator);
        assert!(result.is_ok());
        // parse_query_string should decode the value
        assert_eq!(received_value, "John Doe");
    }

    #[test]
    fn test_no_query_string() {
        // Test validation with empty query string
        let mut operation = Operation::default();
        operation
            .parameters
            .push(make_query_param("filter", false, make_string_schema()));

        // Empty query string should pass for optional params
        let result = validate_query_params("", &operation, noop_validator);
        assert!(result.is_ok());

        // But fail for required params
        operation.parameters.clear();
        operation.parameters.push(make_query_param(
            "required_param",
            true,
            make_string_schema(),
        ));

        let result = validate_query_params("", &operation, noop_validator);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ValidationError::MissingParameter {
                location: ParameterLocation::Query,
                ..
            }
        ));
    }

    #[test]
    fn test_array_param() {
        // Test array query parameter (JSON array format)
        let array_schema = Schema {
            schema_data: Default::default(),
            schema_kind: SchemaKind::Type(Type::Array(openapiv3::ArrayType {
                items: Some(ReferenceOr::Item(Box::new(make_string_schema()))),
                min_items: None,
                max_items: None,
                unique_items: false,
            })),
        };

        // Test conversion of JSON array string
        let result = convert_param_to_json(r#"["a","b","c"]"#, &array_schema);
        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.is_array());
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], serde_json::Value::String("a".to_string()));
        assert_eq!(arr[1], serde_json::Value::String("b".to_string()));
        assert_eq!(arr[2], serde_json::Value::String("c".to_string()));

        // Test comma-separated format (OpenAPI form-style)
        let result = convert_param_to_json("a,b,c", &array_schema);
        assert!(result.is_ok());
        let json = result.unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], serde_json::Value::String("a".to_string()));
        assert_eq!(arr[1], serde_json::Value::String("b".to_string()));
        assert_eq!(arr[2], serde_json::Value::String("c".to_string()));

        // Single value becomes single-element array
        let result = convert_param_to_json("single-value", &array_schema);
        assert!(result.is_ok());
        let json = result.unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0],
            serde_json::Value::String("single-value".to_string())
        );
    }
}
