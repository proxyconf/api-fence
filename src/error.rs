//! Error types for the OpenAPI filter
//!
//! This module defines structured error types for validation and configuration errors,
//! providing clear error messages and proper error handling throughout the filter.
//!
//! ## Error Hierarchy
//!
//! - [`FilterError`]: Top-level error type that wraps all other errors
//! - [`ConfigError`]: Configuration parsing and validation errors
//! - [`ValidationError`]: Request/response validation errors
//! - [`SchemaError`]: JSON Schema compilation and caching errors
//! - [`RoutingError`]: Path and method lookup errors
//! - [`MockError`]: Mock response generation errors
//!
//! ## RFC 7807 Support
//!
//! The [`ProblemDetails`] struct provides RFC 7807 compliant error responses.

use crate::security;
use thiserror::Error;

/// Result type alias using FilterError
pub type Result<T> = std::result::Result<T, FilterError>;

/// Result type alias specifically for validation operations
pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

/// Result type alias specifically for configuration operations
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;

/// Result type alias for mock operations
pub type MockResult<T> = std::result::Result<T, MockError>;

/// Top-level error type for the filter
#[derive(Error, Debug)]
pub enum FilterError {
    /// Configuration-related errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    /// Validation-related errors
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),
    /// Schema compilation errors
    #[error("Schema error: {0}")]
    Schema(#[from] SchemaError),
    /// Routing errors (path/method not found)
    #[error("Routing error: {0}")]
    Routing(#[from] RoutingError),
    /// Mock generation errors
    #[error("Mock error: {0}")]
    Mock(#[from] MockError),
}

/// Configuration errors
#[derive(Error, Debug)]
pub enum ConfigError {
    /// Failed to parse configuration JSON
    #[error("Failed to parse configuration: {message}")]
    ParseError { message: String },
    /// Missing required configuration field
    #[error("Missing required field: {field}")]
    MissingField { field: String },
    /// Invalid configuration value
    #[error("Invalid value for '{field}': {message}")]
    InvalidValue { field: String, message: String },
    /// Failed to load OpenAPI spec
    #[error("Failed to load OpenAPI spec from '{path}': {message}")]
    SpecLoadError { path: String, message: String },
    /// Failed to parse OpenAPI spec
    #[error("Failed to parse OpenAPI spec: {message}")]
    SpecParseError { message: String },
    /// Failed to define Envoy metric
    #[error("Failed to define metric '{name}': {message}")]
    MetricDefinitionError { name: String, message: String },
}

/// Validation errors for request/response validation
#[derive(Error, Debug, Clone)]
pub enum ValidationError {
    /// Missing required parameter
    #[error("Missing required {location} parameter: {name}")]
    MissingParameter {
        location: ParameterLocation,
        name: String,
    },
    /// Invalid parameter value
    #[error("Invalid {location} parameter '{name}': {message}")]
    InvalidParameter {
        location: ParameterLocation,
        name: String,
        message: String,
    },
    /// Type mismatch in parameter
    #[error("{location} parameter '{name}' must be {expected}, got '{actual}'")]
    TypeMismatch {
        location: ParameterLocation,
        name: String,
        expected: String,
        actual: String,
    },
    /// Pattern validation failed
    #[error("{location} parameter '{name}' does not match pattern '{pattern}', got '{value}'")]
    PatternMismatch {
        location: ParameterLocation,
        name: String,
        pattern: String,
        value: String,
    },
    /// Enum validation failed
    #[error("{location} parameter '{name}' must be one of [{allowed_str}], got '{actual}'")]
    EnumMismatch {
        location: ParameterLocation,
        name: String,
        allowed: Vec<String>,
        allowed_str: String, // Pre-computed for display
        actual: String,
    },
    /// Length validation failed
    #[error("{location} parameter '{name}' {constraint}, got {actual} characters")]
    LengthError {
        location: ParameterLocation,
        name: String,
        min: Option<usize>,
        max: Option<usize>,
        constraint: String, // Pre-computed for display
        actual: usize,
    },
    /// Request body is required but missing
    #[error("Request body is required")]
    MissingBody,
    /// Invalid body content
    #[error("Invalid request body (content-type: {content_type}): {message}")]
    InvalidBody {
        content_type: String,
        message: String,
    },
    /// Schema validation failed
    #[error("Schema validation failed: {}", errors.join("; "))]
    SchemaValidation { errors: Vec<String> },
    /// Unsupported content type
    #[error("Unsupported content type: {content_type}. Supported: {}", supported.join(", "))]
    UnsupportedContentType {
        content_type: String,
        supported: Vec<String>,
    },
}

impl ValidationError {
    /// Create an EnumMismatch error with pre-computed allowed_str
    pub fn enum_mismatch(
        location: ParameterLocation,
        name: String,
        allowed: Vec<String>,
        actual: String,
    ) -> Self {
        let allowed_str = allowed.join(", ");
        Self::EnumMismatch {
            location,
            name,
            allowed,
            allowed_str,
            actual,
        }
    }

    /// Create a LengthError with pre-computed constraint string
    pub fn length_error(
        location: ParameterLocation,
        name: String,
        min: Option<usize>,
        max: Option<usize>,
        actual: usize,
    ) -> Self {
        let constraint = match (min, max) {
            (Some(min), Some(max)) => format!("must be between {} and {} characters", min, max),
            (Some(min), None) => format!("must be at least {} characters", min),
            (None, Some(max)) => format!("must be at most {} characters", max),
            (None, None) => "must have valid length".to_string(),
        };
        Self::LengthError {
            location,
            name,
            min,
            max,
            constraint,
            actual,
        }
    }
}

/// Location of a parameter in the HTTP request/response
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterLocation {
    Path,
    Query,
    Header,
    Cookie,
    Body,
}

impl std::fmt::Display for ParameterLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParameterLocation::Path => write!(f, "path"),
            ParameterLocation::Query => write!(f, "query"),
            ParameterLocation::Header => write!(f, "header"),
            ParameterLocation::Cookie => write!(f, "cookie"),
            ParameterLocation::Body => write!(f, "body"),
        }
    }
}

/// Schema compilation and caching errors
#[derive(Error, Debug)]
pub enum SchemaError {
    /// Failed to serialize schema to JSON
    #[error("Failed to serialize schema: {message}")]
    SerializationError { message: String },
    /// Failed to compile JSON schema
    #[error("Failed to compile schema: {message}")]
    CompilationError { message: String },
}

/// Routing errors for path/method lookup
#[derive(Error, Debug)]
pub enum RoutingError {
    /// Path not found in OpenAPI spec
    #[error("No OpenAPI path found for {path}")]
    PathNotFound { path: String },
    /// Method not allowed for path
    #[error("Method {method} not allowed for {path}. Allowed methods: {}", allowed.join(", "))]
    MethodNotAllowed {
        method: String,
        path: String,
        allowed: Vec<String>,
    },
}

impl RoutingError {
    /// Get the HTTP status code for this routing error
    pub fn status_code(&self) -> u16 {
        match self {
            RoutingError::PathNotFound { .. } => 404,
            RoutingError::MethodNotAllowed { .. } => 405,
        }
    }
}

/// Mock response generation errors
#[derive(Error, Debug)]
pub enum MockError {
    /// No suitable response found for mocking
    #[error("No suitable response found for mocking")]
    NoResponse,
    /// No response definition for status code
    #[error("No response definition found for status {status_code}")]
    NoResponseForStatus { status_code: u16 },
    /// No examples found in response
    #[error("No examples found in response")]
    NoExamples,
    /// No schema found in response
    #[error("No schema found in response")]
    NoSchema,
    /// Unsupported schema type for generation
    #[error("Unsupported schema type for generation: {schema_type}")]
    UnsupportedSchemaType { schema_type: String },
    /// Failed to serialize response
    #[error("Failed to serialize response: {reason}")]
    SerializationError { reason: String },
    /// No content types defined in response
    #[error("No content types defined in response")]
    NoContentTypes,
    /// Array items schema missing
    #[error("Array without items schema")]
    ArrayWithoutItems,
    /// Failed to resolve a $ref reference
    #[error("Failed to resolve reference '{reference}': {reason}")]
    RefResolutionError { reference: String, reason: String },
}

/// RFC 7807 Problem Details response
///
/// This struct provides a standardized format for HTTP API error responses
/// as defined in RFC 7807 (Problem Details for HTTP APIs).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProblemDetails {
    /// URI reference identifying the problem type
    #[serde(rename = "type")]
    pub type_uri: String,

    /// Short, human-readable summary
    pub title: String,

    /// HTTP status code
    pub status: u16,

    /// Human-readable explanation specific to this occurrence
    pub detail: String,

    /// URI reference identifying the specific occurrence (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,

    /// Validation errors (extension field for detailed validation failures)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ValidationErrorDetail>,
}

/// Detailed validation error for ProblemDetails extension
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationErrorDetail {
    /// The field or parameter that failed validation
    pub field: String,
    /// Human-readable error message
    pub message: String,
    /// Location of the field (path, query, header, body)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl ProblemDetails {
    /// Create a new ProblemDetails with minimal required fields
    pub fn new(status: u16, title: &str, detail: &str) -> Self {
        Self {
            type_uri: format!("https://httpstatuses.io/{}", status),
            title: title.to_string(),
            status,
            detail: detail.to_string(),
            instance: None,
            errors: Vec::new(),
        }
    }

    /// Create a new ProblemDetails with sanitized detail message
    ///
    /// This version removes sensitive information like internal paths
    /// and stack traces from the detail message.
    pub fn new_sanitized(status: u16, title: &str, detail: &str) -> Self {
        Self {
            type_uri: format!("https://httpstatuses.io/{}", status),
            title: title.to_string(),
            status,
            detail: security::sanitize_error_message(detail),
            instance: None,
            errors: Vec::new(),
        }
    }

    /// Sanitize this ProblemDetails to remove sensitive information
    ///
    /// Removes internal paths, stack traces, and truncates long messages.
    pub fn sanitize(&mut self) {
        self.detail = security::sanitize_error_message(&self.detail);
        for error in &mut self.errors {
            error.message = security::sanitize_error_message(&error.message);
        }
    }

    /// Add an instance identifier
    pub fn with_instance(mut self, instance: &str) -> Self {
        self.instance = Some(instance.to_string());
        self
    }

    /// Add validation error details
    pub fn with_errors(mut self, errors: Vec<ValidationErrorDetail>) -> Self {
        self.errors = errors;
        self
    }

    /// Serialize to JSON bytes
    pub fn to_json_bytes(&self) -> Vec<u8> {
        // Safe to use unwrap here as ProblemDetails is designed to always serialize
        serde_json::to_vec(self).unwrap_or_else(|_| {
            // Fallback in case of serialization failure
            br#"{"type":"about:blank","title":"Internal Error","status":500,"detail":"Failed to serialize error response"}"#.to_vec()
        })
    }

    /// Get the content type for RFC 7807 responses
    pub const fn content_type() -> &'static str {
        "application/problem+json"
    }
}

impl From<&ValidationError> for ProblemDetails {
    fn from(err: &ValidationError) -> Self {
        let (title, errors) = match err {
            ValidationError::MissingParameter { location, name } => (
                "Missing Parameter",
                vec![ValidationErrorDetail {
                    field: name.clone(),
                    message: format!("Missing required {} parameter", location),
                    location: Some(location.to_string()),
                }],
            ),
            ValidationError::InvalidParameter {
                location,
                name,
                message,
            } => (
                "Invalid Parameter",
                vec![ValidationErrorDetail {
                    field: name.clone(),
                    message: message.clone(),
                    location: Some(location.to_string()),
                }],
            ),
            ValidationError::TypeMismatch {
                location,
                name,
                expected,
                actual,
            } => (
                "Type Mismatch",
                vec![ValidationErrorDetail {
                    field: name.clone(),
                    message: format!("Expected {}, got '{}'", expected, actual),
                    location: Some(location.to_string()),
                }],
            ),
            ValidationError::PatternMismatch {
                location,
                name,
                pattern,
                value,
            } => (
                "Pattern Mismatch",
                vec![ValidationErrorDetail {
                    field: name.clone(),
                    message: format!("Value '{}' does not match pattern '{}'", value, pattern),
                    location: Some(location.to_string()),
                }],
            ),
            ValidationError::EnumMismatch {
                location,
                name,
                allowed_str,
                actual,
                ..
            } => (
                "Invalid Enum Value",
                vec![ValidationErrorDetail {
                    field: name.clone(),
                    message: format!("Value '{}' must be one of [{}]", actual, allowed_str),
                    location: Some(location.to_string()),
                }],
            ),
            ValidationError::LengthError {
                location,
                name,
                constraint,
                actual,
                ..
            } => (
                "Length Validation Failed",
                vec![ValidationErrorDetail {
                    field: name.clone(),
                    message: format!("Value {} but got {} characters", constraint, actual),
                    location: Some(location.to_string()),
                }],
            ),
            ValidationError::MissingBody => (
                "Missing Request Body",
                vec![ValidationErrorDetail {
                    field: "body".to_string(),
                    message: "Request body is required".to_string(),
                    location: Some("body".to_string()),
                }],
            ),
            ValidationError::InvalidBody {
                content_type,
                message,
            } => (
                "Invalid Request Body",
                vec![ValidationErrorDetail {
                    field: "body".to_string(),
                    message: format!("{} (content-type: {})", message, content_type),
                    location: Some("body".to_string()),
                }],
            ),
            ValidationError::SchemaValidation { errors } => (
                "Schema Validation Failed",
                errors
                    .iter()
                    .map(|e| ValidationErrorDetail {
                        field: "body".to_string(),
                        message: e.clone(),
                        location: Some("body".to_string()),
                    })
                    .collect(),
            ),
            ValidationError::UnsupportedContentType {
                content_type,
                supported,
            } => (
                "Unsupported Content Type",
                vec![ValidationErrorDetail {
                    field: "content-type".to_string(),
                    message: format!(
                        "Content type '{}' is not supported. Use one of: {}",
                        content_type,
                        supported.join(", ")
                    ),
                    location: Some("header".to_string()),
                }],
            ),
        };

        Self {
            type_uri: "https://httpstatuses.io/400".to_string(),
            title: title.to_string(),
            status: 400,
            detail: err.to_string(),
            instance: None,
            errors,
        }
    }
}

impl From<&RoutingError> for ProblemDetails {
    fn from(err: &RoutingError) -> Self {
        let status = err.status_code();
        let title = match err {
            RoutingError::PathNotFound { .. } => "Not Found",
            RoutingError::MethodNotAllowed { .. } => "Method Not Allowed",
        };

        Self {
            type_uri: format!("https://httpstatuses.io/{}", status),
            title: title.to_string(),
            status,
            detail: err.to_string(),
            instance: None,
            errors: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::MissingParameter {
            location: ParameterLocation::Query,
            name: "user_id".to_string(),
        };
        assert_eq!(err.to_string(), "Missing required query parameter: user_id");
    }

    #[test]
    fn test_type_mismatch_display() {
        let err = ValidationError::TypeMismatch {
            location: ParameterLocation::Path,
            name: "id".to_string(),
            expected: "an integer".to_string(),
            actual: "abc".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "path parameter 'id' must be an integer, got 'abc'"
        );
    }

    #[test]
    fn test_enum_mismatch_display() {
        let err = ValidationError::enum_mismatch(
            ParameterLocation::Query,
            "status".to_string(),
            vec!["active".to_string(), "inactive".to_string()],
            "unknown".to_string(),
        );
        assert_eq!(
            err.to_string(),
            "query parameter 'status' must be one of [active, inactive], got 'unknown'"
        );
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::MissingField {
            field: "api_name".to_string(),
        };
        assert_eq!(err.to_string(), "Missing required field: api_name");
    }

    #[test]
    fn test_routing_error_status_codes() {
        let not_found = RoutingError::PathNotFound {
            path: "/unknown".to_string(),
        };
        assert_eq!(not_found.status_code(), 404);

        let not_allowed = RoutingError::MethodNotAllowed {
            method: "DELETE".to_string(),
            path: "/users".to_string(),
            allowed: vec!["GET".to_string(), "POST".to_string()],
        };
        assert_eq!(not_allowed.status_code(), 405);
    }

    #[test]
    fn test_filter_error_from_conversions() {
        let config_err = ConfigError::MissingField {
            field: "test".to_string(),
        };
        let filter_err: FilterError = config_err.into();
        assert!(matches!(filter_err, FilterError::Config(_)));

        let validation_err = ValidationError::MissingBody;
        let filter_err: FilterError = validation_err.into();
        assert!(matches!(filter_err, FilterError::Validation(_)));

        let mock_err = MockError::NoResponse;
        let filter_err: FilterError = mock_err.into();
        assert!(matches!(filter_err, FilterError::Mock(_)));
    }

    #[test]
    fn test_length_error_display_variants() {
        // Min only
        let err = ValidationError::length_error(
            ParameterLocation::Query,
            "name".to_string(),
            Some(3),
            None,
            1,
        );
        assert!(err.to_string().contains("at least 3 characters"));

        // Max only
        let err = ValidationError::length_error(
            ParameterLocation::Query,
            "name".to_string(),
            None,
            Some(10),
            15,
        );
        assert!(err.to_string().contains("at most 10 characters"));

        // Both
        let err = ValidationError::length_error(
            ParameterLocation::Query,
            "name".to_string(),
            Some(3),
            Some(10),
            15,
        );
        assert!(err.to_string().contains("between 3 and 10 characters"));
    }

    #[test]
    fn test_mock_error_display() {
        let err = MockError::NoResponse;
        assert_eq!(err.to_string(), "No suitable response found for mocking");

        let err = MockError::NoResponseForStatus { status_code: 201 };
        assert_eq!(
            err.to_string(),
            "No response definition found for status 201"
        );

        let err = MockError::UnsupportedSchemaType {
            schema_type: "oneOf".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Unsupported schema type for generation: oneOf"
        );
    }

    #[test]
    fn test_schema_error_display() {
        let err = SchemaError::SerializationError {
            message: "invalid utf-8".to_string(),
        };
        assert_eq!(err.to_string(), "Failed to serialize schema: invalid utf-8");

        let err = SchemaError::CompilationError {
            message: "invalid schema".to_string(),
        };
        assert_eq!(err.to_string(), "Failed to compile schema: invalid schema");
    }

    #[test]
    fn test_problem_details_new() {
        let pd = ProblemDetails::new(400, "Bad Request", "Invalid input");
        assert_eq!(pd.status, 400);
        assert_eq!(pd.title, "Bad Request");
        assert_eq!(pd.detail, "Invalid input");
        assert_eq!(pd.type_uri, "https://httpstatuses.io/400");
        assert!(pd.instance.is_none());
        assert!(pd.errors.is_empty());
    }

    #[test]
    fn test_problem_details_with_instance() {
        let pd = ProblemDetails::new(400, "Bad Request", "Invalid input")
            .with_instance("/api/users/123");
        assert_eq!(pd.instance, Some("/api/users/123".to_string()));
    }

    #[test]
    fn test_problem_details_with_errors() {
        let errors = vec![ValidationErrorDetail {
            field: "name".to_string(),
            message: "Required field".to_string(),
            location: Some("body".to_string()),
        }];
        let pd = ProblemDetails::new(400, "Validation Failed", "One or more fields failed")
            .with_errors(errors);
        assert_eq!(pd.errors.len(), 1);
        assert_eq!(pd.errors[0].field, "name");
    }

    #[test]
    fn test_problem_details_serialization() {
        let pd = ProblemDetails::new(400, "Bad Request", "Invalid input");
        let json_bytes = pd.to_json_bytes();
        let json_str = String::from_utf8(json_bytes).expect("valid utf-8");

        assert!(json_str.contains("\"type\":\"https://httpstatuses.io/400\""));
        assert!(json_str.contains("\"title\":\"Bad Request\""));
        assert!(json_str.contains("\"status\":400"));
        assert!(json_str.contains("\"detail\":\"Invalid input\""));
        // Empty errors should be skipped
        assert!(!json_str.contains("\"errors\""));
    }

    #[test]
    fn test_problem_details_from_validation_error() {
        let err = ValidationError::MissingParameter {
            location: ParameterLocation::Query,
            name: "user_id".to_string(),
        };
        let pd = ProblemDetails::from(&err);

        assert_eq!(pd.status, 400);
        assert_eq!(pd.title, "Missing Parameter");
        assert_eq!(pd.errors.len(), 1);
        assert_eq!(pd.errors[0].field, "user_id");
        assert_eq!(pd.errors[0].location, Some("query".to_string()));
    }

    #[test]
    fn test_problem_details_from_routing_error_404() {
        let err = RoutingError::PathNotFound {
            path: "/unknown".to_string(),
        };
        let pd = ProblemDetails::from(&err);

        assert_eq!(pd.status, 404);
        assert_eq!(pd.title, "Not Found");
        assert!(pd.detail.contains("/unknown"));
    }

    #[test]
    fn test_problem_details_from_routing_error_405() {
        let err = RoutingError::MethodNotAllowed {
            method: "DELETE".to_string(),
            path: "/users".to_string(),
            allowed: vec!["GET".to_string(), "POST".to_string()],
        };
        let pd = ProblemDetails::from(&err);

        assert_eq!(pd.status, 405);
        assert_eq!(pd.title, "Method Not Allowed");
    }

    #[test]
    fn test_problem_details_content_type() {
        assert_eq!(ProblemDetails::content_type(), "application/problem+json");
    }

    #[test]
    fn test_error_source_chain() {
        let config_err = ConfigError::ParseError {
            message: "unexpected token".to_string(),
        };
        let filter_err: FilterError = config_err.into();

        // Verify the source chain works
        use std::error::Error;
        assert!(filter_err.source().is_some());
    }
}
