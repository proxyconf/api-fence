//! Configuration types for the API Fence filter
//!
//! This module contains all configuration-related types including:
//! - Main filter configuration (`Config`)
//! - Cache configuration (`CacheConfig`)
//! - Validation behavior configuration (`ValidationConfig`)
//! - Security limits configuration (`SecurityLimits`)
//! - ModSecurity configuration (`ModSecurityConfig`)
//! - Validation pool configuration (`ValidationPoolConfig`)

use crate::error::{ConfigError, ConfigResult};
use crate::mock::MockConfig;
use crate::modsec::ModSecurityConfig;
use crate::security::SecurityLimits;
use crate::validation::pool::ValidationPoolConfig;
use schemars::JsonSchema;
use serde::Deserialize;

/// Main configuration for the API Fence filter
///
/// This is parsed from JSON provided in the Envoy filter configuration.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(title = "API Fence Configuration")]
pub struct Config {
    /// API name for metric scoping (required)
    ///
    /// This name is used as a prefix for all metrics, allowing multiple filter instances
    /// to have separate metrics. Example: "users_api" -> "api_fence.users_api.cache.hits"
    pub api_name: String,

    /// Path to OpenAPI spec file (mutually exclusive with openapi_spec_inline)
    #[serde(default)]
    pub openapi_spec_path: Option<String>,

    /// Inline OpenAPI spec as YAML/JSON string (mutually exclusive with openapi_spec_path)
    #[serde(default)]
    pub openapi_spec_inline: Option<String>,

    /// Cache configuration for compiled JSON schemas
    #[serde(default)]
    pub cache: CacheConfig,

    /// Validation behavior configuration
    #[serde(default)]
    pub validation: ValidationConfig,

    /// Mock response generation configuration
    #[serde(default)]
    pub mocking: MockConfig,

    /// Security limits configuration
    #[serde(default)]
    pub security: SecurityLimits,

    /// ModSecurity WAF configuration (optional)
    #[serde(default)]
    pub modsecurity: ModSecurityConfig,
}

impl Config {
    /// Parse configuration from JSON string
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ParseError` if JSON parsing fails.
    pub fn from_json(json: &str) -> ConfigResult<Self> {
        serde_json::from_str(json).map_err(|e| ConfigError::ParseError {
            message: e.to_string(),
        })
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if validation fails.
    pub fn validate(&self) -> ConfigResult<()> {
        // Ensure either path or inline spec is provided
        if self.openapi_spec_path.is_none() && self.openapi_spec_inline.is_none() {
            return Err(ConfigError::MissingField {
                field: "openapi_spec_path or openapi_spec_inline".to_string(),
            });
        }

        // Ensure both are not provided
        if self.openapi_spec_path.is_some() && self.openapi_spec_inline.is_some() {
            return Err(ConfigError::InvalidValue {
                field: "openapi_spec".to_string(),
                message: "Only one of openapi_spec_path or openapi_spec_inline should be provided"
                    .to_string(),
            });
        }

        // Validate api_name is not empty
        if self.api_name.trim().is_empty() {
            return Err(ConfigError::InvalidValue {
                field: "api_name".to_string(),
                message: "api_name cannot be empty".to_string(),
            });
        }

        // Validate security limits
        self.security
            .validate()
            .map_err(|e| ConfigError::InvalidValue {
                field: "security".to_string(),
                message: e.to_string(),
            })?;

        // Validate ModSecurity configuration
        self.modsecurity
            .validate()
            .map_err(|e| ConfigError::InvalidValue {
                field: "modsecurity".to_string(),
                message: e,
            })?;

        Ok(())
    }

    /// Load the OpenAPI spec content from the configured source
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::SpecLoadError` if file loading fails.
    pub fn load_spec_content(&self) -> ConfigResult<String> {
        if let Some(ref path) = self.openapi_spec_path {
            std::fs::read_to_string(path).map_err(|e| ConfigError::SpecLoadError {
                path: path.clone(),
                message: e.to_string(),
            })
        } else if let Some(ref inline) = self.openapi_spec_inline {
            Ok(inline.clone())
        } else {
            Err(ConfigError::MissingField {
                field: "openapi_spec_path or openapi_spec_inline".to_string(),
            })
        }
    }
}

/// Validation behavior configuration
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[schemars(title = "Validation Configuration")]
pub struct ValidationConfig {
    /// Whether to validate requests (default: true)
    #[serde(default = "default_true")]
    pub validate_request: bool,

    /// Whether to validate responses (default: false)
    #[serde(default)]
    pub validate_response: bool,

    /// Whether to fail requests on validation errors (default: true)
    ///
    /// If false, validation errors are recorded in metrics and metadata but request continues
    #[serde(default = "default_true")]
    pub fail_on_request_error: bool,

    /// Whether to fail responses on validation errors (default: false)
    ///
    /// If false, validation errors are recorded in metrics and metadata but response continues
    #[serde(default)]
    pub fail_on_response_error: bool,

    /// Validation thread pool configuration (optional)
    ///
    /// When enabled, JSON schema validation is offloaded to a thread pool
    /// to avoid blocking Envoy worker threads.
    #[serde(default)]
    pub pool: ValidationPoolConfig,
}

fn default_true() -> bool {
    true
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            validate_request: true,
            validate_response: false,
            fail_on_request_error: true,
            fail_on_response_error: false,
            pool: ValidationPoolConfig::default(),
        }
    }
}

/// Cache configuration for JSON schema validators
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[schemars(title = "Cache Configuration")]
pub struct CacheConfig {
    /// Maximum number of cached schemas (default: 1000)
    #[serde(default = "default_cache_max_capacity")]
    pub max_capacity: u64,

    /// Time-to-live in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_cache_ttl_seconds")]
    pub ttl_seconds: u64,
}

fn default_cache_max_capacity() -> u64 {
    1000
}

fn default_cache_ttl_seconds() -> u64 {
    3600
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: default_cache_max_capacity(),
            ttl_seconds: default_cache_ttl_seconds(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse_with_inline_spec() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_inline": "openapi: 3.0.0"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        assert_eq!(config.api_name, "test_api");
        assert!(config.openapi_spec_inline.is_some());
        assert!(config.openapi_spec_path.is_none());
    }

    #[test]
    fn test_config_parse_with_file_path() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_path": "/path/to/spec.yaml"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        assert_eq!(config.api_name, "test_api");
        assert!(config.openapi_spec_path.is_some());
        assert!(config.openapi_spec_inline.is_none());
    }

    #[test]
    fn test_config_default_cache() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_inline": "openapi: 3.0.0"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        assert_eq!(config.cache.max_capacity, 1000);
        assert_eq!(config.cache.ttl_seconds, 3600);
    }

    #[test]
    fn test_config_custom_cache() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_inline": "openapi: 3.0.0",
            "cache": {
                "max_capacity": 500,
                "ttl_seconds": 1800
            }
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        assert_eq!(config.cache.max_capacity, 500);
        assert_eq!(config.cache.ttl_seconds, 1800);
    }

    #[test]
    fn test_config_default_validation() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_inline": "openapi: 3.0.0"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        assert!(config.validation.validate_request);
        assert!(!config.validation.validate_response);
        assert!(config.validation.fail_on_request_error);
        assert!(!config.validation.fail_on_response_error);
    }

    #[test]
    fn test_config_custom_validation() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_inline": "openapi: 3.0.0",
            "validation": {
                "validate_request": false,
                "validate_response": true,
                "fail_on_request_error": false,
                "fail_on_response_error": true
            }
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        assert!(!config.validation.validate_request);
        assert!(config.validation.validate_response);
        assert!(!config.validation.fail_on_request_error);
        assert!(config.validation.fail_on_response_error);
    }

    #[test]
    fn test_config_validate_missing_spec() {
        let json = r#"{
            "api_name": "test_api"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_both_specs() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_path": "/path/to/spec.yaml",
            "openapi_spec_inline": "openapi: 3.0.0"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_empty_api_name() {
        let json = r#"{
            "api_name": "  ",
            "openapi_spec_inline": "openapi: 3.0.0"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_success() {
        let json = r#"{
            "api_name": "test_api",
            "openapi_spec_inline": "openapi: 3.0.0"
        }"#;

        let config = Config::from_json(json).expect("Failed to parse config");
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_parse_error() {
        let json = r#"{ invalid json }"#;
        let result = Config::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_config_default() {
        let config = ValidationConfig::default();
        assert!(config.validate_request);
        assert!(!config.validate_response);
        assert!(config.fail_on_request_error);
        assert!(!config.fail_on_response_error);
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();
        assert_eq!(config.max_capacity, 1000);
        assert_eq!(config.ttl_seconds, 3600);
    }
}
