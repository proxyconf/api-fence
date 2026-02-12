//! Observability module
//!
//! This module handles metrics, dynamic metadata, and logging for the filter.

use crate::error::{ConfigError, ConfigResult, ProblemDetails};
use envoy_proxy_dynamic_modules_rust_sdk::*;

/// Namespace for all dynamic metadata set by this filter
pub const METADATA_NAMESPACE: &str = "api_fence";

/// Metrics handles for the filter
#[derive(Clone, Copy)]
pub struct FilterMetrics {
    /// Cache hit counter
    pub cache_hits: EnvoyCounterId,
    /// Cache miss counter
    pub cache_misses: EnvoyCounterId,
    /// Schema compile time histogram (milliseconds)
    pub schema_compile_time_ms: EnvoyHistogramId,
    /// Request validation error counter
    pub request_validation_errors: EnvoyCounterId,
    /// Response validation error counter
    pub response_validation_errors: EnvoyCounterId,
}

impl FilterMetrics {
    /// Define all metrics with the Envoy filter config
    ///
    /// # Arguments
    ///
    /// * `api_name` - The API name used for metric scoping
    /// * `envoy_config` - The Envoy filter config for defining metrics
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::MetricDefinitionError` if any metric definition fails.
    pub fn try_new<EC: EnvoyHttpFilterConfig>(
        api_name: &str,
        envoy_config: &mut EC,
    ) -> ConfigResult<Self> {
        let cache_hits_name = format!("api_fence.{}.cache.hits", api_name);
        let cache_hits = envoy_config.define_counter(&cache_hits_name).map_err(|e| {
            ConfigError::MetricDefinitionError {
                name: cache_hits_name,
                message: format!("Failed to define counter: {:?}", e),
            }
        })?;

        let cache_misses_name = format!("api_fence.{}.cache.misses", api_name);
        let cache_misses = envoy_config
            .define_counter(&cache_misses_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: cache_misses_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let compile_time_name = format!("api_fence.{}.schema.compile_time_ms", api_name);
        let schema_compile_time_ms =
            envoy_config
                .define_histogram(&compile_time_name)
                .map_err(|e| ConfigError::MetricDefinitionError {
                    name: compile_time_name,
                    message: format!("Failed to define histogram: {:?}", e),
                })?;

        let request_errors_name = format!("api_fence.{}.request.validation_errors", api_name);
        let request_validation_errors =
            envoy_config
                .define_counter(&request_errors_name)
                .map_err(|e| ConfigError::MetricDefinitionError {
                    name: request_errors_name,
                    message: format!("Failed to define counter: {:?}", e),
                })?;

        let response_errors_name = format!("api_fence.{}.response.validation_errors", api_name);
        let response_validation_errors = envoy_config
            .define_counter(&response_errors_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: response_errors_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        Ok(Self {
            cache_hits,
            cache_misses,
            schema_compile_time_ms,
            request_validation_errors,
            response_validation_errors,
        })
    }

    /// Define all metrics with the Envoy filter config
    ///
    /// # Arguments
    ///
    /// * `api_name` - The API name used for metric scoping
    /// * `envoy_config` - The Envoy filter config for defining metrics
    ///
    /// # Panics
    ///
    /// Panics if any metric definition fails.
    /// Prefer using `try_new()` for proper error handling.
    #[deprecated(since = "0.2.0", note = "Use try_new() for proper error handling")]
    pub fn new<EC: EnvoyHttpFilterConfig>(api_name: &str, envoy_config: &mut EC) -> Self {
        Self::try_new(api_name, envoy_config).expect("Failed to define metrics")
    }
}

/// Set dynamic metadata for request validation results
///
/// Sets the following metadata keys:
/// - `request.verdict`: "valid" or "invalid"
/// - `request.error_count`: number of errors
/// - `request.errors`: concatenated error messages (if any)
pub fn set_request_metadata<EHF: EnvoyHttpFilter>(envoy_filter: &mut EHF, errors: &[String]) {
    // Set verdict
    let verdict = if errors.is_empty() {
        "valid"
    } else {
        "invalid"
    };
    envoy_filter.set_dynamic_metadata_string(METADATA_NAMESPACE, "request.verdict", verdict);

    // Set error count
    envoy_filter.set_dynamic_metadata_number(
        METADATA_NAMESPACE,
        "request.error_count",
        errors.len() as f64,
    );

    // Set errors as concatenated string (Envoy metadata doesn't support arrays easily)
    if !errors.is_empty() {
        let errors_str = errors.join(" | ");
        envoy_filter.set_dynamic_metadata_string(METADATA_NAMESPACE, "request.errors", &errors_str);
    }
}

/// Set dynamic metadata for response validation results
///
/// Sets the following metadata keys:
/// - `response.verdict`: "valid" or "invalid"
/// - `response.error_count`: number of errors
/// - `response.errors`: concatenated error messages (if any)
pub fn set_response_metadata<EHF: EnvoyHttpFilter>(envoy_filter: &mut EHF, errors: &[String]) {
    // Set verdict
    let verdict = if errors.is_empty() {
        "valid"
    } else {
        "invalid"
    };
    envoy_filter.set_dynamic_metadata_string(METADATA_NAMESPACE, "response.verdict", verdict);

    // Set error count
    envoy_filter.set_dynamic_metadata_number(
        METADATA_NAMESPACE,
        "response.error_count",
        errors.len() as f64,
    );

    // Set errors as concatenated string
    if !errors.is_empty() {
        let errors_str = errors.join(" | ");
        envoy_filter.set_dynamic_metadata_string(
            METADATA_NAMESPACE,
            "response.errors",
            &errors_str,
        );
    }
}

/// Send a JSON error response
///
/// Sends a local reply with a JSON body containing the error message.
/// Uses RFC 7807 Problem Details format.
///
/// **Security**: Error messages are sanitized to remove internal paths
/// and other potentially sensitive information.
pub fn send_error_response<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    status_code: u32,
    message: &str,
) {
    let title = match status_code {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "Error",
    };

    // Use sanitized version to remove sensitive information from error messages
    let problem = ProblemDetails::new_sanitized(status_code as u16, title, message);
    let body = problem.to_json_bytes();
    let status_line = format!("{}", status_code);

    // Send response headers
    envoy_filter.send_response_headers(
        vec![
            (":status", status_line.as_bytes()),
            ("content-type", ProblemDetails::content_type().as_bytes()),
        ],
        false, // not end_stream, we'll send body next
    );

    // Send response body
    envoy_filter.send_response_data(&body, true); // end_stream = true
}

/// Send an RFC 7807 Problem Details error response directly
///
/// This is a more flexible version that accepts a pre-built ProblemDetails.
pub fn send_problem_response<EHF: EnvoyHttpFilter>(
    envoy_filter: &mut EHF,
    problem: &ProblemDetails,
) {
    let body = problem.to_json_bytes();
    let status_line = format!("{}", problem.status);

    // Send response headers
    envoy_filter.send_response_headers(
        vec![
            (":status", status_line.as_bytes()),
            ("content-type", ProblemDetails::content_type().as_bytes()),
        ],
        false,
    );

    // Send response body
    envoy_filter.send_response_data(&body, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Most observability functions require Envoy SDK mocks which are complex
    // to set up. These tests focus on the logic that can be tested without mocks.

    #[test]
    fn test_metadata_namespace() {
        assert_eq!(METADATA_NAMESPACE, "api_fence");
    }
}
