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

    // ModSecurity request scanning metrics
    /// ModSecurity request scans performed
    pub modsec_request_scans: EnvoyCounterId,
    /// ModSecurity request blocks
    pub modsec_request_blocked: EnvoyCounterId,
    /// ModSecurity request alerts (matched but not blocked)
    pub modsec_request_alerts: EnvoyCounterId,
    /// ModSecurity request scan timeouts
    pub modsec_request_timeouts: EnvoyCounterId,
    /// ModSecurity request scan time histogram (milliseconds)
    pub modsec_request_scan_time_ms: EnvoyHistogramId,

    // ModSecurity response scanning metrics
    /// ModSecurity response scans performed
    pub modsec_response_scans: EnvoyCounterId,
    /// ModSecurity response blocks
    pub modsec_response_blocked: EnvoyCounterId,
    /// ModSecurity response alerts (matched but not blocked)
    pub modsec_response_alerts: EnvoyCounterId,
    /// ModSecurity response scan timeouts
    pub modsec_response_timeouts: EnvoyCounterId,
    /// ModSecurity response scan time histogram (milliseconds)
    pub modsec_response_scan_time_ms: EnvoyHistogramId,
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

        // ModSecurity request metrics
        let modsec_request_scans_name = format!("api_fence.{}.modsec.request.scans", api_name);
        let modsec_request_scans = envoy_config
            .define_counter(&modsec_request_scans_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_request_scans_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_request_blocked_name = format!("api_fence.{}.modsec.request.blocked", api_name);
        let modsec_request_blocked = envoy_config
            .define_counter(&modsec_request_blocked_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_request_blocked_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_request_alerts_name = format!("api_fence.{}.modsec.request.alerts", api_name);
        let modsec_request_alerts = envoy_config
            .define_counter(&modsec_request_alerts_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_request_alerts_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_request_timeouts_name =
            format!("api_fence.{}.modsec.request.timeouts", api_name);
        let modsec_request_timeouts = envoy_config
            .define_counter(&modsec_request_timeouts_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_request_timeouts_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_request_scan_time_name =
            format!("api_fence.{}.modsec.request.scan_time_ms", api_name);
        let modsec_request_scan_time_ms = envoy_config
            .define_histogram(&modsec_request_scan_time_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_request_scan_time_name,
                message: format!("Failed to define histogram: {:?}", e),
            })?;

        // ModSecurity response metrics
        let modsec_response_scans_name = format!("api_fence.{}.modsec.response.scans", api_name);
        let modsec_response_scans = envoy_config
            .define_counter(&modsec_response_scans_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_response_scans_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_response_blocked_name =
            format!("api_fence.{}.modsec.response.blocked", api_name);
        let modsec_response_blocked = envoy_config
            .define_counter(&modsec_response_blocked_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_response_blocked_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_response_alerts_name = format!("api_fence.{}.modsec.response.alerts", api_name);
        let modsec_response_alerts = envoy_config
            .define_counter(&modsec_response_alerts_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_response_alerts_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_response_timeouts_name =
            format!("api_fence.{}.modsec.response.timeouts", api_name);
        let modsec_response_timeouts = envoy_config
            .define_counter(&modsec_response_timeouts_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_response_timeouts_name,
                message: format!("Failed to define counter: {:?}", e),
            })?;

        let modsec_response_scan_time_name =
            format!("api_fence.{}.modsec.response.scan_time_ms", api_name);
        let modsec_response_scan_time_ms = envoy_config
            .define_histogram(&modsec_response_scan_time_name)
            .map_err(|e| ConfigError::MetricDefinitionError {
                name: modsec_response_scan_time_name,
                message: format!("Failed to define histogram: {:?}", e),
            })?;

        Ok(Self {
            cache_hits,
            cache_misses,
            schema_compile_time_ms,
            request_validation_errors,
            response_validation_errors,
            modsec_request_scans,
            modsec_request_blocked,
            modsec_request_alerts,
            modsec_request_timeouts,
            modsec_request_scan_time_ms,
            modsec_response_scans,
            modsec_response_blocked,
            modsec_response_alerts,
            modsec_response_timeouts,
            modsec_response_scan_time_ms,
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
