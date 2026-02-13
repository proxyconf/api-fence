//! OpenAPI Filter implementation
//!
//! This module contains the main filter implementation including:
//! - `FilterConfig`: Per-filter-chain configuration
//! - `OpenApiFilter`: Per-HTTP-stream filter implementation

use crate::config::{Config, ValidationConfig};
use crate::error::{ConfigError, ConfigResult, ParameterLocation, ValidationError};
use crate::mock::{self, MockConfig};
use crate::modsec::{
    extract_strings, set_modsec_request_metadata, set_modsec_response_metadata, DualRulesetScanner,
    DualScanResult, MetadataSetter, ModSecurityConfig, ScanAction, ScanPayload, ScanType,
    TimeoutAction,
};
use crate::observability::{self, FilterMetrics};
use crate::resolver::RefResolver;
use crate::router::Router;
use crate::schema::{SchemaCache, SchemaCompiler};
use crate::security::{self, InputType, SecurityLimits};
use crate::validation::{
    self, ParamSchema, ValidationJobType, ValidationPool, ValidationTimeoutAction,
};
use envoy_proxy_dynamic_modules_rust_sdk::*;
use openapiv3::{OpenAPI, Operation, Parameter, ParameterSchemaOrContent, Schema};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Wrapper for implementing MetadataSetter on EnvoyHttpFilter
///
/// This enables setting ModSecurity metadata on the Envoy filter
/// using the `MetadataSetter` trait from the modsec module.
struct EnvoyMetadataSetter<'a, EHF: EnvoyHttpFilter> {
    filter: &'a mut EHF,
}

impl<'a, EHF: EnvoyHttpFilter> EnvoyMetadataSetter<'a, EHF> {
    fn new(filter: &'a mut EHF) -> Self {
        Self { filter }
    }
}

impl<EHF: EnvoyHttpFilter> MetadataSetter for EnvoyMetadataSetter<'_, EHF> {
    fn set_metadata_string(&mut self, namespace: &str, key: &str, value: &str) {
        // Use Envoy's set_dynamic_metadata_string API
        self.filter
            .set_dynamic_metadata_string(namespace, key, value);
    }

    fn set_metadata_number(&mut self, namespace: &str, key: &str, value: f64) {
        self.filter
            .set_dynamic_metadata_number(namespace, key, value);
    }

    fn set_metadata_bool(&mut self, namespace: &str, key: &str, value: bool) {
        // SDK doesn't have a set_dynamic_metadata_bool, use string representation
        self.filter.set_dynamic_metadata_string(
            namespace,
            key,
            if value { "true" } else { "false" },
        );
    }
}

/// OpenAPI Filter configuration (per filter chain)
///
/// This struct is created once per filter chain and holds shared resources
/// like the compiled OpenAPI spec, router, and schema cache.
pub struct FilterConfig {
    /// Parsed OpenAPI specification
    spec: Arc<OpenAPI>,
    /// Reference resolver for $ref resolution
    resolver: RefResolver,
    /// Path router for efficient operation lookup
    router: Router,
    /// Schema compiler with cache (used when validation pool is disabled)
    schema_compiler: SchemaCompiler,
    /// Validation thread pool (global shared pool, used when enabled for async validation)
    validation_pool: Option<&'static ValidationPool>,
    /// Validation behavior configuration
    validation_config: ValidationConfig,
    /// Mock response configuration
    mock_config: MockConfig,
    /// Security limits configuration
    security_limits: SecurityLimits,
    /// Metrics handles
    metrics: FilterMetrics,
    /// Spec load time in milliseconds (for debugging)
    #[allow(dead_code)]
    spec_load_time_ms: u64,
    /// ModSecurity scanner (shared across all filter instances)
    modsec_scanner: Option<Arc<DualRulesetScanner>>,
    /// ModSecurity configuration
    modsec_config: ModSecurityConfig,
}

impl FilterConfig {
    /// Create a new filter configuration from JSON config string
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if configuration parsing, validation, or OpenAPI spec loading fails.
    pub fn try_new<EC: EnvoyHttpFilterConfig>(
        filter_config: &str,
        envoy_config: &mut EC,
    ) -> ConfigResult<Self> {
        // Parse the filter configuration
        let config = Config::from_json(filter_config)?;

        // Validate configuration
        config.validate()?;

        // Measure spec load time
        let spec_load_start = Instant::now();

        // Load OpenAPI spec content
        let spec_content = config.load_spec_content()?;

        // Parse OpenAPI spec from YAML/JSON string
        let spec: OpenAPI =
            serde_yaml::from_str(&spec_content).map_err(|e| ConfigError::SpecParseError {
                message: e.to_string(),
            })?;

        let spec = Arc::new(spec);

        // Create reference resolver (for $ref resolution)
        let resolver = RefResolver::new(spec.clone());

        // Build path router for efficient routing
        let router = Router::from_spec(&spec);

        let spec_load_time_ms = spec_load_start.elapsed().as_millis() as u64;

        // Initialize schema cache and compiler
        let schema_cache = SchemaCache::new(&config.cache);
        let schema_compiler = SchemaCompiler::new(schema_cache);

        // Initialize validation thread pool if enabled
        let validation_pool = if config.validation.pool.enabled {
            // Validate pool config first
            config
                .validation
                .pool
                .validate()
                .map_err(|e| ConfigError::InvalidValue {
                    field: "validation.pool".to_string(),
                    message: e,
                })?;

            Some(crate::validation::global::global_validation_pool())
        } else {
            None
        };

        // Define metrics
        let metrics = FilterMetrics::try_new(&config.api_name, envoy_config)?;

        // Initialize ModSecurity scanner if enabled
        let modsec_scanner = if config.modsecurity.is_enabled() {
            if let Some(ref primary_config) = config.modsecurity.primary_ruleset {
                let scanner = DualRulesetScanner::new(
                    primary_config,
                    config.modsecurity.secondary_ruleset.as_ref(),
                    config.modsecurity.pool.timeout_ms,
                )
                .map_err(|e| ConfigError::InvalidValue {
                    field: "modsecurity".to_string(),
                    message: format!("failed to initialize ModSecurity scanner: {}", e),
                })?;
                Some(Arc::new(scanner))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            spec,
            resolver,
            router,
            schema_compiler,
            validation_pool,
            validation_config: config.validation,
            mock_config: config.mocking,
            security_limits: config.security,
            metrics,
            spec_load_time_ms,
            modsec_scanner,
            modsec_config: config.modsecurity,
        })
    }

    /// Create a new filter configuration from JSON config string
    ///
    /// # Panics
    ///
    /// Panics if the configuration is invalid or the OpenAPI spec cannot be loaded.
    /// Prefer using `try_new()` for proper error handling.
    #[deprecated(since = "0.2.0", note = "Use try_new() for proper error handling")]
    pub fn new<EC: EnvoyHttpFilterConfig>(filter_config: &str, envoy_config: &mut EC) -> Self {
        Self::try_new(filter_config, envoy_config).expect("Failed to create filter config")
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilterConfig<EHF> for FilterConfig {
    /// Create a new filter instance for each HTTP stream
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(OpenApiFilter {
            spec: self.spec.clone(),
            resolver: self.resolver.clone(),
            router: self.router.clone(),
            schema_compiler: self.schema_compiler.clone(),
            validation_pool: self.validation_pool,
            current_operation: None,
            current_response_operation: None,
            path_params: HashMap::new(),
            param_schemas: HashMap::new(),
            validation_config: self.validation_config.clone(),
            mock_config: self.mock_config.clone(),
            security_limits: self.security_limits.clone(),
            metrics: self.metrics,
            request_errors: Vec::new(),
            response_errors: Vec::new(),
            modsec_scanner: self.modsec_scanner.clone(),
            modsec_config: self.modsec_config.clone(),
            request_method: None,
            request_uri: None,
            request_headers: Vec::new(),
        })
    }
}

/// OpenAPI Filter implementation (per HTTP stream)
///
/// This struct is created for each HTTP request/response and handles
/// the actual validation logic.
pub struct OpenApiFilter {
    /// Parsed OpenAPI specification (shared)
    /// Note: Currently unused but kept for potential future debugging/introspection
    #[allow(dead_code)]
    spec: Arc<OpenAPI>,
    /// Reference resolver for $ref resolution (shared)
    resolver: RefResolver,
    /// Path router (shared)
    router: Router,
    /// Schema compiler with cache (shared, used when validation pool is disabled)
    schema_compiler: SchemaCompiler,
    /// Validation thread pool (global shared pool, used when enabled for async validation)
    validation_pool: Option<&'static ValidationPool>,
    /// Current operation being validated (set in on_request_headers)
    current_operation: Option<Arc<Operation>>,
    /// Operation for response validation
    current_response_operation: Option<Arc<Operation>>,
    /// Path parameters extracted from the URL
    path_params: HashMap<String, String>,
    /// Path parameter schemas for the current route
    param_schemas: HashMap<String, ParamSchema>,
    /// Validation behavior configuration
    validation_config: ValidationConfig,
    /// Mock response configuration
    mock_config: MockConfig,
    /// Security limits configuration
    security_limits: SecurityLimits,
    /// Metrics handles
    metrics: FilterMetrics,
    /// Collected request validation errors
    request_errors: Vec<String>,
    /// Collected response validation errors
    response_errors: Vec<String>,
    /// ModSecurity scanner (shared)
    modsec_scanner: Option<Arc<DualRulesetScanner>>,
    /// ModSecurity configuration
    modsec_config: ModSecurityConfig,
    /// Request method (stored for response scanning context)
    request_method: Option<String>,
    /// Request URI (stored for response scanning context)
    request_uri: Option<String>,
    /// Request headers (stored for response scanning context)
    request_headers: Vec<(String, String)>,
}

impl OpenApiFilter {
    /// Get a specific request header value
    fn get_header<EHF: EnvoyHttpFilter>(envoy_filter: &EHF, name: &str) -> Option<String> {
        let headers = envoy_filter.get_request_headers();
        for (key, value) in headers {
            if key.as_slice() == name.as_bytes() {
                return String::from_utf8(value.as_slice().to_vec()).ok();
            }
        }
        None
    }

    /// Get a specific request header value (case-insensitive)
    fn get_header_case_insensitive<EHF: EnvoyHttpFilter>(
        envoy_filter: &EHF,
        name: &str,
    ) -> Option<String> {
        let headers = envoy_filter.get_request_headers();
        let name_lower = name.to_lowercase();
        for (key, value) in headers {
            let key_str = String::from_utf8_lossy(key.as_slice());
            if key_str.to_lowercase() == name_lower {
                return String::from_utf8(value.as_slice().to_vec()).ok();
            }
        }
        None
    }

    /// Get a specific response header value
    fn get_response_header<EHF: EnvoyHttpFilter>(envoy_filter: &EHF, name: &str) -> Option<String> {
        let headers = envoy_filter.get_response_headers();
        for (key, value) in headers {
            if key.as_slice() == name.as_bytes() {
                return String::from_utf8(value.as_slice().to_vec()).ok();
            }
        }
        None
    }

    /// Validate a parameter value against its JSON Schema
    fn validate_param_with_schema<EHF: EnvoyHttpFilter>(
        &mut self,
        value: &str,
        schema: &Schema,
        param_name: &str,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        // Convert the string value to appropriate JSON type based on schema
        let value_json = validation::convert_param_to_json(value, schema)?;

        // Get or compile schema from cache
        let compile_result = self
            .schema_compiler
            .get_or_compile(schema)
            .map_err(|e| format!("Invalid schema for parameter '{}': {}", param_name, e))?;

        // Record metrics
        if compile_result.cache_hit {
            envoy_filter
                .increment_counter(self.metrics.cache_hits, 1)
                .ok();
        } else {
            envoy_filter
                .increment_counter(self.metrics.cache_misses, 1)
                .ok();
            envoy_filter
                .record_histogram_value(
                    self.metrics.schema_compile_time_ms,
                    compile_result.compile_time_ms,
                )
                .ok();
        }

        let result = compile_result.schema.validate(&value_json);
        if let Err(errors) = result {
            let error_msgs: Vec<String> = errors.map(|e| e.to_string()).collect();
            return Err(format!(
                "Invalid parameter '{}': {}",
                param_name,
                error_msgs.join(", ")
            ));
        }

        Ok(())
    }

    /// Validate query parameters against OpenAPI spec
    fn validate_query_params<EHF: EnvoyHttpFilter>(
        &mut self,
        query_string: &str,
        operation: &Operation,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        use crate::util::parse_query_string;

        let query_params = parse_query_string(query_string);

        for param in &operation.parameters {
            // Resolve parameter reference if needed
            let resolved_param = self
                .resolver
                .resolve_parameter(param)
                .map_err(|e| format!("Failed to resolve parameter reference: {}", e))?;

            if let Parameter::Query { parameter_data, .. } = resolved_param.as_ref() {
                // Check required parameters
                if parameter_data.required && !query_params.contains_key(&parameter_data.name) {
                    return Err(ValidationError::MissingParameter {
                        location: ParameterLocation::Query,
                        name: parameter_data.name.clone(),
                    }
                    .to_string());
                }

                // Validate parameter values if present using JSON Schema
                if let Some(value) = query_params.get(&parameter_data.name) {
                    if let ParameterSchemaOrContent::Schema(schema_ref) = &parameter_data.format {
                        // Resolve schema reference if needed
                        let schema = self
                            .resolver
                            .resolve_schema(schema_ref)
                            .map_err(|e| format!("Failed to resolve schema reference: {}", e))?;
                        self.validate_param_with_schema(
                            value,
                            &schema,
                            &parameter_data.name,
                            envoy_filter,
                        )
                        .map_err(|e| {
                            ValidationError::InvalidParameter {
                                location: ParameterLocation::Query,
                                name: parameter_data.name.clone(),
                                message: e,
                            }
                            .to_string()
                        })?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate request headers against OpenAPI spec
    fn validate_request_headers<EHF: EnvoyHttpFilter>(
        &mut self,
        operation: &Operation,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        // Collect headers first to avoid borrow issues
        let headers: HashMap<String, String> = {
            let raw_headers = envoy_filter.get_request_headers();
            raw_headers
                .iter()
                .filter_map(|(k, v)| {
                    let key = String::from_utf8_lossy(k.as_slice()).to_lowercase();
                    let value = String::from_utf8(v.as_slice().to_vec()).ok()?;
                    Some((key, value))
                })
                .collect()
        };

        // Security check: Validate header value lengths
        for (name, value) in &headers {
            if let Err(e) = security::check_string_length(
                value,
                InputType::Header,
                self.security_limits.max_header_value_length,
            ) {
                return Err(format!("Header '{}': {}", name, e));
            }
        }

        for param in &operation.parameters {
            // Resolve parameter reference if needed
            let resolved_param = self
                .resolver
                .resolve_parameter(param)
                .map_err(|e| format!("Failed to resolve parameter reference: {}", e))?;

            if let Parameter::Header { parameter_data, .. } = resolved_param.as_ref() {
                let name_lower = parameter_data.name.to_lowercase();
                let header_value = headers.get(&name_lower);

                // Check if required
                if parameter_data.required && header_value.is_none() {
                    return Err(format!("Missing required header: {}", parameter_data.name));
                }

                // Validate parameter value if present
                if let Some(value) = header_value {
                    if let ParameterSchemaOrContent::Schema(schema_ref) = &parameter_data.format {
                        // Resolve schema reference if needed
                        let schema = self
                            .resolver
                            .resolve_schema(schema_ref)
                            .map_err(|e| format!("Failed to resolve schema reference: {}", e))?;
                        self.validate_param_with_schema(
                            value,
                            &schema,
                            &parameter_data.name,
                            envoy_filter,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate path parameters using JSON Schema
    fn validate_path_params<EHF: EnvoyHttpFilter>(
        &mut self,
        path_params: &HashMap<String, String>,
        operation: &Operation,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        for param in &operation.parameters {
            // Resolve parameter reference if needed
            let resolved_param = self
                .resolver
                .resolve_parameter(param)
                .map_err(|e| format!("Failed to resolve parameter reference: {}", e))?;

            if let Parameter::Path { parameter_data, .. } = resolved_param.as_ref() {
                if let Some(value) = path_params.get(&parameter_data.name) {
                    if let ParameterSchemaOrContent::Schema(schema_ref) = &parameter_data.format {
                        // Resolve schema reference if needed
                        let schema = self
                            .resolver
                            .resolve_schema(schema_ref)
                            .map_err(|e| format!("Failed to resolve schema reference: {}", e))?;
                        self.validate_param_with_schema(
                            value,
                            &schema,
                            &parameter_data.name,
                            envoy_filter,
                        )
                        .map_err(|e| format!("Invalid path parameter: {}", e))?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate request body using JSON Schema
    fn validate_body_with_schema<EHF: EnvoyHttpFilter>(
        &mut self,
        body: &[u8],
        operation: &Operation,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        // Resolve request body reference if needed
        let body_spec = match &operation.request_body {
            Some(ref_or_body) => {
                let resolved = self
                    .resolver
                    .resolve_request_body(ref_or_body)
                    .map_err(|e| format!("Failed to resolve request body reference: {}", e))?;
                Some(resolved)
            }
            None => None,
        };

        if let Some(body_spec) = body_spec {
            // Check if body is required
            if body_spec.required && body.is_empty() {
                return Err("Request body is required".to_string());
            }

            if !body.is_empty() {
                // Get Content-Type header to determine how to parse the body
                let content_type = Self::get_header_case_insensitive(envoy_filter, "content-type")
                    .unwrap_or_else(|| "application/octet-stream".to_string());

                // Find matching media type in OpenAPI spec
                let (spec_media_type, content) =
                    validation::find_matching_content_type(&body_spec.content, &content_type)
                        .map_err(|e| e.to_string())?;

                // Convert body to JSON based on content type (with security limits)
                let body_json =
                    validation::body_to_json_secure(body, &content_type, &self.security_limits)
                        .map_err(|e| {
                            format!(
                                "Failed to parse request body (content-type: {}): {}",
                                content_type, e
                            )
                        })?;

                // Validate against schema if present
                if let Some(schema_ref) = &content.schema {
                    // Resolve schema reference deeply, inlining all nested $refs
                    // This is necessary because jsonschema crate cannot resolve OpenAPI refs
                    let schema = self
                        .resolver
                        .resolve_schema_deep(schema_ref)
                        .map_err(|e| format!("Failed to resolve schema reference: {}", e))?;

                    // For form-urlencoded and multipart content, coerce string values to
                    // expected types (integers, booleans, etc.) based on schema
                    let body_json = if content_type.contains("x-www-form-urlencoded")
                        || content_type.contains("multipart/form-data")
                    {
                        validation::coerce_form_data_to_schema(&body_json, &schema).map_err(
                            |e| {
                                format!(
                                    "Failed to coerce form data (content-type: {}): {}",
                                    content_type, e
                                )
                            },
                        )?
                    } else {
                        body_json
                    };

                    // Validate using thread pool if enabled, otherwise use direct validation
                    if let Some(ref pool) = self.validation_pool {
                        // Use thread pool for validation
                        let result = pool.validate_blocking(
                            ValidationJobType::RequestBody,
                            body_json,
                            schema,
                            Some(self.security_limits.clone()),
                        );

                        // Record metrics
                        if result.cache_hit {
                            envoy_filter
                                .increment_counter(self.metrics.cache_hits, 1)
                                .ok();
                        } else if !result.timed_out {
                            envoy_filter
                                .increment_counter(self.metrics.cache_misses, 1)
                                .ok();
                            if result.compile_time_ms > 0 {
                                envoy_filter
                                    .record_histogram_value(
                                        self.metrics.schema_compile_time_ms,
                                        result.compile_time_ms,
                                    )
                                    .ok();
                            }
                        }

                        // Handle timeout
                        if result.timed_out {
                            match self.validation_config.pool.timeout_action {
                                ValidationTimeoutAction::Allow => {
                                    // Log warning but allow request through
                                    // Timeout is already recorded in metrics by pool
                                }
                                ValidationTimeoutAction::Block => {
                                    return Err(format!(
                                        "Request body validation timed out after {}ms",
                                        self.validation_config.pool.timeout_ms
                                    ));
                                }
                            }
                        } else if !result.valid {
                            return Err(format!(
                                "Request body validation failed ({}): {}",
                                spec_media_type,
                                result.errors.join("; ")
                            ));
                        }
                    } else {
                        // Direct validation (pool disabled)
                        let compile_result = self
                            .schema_compiler
                            .get_or_compile(&schema)
                            .map_err(|e| format!("Invalid request body schema: {}", e))?;

                        // Record metrics
                        if compile_result.cache_hit {
                            envoy_filter
                                .increment_counter(self.metrics.cache_hits, 1)
                                .ok();
                        } else {
                            envoy_filter
                                .increment_counter(self.metrics.cache_misses, 1)
                                .ok();
                            envoy_filter
                                .record_histogram_value(
                                    self.metrics.schema_compile_time_ms,
                                    compile_result.compile_time_ms,
                                )
                                .ok();
                        }

                        let result = compile_result.schema.validate(&body_json);
                        if let Err(errors) = result {
                            let error_msgs: Vec<String> = errors
                                .map(|e| format!("{} at {}", e, e.instance_path))
                                .collect();
                            return Err(format!(
                                "Request body validation failed ({}): {}",
                                spec_media_type,
                                error_msgs.join("; ")
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Validate response body using JSON Schema
    fn validate_response_body_with_schema<EHF: EnvoyHttpFilter>(
        &mut self,
        body: &[u8],
        operation: &Operation,
        status_code: u16,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        use crate::util::find_json_content;

        // Get and resolve response reference
        let response = self.get_resolved_response(operation, status_code)?;
        let response = match response {
            Some(r) => r,
            None => return Ok(()), // No response spec, skip validation
        };

        // Validate JSON body - look for any JSON-compatible media type
        if body.is_empty() {
            return Ok(());
        }

        if let Some((media_type, content)) = find_json_content(&response.content) {
            // Parse the body as JSON with security limits
            let body_json =
                security::parse_json_with_depth_limit(body, self.security_limits.max_json_depth)
                    .map_err(|e| {
                        format!("Invalid JSON in response body ({}): {}", media_type, e)
                    })?;

            // Validate against schema if present
            if let Some(schema_ref) = &content.schema {
                // Resolve schema reference deeply, inlining all nested $refs
                let schema = self
                    .resolver
                    .resolve_schema_deep(schema_ref)
                    .map_err(|e| format!("Failed to resolve schema reference: {}", e))?;

                // Validate using thread pool if enabled, otherwise use direct validation
                if let Some(ref pool) = self.validation_pool {
                    // Use thread pool for validation
                    let result = pool.validate_blocking(
                        ValidationJobType::ResponseBody,
                        body_json,
                        schema,
                        Some(self.security_limits.clone()),
                    );

                    // Record metrics
                    if result.cache_hit {
                        envoy_filter
                            .increment_counter(self.metrics.cache_hits, 1)
                            .ok();
                    } else if !result.timed_out {
                        envoy_filter
                            .increment_counter(self.metrics.cache_misses, 1)
                            .ok();
                        if result.compile_time_ms > 0 {
                            envoy_filter
                                .record_histogram_value(
                                    self.metrics.schema_compile_time_ms,
                                    result.compile_time_ms,
                                )
                                .ok();
                        }
                    }

                    // Handle timeout
                    if result.timed_out {
                        match self.validation_config.pool.timeout_action {
                            ValidationTimeoutAction::Allow => {
                                // Log warning but allow response through
                                // Timeout is already recorded in metrics by pool
                            }
                            ValidationTimeoutAction::Block => {
                                return Err(format!(
                                    "Response body validation timed out after {}ms",
                                    self.validation_config.pool.timeout_ms
                                ));
                            }
                        }
                    } else if !result.valid {
                        return Err(format!(
                            "Response body validation failed: {}",
                            result.errors.join("; ")
                        ));
                    }
                } else {
                    // Direct validation (pool disabled)
                    let compile_result = self
                        .schema_compiler
                        .get_or_compile(&schema)
                        .map_err(|e| format!("Invalid response body schema: {}", e))?;

                    // Record metrics
                    if compile_result.cache_hit {
                        envoy_filter
                            .increment_counter(self.metrics.cache_hits, 1)
                            .ok();
                    } else {
                        envoy_filter
                            .increment_counter(self.metrics.cache_misses, 1)
                            .ok();
                        envoy_filter
                            .record_histogram_value(
                                self.metrics.schema_compile_time_ms,
                                compile_result.compile_time_ms,
                            )
                            .ok();
                    }

                    let validation_result = compile_result.schema.validate(&body_json);
                    if let Err(errors) = validation_result {
                        let error_msgs: Vec<String> = errors
                            .map(|e| format!("{} at {}", e, e.instance_path))
                            .collect();
                        return Err(format!(
                            "Response body validation failed: {}",
                            error_msgs.join("; ")
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Get and resolve response for a status code
    fn get_resolved_response(
        &self,
        operation: &Operation,
        status_code: u16,
    ) -> Result<Option<std::sync::Arc<openapiv3::Response>>, String> {
        use openapiv3::StatusCode;

        // Try exact match
        if let Some(response_ref) = operation
            .responses
            .responses
            .get(&StatusCode::Code(status_code))
        {
            let resolved = self
                .resolver
                .resolve_response(response_ref)
                .map_err(|e| format!("Failed to resolve response reference: {}", e))?;
            return Ok(Some(resolved));
        }

        // Try range match (e.g., 2XX for 200)
        let range = status_code / 100;
        if let Some(response_ref) = operation.responses.responses.get(&StatusCode::Range(range)) {
            let resolved = self
                .resolver
                .resolve_response(response_ref)
                .map_err(|e| format!("Failed to resolve response reference: {}", e))?;
            return Ok(Some(resolved));
        }

        // Try default
        if let Some(response_ref) = &operation.responses.default {
            let resolved = self
                .resolver
                .resolve_response(response_ref)
                .map_err(|e| format!("Failed to resolve response reference: {}", e))?;
            return Ok(Some(resolved));
        }

        Ok(None)
    }

    /// Validate response headers against OpenAPI spec
    fn validate_response_headers<EHF: EnvoyHttpFilter>(
        &mut self,
        operation: &Operation,
        status_code: u16,
        envoy_filter: &mut EHF,
    ) -> Result<(), String> {
        // Get and resolve response reference
        let response = self.get_resolved_response(operation, status_code)?;
        let response = match response {
            Some(r) => r,
            None => return Ok(()), // No response spec, skip validation
        };

        // Collect headers first to avoid borrow issues
        let headers: HashMap<String, String> = {
            let raw_headers = envoy_filter.get_response_headers();
            raw_headers
                .iter()
                .filter_map(|(k, v)| {
                    let key = String::from_utf8_lossy(k.as_slice()).to_lowercase();
                    let value = String::from_utf8(v.as_slice().to_vec()).ok()?;
                    Some((key, value))
                })
                .collect()
        };

        for (header_name, header_ref) in &response.headers {
            // Resolve header reference if needed
            let header = self
                .resolver
                .resolve_header(header_ref)
                .map_err(|e| format!("Failed to resolve header reference: {}", e))?;

            let name_lower = header_name.to_lowercase();
            let header_value = headers.get(&name_lower);

            // Check if required
            if header.required && header_value.is_none() {
                return Err(format!("Missing required response header: {}", header_name));
            }

            // Validate parameter value if present
            if let Some(value) = header_value {
                if let ParameterSchemaOrContent::Schema(schema_ref) = &header.format {
                    // Resolve schema reference if needed
                    let schema = self
                        .resolver
                        .resolve_schema(schema_ref)
                        .map_err(|e| format!("Failed to resolve schema reference: {}", e))?;
                    self.validate_param_with_schema(value, &schema, header_name, envoy_filter)?;
                }
            }
        }
        Ok(())
    }

    /// Send a mock response if mocking is enabled
    fn try_send_mock_response<EHF: EnvoyHttpFilter>(
        &self,
        operation: &Operation,
        envoy_filter: &mut EHF,
    ) -> bool {
        if !self.mock_config.enabled {
            return false;
        }

        match mock::generate_mock_response(operation, &self.mock_config, &self.resolver) {
            Ok(mock_response) => {
                // Build response headers
                let status_str = mock_response.status_code.to_string();
                let mut headers: Vec<(&str, &[u8])> = vec![(":status", status_str.as_bytes())];

                // Add mock indicator header if configured
                if self.mock_config.add_mock_header {
                    headers.push(("x-mock-response", b"true"));
                }

                // Add content-type and other response headers
                let header_strings: Vec<(String, Vec<u8>)> = mock_response
                    .headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.as_bytes().to_vec()))
                    .collect();

                for (name, value) in &header_strings {
                    headers.push((name.as_str(), value.as_slice()));
                }

                // Send mock response
                envoy_filter.send_response_headers(headers, false);
                envoy_filter.send_response_data(&mock_response.body, true);

                true
            }
            Err(_) => {
                // Mock generation failed - continue without mock (best-effort)
                false
            }
        }
    }

    /// Perform ModSecurity request scanning
    ///
    /// Returns `Some(true)` if the request should be blocked,
    /// `Some(false)` if scanning passed, or `None` if scanning is disabled.
    fn scan_request_with_modsec<EHF: EnvoyHttpFilter>(
        &self,
        body: Option<&[u8]>,
        envoy_filter: &mut EHF,
    ) -> Option<DualScanResult> {
        // Skip if modsec is not enabled for requests
        if !self.modsec_config.scan_request {
            return None;
        }

        let scanner = self.modsec_scanner.as_ref()?;

        // Get request context
        let method = self.request_method.as_deref().unwrap_or("GET");
        let uri = self.request_uri.as_deref().unwrap_or("/");

        // Build scan payload
        let payload = ScanPayload::request(
            method,
            uri,
            self.request_headers.clone(),
            body.map(|b| b.to_vec()),
        );

        // Check if we should extract strings for JSON optimization
        let payload = if self.modsec_config.string_extraction.max_unique_strings > 0 {
            if let Some(body_bytes) = body {
                // Check content type
                let content_type = self
                    .request_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");

                if content_type.contains("application/json") {
                    // Extract strings from JSON for optimized scanning
                    let extraction_result =
                        extract_strings(body_bytes, &self.modsec_config.string_extraction);
                    payload.with_extracted_strings(extraction_result.strings)
                } else {
                    payload
                }
            } else {
                payload
            }
        } else {
            payload
        };

        // Generate a request ID (using a simple timestamp-based ID for now)
        let request_id = format!(
            "req-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        // Perform blocking scan
        let result = scanner.scan_blocking(&request_id, ScanType::Request, payload);

        // Set metadata
        {
            let mut setter = EnvoyMetadataSetter::new(envoy_filter);
            set_modsec_request_metadata(&mut setter, &result, &self.modsec_config.request_action);
        }

        // Record Envoy metrics
        envoy_filter
            .increment_counter(self.metrics.modsec_request_scans, 1)
            .ok();
        envoy_filter
            .record_histogram_value(
                self.metrics.modsec_request_scan_time_ms,
                result.total_scan_time_ms(),
            )
            .ok();

        if result.any_timeout() {
            envoy_filter
                .increment_counter(self.metrics.modsec_request_timeouts, 1)
                .ok();
        }

        let effective = result.effective_result();
        if effective.blocked {
            match self.modsec_config.request_action {
                ScanAction::Block => {
                    envoy_filter
                        .increment_counter(self.metrics.modsec_request_blocked, 1)
                        .ok();
                }
                ScanAction::Alert => {
                    envoy_filter
                        .increment_counter(self.metrics.modsec_request_alerts, 1)
                        .ok();
                }
            }
        }

        Some(result)
    }

    /// Perform ModSecurity response scanning
    ///
    /// Returns `Some(result)` with scan result, or `None` if scanning is disabled.
    fn scan_response_with_modsec<EHF: EnvoyHttpFilter>(
        &self,
        body: &[u8],
        status_code: u16,
        envoy_filter: &mut EHF,
    ) -> Option<DualScanResult> {
        // Skip if modsec is not enabled for responses
        if !self.modsec_config.scan_response {
            return None;
        }

        let scanner = self.modsec_scanner.as_ref()?;

        // Get request context
        let method = self.request_method.as_deref().unwrap_or("GET");
        let uri = self.request_uri.as_deref().unwrap_or("/");

        // Get response headers
        let response_headers: Vec<(String, String)> = envoy_filter
            .get_response_headers()
            .iter()
            .filter_map(|(k, v)| {
                let key = String::from_utf8(k.as_slice().to_vec()).ok()?;
                let value = String::from_utf8(v.as_slice().to_vec()).ok()?;
                Some((key, value))
            })
            .collect();

        // Determine scan type based on configuration
        let scan_type = if self.modsec_config.scan_response_as_request {
            ScanType::ResponseAsRequest
        } else {
            ScanType::Response
        };

        // Build scan payload
        let payload = ScanPayload::response(
            method,
            uri,
            self.request_headers.clone(),
            status_code,
            response_headers,
            Some(body.to_vec()),
        );

        // Check if we should extract strings for JSON optimization
        let payload = if self.modsec_config.string_extraction.max_unique_strings > 0 {
            // Check content type from response headers
            let content_type = envoy_filter
                .get_response_headers()
                .iter()
                .find(|(k, _)| k.as_slice().eq_ignore_ascii_case(b"content-type"))
                .and_then(|(_, v)| String::from_utf8(v.as_slice().to_vec()).ok())
                .unwrap_or_default();

            if content_type.contains("application/json") {
                // Extract strings from JSON for optimized scanning
                let extraction_result =
                    extract_strings(body, &self.modsec_config.string_extraction);
                payload.with_extracted_strings(extraction_result.strings)
            } else {
                payload
            }
        } else {
            payload
        };

        // Generate a request ID
        let request_id = format!(
            "resp-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        // Perform blocking scan
        let result = scanner.scan_blocking(&request_id, scan_type, payload);

        // Set metadata
        {
            let mut setter = EnvoyMetadataSetter::new(envoy_filter);
            set_modsec_response_metadata(&mut setter, &result, &self.modsec_config.response_action);
        }

        // Record Envoy metrics
        envoy_filter
            .increment_counter(self.metrics.modsec_response_scans, 1)
            .ok();
        envoy_filter
            .record_histogram_value(
                self.metrics.modsec_response_scan_time_ms,
                result.total_scan_time_ms(),
            )
            .ok();

        if result.any_timeout() {
            envoy_filter
                .increment_counter(self.metrics.modsec_response_timeouts, 1)
                .ok();
        }

        let effective = result.effective_result();
        if effective.blocked {
            match self.modsec_config.response_action {
                ScanAction::Block => {
                    envoy_filter
                        .increment_counter(self.metrics.modsec_response_blocked, 1)
                        .ok();
                }
                ScanAction::Alert => {
                    envoy_filter
                        .increment_counter(self.metrics.modsec_response_alerts, 1)
                        .ok();
                }
            }
        }

        Some(result)
    }

    /// Send a ModSecurity block response
    fn send_modsec_block_response<EHF: EnvoyHttpFilter>(
        envoy_filter: &mut EHF,
        result: &DualScanResult,
    ) {
        let effective = result.effective_result();
        let message = if !effective.matched_rules.is_empty() {
            format!(
                "Request blocked by WAF: {}",
                effective
                    .matched_rules
                    .iter()
                    .map(|r| r.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        } else {
            "Request blocked by WAF".to_string()
        };

        // Use 403 Forbidden for security blocks
        observability::send_error_response(envoy_filter, 403, &message);
    }

    /// Send a timeout block response
    fn send_modsec_timeout_response<EHF: EnvoyHttpFilter>(envoy_filter: &mut EHF) {
        observability::send_error_response(envoy_filter, 503, "Request blocked: WAF scan timeout");
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for OpenApiFilter {
    fn on_request_headers(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_headers_status {
        // Skip validation if disabled
        if !self.validation_config.validate_request {
            return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue;
        }

        // Clear previous request errors
        self.request_errors.clear();

        // Get request method and path
        let method = match Self::get_header(envoy_filter, ":method") {
            Some(m) => m,
            None => {
                observability::send_error_response(envoy_filter, 400, "Missing :method header");
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }
        };

        let path_with_query = match Self::get_header(envoy_filter, ":path") {
            Some(p) => p,
            None => {
                observability::send_error_response(envoy_filter, 400, "Missing :path header");
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }
        };

        // Security check: Path length limit
        if let Err(e) = security::check_string_length(
            &path_with_query,
            InputType::Path,
            self.security_limits.max_path_length,
        ) {
            observability::send_error_response(
                envoy_filter,
                e.status_code() as u32,
                &e.to_string(),
            );
            return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
        }

        // Split path and query string
        let (path, query_string) = match path_with_query.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (path_with_query, None),
        };

        // Find matching operation in OpenAPI spec
        let route_match = match self.router.find_operation(&method, &path) {
            Ok(result) => result,
            Err(e) => {
                observability::send_error_response(
                    envoy_filter,
                    e.status_code() as u32,
                    &e.to_string(),
                );
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }
        };

        let operation = route_match.operation;
        let path_params = route_match.path_params;
        let param_schemas = route_match.route.param_schemas.clone();

        // Validate path parameter types early (before full validation)
        if let Err(e) = validation::validate_path_param_types(&path_params, &param_schemas) {
            self.request_errors
                .push(format!("Path parameter type error: {}", e));
            envoy_filter
                .increment_counter(self.metrics.request_validation_errors, 1)
                .ok();
            if self.validation_config.fail_on_request_error {
                observability::set_request_metadata(envoy_filter, &self.request_errors);
                observability::send_error_response(envoy_filter, 400, &e.to_string());
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }
        }

        // Validate path parameters
        if let Err(e) = self.validate_path_params(&path_params, &operation, envoy_filter) {
            self.request_errors.push(format!("Path validation: {}", e));
            envoy_filter
                .increment_counter(self.metrics.request_validation_errors, 1)
                .ok();
        }

        // Validate query parameters (always validate, even if no query string present,
        // to catch missing required parameters)
        let query = query_string.as_deref().unwrap_or("");

        // Security check: Query string length limit (only if query string present)
        if !query.is_empty() {
            if let Err(e) = security::check_string_length(
                query,
                InputType::QueryString,
                self.security_limits.max_query_string_length,
            ) {
                observability::send_error_response(
                    envoy_filter,
                    e.status_code() as u32,
                    &e.to_string(),
                );
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }
        }

        if let Err(e) = self.validate_query_params(query, &operation, envoy_filter) {
            self.request_errors.push(format!("Query validation: {}", e));
            envoy_filter
                .increment_counter(self.metrics.request_validation_errors, 1)
                .ok();
        }

        // Validate request headers
        if let Err(e) = self.validate_request_headers(&operation, envoy_filter) {
            self.request_errors
                .push(format!("Header validation: {}", e));
            envoy_filter
                .increment_counter(self.metrics.request_validation_errors, 1)
                .ok();
        }

        // Store operation for body validation
        self.current_operation = Some(operation.clone());
        self.path_params = path_params;
        self.param_schemas = param_schemas;

        // Store request context for ModSecurity scanning
        // We need the full URI (path + query string) so that ModSecurity can
        // parse query parameters into ARGS_GET for CRS rule inspection.
        self.request_method = Some(method);
        self.request_uri = Some(match &query_string {
            Some(qs) => format!("{}?{}", path, qs),
            None => path,
        });
        self.request_headers = {
            let raw_headers = envoy_filter.get_request_headers();
            raw_headers
                .iter()
                .filter_map(|(k, v)| {
                    let key = String::from_utf8(k.as_slice().to_vec()).ok()?;
                    let value = String::from_utf8(v.as_slice().to_vec()).ok()?;

                    // Convert HTTP/2 pseudo-headers for ModSecurity compatibility
                    // CRS rules expect HTTP/1.1 style headers
                    if key == ":authority" {
                        // Convert :authority to Host header
                        Some(("Host".to_string(), value))
                    } else if key.starts_with(':') {
                        // Skip other pseudo-headers (:method, :path, :scheme)
                        // These are handled separately by ModSecurity via processConnection/processURI
                        None
                    } else {
                        Some((key, value))
                    }
                })
                .collect()
        };

        // Check if we have validation errors and should fail
        if !self.request_errors.is_empty() && self.validation_config.fail_on_request_error {
            observability::set_request_metadata(envoy_filter, &self.request_errors);
            observability::send_error_response(
                envoy_filter,
                400,
                &format!("Validation failed: {}", self.request_errors.join("; ")),
            );
            return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
        }

        // For methods with body, we need to wait for the body to arrive
        // We return StopIteration to tell Envoy to stop header iteration
        // but still call on_request_body when body data arrives.
        // After processing the body, we either send a mock response or
        // continue decoding to let the request proceed.

        // Set metadata even if no errors (verdict: valid)
        observability::set_request_metadata(envoy_filter, &self.request_errors);

        // ModSecurity scanning for requests without body (GET, DELETE, etc.)
        // For requests WITH body, scanning happens in on_request_body instead
        if end_of_stream {
            // No body is coming, perform ModSecurity scan now on URI/headers only
            if let Some(result) = self.scan_request_with_modsec(None, envoy_filter) {
                // Check for timeout first
                if result.any_timeout() {
                    match self.modsec_config.pool.timeout_action {
                        TimeoutAction::Block => {
                            Self::send_modsec_timeout_response(envoy_filter);
                            return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
                        }
                        TimeoutAction::Allow => {
                            // Log warning but continue - timeout metadata already set
                        }
                    }
                }

                // Check if we should block
                if result.should_block(&self.modsec_config.request_action) {
                    Self::send_modsec_block_response(envoy_filter, &result);
                    return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
                }
            }
        }

        // Check if mocking is enabled and handle body waiting
        if let Some(ref operation) = self.current_operation {
            // Check if we're expecting a request body that's actually coming
            // end_of_stream=true means no body is being sent
            // end_of_stream=false means body data will follow
            let body_is_coming = !end_of_stream;

            // If body is expected and actually coming, wait for it
            // Body validation and mock response will happen in on_request_body
            if operation.request_body.is_some() && body_is_coming {
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }

            // No body coming (either not expected or optional and not sent)
            // Check for required body validation
            if let Some(ref ref_or_body) = operation.request_body {
                // Resolve the request body reference to check if it's required
                if let Ok(body_spec) = self.resolver.resolve_request_body(ref_or_body) {
                    if body_spec.required && end_of_stream {
                        // Required body is missing
                        self.request_errors
                            .push("Request body is required but not provided".to_string());
                        envoy_filter
                            .increment_counter(self.metrics.request_validation_errors, 1)
                            .ok();

                        if self.validation_config.fail_on_request_error {
                            observability::set_request_metadata(envoy_filter, &self.request_errors);
                            observability::send_error_response(
                                envoy_filter,
                                400,
                                "Request body is required but not provided",
                            );
                            return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
                        }
                    }
                }
            }

            // No body to wait for, try to send mock response now
            if self.try_send_mock_response(operation, envoy_filter) {
                return abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::StopIteration;
            }
        }

        abi::envoy_dynamic_module_type_on_http_filter_request_headers_status::Continue
    }

    fn on_request_body(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_request_body_status {
        if !end_of_stream {
            return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndBuffer;
        }

        // Get the buffered body
        let body_buffers = match envoy_filter.get_buffered_request_body() {
            Some(buffers) => buffers,
            None => {
                return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::Continue;
            }
        };

        // Concatenate all body buffers
        let mut body = Vec::new();
        for buffer in body_buffers {
            body.extend_from_slice(buffer.as_slice());
        }

        // Security check: Body size limit
        if let Err(e) =
            security::check_input_length(&body, InputType::Body, self.security_limits.max_body_size)
        {
            observability::send_error_response(
                envoy_filter,
                e.status_code() as u32,
                &e.to_string(),
            );
            return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndWatermark;
        }

        // ModSecurity request body scanning (BEFORE OpenAPI validation - security first)
        // This ensures malicious payloads are blocked before any processing
        if let Some(result) = self.scan_request_with_modsec(Some(&body), envoy_filter) {
            // Check for timeout first
            if result.any_timeout() {
                match self.modsec_config.pool.timeout_action {
                    TimeoutAction::Block => {
                        Self::send_modsec_timeout_response(envoy_filter);
                        return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndWatermark;
                    }
                    TimeoutAction::Allow => {
                        // Log warning but continue - timeout metadata already set
                    }
                }
            }

            // Check if we should block
            if result.should_block(&self.modsec_config.request_action) {
                Self::send_modsec_block_response(envoy_filter, &result);
                return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndWatermark;
            }
        }

        // Validate body against OpenAPI spec (after security scanning)
        if let Some(operation) = self.current_operation.clone() {
            if let Err(e) = self.validate_body_with_schema(&body, &operation, envoy_filter) {
                self.request_errors.push(format!("Body validation: {}", e));
                envoy_filter
                    .increment_counter(self.metrics.request_validation_errors, 1)
                    .ok();

                observability::set_request_metadata(envoy_filter, &self.request_errors);

                if self.validation_config.fail_on_request_error {
                    observability::send_error_response(envoy_filter, 400, &e);
                    return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndWatermark;
                }
            } else {
                observability::set_request_metadata(envoy_filter, &self.request_errors);
            }

            // Check if mocking is enabled (after validation)
            if self.try_send_mock_response(&operation, envoy_filter) {
                return abi::envoy_dynamic_module_type_on_http_filter_request_body_status::StopIterationAndWatermark;
            }
        }

        abi::envoy_dynamic_module_type_on_http_filter_request_body_status::Continue
    }

    fn on_response_headers(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_headers_status {
        // Skip validation if disabled
        if !self.validation_config.validate_response {
            return abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue;
        }

        // Clear previous response errors
        self.response_errors.clear();

        // Store operation for response validation
        self.current_response_operation = self.current_operation.clone();

        // Validate response headers if we have an operation
        if let Some(operation) = self.current_response_operation.clone() {
            let status_code = Self::get_response_header(envoy_filter, ":status")
                .and_then(|s| s.parse().ok())
                .unwrap_or(200u16);

            if let Err(e) = self.validate_response_headers(&operation, status_code, envoy_filter) {
                self.response_errors
                    .push(format!("Response header validation: {}", e));
                envoy_filter
                    .increment_counter(self.metrics.response_validation_errors, 1)
                    .ok();
            }
        }

        // Buffer response for body validation
        if !end_of_stream && self.current_response_operation.is_some() {
            return abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::StopAllIterationAndBuffer;
        }

        // If end_of_stream (no body), set metadata now
        if end_of_stream {
            observability::set_response_metadata(envoy_filter, &self.response_errors);
        }

        abi::envoy_dynamic_module_type_on_http_filter_response_headers_status::Continue
    }

    fn on_response_body(
        &mut self,
        envoy_filter: &mut EHF,
        end_of_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_http_filter_response_body_status {
        // Skip validation if disabled
        if !self.validation_config.validate_response {
            return abi::envoy_dynamic_module_type_on_http_filter_response_body_status::Continue;
        }

        if !end_of_stream {
            return abi::envoy_dynamic_module_type_on_http_filter_response_body_status::StopIterationAndBuffer;
        }

        // Get the buffered response body
        let body_buffers = match envoy_filter.get_buffered_response_body() {
            Some(buffers) => buffers,
            None => {
                return abi::envoy_dynamic_module_type_on_http_filter_response_body_status::Continue;
            }
        };

        // Concatenate all body buffers
        let mut body = Vec::new();
        for buffer in body_buffers {
            body.extend_from_slice(buffer.as_slice());
        }

        // Get response status code
        let status_code = Self::get_response_header(envoy_filter, ":status")
            .and_then(|s| s.parse().ok())
            .unwrap_or(200u16);

        // ModSecurity response body scanning (BEFORE OpenAPI validation - security first)
        // This ensures malicious/sensitive data in responses is blocked before any processing
        if let Some(result) = self.scan_response_with_modsec(&body, status_code, envoy_filter) {
            // Check for timeout first
            if result.any_timeout() {
                match self.modsec_config.pool.timeout_action {
                    TimeoutAction::Block => {
                        Self::send_modsec_timeout_response(envoy_filter);
                        return abi::envoy_dynamic_module_type_on_http_filter_response_body_status::StopIterationAndWatermark;
                    }
                    TimeoutAction::Allow => {
                        // Log warning but continue - timeout metadata already set
                    }
                }
            }

            // Check if we should block the response
            if result.should_block(&self.modsec_config.response_action) {
                Self::send_modsec_block_response(envoy_filter, &result);
                return abi::envoy_dynamic_module_type_on_http_filter_response_body_status::StopIterationAndWatermark;
            }
        }

        // Validate response body against OpenAPI spec (after security scanning)
        if let Some(operation) = self.current_response_operation.clone() {
            if let Err(e) = self.validate_response_body_with_schema(
                &body,
                &operation,
                status_code,
                envoy_filter,
            ) {
                self.response_errors
                    .push(format!("Response body validation: {}", e));
                envoy_filter
                    .increment_counter(self.metrics.response_validation_errors, 1)
                    .ok();
            }
        }

        observability::set_response_metadata(envoy_filter, &self.response_errors);

        abi::envoy_dynamic_module_type_on_http_filter_response_body_status::Continue
    }
}
