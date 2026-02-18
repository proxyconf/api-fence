// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Envoy API Fence - Dynamic Module
//!
//! This is an Envoy HTTP filter implemented as a dynamic module using Rust.
//! It provides dual protection layers:
//! 
//! 1. **OpenAPI Validation**: Validates incoming HTTP requests/responses against OpenAPI 3.x specifications
//! 2. **ModSecurity WAF**: Web Application Firewall protection using libmodsecurity3 with OWASP CoreRuleSet v4.0.0
//!
//! # Module Structure
//!
//! - [`config`]: Configuration types for the filter
//! - [`error`]: Error types and result aliases
//! - [`filter`]: Main filter implementation
//! - [`mock`]: Mock response generation
//! - [`modsec`]: ModSecurity WAF integration
//! - [`observability`]: Metrics and dynamic metadata
//! - [`router`]: OpenAPI path routing
//! - [`schema`]: JSON Schema caching and compilation
//! - [`util`]: Shared utility functions
//! - [`validation`]: Request/response validation logic

// Internal modules
pub mod config;
pub mod error;
pub mod filter;
pub mod mock;
pub mod modsec;
pub mod observability;
pub mod resolver;
pub mod router;
pub mod schema;
pub mod security;
pub mod util;
pub mod validation;

// Re-export main public types
pub use config::{CacheConfig, Config, ValidationConfig};
pub use error::{
    ConfigError, FilterError, MockError, ProblemDetails, RoutingError, SchemaError, ValidationError,
};
pub use filter::{FilterConfig, OpenApiFilter};
pub use resolver::{RefError, RefResolver, RefTarget};
pub use router::Router;
pub use schema::{SchemaCache, SchemaCompiler};
pub use security::{SecurityError, SecurityLimits};

// Envoy SDK imports
use envoy_proxy_dynamic_modules_rust_sdk::*;

// Declare module initialization functions
declare_init_functions!(init, new_http_filter_config_fn);

/// Program initialization - called once when module is loaded
fn init() -> bool {
    true
}

/// Create new HTTP filter config based on filter name and config
fn new_http_filter_config_fn<EC: EnvoyHttpFilterConfig, EHF: EnvoyHttpFilter>(
    envoy_filter_config: &mut EC,
    filter_name: &str,
    filter_config: &[u8],
) -> Option<Box<dyn HttpFilterConfig<EHF>>> {
    let config_str = std::str::from_utf8(filter_config).ok()?;

    match filter_name {
        "api_fence" => {
            match FilterConfig::try_new(config_str, envoy_filter_config) {
                Ok(config) => Some(Box::new(config)),
                Err(e) => {
                    // Log the error and return None to let Envoy handle gracefully
                    eprintln!("API Fence configuration error: {}", e);
                    None
                }
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_exports() {
        // Verify that key types are accessible via public exports
        let _: fn() -> config::CacheConfig = config::CacheConfig::default;
        let _: fn() -> config::ValidationConfig = config::ValidationConfig::default;
    }
}
