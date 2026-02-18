// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Integration test modules for OpenAPI Filter
//!
//! This module provides shared infrastructure for integration testing
//! of the OpenAPI filter running inside Envoy.
//!
//! # Architecture
//!
//! A single Envoy process hosts two listeners:
//! - **Port 18080**: Validation-only (no ModSecurity) -- used by most test modules
//! - **Port 18090**: Validation + ModSecurity WAF -- used by `test_modsecurity`
//!
//! Envoy lifecycle (start/stop) is managed by `mise run test-integration`.
//! Tests only need to verify Envoy is ready before sending requests.
//!
//! # Usage
//!
//! ```bash
//! # Run all integration tests (starts Envoy automatically)
//! mise run test-integration
//!
//! # Run only ModSecurity tests
//! mise run test-modsec
//! ```

pub mod client;
pub mod envoy;

// Test modules
pub mod test_body_validation;
pub mod test_error_responses;
pub mod test_header_validation;
pub mod test_mock_responses;
pub mod test_modsecurity;
pub mod test_path_validation;
pub mod test_query_validation;
pub mod test_security_limits;

use std::sync::OnceLock;

use client::TestClient;

/// Ensures we have verified Envoy readiness exactly once.
static ENVOY_READY: OnceLock<()> = OnceLock::new();

/// Verify Envoy is ready (called once, result cached).
fn ensure_envoy_ready() {
    ENVOY_READY.get_or_init(|| {
        envoy::wait_for_envoy(30)
            .expect("Envoy is not running. Start it with: mise run test-integration");
    });
}

/// Get a test client connected to the validation-only listener (port 18080).
///
/// Used by: test_path_validation, test_query_validation, test_header_validation,
///          test_body_validation, test_mock_responses, test_error_responses,
///          test_security_limits
pub fn get_test_client() -> TestClient {
    ensure_envoy_ready();
    TestClient::new(envoy::validation_base_url())
}

/// Get a test client connected to the ModSecurity listener (port 18090).
///
/// Used by: test_modsecurity
pub fn get_modsec_test_client() -> TestClient {
    ensure_envoy_ready();
    TestClient::new(envoy::modsec_base_url())
}
