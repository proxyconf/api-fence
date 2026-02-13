//! Integration test modules for OpenAPI Filter
//!
//! This module provides shared infrastructure for integration testing
//! of the OpenAPI filter running inside Envoy.
//!
//! # Architecture
//!
//! A single Envoy process hosts two listeners:
//! - **Port 18080**: Validation-only (no ModSecurity) — used by most test modules
//! - **Port 18090**: Validation + ModSecurity WAF — used by `test_modsecurity`
//!
//! The process is lazily initialized on first use and cleaned up when
//! the test process exits. All tests share this single Envoy process.
//!
//! # Usage
//!
//! ```bash
//! # Run all integration tests (requires Envoy binary)
//! mise run test-integration
//!
//! # Or manually:
//! cargo test --test integration -- --ignored
//!
//! # Run with parallelism (safe — all tests share one Envoy process)
//! cargo test --test integration -- --ignored --test-threads=4
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
use envoy::EnvoyProcess;

/// The single shared Envoy process for all integration tests.
/// Hosts both validation-only (18080) and modsec (18090) listeners.
/// Lazily initialized on first access, automatically cleaned up on process exit.
static SHARED_ENVOY: OnceLock<EnvoyProcess> = OnceLock::new();

/// Get or create the shared Envoy process, then return it.
fn shared_envoy() -> &'static EnvoyProcess {
    SHARED_ENVOY.get_or_init(|| {
        require_envoy();
        EnvoyProcess::start().expect("Failed to start Envoy process")
    })
}

/// Get a test client connected to the validation-only listener (port 18080).
///
/// Used by: test_path_validation, test_query_validation, test_header_validation,
///          test_body_validation, test_mock_responses, test_error_responses,
///          test_security_limits
pub fn get_test_client() -> TestClient {
    TestClient::new(shared_envoy().validation_base_url())
}

/// Get a test client connected to the ModSecurity listener (port 18090).
///
/// Used by: test_modsecurity
pub fn get_modsec_test_client() -> TestClient {
    TestClient::new(shared_envoy().modsec_base_url())
}

/// Check if Envoy is available
pub fn envoy_available() -> bool {
    std::process::Command::new("envoy")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Skip test if Envoy is not available.
/// This macro should only be used inside test functions.
#[macro_export]
macro_rules! skip_if_no_envoy {
    () => {
        if !$crate::integration_tests::envoy_available() {
            eprintln!("Skipping test: Envoy not available");
            return;
        }
    };
}

/// Check Envoy availability and panic if not available.
pub fn require_envoy() {
    if !envoy_available() {
        panic!(
            "Envoy is not available - cannot run integration tests.\n\
             Make sure envoy is in PATH or run: mise run test-integration"
        );
    }
}
