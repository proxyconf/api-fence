//! Integration test modules for OpenAPI Filter
//!
//! This module provides shared infrastructure for integration testing
//! of the OpenAPI filter running inside Envoy.
//!
//! # Architecture
//!
//! A single Envoy process is started once and shared across all tests.
//! The process is lazily initialized on first use and cleaned up when
//! the test process exits.
//!
//! # Usage
//!
//! ```bash
//! # Run all integration tests (requires Envoy binary from Nix)
//! cargo test --test integration -- --ignored
//!
//! # Run with parallelism (safe - all tests share one Envoy process)
//! cargo test --test integration -- --ignored --test-threads=4
//! ```

pub mod client;
pub mod envoy;

// Test modules
pub mod test_body_validation;
pub mod test_error_responses;
pub mod test_header_validation;
pub mod test_mock_responses;
pub mod test_path_validation;
pub mod test_query_validation;
pub mod test_security_limits;

use std::sync::OnceLock;

use client::TestClient;
use envoy::EnvoyProcess;

/// The single shared Envoy process for all integration tests.
/// Lazily initialized on first access, automatically cleaned up on process exit.
static SHARED_ENVOY: OnceLock<EnvoyProcess> = OnceLock::new();

/// Get or create the shared Envoy process and return a client to it.
///
/// This function:
/// 1. Builds the filter in release mode (if not already built)
/// 2. Starts Envoy with the filter loaded (if not already running)
/// 3. Returns a client connected to the Envoy instance
///
/// The Envoy instance uses the comprehensive.yaml spec which includes all test endpoints.
/// All test modules share this single process to minimize resource usage and startup time.
pub fn get_test_client() -> TestClient {
    let envoy = SHARED_ENVOY.get_or_init(|| {
        require_envoy();
        EnvoyProcess::start().expect("Failed to start Envoy process")
    });

    TestClient::new(envoy.base_url())
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
             Make sure you are running in the Nix development shell (nix develop)"
        );
    }
}
