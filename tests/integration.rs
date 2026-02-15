//! Integration Test Suite for OpenAPI Filter
//!
//! Tests the OpenAPI filter running inside a real Envoy process.
//! Envoy lifecycle is managed by `mise run test-integration`.
//!
//! # Running Tests
//!
//! ```bash
//! # Run all integration tests (builds filter, starts Envoy, runs tests, stops Envoy)
//! mise run test-integration
//!
//! # Run only ModSecurity tests
//! mise run test-modsec
//! ```

// Integration test modules
mod integration_tests;

// Re-export key items for use in tests
pub use integration_tests::*;
