//! Integration Test Suite for OpenAPI Filter
//!
//! This is the entry point for Docker-based integration tests that verify
//! the OpenAPI filter running inside Envoy containers.
//!
//! # Running Tests
//!
//! Tests are marked `#[ignore]` by default because they require Docker.
//!
//! ```bash
//! # Run all integration tests (requires Docker)
//! cargo test --test integration -- --ignored
//!
//! # Run with parallelism
//! cargo test --test integration -- --ignored --test-threads=4
//!
//! # Run specific test module
//! cargo test --test integration test_path -- --ignored
//! ```
//!
//! # Architecture
//!
//! Each test module (path, query, header, body, etc.) runs tests in isolation.
//! The framework:
//!
//! 1. Builds the filter Docker image
//! 2. Starts an Envoy container with the filter loaded
//! 3. Sends HTTP requests to test validation behavior
//! 4. Verifies responses match expected behavior
//! 5. Cleans up containers
//!
//! Mock mode enables self-validating tests where the filter validates
//! both requests and generates mock responses from the OpenAPI spec.

// Integration test modules
mod integration_tests;

// Re-export key items for use in tests
pub use integration_tests::*;
