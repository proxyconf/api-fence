//! Envoy readiness utilities for integration tests
//!
//! The Envoy process lifecycle (start/stop) is managed externally by
//! `mise run test-integration`. This module provides constants and a
//! readiness check that tests use before sending requests.
//!
//! Envoy hosts two listeners:
//! - **Port 18080**: OpenAPI validation only (no ModSecurity)
//! - **Port 18090**: OpenAPI validation + ModSecurity WAF
//! - **Port 18081**: Admin interface

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Fixed ports — must match tests/fixtures/envoy/integration-test.yaml
pub const VALIDATION_PORT: u16 = 18080;
pub const MODSEC_PORT: u16 = 18090;
pub const ADMIN_PORT: u16 = 18081;

/// Base URL for the validation-only listener
pub fn validation_base_url() -> String {
    format!("http://127.0.0.1:{}", VALIDATION_PORT)
}

/// Base URL for the ModSecurity listener
pub fn modsec_base_url() -> String {
    format!("http://127.0.0.1:{}", MODSEC_PORT)
}

/// Wait for Envoy to become ready by polling the admin endpoint.
///
/// Returns `Ok(())` when Envoy responds on the admin port, or `Err`
/// if the timeout is reached.
pub fn wait_for_envoy(timeout_secs: u64) -> Result<(), String> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let admin_url = format!("http://127.0.0.1:{}/ready", ADMIN_PORT);

    while start.elapsed() < timeout {
        let result = Command::new("curl")
            .args(["-s", "-f", &admin_url])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        if let Ok(status) = result {
            if status.success() {
                return Ok(());
            }
        }

        thread::sleep(Duration::from_millis(200));
    }

    Err(format!(
        "Envoy did not become ready within {} seconds. \
         Make sure Envoy is running: mise run test-integration",
        timeout_secs
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_urls() {
        assert_eq!(validation_base_url(), "http://127.0.0.1:18080");
        assert_eq!(modsec_base_url(), "http://127.0.0.1:18090");
    }
}
