//! Integration tests for API Fence with Envoy
//!
//! This test suite:
//! 1. Builds the filter as a dynamic module
//! 2. Starts Envoy with the filter loaded
//! 3. Runs openapi-fuzzer against the Envoy instance
//! 4. Verifies the filter behavior

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

/// Wrapper for managing an Envoy test server
pub struct EnvoyTestServer {
    process: Child,
    port: u16,
    admin_port: u16,
    _temp_dir: TempDir,
    pub base_url: String,
}

impl EnvoyTestServer {
    /// Start Envoy with the API Fence loaded
    pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
        // Ensure the filter is built
        println!("Building API Fence...");
        let build_output = Command::new("cargo")
            .args(&["build", "--release"])
            .output()?;

        if !build_output.status.success() {
            return Err(format!(
                "Failed to build filter: {}",
                String::from_utf8_lossy(&build_output.stderr)
            )
            .into());
        }

        let filter_path = PathBuf::from("target/release/libapi_fence.so");
        if !filter_path.exists() {
            return Err(format!("Filter not found at {:?}", filter_path).into());
        }

        // Create temporary directory for test artifacts
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("envoy-test.yaml");
        let filter_abs_path = fs::canonicalize(&filter_path)?;

        // Generate Envoy configuration with our filter
        let envoy_config = generate_envoy_config(&filter_abs_path, 10000, 9901);
        fs::write(&config_path, envoy_config)?;

        println!("Starting Envoy with config: {:?}", config_path);
        println!("Filter path: {:?}", filter_abs_path);

        // Start Envoy
        let process = Command::new("envoy")
            .arg("-c")
            .arg(&config_path)
            .arg("--log-level")
            .arg("info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let server = Self {
            process,
            port: 10000,
            admin_port: 9901,
            _temp_dir: temp_dir,
            base_url: "http://127.0.0.1:10000".to_string(),
        };

        // Wait for Envoy to be ready
        server.wait_for_ready()?;

        Ok(server)
    }

    /// Wait for Envoy to be ready by polling the admin endpoint
    fn wait_for_ready(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Waiting for Envoy to be ready...");

        for attempt in 1..=30 {
            thread::sleep(Duration::from_millis(500));

            let result = Command::new("curl")
                .arg("-s")
                .arg(format!("http://127.0.0.1:{}/ready", self.admin_port))
                .output();

            if let Ok(output) = result {
                if output.status.success() {
                    println!("Envoy is ready!");
                    return Ok(());
                }
            }

            if attempt % 5 == 0 {
                println!("  Still waiting... (attempt {}/30)", attempt);
            }
        }

        Err("Envoy failed to become ready within timeout".into())
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Drop for EnvoyTestServer {
    fn drop(&mut self) {
        println!("Stopping Envoy...");
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Generate Envoy configuration with the dynamic module filter
fn generate_envoy_config(_filter_path: &Path, port: u16, admin_port: u16) -> String {
    // Get absolute path to the sample OpenAPI spec
    let openapi_spec_path = fs::canonicalize("examples/sample-openapi.yaml")
        .expect("Failed to find sample-openapi.yaml");

    format!(
        r#"
admin:
  address:
    socket_address:
      address: 0.0.0.0
      port_value: {}

static_resources:
  listeners:
    - name: listener_0
      address:
        socket_address:
          address: 0.0.0.0
          port_value: {}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                codec_type: AUTO
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: "OK"
                http_filters:
                  # API Fence (Dynamic Module)
                  - name: envoy.filters.http.dynamic_modules
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
                      dynamic_module_config:
                        name: api_fence
                        do_not_close: true
                      filter_name: api_fence
                      filter_config:
                        "@type": type.googleapis.com/google.protobuf.StringValue
                        value: |
                          {{
                            "api_name": "legacy_test",
                            "openapi_spec_path": "{}"
                          }}
                  # Router filter (required)
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#,
        admin_port,
        port,
        openapi_spec_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Run with: cargo test --test integration -- --ignored
    fn test_envoy_starts_with_filter() {
        let server = EnvoyTestServer::start().expect("Failed to start Envoy");

        // Make a simple request to verify Envoy is working
        let output = Command::new("curl")
            .arg("-s")
            .arg("-w")
            .arg("\n%{http_code}")
            .arg(&server.url("/"))
            .output()
            .expect("Failed to execute curl");

        let response = String::from_utf8_lossy(&output.stdout);
        println!("Response: {}", response);

        assert!(response.contains("200"), "Expected 200 status code");
    }
}
