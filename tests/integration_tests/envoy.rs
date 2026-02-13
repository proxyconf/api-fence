//! Native Envoy process management for integration tests
//!
//! This module manages a single Envoy process that runs for the lifetime of
//! the test suite. The process hosts TWO listeners:
//!
//! - **Validation listener** (port 18080): OpenAPI validation only, no ModSecurity
//! - **ModSecurity listener** (port 18090): OpenAPI validation + ModSecurity WAF
//!
//! Both listeners share the same Envoy process, admin interface, and filter `.so`.
//! This proves that multiple filter instances with different configs can coexist
//! in a single Envoy, and eliminates the need for separate Envoy processes.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Error type for Envoy operations
#[derive(Debug)]
pub struct EnvoyError {
    pub message: String,
    pub logs: Option<String>,
}

impl std::fmt::Display for EnvoyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(logs) = &self.logs {
            write!(f, "\n\nEnvoy logs:\n{}", logs)?;
        }
        Ok(())
    }
}

impl std::error::Error for EnvoyError {}

impl EnvoyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            logs: None,
        }
    }

    pub fn with_logs(mut self, logs: String) -> Self {
        self.logs = Some(logs);
        self
    }
}

/// Fixed ports for the shared Envoy process
const VALIDATION_PORT: u16 = 18080;
const MODSEC_PORT: u16 = 18090;
const ADMIN_PORT: u16 = 18081;

/// Path to store the Envoy PID for cleanup
const PID_FILE: &str = "/tmp/envoy-integration-test.pid";

/// A shared Envoy process that runs for the lifetime of the test suite.
///
/// This process hosts two listeners with different filter configurations:
/// - Port 18080: validation-only (no ModSecurity)
/// - Port 18090: validation + ModSecurity WAF scanning
///
/// Both listeners use the same `comprehensive.yaml` OpenAPI spec and the same
/// filter `.so`, but with different `filter_config` JSON payloads.
///
/// Note: Envoy is started via `setsid` to create a new session, which prevents
/// the parent death signal (PR_SET_PDEATHSIG) from killing Envoy when test
/// threads exit. The PID is tracked via a file for cleanup.
pub struct EnvoyProcess {
    /// Path to the temp config file (kept alive by this struct)
    _config_path: PathBuf,
    /// Path to the log file
    log_path: PathBuf,
}

/// Check if release mode is requested via environment variable
fn use_release_mode() -> bool {
    std::env::var("INTEGRATION_TEST_RELEASE")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false)
}

impl EnvoyProcess {
    /// Start the shared Envoy process with both listeners.
    ///
    /// This builds the filter (if needed), starts Envoy with two listeners
    /// (validation-only and modsec), and waits for it to become ready.
    ///
    /// By default, uses debug builds for faster iteration. Set environment
    /// variable `INTEGRATION_TEST_RELEASE=1` to use release builds.
    pub fn start() -> Result<Self, EnvoyError> {
        // Check if any of our ports are already in use
        for (name, port) in [
            ("validation", VALIDATION_PORT),
            ("modsec", MODSEC_PORT),
            ("admin", ADMIN_PORT),
        ] {
            if Self::is_port_in_use(port) {
                return Err(EnvoyError::new(format!(
                    "Port {} ({}) is already in use. Stop any existing Envoy processes first.\n\
                     Hint: pkill -f 'envoy.*integration'; rm -f {}",
                    port, name, PID_FILE
                )));
            }
        }

        let release_mode = use_release_mode();

        // Build the filter
        Self::build_filter(release_mode)?;

        // Get paths
        let project_root = Self::project_root()?;
        let target_dir = if release_mode { "release" } else { "debug" };
        let filter_path = project_root.join(format!("target/{}/libapi_fence.so", target_dir));

        if !filter_path.exists() {
            return Err(EnvoyError::new(format!(
                "Filter not found at {:?}. Build with `cargo build{}`",
                filter_path,
                if release_mode { " --release" } else { "" }
            )));
        }

        let filter_abs_path = fs::canonicalize(&filter_path)
            .map_err(|e| EnvoyError::new(format!("Failed to canonicalize filter path: {}", e)))?;

        let spec_path = project_root.join("tests/fixtures/openapi/comprehensive.yaml");
        let spec_abs_path = fs::canonicalize(&spec_path)
            .map_err(|e| EnvoyError::new(format!("Failed to canonicalize spec path: {}", e)))?;

        // Generate and write unified Envoy config
        let config = Self::generate_config(&filter_abs_path, &spec_abs_path);
        let config_path = std::env::temp_dir().join("envoy-integration-test.yaml");
        fs::write(&config_path, &config)
            .map_err(|e| EnvoyError::new(format!("Failed to write config: {}", e)))?;

        // Create log file path
        let log_path = std::env::temp_dir().join("envoy-integration-test.log");

        // Get the directory containing the filter .so file
        let filter_dir = filter_abs_path
            .parent()
            .ok_or_else(|| EnvoyError::new("Failed to get filter directory"))?;

        eprintln!(
            "Starting Envoy (Validation: {}, ModSec: {}, Admin: {})...",
            VALIDATION_PORT, MODSEC_PORT, ADMIN_PORT
        );
        eprintln!("  Config: {}", config_path.display());
        eprintln!("  Filter dir: {}", filter_dir.display());
        eprintln!("  Spec: {}", spec_abs_path.display());
        eprintln!("  Logs: {}", log_path.display());

        // Open log file for stderr
        let log_file = fs::File::create(&log_path)
            .map_err(|e| EnvoyError::new(format!("Failed to create log file: {}", e)))?;

        // Start Envoy via setsid to create a new session.
        // This prevents Envoy's PR_SET_PDEATHSIG from killing it when test threads exit.
        // We use a shell command to capture the PID and write it to a file.
        let pid_file = PathBuf::from(PID_FILE);

        // Create a shell script that starts envoy and writes its PID
        let script = format!(
            r#"ENVOY_DYNAMIC_MODULES_SEARCH_PATH="{filter_dir}" envoy -c "{config}" --log-level warn & echo $! > "{pid_file}""#,
            filter_dir = filter_dir.display(),
            config = config_path.display(),
            pid_file = pid_file.display(),
        );

        let mut cmd = Command::new("setsid");
        cmd.arg("--fork")
            .arg("sh")
            .arg("-c")
            .arg(&script)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file));

        let status = cmd
            .status()
            .map_err(|e| EnvoyError::new(format!("Failed to start Envoy: {}", e)))?;

        if !status.success() {
            return Err(EnvoyError::new("Failed to start Envoy via setsid"));
        }

        let envoy = Self {
            _config_path: config_path,
            log_path,
        };

        // Wait for Envoy to be ready (admin endpoint serves both listeners)
        envoy.wait_for_ready(30)?;

        eprintln!("Envoy is ready! (both listeners active)");

        Ok(envoy)
    }

    /// Check if a port is already in use
    fn is_port_in_use(port: u16) -> bool {
        std::net::TcpListener::bind(("127.0.0.1", port)).is_err()
    }

    /// Build the filter
    fn build_filter(release_mode: bool) -> Result<(), EnvoyError> {
        // Skip build if SKIP_FILTER_BUILD is set (useful when filter is pre-built)
        if std::env::var("SKIP_FILTER_BUILD").is_ok() {
            eprintln!("Skipping filter build (SKIP_FILTER_BUILD set)");
            return Ok(());
        }

        let mode_str = if release_mode { "release" } else { "debug" };
        eprintln!("Building filter ({} mode)...", mode_str);

        let mut args = vec!["build"];
        if release_mode {
            args.push("--release");
        }

        let output = Command::new("cargo")
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| EnvoyError::new(format!("Failed to run cargo build: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(EnvoyError::new(format!("cargo build failed: {}", stderr)));
        }

        eprintln!("Filter built successfully.");
        Ok(())
    }

    /// Get the project root directory
    fn project_root() -> Result<PathBuf, EnvoyError> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());

        Ok(manifest_dir)
    }

    /// Generate unified Envoy configuration with two listeners.
    ///
    /// Listener 1 (validation-only): Port 18080
    ///   - OpenAPI validation with mocking enabled
    ///   - No ModSecurity scanning
    ///
    /// Listener 2 (modsec): Port 18090
    ///   - OpenAPI validation with mocking enabled
    ///   - ModSecurity WAF scanning with bundled CRS "minimal" profile
    fn generate_config(_filter_path: &PathBuf, spec_path: &PathBuf) -> String {
        format!(
            r#"admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: {admin_port}

static_resources:
  listeners:
    # =========================================================================
    # Listener 1: Validation-only (no ModSecurity)
    # Used by: test_path_validation, test_query_validation, test_header_validation,
    #          test_body_validation, test_mock_responses, test_error_responses,
    #          test_security_limits
    # =========================================================================
    - name: validation_listener
      address:
        socket_address:
          address: 127.0.0.1
          port_value: {validation_port}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: validation_http
                codec_type: AUTO
                route_config:
                  name: validation_route
                  virtual_hosts:
                    - name: validation_backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: '{{"status": "ok"}}'
                http_filters:
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
                            "api_name": "integration_test",
                            "openapi_spec_path": "{spec_path}",
                            "mocking": {{
                              "enabled": true
                            }}
                          }}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

    # =========================================================================
    # Listener 2: Validation + ModSecurity WAF
    # Used by: test_modsecurity
    # =========================================================================
    - name: modsec_listener
      address:
        socket_address:
          address: 127.0.0.1
          port_value: {modsec_port}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: modsec_http
                codec_type: AUTO
                route_config:
                  name: modsec_route
                  virtual_hosts:
                    - name: modsec_backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          direct_response:
                            status: 200
                            body:
                              inline_string: '{{"status": "ok"}}'
                http_filters:
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
                            "api_name": "modsec_test",
                            "openapi_spec_path": "{spec_path}",
                            "mocking": {{
                              "enabled": true
                            }},
                            "modsecurity": {{
                              "scan_request": true,
                              "scan_response": false,
                              "request_action": "block",
                              "pool": {{
                                "thread_count": 1,
                                "timeout_ms": 2000
                              }},
                              "primary_ruleset": {{
                                "name": "bundled_crs",
                                "use_bundled_crs": true,
                                "bundled_crs_profile": "minimal"
                              }}
                            }}
                          }}
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#,
            admin_port = ADMIN_PORT,
            validation_port = VALIDATION_PORT,
            modsec_port = MODSEC_PORT,
            spec_path = spec_path.display(),
        )
    }

    /// Wait for Envoy to become ready
    fn wait_for_ready(&self, timeout_secs: u64) -> Result<(), EnvoyError> {
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

        let logs = self.logs();
        Err(EnvoyError::new("Envoy failed to become ready within timeout").with_logs(logs))
    }

    /// Get the base URL for the validation-only listener (port 18080)
    pub fn validation_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", VALIDATION_PORT)
    }

    /// Get the base URL for the ModSecurity listener (port 18090)
    pub fn modsec_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", MODSEC_PORT)
    }

    /// Get Envoy logs
    pub fn logs(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_else(|e| format!("Failed to read logs: {}", e))
    }
}

impl Drop for EnvoyProcess {
    fn drop(&mut self) {
        eprintln!("Stopping Envoy...");

        // Read PID from file and kill the process
        let pid_file = PathBuf::from(PID_FILE);
        if let Ok(pid_str) = fs::read_to_string(&pid_file) {
            let pid = pid_str.trim();
            if !pid.is_empty() {
                // Send SIGTERM to gracefully stop Envoy
                let _ = Command::new("kill")
                    .args(["-TERM", pid])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();

                // Give it a moment to shut down gracefully
                thread::sleep(Duration::from_millis(100));

                // Force kill if still running
                let _ = Command::new("kill")
                    .args(["-9", pid])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            // Clean up PID file
            let _ = fs::remove_file(&pid_file);
        } else {
            eprintln!("Warning: Could not read PID file, Envoy may still be running");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_generation() {
        let filter_path = PathBuf::from("/usr/local/lib/libapi_fence.so");
        let spec_path = PathBuf::from("/etc/envoy/specs/comprehensive.yaml");
        let config = EnvoyProcess::generate_config(&filter_path, &spec_path);

        assert!(config.contains("comprehensive.yaml"));
        assert!(config.contains("mocking"));
        assert!(config.contains("api_fence")); // filter name in config
        assert!(config.contains(&VALIDATION_PORT.to_string()));
        assert!(config.contains(&MODSEC_PORT.to_string()));
        assert!(config.contains(&ADMIN_PORT.to_string()));
        // Both listeners present
        assert!(config.contains("validation_listener"));
        assert!(config.contains("modsec_listener"));
        // ModSecurity config only on second listener
        assert!(config.contains("modsecurity"));
        assert!(config.contains("bundled_crs_profile"));
        // filename should NOT be in config - uses ENVOY_DYNAMIC_MODULES_SEARCH_PATH instead
        assert!(!config.contains("filename:"));
    }
}
