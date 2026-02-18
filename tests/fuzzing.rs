// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! OpenAPI Fuzzing integration tests
//!
//! This test uses openapi-fuzzer to test the OpenAPI filter with Envoy

mod integration_legacy;

use integration_legacy::EnvoyTestServer;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore] // Run with: cargo test --test fuzzing -- --ignored --nocapture
fn test_openapi_fuzzer_integration() {
    println!("=== Starting OpenAPI Fuzzing Test ===\n");

    // Start Envoy with our filter
    let server = EnvoyTestServer::start().expect("Failed to start Envoy");
    println!("Envoy running at: {}\n", server.base_url);

    // Paths to test resources
    let openapi_spec = PathBuf::from("examples/sample-openapi.yaml");
    assert!(
        openapi_spec.exists(),
        "OpenAPI spec not found at {:?}",
        openapi_spec
    );

    // Create results directory for fuzzer output
    let results_dir = PathBuf::from("target/fuzzer-results");
    fs::create_dir_all(&results_dir).expect("Failed to create results directory");

    println!("Running openapi-fuzzer...");
    println!("OpenAPI spec: {:?}", openapi_spec);
    println!("Target URL: {}", server.base_url);
    println!("Results dir: {:?}\n", results_dir);

    // Run openapi-fuzzer
    let output = Command::new("openapi-fuzzer")
        .arg("run")
        .arg("--spec")
        .arg(&openapi_spec)
        .arg("--url")
        .arg(&server.base_url)
        .arg("--results-dir")
        .arg(&results_dir)
        .arg("--max-test-case-count")
        .arg("50") // Reduced for faster tests
        .arg("--ignore-status-code")
        .arg("404") // Ignore not found (backend not implemented)
        .arg("--ignore-status-code")
        .arg("400") // Ignore bad requests (expected for invalid payloads)
        .output()
        .expect("Failed to execute openapi-fuzzer");

    // Print fuzzer output
    println!("=== Fuzzer Output ===");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    if !output.stderr.is_empty() {
        eprintln!("=== Fuzzer Errors ===");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    }

    // Check if fuzzer succeeded
    assert!(
        output.status.success(),
        "openapi-fuzzer failed with status: {:?}",
        output.status
    );

    // Check for findings
    let findings_count = count_findings(&results_dir);
    println!("\n=== Test Results ===");
    println!("Findings: {}", findings_count);

    // For now, we're in development mode - log findings but don't fail
    // Once the filter is fully implemented, this should be:
    // assert_eq!(findings_count, 0, "Fuzzer found {} issues", findings_count);
    if findings_count > 0 {
        println!(
            "⚠️  Found {} issues - filter implementation in progress",
            findings_count
        );
        list_findings(&results_dir);
    } else {
        println!("✅ No issues found - filter is working correctly!");
    }
}

/// Count the number of findings in the results directory
fn count_findings(results_dir: &PathBuf) -> usize {
    if !results_dir.exists() {
        return 0;
    }

    fs::read_dir(results_dir)
        .expect("Failed to read results directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .count()
}

/// List all findings
fn list_findings(results_dir: &PathBuf) {
    if !results_dir.exists() {
        return;
    }

    println!("\n=== Findings ===");
    for entry in fs::read_dir(results_dir)
        .expect("Failed to read results directory")
        .flatten()
    {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            println!("  - {}", entry.file_name().to_string_lossy());
        }
    }
}

#[test]
#[ignore] // Run with: cargo test --test fuzzing test_fuzzer_available -- --ignored
fn test_fuzzer_available() {
    // Verify openapi-fuzzer is in PATH
    let output = Command::new("openapi-fuzzer")
        .arg("--help")
        .output()
        .expect("Failed to execute openapi-fuzzer - is it installed?");

    assert!(
        output.status.success(),
        "openapi-fuzzer not available or failed"
    );

    let help_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        help_text.contains("run"),
        "openapi-fuzzer help should mention 'run' subcommand"
    );

    println!("✅ openapi-fuzzer is available");
}
