// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! ModSecurity WAF integration tests
//!
//! These tests verify that ModSecurity scanning works correctly end-to-end
//! through Envoy with the api_fence filter loaded. They focus on Envoy-level
//! behavior that cannot be tested at the unit level:
//!
//! - Request/response flow through Envoy's HTTP filter chain
//! - JSON body extraction and scanning through the filter pipeline
//! - WAF block response format (RFC 7807 Problem Details)
//! - Stability under concurrent load through Envoy
//! - Edge cases specific to the Envoy integration (empty bodies, large bodies)
//!
//! **WAF detection logic** (SQLi/XSS/RCE payloads, CRS rule coverage, anomaly
//! scoring, header attacks, body processor activation, etc.) is thoroughly
//! covered by the 33 unit tests in `src/modsec/crs_tests.rs`.
//!
//! # Configuration
//!
//! The test Envoy uses `bundled_crs_profile: "minimal"` which includes only:
//! - SQL Injection detection (CRS 942xxx)
//! - Cross-Site Scripting detection (CRS 941xxx)
//! - Remote Code Execution detection (CRS 932xxx)
//!
//! # Running tests
//!
//! ```bash
//! cargo test --test integration test_modsecurity -- --ignored
//! ```

use serde_json::json;
use std::sync::Arc;
use std::thread;

use super::client::TestClient;

/// Get a test client connected to the ModSecurity listener (port 18090).
///
/// Uses the shared Envoy process started by the test infrastructure in mod.rs.
fn setup() -> TestClient {
    super::get_modsec_test_client()
}

// =============================================================================
// Attack Detection Through Envoy
//
// One representative test per attack category (SQLi, XSS, RCE) to verify
// that CRS rules fire correctly when requests flow through Envoy.
// Detailed payload/rule coverage is in src/modsec/crs_tests.rs.
// =============================================================================

#[test]
#[ignore]
fn test_sqli_in_query_blocked() {
    let client = setup();

    client
        .get("/search")
        .query("q", "'; DROP TABLE users; --")
        .send()
        .assert_status(403);
}

#[test]
#[ignore]
fn test_xss_in_query_blocked() {
    let client = setup();

    client
        .get("/search")
        .query("q", "<script>alert('xss')</script>")
        .send()
        .assert_status(403);
}

#[test]
#[ignore]
fn test_rce_in_query_blocked() {
    let client = setup();

    // Use command substitution syntax which CRS 932xxx rules detect
    client
        .get("/search")
        .query("q", "$(cat /etc/passwd)")
        .send()
        .assert_status(403);
}

// =============================================================================
// JSON Body Scanning Through Envoy
//
// Verifies that the full pipeline works: Envoy receives JSON body ->
// filter extracts strings -> body processor activation (Rule 900700) ->
// CRS detection rules inspect ARGS from parsed JSON.
// =============================================================================

#[test]
#[ignore]
fn test_sqli_in_json_body_blocked() {
    let client = setup();

    client
        .post("/users")
        .json(&json!({
            "name": "'; DELETE FROM users; --",
            "email": "test@example.com"
        }))
        .send()
        .assert_status(403);
}

// =============================================================================
// Clean Requests (Should Pass)
//
// Verify that normal requests are not blocked by CRS false positives
// when flowing through Envoy.
// =============================================================================

#[test]
#[ignore]
fn test_clean_get_passes() {
    let client = setup();

    client
        .get("/search")
        .query("q", "hello world")
        .send()
        .assert_success();
}

#[test]
#[ignore]
fn test_clean_post_with_json_body_passes() {
    let client = setup();

    client
        .post("/users")
        .json(&json!({
            "name": "John Doe",
            "email": "john.doe@example.com"
        }))
        .send()
        .assert_success();
}

#[test]
#[ignore]
fn test_clean_json_with_special_chars_no_false_positive() {
    let client = setup();

    // Names with apostrophes should not trigger SQLi false positives
    client
        .post("/users")
        .json(&json!({
            "name": "O'Brien",
            "email": "obrien@example.com"
        }))
        .send()
        .assert_success();
}

// =============================================================================
// Edge Cases (Envoy-Specific)
// =============================================================================

#[test]
#[ignore]
fn test_empty_body_passes() {
    let client = setup();

    client
        .post("/optional-body")
        .content_type("application/json")
        .send()
        .assert_success();
}

#[test]
#[ignore]
fn test_large_clean_body_passes() {
    let client = setup();

    // Use /optional-body endpoint which has no maxLength constraint
    // to test that large clean bodies pass through without WAF false positives
    let large_body = json!({
        "data": "A".repeat(10_000),
    });

    client
        .post("/optional-body")
        .json(&large_body)
        .send()
        .assert_success();
}

// =============================================================================
// WAF Block Response Format
//
// Verifies that blocked requests return proper RFC 7807 Problem Details
// responses through Envoy's filter chain.
// =============================================================================

#[test]
#[ignore]
fn test_waf_block_returns_403_with_problem_details() {
    let client = setup();

    let response = client
        .get("/search")
        .query("q", "'; DROP TABLE users; --")
        .send();

    response
        .assert_status(403)
        .assert_body_contains("blocked by WAF");
}

// =============================================================================
// Stability Under Load
//
// These tests verify that the Envoy + filter + ModSecurity pipeline
// remains stable under repeated and concurrent requests.
// =============================================================================

#[test]
#[ignore]
fn test_repeated_attacks_dont_crash_envoy() {
    let client = setup();

    // Send 10 attack requests in sequence
    for i in 0..10 {
        let query = format!("test{} '; DROP TABLE users; --", i);
        client
            .get("/search")
            .query("q", &query)
            .send()
            .assert_status(403);
    }

    // Verify Envoy is still responsive with a clean request
    client
        .get("/search")
        .query("q", "normal search")
        .send()
        .assert_success();
}

#[test]
#[ignore]
fn test_concurrent_mixed_traffic_stability() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let client = Arc::new(setup());
    let blocked_count = Arc::new(AtomicUsize::new(0));
    let allowed_count = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    // 10 threads, each sending 10 requests (alternating clean/attack)
    for thread_id in 0..10 {
        let client = Arc::clone(&client);
        let blocked = Arc::clone(&blocked_count);
        let allowed = Arc::clone(&allowed_count);

        let handle = thread::spawn(move || {
            for req_id in 0..10 {
                let (query, is_attack) = if req_id % 2 == 0 {
                    (format!("clean search {}", req_id), false)
                } else {
                    (format!("attack{} ' OR '1'='1", thread_id), true)
                };

                let status = client.get("/search").query("q", &query).send().status();

                if is_attack && status == 403 {
                    blocked.fetch_add(1, Ordering::SeqCst);
                } else if !is_attack && status == 200 {
                    allowed.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_blocked = blocked_count.load(Ordering::SeqCst);
    let total_allowed = allowed_count.load(Ordering::SeqCst);

    // 50 attack requests total (10 threads * 5 attacks each)
    assert!(
        total_blocked >= 45,
        "Expected at least 45/50 blocked attack requests, got {}",
        total_blocked
    );
    // 50 clean requests total (10 threads * 5 clean each)
    assert!(
        total_allowed >= 45,
        "Expected at least 45/50 allowed clean requests, got {}",
        total_allowed
    );

    // Verify Envoy is still responsive after concurrent load
    client
        .get("/search")
        .query("q", "final check")
        .send()
        .assert_success();
}
