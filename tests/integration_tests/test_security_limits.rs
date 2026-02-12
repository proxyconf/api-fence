//! Security limits integration tests
//!
//! Tests cover:
//! - Path length limits
//! - Header length limits
//! - Query string length limits
//! - Body size limits
//! - JSON depth limits
//! - Error message sanitization
//! - Regex input limits
//!
//! Note: These tests use the same comprehensive.yaml spec as other tests.
//! The security limits are enforced by the filter's configuration.
//! Tests use existing endpoints from the spec where possible.

use super::client::TestClient;
use serde_json::json;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore]
fn test_path_length_limit() {
    let client = setup();

    // Path over 2048 bytes should be rejected with 414
    let long_segment = "a".repeat(500);
    let long_path = format!(
        "/long-path/{}/{}/{}/{}/{}",
        long_segment, long_segment, long_segment, long_segment, long_segment
    );

    client.get(&long_path).send().assert_status(414);
}

#[test]
#[ignore]
fn test_header_length_limit() {
    let client = setup();

    // Header over 8192 bytes should be rejected
    // Use an existing endpoint (/search with required q param)
    let large_header = "x".repeat(9000);

    client
        .get("/search")
        .query("q", "test")
        .header("X-Large-Header", &large_header)
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_query_length_limit() {
    let client = setup();

    // Query string over 8192 bytes should be rejected
    // Note: Envoy itself may reject very long URIs with 414
    // Use existing /search endpoint
    let large_query = "x".repeat(9000);

    let response = client.get("/search").query("q", &large_query).send();

    // Accept either 400 (filter limit) or 414 (Envoy URI limit)
    let status = response.status();
    assert!(
        status == 400 || status == 414,
        "Expected 400 or 414, got {}",
        status
    );
}

#[test]
#[ignore]
fn test_body_size_limit() {
    let client = setup();

    // Body over 10MB should be rejected with 413
    // Use existing /users endpoint which accepts JSON body
    let large_data = "x".repeat(11 * 1024 * 1024); // 11MB

    client
        .post("/users")
        .json(&json!({
            "name": "Test User",
            "email": "test@example.com",
            "data": large_data
        }))
        .send()
        .assert_status(413);
}

#[test]
#[ignore]
fn test_json_depth_limit() {
    let client = setup();

    // Deeply nested JSON (over 32 levels) should be rejected
    // Build a 40-level deep JSON structure
    // Use existing /users endpoint
    let mut deep_json = json!({ "value": "bottom" });
    for i in 0..40 {
        deep_json = json!({ format!("level{}", 40 - i): deep_json });
    }

    // Wrap in expected structure for /users
    let body = json!({
        "name": deep_json,
        "email": "test@example.com"
    });

    client.post("/users").json(&body).send().assert_status(400);
}

#[test]
#[ignore]
fn test_error_message_sanitized() {
    let client = setup();

    // Trigger an error and verify the message doesn't leak internal paths
    // Use /users/{userId} with invalid integer
    let response = client
        .get("/users/not-an-integer")
        .send()
        .assert_status(400);

    let body = response.text();

    // Error should NOT contain internal file paths
    assert!(
        !body.contains("/usr/local/lib"),
        "Error message should not contain internal paths"
    );
    assert!(
        !body.contains("/etc/envoy"),
        "Error message should not contain config paths"
    );
    assert!(
        !body.contains(".rs:"),
        "Error message should not contain Rust source references"
    );
}

#[test]
#[ignore]
fn test_regex_input_limit() {
    let client = setup();

    // Large input for regex pattern matching should be handled safely
    // (not cause ReDoS)
    // Use /products/{sku} endpoint which has a pattern constraint
    let large_input = "A".repeat(1001); // Over the 1000 char limit

    client
        .get(&format!("/products/{}", large_input))
        .send()
        .assert_status(400);
}
