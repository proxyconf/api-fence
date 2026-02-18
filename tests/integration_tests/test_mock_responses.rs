// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Mock response generation integration tests
//!
//! Tests cover:
//! - Mock from inline example
//! - Mock from schema
//! - Correct status code
//! - Response headers
//! - Mock indicator header
//! - Valid JSON format

use super::client::TestClient;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore]
fn test_mock_from_example() {
    let client = setup();

    // Should return mock response using inline example
    let response = client.get("/mock/example").send().assert_status(200);

    // Parse response body
    let body: serde_json::Value = response.json();

    // Should contain example data
    assert_eq!(body["id"], 999, "Should use example id");
    assert_eq!(body["name"], "Mock User", "Should use example name");
    assert_eq!(
        body["email"], "mock@example.com",
        "Should use example email"
    );
}

#[test]
#[ignore]
fn test_mock_from_schema() {
    let client = setup();

    // Should generate mock from schema
    let response = client.get("/mock/schema").send().assert_status(200);

    // Parse response body
    let body: serde_json::Value = response.json();

    // Should have required fields from schema
    assert!(body["id"].is_number(), "Should have id field");
    assert!(body["timestamp"].is_string(), "Should have timestamp field");
}

#[test]
#[ignore]
fn test_mock_status_code() {
    let client = setup();

    // Various endpoints should return correct status codes

    // GET existing user - 200
    client.get("/users/1").send().assert_status(200);

    // POST to create user - 201
    client
        .post("/users")
        .json(&serde_json::json!({
            "name": "Test",
            "email": "test@example.com"
        }))
        .send()
        .assert_status(201);
}

#[test]
#[ignore]
fn test_mock_headers() {
    let client = setup();

    // Response should include defined headers
    client
        .get("/protected")
        .header("X-API-Key", "abcdefghijklmnopqrstuvwxyz123456")
        .send()
        .assert_status(200)
        .assert_has_header("X-RateLimit-Remaining");
}

#[test]
#[ignore]
fn test_mock_indicator_header() {
    let client = setup();

    // Mock responses should have indicator header
    client
        .get("/mock/example")
        .send()
        .assert_status(200)
        .assert_has_header("X-Mock-Response");
}

#[test]
#[ignore]
fn test_mock_json_format() {
    let client = setup();

    // Response should be valid JSON
    let response = client
        .get("/users/1")
        .send()
        .assert_status(200)
        .assert_content_type_starts_with("application/json");

    // Should parse as valid JSON
    let body: serde_json::Value = response.json();
    assert!(body.is_object(), "Response should be a JSON object");
}
