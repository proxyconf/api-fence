// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Query parameter validation integration tests
//!
//! Tests cover:
//! - Required query parameters
//! - Optional query parameters
//! - Integer query parameters
//! - Boolean query parameters
//! - Array query parameters
//! - URL encoding
//! - Empty values

use super::client::TestClient;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore]
fn test_query_required_present() {
    let client = setup();

    // Required query param provided
    client
        .get("/search")
        .query("q", "test")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_required_missing() {
    let client = setup();

    // Required query param missing
    client.get("/search").send().assert_status(400);
}

#[test]
#[ignore]
fn test_query_optional_missing() {
    let client = setup();

    // Optional params can be absent (only required param provided)
    client
        .get("/search")
        .query("q", "test")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_integer_valid() {
    let client = setup();

    // Valid integer query param
    client
        .get("/search")
        .query("q", "test")
        .query("limit", "50")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_integer_invalid() {
    let client = setup();

    // Invalid: string instead of integer
    client
        .get("/search")
        .query("q", "test")
        .query("limit", "not-a-number")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_query_boolean_true() {
    let client = setup();

    // Boolean query param with true value
    client
        .get("/search")
        .query("q", "test")
        .query("active", "true")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_boolean_false() {
    let client = setup();

    // Boolean query param with false value
    client
        .get("/search")
        .query("q", "test")
        .query("active", "false")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_array_values() {
    let client = setup();

    // Array query param (comma-separated)
    client
        .get("/search")
        .query("q", "test")
        .query("ids", "1,2,3")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_url_encoded() {
    let client = setup();

    // URL-encoded values
    client
        .get("/search")
        .query("q", "hello world") // Should be URL encoded by reqwest
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_query_empty_value() {
    let client = setup();

    // Empty query value - behavior depends on schema
    // In comprehensive.yaml, 'q' has minLength: 1
    client
        .get("/search")
        .query("q", "")
        .send()
        .assert_status(400);
}
