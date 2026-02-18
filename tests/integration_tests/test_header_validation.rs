// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Header validation integration tests
//!
//! Tests cover:
//! - Required headers
//! - Optional headers
//! - Header case insensitivity
//! - Header pattern validation
//! - Header enum validation
//! - Content-Type handling

use super::client::TestClient;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore]
fn test_header_required_present() {
    let client = setup();

    // Required header provided (32 alphanumeric characters for API key)
    client
        .get("/protected")
        .header("X-API-Key", "abcdefghijklmnopqrstuvwxyz123456")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_header_required_missing() {
    let client = setup();

    // Required header missing
    client.get("/protected").send().assert_status(400);
}

#[test]
#[ignore]
fn test_header_optional_missing() {
    let client = setup();

    // Optional header (X-Request-ID) can be absent
    client
        .get("/protected")
        .header("X-API-Key", "abcdefghijklmnopqrstuvwxyz123456")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_header_case_insensitive() {
    let client = setup();

    // Headers are case-insensitive per HTTP spec
    client
        .get("/protected")
        .header("x-api-key", "abcdefghijklmnopqrstuvwxyz123456")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_header_pattern_valid() {
    let client = setup();

    // Valid: matches pattern ^[a-zA-Z0-9]{32}$
    client
        .get("/protected")
        .header("X-API-Key", "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_header_pattern_invalid() {
    let client = setup();

    // Invalid: doesn't match pattern (too short)
    client
        .get("/protected")
        .header("X-API-Key", "too-short")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_header_enum_valid() {
    let client = setup();

    // Valid: environment in enum
    client
        .get("/protected")
        .header("X-API-Key", "abcdefghijklmnopqrstuvwxyz123456")
        .header("X-Environment", "production")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_header_enum_invalid() {
    let client = setup();

    // Invalid: environment not in enum
    client
        .get("/protected")
        .header("X-API-Key", "abcdefghijklmnopqrstuvwxyz123456")
        .header("X-Environment", "invalid-env")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_content_type_json() {
    let client = setup();

    // JSON content type for body
    client
        .post("/users")
        .header("Content-Type", "application/json")
        .body(r#"{"name": "Test", "email": "test@example.com"}"#)
        .send()
        .assert_status(201);
}

#[test]
#[ignore]
fn test_content_type_form() {
    let client = setup();

    // Form urlencoded content type
    client
        .post("/feedback")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("rating=5&message=This+is+a+test+message+for+feedback")
        .send()
        .assert_status(200);
}
