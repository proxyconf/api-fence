// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Error response format integration tests
//!
//! Tests cover:
//! - RFC 7807 Problem Details format
//! - Content-Type: application/problem+json
//! - Error type field
//! - Status field matching HTTP status
//! - Detail field
//! - Validation errors array

use super::client::TestClient;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore]
fn test_error_rfc7807_format() {
    let client = setup();

    // Trigger a validation error
    let response = client
        .get("/users/not-an-integer")
        .send()
        .assert_status(400);

    // Parse as Problem Details
    let problem = response.problem_details();

    // Should have standard fields
    assert!(
        problem.error_type.is_some() || problem.title.is_some(),
        "Should have type or title field"
    );
    assert!(problem.status.is_some(), "Should have status field");
}

#[test]
#[ignore]
fn test_error_content_type() {
    let client = setup();

    // Error responses should have application/problem+json content type
    client
        .get("/users/not-an-integer")
        .send()
        .assert_status(400)
        .assert_content_type_starts_with("application/problem+json");
}

#[test]
#[ignore]
fn test_error_type_field() {
    let client = setup();

    // Error should have type field
    let response = client
        .post("/users")
        .json(&serde_json::json!({
            "name": "Missing Email"
            // email is required but missing
        }))
        .send()
        .assert_status(400);

    let problem = response.problem_details();
    assert!(problem.error_type.is_some(), "Should have error type field");
}

#[test]
#[ignore]
fn test_error_status_field() {
    let client = setup();

    // Status in body should match HTTP status
    let response = client
        .get("/search")
        // Missing required 'q' param
        .send()
        .assert_status(400);

    let problem = response.problem_details();
    assert_eq!(
        problem.status.unwrap_or(0),
        400,
        "Status in body should match HTTP status"
    );
}

#[test]
#[ignore]
fn test_error_detail_field() {
    let client = setup();

    // Error should have descriptive detail
    let response = client
        .get("/categories/invalid-category")
        .send()
        .assert_status(400);

    let problem = response.problem_details();
    assert!(problem.detail.is_some(), "Should have detail field");

    let detail = problem.detail.unwrap();
    assert!(!detail.is_empty(), "Detail should not be empty");
}

#[test]
#[ignore]
fn test_error_validation_errors() {
    let client = setup();

    // Validation errors should include field-level details
    let response = client
        .post("/users")
        .json(&serde_json::json!({
            "name": "Test"
            // missing required email
        }))
        .send()
        .assert_status(400);

    let problem = response.problem_details();

    // May have validation errors array
    // (This depends on implementation - some may use detail only)
    if !problem.errors.is_empty() {
        let first_error = &problem.errors[0];
        assert!(
            first_error.field.is_some() || first_error.message.is_some(),
            "Validation error should have field or message"
        );
    }
}
