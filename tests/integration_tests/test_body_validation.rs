//! Request and response body validation integration tests
//!
//! Tests cover:
//! - Valid JSON body
//! - Invalid JSON syntax
//! - JSON schema validation
//! - Required field validation
//! - Wrong type validation
//! - Nested object validation
//! - Array items validation
//! - Form urlencoded body
//! - Empty body handling
//! - Response body validation

use super::client::TestClient;
use serde_json::json;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore]
fn test_body_json_valid() {
    let client = setup();

    // Valid JSON body
    client
        .post("/users")
        .json(&json!({
            "name": "John Doe",
            "email": "john@example.com",
            "age": 30
        }))
        .send()
        .assert_status(201);
}

#[test]
#[ignore]
fn test_body_json_invalid_syntax() {
    let client = setup();

    // Malformed JSON
    client
        .post("/users")
        .content_type("application/json")
        .body("{invalid json}")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_body_json_schema_valid() {
    let client = setup();

    // JSON matching schema
    client
        .post("/users")
        .json(&json!({
            "name": "Valid Name",
            "email": "valid@example.com"
        }))
        .send()
        .assert_status(201);
}

#[test]
#[ignore]
fn test_body_json_schema_invalid() {
    let client = setup();

    // JSON with invalid email format
    client
        .post("/users")
        .json(&json!({
            "name": "Valid Name",
            "email": "not-an-email"
        }))
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_body_required_field_missing() {
    let client = setup();

    // Missing required field 'email'
    client
        .post("/users")
        .json(&json!({
            "name": "No Email User"
        }))
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_body_wrong_type() {
    let client = setup();

    // Wrong type: age should be integer
    client
        .post("/users")
        .json(&json!({
            "name": "Test User",
            "email": "test@example.com",
            "age": "not-a-number"
        }))
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_body_nested_object() {
    let client = setup();

    // Valid nested object (order with shipping address)
    client
        .post("/orders")
        .json(&json!({
            "customerId": 123,
            "items": [
                {"productId": 1, "quantity": 2}
            ],
            "shippingAddress": {
                "street": "123 Main St",
                "city": "Anytown",
                "country": "USA"
            }
        }))
        .send()
        .assert_status(201);
}

#[test]
#[ignore]
fn test_body_array_items() {
    let client = setup();

    // Valid array items
    client
        .post("/orders")
        .json(&json!({
            "customerId": 123,
            "items": [
                {"productId": 1, "quantity": 1},
                {"productId": 2, "quantity": 3}
            ]
        }))
        .send()
        .assert_status(201);
}

#[test]
#[ignore]
fn test_body_array_items_invalid() {
    let client = setup();

    // Invalid: quantity must be >= 1
    client
        .post("/orders")
        .json(&json!({
            "customerId": 123,
            "items": [
                {"productId": 1, "quantity": 0}
            ]
        }))
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_body_form_urlencoded() {
    let client = setup();

    // Form data validation
    client
        .post("/feedback")
        .content_type("application/x-www-form-urlencoded")
        .body("rating=5&message=This+is+a+really+great+service")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_body_empty_required() {
    let client = setup();

    // Empty body when required
    client
        .post("/users")
        .content_type("application/json")
        .body("")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_body_empty_optional() {
    let client = setup();

    // Empty body when optional
    client.post("/optional-body").send().assert_status(200);
}

#[test]
#[ignore]
fn test_response_body_valid() {
    let client = setup();

    // Mock response should be valid JSON
    let response = client.get("/users/1").send().assert_status(200);

    // Response should be parseable as JSON
    let body: serde_json::Value = response.json();
    assert!(body.is_object(), "Response should be a JSON object");
}
