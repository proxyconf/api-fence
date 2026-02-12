//! Path parameter validation integration tests
//!
//! Tests cover:
//! - Integer path parameters
//! - String path parameters
//! - Enum path parameters
//! - Regex pattern validation
//! - Length constraints (min/max)
//! - Path not found (404)
//! - Method not allowed (405)

use super::client::TestClient;

/// Get a test client connected to the shared container
fn setup() -> TestClient {
    super::get_test_client()
}

#[test]
#[ignore] // Run with: cargo test --test integration -- --ignored
fn test_path_param_integer_valid() {
    let client = setup();

    // Valid integer path parameter
    client.get("/users/123").send().assert_status(200);
}

#[test]
#[ignore]
fn test_path_param_integer_invalid() {
    let client = setup();

    // Invalid: string instead of integer
    client.get("/users/abc").send().assert_status(400);
}

#[test]
#[ignore]
fn test_path_param_string_valid() {
    let client = setup();

    // Valid string path parameter with length within bounds
    client.get("/slugs/hello-world").send().assert_status(200);
}

#[test]
#[ignore]
fn test_path_param_enum_valid() {
    let client = setup();

    // Valid enum value
    client
        .get("/categories/electronics")
        .send()
        .assert_status(200);
}

#[test]
#[ignore]
fn test_path_param_enum_invalid() {
    let client = setup();

    // Invalid: value not in enum
    client
        .get("/categories/invalid-category")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_path_param_pattern_valid() {
    let client = setup();

    // Valid: matches pattern ^[A-Z]{3}-[0-9]{4}$
    client.get("/products/ABC-1234").send().assert_status(200);
}

#[test]
#[ignore]
fn test_path_param_pattern_invalid() {
    let client = setup();

    // Invalid: doesn't match pattern
    client
        .get("/products/invalid-sku")
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_path_param_min_length() {
    let client = setup();

    // Invalid: too short (minLength is 3)
    client.get("/slugs/ab").send().assert_status(400);
}

#[test]
#[ignore]
fn test_path_param_max_length() {
    let client = setup();

    // Invalid: too long (maxLength is 50)
    let long_slug = "a".repeat(51);
    client
        .get(&format!("/slugs/{}", long_slug))
        .send()
        .assert_status(400);
}

#[test]
#[ignore]
fn test_path_not_found() {
    let client = setup();

    // Unknown path
    client.get("/unknown/path").send().assert_status(404);
}

#[test]
#[ignore]
fn test_method_not_allowed() {
    let client = setup();

    // POST to a GET-only endpoint
    client.post("/users/123").send().assert_status(405);
}
