// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! HTTP client wrapper for integration tests
//!
//! Provides a fluent API for making HTTP requests and asserting on responses.
//! Designed to work with the Envoy container to test OpenAPI filter behavior.

use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// HTTP client for testing against Envoy container
pub struct TestClient {
    client: Client,
    base_url: String,
}

impl TestClient {
    /// Create a new test client pointing to the given base URL
    pub fn new(base_url: impl Into<String>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            base_url: base_url.into(),
        }
    }

    /// Build a GET request
    pub fn get(&self, path: &str) -> TestRequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        TestRequestBuilder::new(self.client.get(&url))
    }

    /// Build a POST request
    pub fn post(&self, path: &str) -> TestRequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        TestRequestBuilder::new(self.client.post(&url))
    }

    /// Build a PUT request
    pub fn put(&self, path: &str) -> TestRequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        TestRequestBuilder::new(self.client.put(&url))
    }

    /// Build a DELETE request
    pub fn delete(&self, path: &str) -> TestRequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        TestRequestBuilder::new(self.client.delete(&url))
    }

    /// Build a PATCH request
    pub fn patch(&self, path: &str) -> TestRequestBuilder {
        let url = format!("{}{}", self.base_url, path);
        TestRequestBuilder::new(self.client.patch(&url))
    }
}

/// Builder for constructing and sending test requests
pub struct TestRequestBuilder {
    builder: RequestBuilder,
}

impl TestRequestBuilder {
    fn new(builder: RequestBuilder) -> Self {
        Self { builder }
    }

    /// Add a header to the request
    pub fn header(self, name: &str, value: &str) -> Self {
        Self {
            builder: self.builder.header(name, value),
        }
    }

    /// Add multiple headers
    pub fn headers(mut self, headers: &[(&str, &str)]) -> Self {
        for (name, value) in headers {
            self = self.header(name, value);
        }
        self
    }

    /// Add a query parameter
    pub fn query(self, key: &str, value: &str) -> Self {
        Self {
            builder: self.builder.query(&[(key, value)]),
        }
    }

    /// Add multiple query parameters
    pub fn queries(self, params: &[(&str, &str)]) -> Self {
        Self {
            builder: self.builder.query(params),
        }
    }

    /// Set the request body as JSON
    pub fn json<T: serde::Serialize>(self, body: &T) -> Self {
        Self {
            builder: self.builder.json(body),
        }
    }

    /// Set the request body as raw bytes
    pub fn body(self, body: impl Into<reqwest::blocking::Body>) -> Self {
        Self {
            builder: self.builder.body(body),
        }
    }

    /// Set the Content-Type header
    pub fn content_type(self, content_type: &str) -> Self {
        self.header("Content-Type", content_type)
    }

    /// Send the request and wrap the response
    pub fn send(self) -> TestResponse {
        match self.builder.send() {
            Ok(response) => TestResponse::Success(response),
            Err(e) => TestResponse::Error(format!("Request failed: {}", e)),
        }
    }
}

/// Wrapper around HTTP response for fluent assertions
pub enum TestResponse {
    Success(Response),
    Error(String),
}

impl TestResponse {
    /// Get the response, panicking if there was an error
    fn response(&self) -> &Response {
        match self {
            TestResponse::Success(r) => r,
            TestResponse::Error(e) => panic!("Request failed: {}", e),
        }
    }

    /// Get mutable response, panicking if there was an error
    fn into_response(self) -> Response {
        match self {
            TestResponse::Success(r) => r,
            TestResponse::Error(e) => panic!("Request failed: {}", e),
        }
    }

    /// Assert the response has the expected status code
    pub fn assert_status(self, expected: u16) -> Self {
        let actual = self.response().status().as_u16();
        assert_eq!(
            actual, expected,
            "Expected status {}, got {}",
            expected, actual
        );
        self
    }

    /// Assert the response has a 2xx status code
    pub fn assert_success(self) -> Self {
        let status = self.response().status();
        assert!(
            status.is_success(),
            "Expected success status, got {}",
            status
        );
        self
    }

    /// Assert the response has a 4xx status code
    pub fn assert_client_error(self) -> Self {
        let status = self.response().status();
        assert!(
            status.is_client_error(),
            "Expected client error status, got {}",
            status
        );
        self
    }

    /// Assert the response has a 5xx status code
    pub fn assert_server_error(self) -> Self {
        let status = self.response().status();
        assert!(
            status.is_server_error(),
            "Expected server error status, got {}",
            status
        );
        self
    }

    /// Assert the response contains a specific header
    pub fn assert_header(self, name: &str, expected: &str) -> Self {
        let headers = self.response().headers();
        let value = headers
            .get(name)
            .unwrap_or_else(|| panic!("Header '{}' not found", name));

        let actual = value
            .to_str()
            .unwrap_or_else(|_| panic!("Header '{}' is not valid UTF-8", name));

        assert_eq!(
            actual, expected,
            "Header '{}': expected '{}', got '{}'",
            name, expected, actual
        );
        self
    }

    /// Assert the response contains a header (any value)
    pub fn assert_has_header(self, name: &str) -> Self {
        let headers = self.response().headers();
        assert!(
            headers.contains_key(name),
            "Expected header '{}' to be present",
            name
        );
        self
    }

    /// Assert the response has the expected Content-Type
    pub fn assert_content_type(self, expected: &str) -> Self {
        self.assert_header("content-type", expected)
    }

    /// Assert the response Content-Type starts with the expected value
    pub fn assert_content_type_starts_with(self, prefix: &str) -> Self {
        let headers = self.response().headers();
        let content_type = headers
            .get("content-type")
            .expect("Content-Type header not found")
            .to_str()
            .expect("Content-Type is not valid UTF-8");

        assert!(
            content_type.starts_with(prefix),
            "Expected Content-Type to start with '{}', got '{}'",
            prefix,
            content_type
        );
        self
    }

    /// Get the status code
    pub fn status(&self) -> u16 {
        self.response().status().as_u16()
    }

    /// Get a header value
    pub fn header(&self, name: &str) -> Option<String> {
        self.response()
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Parse the response body as JSON
    pub fn json<T: DeserializeOwned>(self) -> T {
        let response = self.into_response();
        response.json().expect("Failed to parse response as JSON")
    }

    /// Get the response body as text
    pub fn text(self) -> String {
        let response = self.into_response();
        response.text().expect("Failed to read response body")
    }

    /// Parse the response body as JSON Value
    pub fn json_value(self) -> Value {
        self.json()
    }

    /// Parse as RFC 7807 Problem Details
    pub fn problem_details(self) -> ProblemDetails {
        self.json()
    }

    /// Assert this is a WAF block (403 with expected response structure)
    pub fn assert_waf_blocked(self) -> Self {
        let status = self.response().status();
        assert_eq!(
            status.as_u16(),
            403,
            "Expected WAF block to return 403, got {}",
            status
        );
        self
    }

    /// Assert the response body contains a substring (consumes the response)
    pub fn assert_body_contains(self, substring: &str) {
        let body = self.text();
        assert!(
            body.contains(substring),
            "Expected body to contain '{}', got: '{}'",
            substring,
            &body[..body.len().min(500)]
        );
    }
}

/// RFC 7807 Problem Details structure for error responses
#[derive(Debug, serde::Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    pub title: Option<String>,
    pub status: Option<u16>,
    pub detail: Option<String>,
    pub instance: Option<String>,
    #[serde(default)]
    pub errors: Vec<ValidationError>,
    /// WAF-specific: rule ID that triggered the block
    pub rule_id: Option<u32>,
    /// WAF-specific: message from the matched rule
    pub rule_message: Option<String>,
}

/// Validation error detail
#[derive(Debug, serde::Deserialize)]
pub struct ValidationError {
    pub field: Option<String>,
    pub message: Option<String>,
    pub code: Option<String>,
}

impl ProblemDetails {
    /// Assert the error type matches
    pub fn assert_type(self, expected: &str) -> Self {
        let actual = self.error_type.as_deref().unwrap_or("");
        assert_eq!(
            actual, expected,
            "Expected error type '{}', got '{}'",
            expected, actual
        );
        self
    }

    /// Assert the status matches
    pub fn assert_status(self, expected: u16) -> Self {
        let actual = self.status.unwrap_or(0);
        assert_eq!(
            actual, expected,
            "Expected status {}, got {}",
            expected, actual
        );
        self
    }

    /// Assert detail contains a substring
    pub fn assert_detail_contains(self, substring: &str) -> Self {
        let detail = self.detail.as_deref().unwrap_or("");
        assert!(
            detail.contains(substring),
            "Expected detail to contain '{}', got '{}'",
            substring,
            detail
        );
        self
    }

    /// Assert there are validation errors
    pub fn assert_has_errors(self) -> Self {
        assert!(
            !self.errors.is_empty(),
            "Expected validation errors to be present"
        );
        self
    }

    /// Assert this is a WAF block response (has rule_id or WAF-related type)
    pub fn assert_waf_blocked(self) -> Self {
        let error_type = self.error_type.as_deref().unwrap_or("");
        let is_waf_block =
            error_type.contains("waf") || error_type.contains("blocked") || self.rule_id.is_some();
        assert!(
            is_waf_block,
            "Expected WAF block response, got type: '{}', rule_id: {:?}",
            error_type, self.rule_id
        );
        self
    }

    /// Assert the response has a rule ID
    pub fn assert_has_rule_id(self) -> Self {
        assert!(
            self.rule_id.is_some(),
            "Expected rule_id to be present in WAF response"
        );
        self
    }

    /// Assert the rule ID matches expected value
    pub fn assert_rule_id(self, expected: u32) -> Self {
        let actual = self.rule_id.unwrap_or(0);
        assert_eq!(
            actual, expected,
            "Expected rule_id {}, got {}",
            expected, actual
        );
        self
    }

    /// Assert the rule message contains a substring
    pub fn assert_rule_message_contains(self, substring: &str) -> Self {
        let message = self.rule_message.as_deref().unwrap_or("");
        assert!(
            message.contains(substring),
            "Expected rule_message to contain '{}', got '{}'",
            substring,
            message
        );
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_url_construction() {
        let client = TestClient::new("http://localhost:8080");
        // Just verify construction works
        let _ = client.get("/test");
        let _ = client.post("/test");
    }
}
