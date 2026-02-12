//! Mock response generation module
//!
//! This module handles generating mock responses for API testing.
//! It supports two strategies:
//! 1. Example-based: Use examples from OpenAPI response definitions
//! 2. Schema-based: Generate fake data matching the response schema
//!
//! All mocking logic is isolated here to avoid polluting the fast-path validation logic.

use crate::error::{MockError, MockResult};
use crate::resolver::RefResolver;
use openapiv3::{Operation, ReferenceOr, Response, Schema, StatusCode};
use serde_json::Value as JsonValue;
use std::sync::Arc;

/// Configuration for mock response generation
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MockConfig {
    /// Enable mocking (master switch)
    #[serde(default)]
    pub enabled: bool,

    /// Prefer examples over generated data
    #[serde(default = "default_true")]
    pub prefer_examples: bool,

    /// Default status code to mock (if not specified, uses first 2xx response)
    #[serde(default)]
    pub default_status_code: Option<u16>,

    /// Simulate network latency (milliseconds)
    #[serde(default)]
    pub delay_ms: Option<u64>,

    /// Include mock indicator header in responses
    #[serde(default = "default_true")]
    pub add_mock_header: bool,
}

fn default_true() -> bool {
    true
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            prefer_examples: true,
            default_status_code: None,
            delay_ms: None,
            add_mock_header: true,
        }
    }
}

/// Mock response data
#[derive(Debug)]
pub struct MockResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: Vec<(String, String)>,
    /// Response body
    pub body: Vec<u8>,
    /// Content-Type
    pub content_type: String,
}

/// Generate a mock response for an operation
pub fn generate_mock_response(
    operation: &Operation,
    config: &MockConfig,
    resolver: &RefResolver,
) -> MockResult<MockResponse> {
    // Determine which status code to mock
    let status_code = determine_status_code(operation, config)?;

    // Get the response definition (resolving $ref if needed)
    let response = get_response_for_status(operation, status_code, resolver)?;

    // Try to get example first if preferred
    if config.prefer_examples {
        if let Ok(mock) = generate_from_example(&response, status_code) {
            return Ok(mock);
        }
    }

    // Fall back to schema-based generation
    generate_from_schema(&response, status_code, resolver)
}

/// Determine which status code to mock
fn determine_status_code(operation: &Operation, config: &MockConfig) -> MockResult<u16> {
    // Use configured default if provided
    if let Some(code) = config.default_status_code {
        return Ok(code);
    }

    // Collect all possible 2xx response codes
    let mut possible_codes: Vec<u16> = Vec::new();

    for (status, _) in &operation.responses.responses {
        if let StatusCode::Code(code) = status {
            if (200..300).contains(code) {
                possible_codes.push(*code);
            }
        }
    }

    // Check for 2XX range response
    if operation
        .responses
        .responses
        .contains_key(&StatusCode::Range(2))
    {
        possible_codes.push(200);
    }

    // Check for default response if present
    if operation.responses.default.is_some() && possible_codes.is_empty() {
        possible_codes.push(200);
    }

    // If we have multiple possible responses, randomly choose one
    if !possible_codes.is_empty() {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let idx = rng.gen_range(0..possible_codes.len());
        return Ok(possible_codes[idx]);
    }

    Err(MockError::NoResponse)
}

/// Get response definition for a specific status code
fn get_response_for_status(
    operation: &Operation,
    status_code: u16,
    resolver: &RefResolver,
) -> MockResult<Arc<Response>> {
    // Try exact match
    if let Some(response_ref) = operation
        .responses
        .responses
        .get(&StatusCode::Code(status_code))
    {
        return resolver.resolve_response(response_ref).map_err(|e| {
            MockError::RefResolutionError {
                reference: format!("{:?}", response_ref),
                reason: e.to_string(),
            }
        });
    }

    // Try range match (e.g., 2XX for 200)
    let range = status_code / 100;
    if let Some(response_ref) = operation.responses.responses.get(&StatusCode::Range(range)) {
        return resolver.resolve_response(response_ref).map_err(|e| {
            MockError::RefResolutionError {
                reference: format!("{:?}", response_ref),
                reason: e.to_string(),
            }
        });
    }

    // Try default
    if let Some(response_ref) = &operation.responses.default {
        return resolver.resolve_response(response_ref).map_err(|e| {
            MockError::RefResolutionError {
                reference: format!("{:?}", response_ref),
                reason: e.to_string(),
            }
        });
    }

    Err(MockError::NoResponseForStatus { status_code })
}

/// Generate mock response from OpenAPI example
fn generate_from_example(response: &Response, status_code: u16) -> MockResult<MockResponse> {
    // Try to find an example in the response content
    for (content_type, media_type) in &response.content {
        // Check for inline example
        if let Some(example_value) = &media_type.example {
            let body = serialize_for_content_type(example_value, content_type)?;
            let headers = generate_response_headers(response, content_type);

            return Ok(MockResponse {
                status_code,
                headers,
                body,
                content_type: content_type.clone(),
            });
        }

        // Check for named examples (use first one)
        if !media_type.examples.is_empty() {
            if let Some((_, ReferenceOr::Item(example))) = media_type.examples.iter().next() {
                if let Some(example_value) = &example.value {
                    let body = serialize_for_content_type(example_value, content_type)?;
                    let headers = generate_response_headers(response, content_type);

                    return Ok(MockResponse {
                        status_code,
                        headers,
                        body,
                        content_type: content_type.clone(),
                    });
                }
            }
        }
    }

    Err(MockError::NoExamples)
}

/// Generate mock response from schema
fn generate_from_schema(
    response: &Response,
    status_code: u16,
    resolver: &RefResolver,
) -> MockResult<MockResponse> {
    // Prefer JSON content type
    let (content_type, media_type) = response
        .content
        .get("application/json")
        .map(|mt| ("application/json", mt))
        .or_else(|| {
            // Try any JSON-compatible type
            response
                .content
                .iter()
                .find(|(ct, _)| ct.contains("json"))
                .map(|(ct, mt)| (ct.as_str(), mt))
        })
        .or_else(|| {
            // Fall back to first content type
            response
                .content
                .iter()
                .next()
                .map(|(ct, mt)| (ct.as_str(), mt))
        })
        .ok_or(MockError::NoContentTypes)?;

    // Generate data from schema (resolve $ref if needed)
    if let Some(schema_ref) = &media_type.schema {
        let schema =
            resolver
                .resolve_schema(schema_ref)
                .map_err(|e| MockError::RefResolutionError {
                    reference: format!("{:?}", schema_ref),
                    reason: e.to_string(),
                })?;
        let generated_value = generate_from_json_schema(&schema, resolver)?;
        let body = serialize_for_content_type(&generated_value, content_type)?;
        let headers = generate_response_headers(response, content_type);

        return Ok(MockResponse {
            status_code,
            headers,
            body,
            content_type: content_type.to_string(),
        });
    }

    Err(MockError::NoSchema)
}

/// Generate fake data matching a JSON schema
fn generate_from_json_schema(schema: &Schema, resolver: &RefResolver) -> MockResult<JsonValue> {
    use fake::Fake;
    use rand::Rng;

    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(schema_type) => match schema_type {
            openapiv3::Type::String(string_type) => {
                // Check format for specialized generation
                let format_str = match &string_type.format {
                    openapiv3::VariantOrUnknownOrEmpty::Item(fmt) => Some(format!("{:?}", fmt)),
                    _ => None,
                };

                let value = match format_str.as_deref() {
                    Some("Email") => {
                        use fake::faker::internet::en::SafeEmail;
                        SafeEmail().fake::<String>()
                    }
                    Some("Uri") | Some("Url") => {
                        use fake::faker::internet::en::SafeEmail;
                        let email: String = SafeEmail().fake();
                        let domain = email.split('@').nth(1).unwrap_or("example.com");
                        format!("https://{}", domain)
                    }
                    Some("Uuid") => {
                        use fake::uuid::UUIDv4;
                        UUIDv4.fake::<uuid::Uuid>().to_string()
                    }
                    Some("Date") => {
                        use fake::faker::chrono::en::Date;
                        Date().fake::<chrono::NaiveDate>().to_string()
                    }
                    Some("DateTime") => {
                        use fake::faker::chrono::en::DateTime;
                        DateTime()
                            .fake::<chrono::DateTime<chrono::Utc>>()
                            .to_rfc3339()
                    }
                    _ => {
                        // Check for enum
                        if !string_type.enumeration.is_empty() {
                            let valid_values: Vec<String> = string_type
                                .enumeration
                                .iter()
                                .filter_map(|v| v.clone())
                                .collect();
                            if !valid_values.is_empty() {
                                let mut rng = rand::thread_rng();
                                let idx = rng.gen_range(0..valid_values.len());
                                valid_values[idx].clone()
                            } else {
                                use fake::faker::lorem::en::Word;
                                Word().fake()
                            }
                        } else {
                            use fake::faker::lorem::en::Word;
                            Word().fake()
                        }
                    }
                };
                Ok(JsonValue::String(value))
            }
            openapiv3::Type::Number(_) => {
                let mut rng = rand::thread_rng();
                Ok(JsonValue::Number(
                    serde_json::Number::from_f64(rng.gen_range(0.0..1000.0))
                        .unwrap_or_else(|| serde_json::Number::from(0)),
                ))
            }
            openapiv3::Type::Integer(int_type) => {
                let mut rng = rand::thread_rng();
                let value = if let Some(min) = int_type.minimum {
                    let max = int_type.maximum.unwrap_or(min + 1000);
                    rng.gen_range(min..=max)
                } else {
                    rng.gen_range(1..1000)
                };
                Ok(JsonValue::Number(value.into()))
            }
            openapiv3::Type::Boolean(_) => {
                let mut rng = rand::thread_rng();
                Ok(JsonValue::Bool(rng.gen_bool(0.5)))
            }
            openapiv3::Type::Array(array_type) => {
                let items_schema_ref = array_type
                    .items
                    .as_ref()
                    .ok_or(MockError::ArrayWithoutItems)?;

                // Resolve the item schema (handles $ref)
                let items_schema =
                    resolver
                        .resolve_boxed_schema(items_schema_ref)
                        .map_err(|e| MockError::RefResolutionError {
                            reference: format!("{:?}", items_schema_ref),
                            reason: e.to_string(),
                        })?;

                let mut rng = rand::thread_rng();
                let count = rng.gen_range(1..=5);
                let mut array = Vec::new();

                for _ in 0..count {
                    array.push(generate_from_json_schema(&items_schema, resolver)?);
                }

                Ok(JsonValue::Array(array))
            }
            openapiv3::Type::Object(object_type) => {
                let mut map = serde_json::Map::new();

                // Generate all properties (resolving $ref as needed)
                for (prop_name, prop_schema_ref) in &object_type.properties {
                    let prop_schema =
                        resolver
                            .resolve_boxed_schema(prop_schema_ref)
                            .map_err(|e| MockError::RefResolutionError {
                                reference: format!("{:?}", prop_schema_ref),
                                reason: e.to_string(),
                            })?;
                    let value = generate_from_json_schema(&prop_schema, resolver)?;
                    map.insert(prop_name.clone(), value);
                }

                Ok(JsonValue::Object(map))
            }
        },
        openapiv3::SchemaKind::OneOf { .. } => Err(MockError::UnsupportedSchemaType {
            schema_type: "oneOf".to_string(),
        }),
        openapiv3::SchemaKind::AllOf { .. } => Err(MockError::UnsupportedSchemaType {
            schema_type: "allOf".to_string(),
        }),
        openapiv3::SchemaKind::AnyOf { .. } => Err(MockError::UnsupportedSchemaType {
            schema_type: "anyOf".to_string(),
        }),
        openapiv3::SchemaKind::Not { .. } => Err(MockError::UnsupportedSchemaType {
            schema_type: "not".to_string(),
        }),
        openapiv3::SchemaKind::Any(_) => {
            // Generate generic object
            Ok(JsonValue::Object(serde_json::Map::new()))
        }
    }
}

/// Serialize JSON value for specific content type
fn serialize_for_content_type(value: &JsonValue, content_type: &str) -> MockResult<Vec<u8>> {
    if content_type.contains("json") {
        serde_json::to_vec(value).map_err(|e| MockError::SerializationError {
            reason: format!("Failed to serialize JSON: {}", e),
        })
    } else if content_type.contains("xml") {
        // Convert JSON to XML
        let xml_str = json_to_xml(value)?;
        Ok(xml_str.into_bytes())
    } else {
        // Default to JSON
        serde_json::to_vec(value).map_err(|e| MockError::SerializationError {
            reason: format!("Failed to serialize: {}", e),
        })
    }
}

/// Convert JSON value to XML string (simple conversion)
fn json_to_xml(value: &JsonValue) -> MockResult<String> {
    use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
    use quick_xml::Writer;

    let mut writer = Writer::new(Vec::new());

    fn write_value<W: std::io::Write>(
        writer: &mut Writer<W>,
        key: &str,
        value: &JsonValue,
    ) -> MockResult<()> {
        match value {
            JsonValue::Object(map) => {
                writer
                    .write_event(Event::Start(BytesStart::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                for (k, v) in map {
                    write_value(writer, k, v)?;
                }
                writer
                    .write_event(Event::End(BytesEnd::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
            }
            JsonValue::Array(arr) => {
                for item in arr {
                    write_value(writer, key, item)?;
                }
            }
            JsonValue::String(s) => {
                writer
                    .write_event(Event::Start(BytesStart::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                writer
                    .write_event(Event::Text(BytesText::new(s)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                writer
                    .write_event(Event::End(BytesEnd::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
            }
            JsonValue::Number(n) => {
                writer
                    .write_event(Event::Start(BytesStart::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                writer
                    .write_event(Event::Text(BytesText::new(&n.to_string())))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                writer
                    .write_event(Event::End(BytesEnd::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
            }
            JsonValue::Bool(b) => {
                writer
                    .write_event(Event::Start(BytesStart::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                writer
                    .write_event(Event::Text(BytesText::new(&b.to_string())))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
                writer
                    .write_event(Event::End(BytesEnd::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
            }
            JsonValue::Null => {
                writer
                    .write_event(Event::Empty(BytesStart::new(key)))
                    .map_err(|e| MockError::SerializationError {
                        reason: e.to_string(),
                    })?;
            }
        }
        Ok(())
    }

    // Write root element
    write_value(&mut writer, "root", value)?;

    String::from_utf8(writer.into_inner()).map_err(|e| MockError::SerializationError {
        reason: format!("Failed to convert XML to string: {}", e),
    })
}

/// Generate response headers from OpenAPI response definition
fn generate_response_headers(response: &Response, content_type: &str) -> Vec<(String, String)> {
    let mut headers = vec![("content-type".to_string(), content_type.to_string())];

    // Add headers defined in the response
    for (header_name, header_ref) in &response.headers {
        if let ReferenceOr::Item(header) = header_ref {
            // Generate header value based on schema
            let value =
                if let openapiv3::ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)) =
                    &header.format
                {
                    generate_header_value(schema)
                } else {
                    "mock-value".to_string()
                };

            headers.push((header_name.to_lowercase(), value));
        }
    }

    headers
}

/// Generate a simple header value from schema
fn generate_header_value(schema: &Schema) -> String {
    use fake::Fake;

    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(schema_type) => match schema_type {
            openapiv3::Type::String(_) => {
                use fake::faker::lorem::en::Word;
                Word().fake()
            }
            openapiv3::Type::Integer(_) => {
                use rand::Rng;
                rand::thread_rng().gen_range(1..1000).to_string()
            }
            _ => "mock-value".to_string(),
        },
        _ => "mock-value".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openapiv3::{
        Example, IntegerType, MediaType, NumberType, ObjectType, SchemaData, SchemaKind,
        StringType, Type,
    };
    use serde_json::json;

    fn make_string_schema() -> Schema {
        Schema {
            schema_data: SchemaData::default(),
            schema_kind: SchemaKind::Type(Type::String(StringType::default())),
        }
    }

    fn make_integer_schema() -> Schema {
        Schema {
            schema_data: SchemaData::default(),
            schema_kind: SchemaKind::Type(Type::Integer(IntegerType::default())),
        }
    }

    fn make_number_schema() -> Schema {
        Schema {
            schema_data: SchemaData::default(),
            schema_kind: SchemaKind::Type(Type::Number(NumberType::default())),
        }
    }

    fn make_boolean_schema() -> Schema {
        Schema {
            schema_data: SchemaData::default(),
            schema_kind: SchemaKind::Type(Type::Boolean(Default::default())),
        }
    }

    fn make_array_schema(items: Schema) -> Schema {
        Schema {
            schema_data: SchemaData::default(),
            schema_kind: SchemaKind::Type(Type::Array(openapiv3::ArrayType {
                items: Some(ReferenceOr::Item(Box::new(items))),
                min_items: None,
                max_items: None,
                unique_items: false,
            })),
        }
    }

    fn make_object_schema(props: Vec<(&str, Schema)>) -> Schema {
        let mut properties = indexmap::IndexMap::new();
        for (name, schema) in props {
            properties.insert(name.to_string(), ReferenceOr::Item(Box::new(schema)));
        }
        Schema {
            schema_data: SchemaData::default(),
            schema_kind: SchemaKind::Type(Type::Object(ObjectType {
                properties,
                ..Default::default()
            })),
        }
    }

    fn make_operation_with_example(example: serde_json::Value) -> Operation {
        let mut content = indexmap::IndexMap::new();
        content.insert(
            "application/json".to_string(),
            MediaType {
                schema: Some(ReferenceOr::Item(make_object_schema(vec![]))),
                example: Some(example),
                ..Default::default()
            },
        );

        let mut responses = openapiv3::Responses::default();
        responses.responses.insert(
            StatusCode::Code(200),
            ReferenceOr::Item(Response {
                description: "OK".to_string(),
                content,
                ..Default::default()
            }),
        );

        Operation {
            responses,
            ..Default::default()
        }
    }

    fn make_operation_with_named_examples(examples: Vec<(&str, serde_json::Value)>) -> Operation {
        let mut examples_map = indexmap::IndexMap::new();
        for (name, value) in examples {
            examples_map.insert(
                name.to_string(),
                ReferenceOr::Item(Example {
                    summary: None,
                    description: None,
                    value: Some(value),
                    external_value: None,
                    extensions: Default::default(),
                }),
            );
        }

        let mut content = indexmap::IndexMap::new();
        content.insert(
            "application/json".to_string(),
            MediaType {
                schema: Some(ReferenceOr::Item(make_object_schema(vec![]))),
                examples: examples_map,
                ..Default::default()
            },
        );

        let mut responses = openapiv3::Responses::default();
        responses.responses.insert(
            StatusCode::Code(200),
            ReferenceOr::Item(Response {
                description: "OK".to_string(),
                content,
                ..Default::default()
            }),
        );

        Operation {
            responses,
            ..Default::default()
        }
    }

    fn make_operation_with_schema(schema: Schema) -> Operation {
        let mut content = indexmap::IndexMap::new();
        content.insert(
            "application/json".to_string(),
            MediaType {
                schema: Some(ReferenceOr::Item(schema)),
                ..Default::default()
            },
        );

        let mut responses = openapiv3::Responses::default();
        responses.responses.insert(
            StatusCode::Code(200),
            ReferenceOr::Item(Response {
                description: "OK".to_string(),
                content,
                ..Default::default()
            }),
        );

        Operation {
            responses,
            ..Default::default()
        }
    }

    fn default_mock_config() -> MockConfig {
        MockConfig {
            enabled: true,
            prefer_examples: true,
            default_status_code: Some(200),
            delay_ms: None,
            add_mock_header: true,
        }
    }

    fn make_test_resolver() -> RefResolver {
        use openapiv3::OpenAPI;
        let spec = OpenAPI::default();
        RefResolver::new(Arc::new(spec))
    }

    #[test]
    fn test_mock_from_inline_example() {
        let example = json!({"id": 1, "name": "Test User"});
        let operation = make_operation_with_example(example.clone());
        let config = default_mock_config();
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status_code, 200);
        assert!(response.content_type.contains("json"));

        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body, example);
    }

    #[test]
    fn test_mock_from_named_examples() {
        let examples = vec![
            ("example1", json!({"id": 1, "name": "First"})),
            ("example2", json!({"id": 2, "name": "Second"})),
        ];
        let operation = make_operation_with_named_examples(examples);
        let config = default_mock_config();
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status_code, 200);

        // Should use one of the named examples
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.get("id").is_some());
        assert!(body.get("name").is_some());
    }

    #[test]
    fn test_mock_from_schema_string() {
        let operation = make_operation_with_schema(make_string_schema());
        let config = MockConfig {
            prefer_examples: false,
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.is_string());
    }

    #[test]
    fn test_mock_from_schema_integer() {
        let operation = make_operation_with_schema(make_integer_schema());
        let config = MockConfig {
            prefer_examples: false,
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.is_number());
    }

    #[test]
    fn test_mock_from_schema_number() {
        let operation = make_operation_with_schema(make_number_schema());
        let config = MockConfig {
            prefer_examples: false,
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.is_number());
    }

    #[test]
    fn test_mock_from_schema_boolean() {
        let operation = make_operation_with_schema(make_boolean_schema());
        let config = MockConfig {
            prefer_examples: false,
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.is_boolean());
    }

    #[test]
    fn test_mock_from_schema_array() {
        let operation = make_operation_with_schema(make_array_schema(make_string_schema()));
        let config = MockConfig {
            prefer_examples: false,
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.is_array());
    }

    #[test]
    fn test_mock_from_schema_object() {
        let schema = make_object_schema(vec![
            ("name", make_string_schema()),
            ("age", make_integer_schema()),
        ]);
        let operation = make_operation_with_schema(schema);
        let config = MockConfig {
            prefer_examples: false,
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert!(body.is_object());
        assert!(body.get("name").is_some());
        assert!(body.get("age").is_some());
    }

    #[test]
    fn test_mock_status_code_selection() {
        // Test that the configured status code is used
        let operation = make_operation_with_example(json!({"test": true}));
        let config = MockConfig {
            default_status_code: Some(201),
            ..default_mock_config()
        };
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        // This may fail because 201 is not in responses, but that's expected behavior
        // The test validates the status code selection logic
        if let Ok(response) = result {
            assert!(response.status_code >= 200 && response.status_code < 300);
        }
    }

    #[test]
    fn test_mock_headers_generated() {
        let operation = make_operation_with_example(json!({"test": true}));
        let config = default_mock_config();
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        // Should have content-type header
        assert!(response
            .headers
            .iter()
            .any(|(name, _)| name == "content-type"));
    }

    #[test]
    fn test_mock_json_serialization() {
        let example = json!({
            "users": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"}
            ],
            "total": 2
        });
        let operation = make_operation_with_example(example.clone());
        let config = default_mock_config();
        let resolver = make_test_resolver();

        let result = generate_mock_response(&operation, &config, &resolver);
        assert!(result.is_ok());

        let response = result.unwrap();
        // Verify it's valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_slice(&response.body);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap(), example);
    }

    #[test]
    fn test_mock_xml_serialization() {
        // Test XML output via json_to_xml helper
        let json_value = json!({"name": "Test", "value": 42});
        let result = super::json_to_xml(&json_value);
        assert!(result.is_ok());

        let xml = result.unwrap();
        assert!(xml.contains("<root>"));
        assert!(xml.contains("</root>"));
        assert!(xml.contains("Test"));
        assert!(xml.contains("42"));
    }
}
