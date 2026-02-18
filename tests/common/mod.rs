// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

//! Shared test fixtures and helpers for integration and unit tests
//!
//! This module provides reusable test utilities for creating OpenAPI specs,
//! schemas, and other test data.

use openapiv3::{
    Header, MediaType, ObjectType, OpenAPI, Operation, Parameter, ParameterData,
    ParameterSchemaOrContent, ReferenceOr, Response, Schema, SchemaData, SchemaKind, StatusCode,
    StringType, Type,
};
use std::collections::BTreeMap;

/// Create a minimal valid OpenAPI spec
#[allow(dead_code)]
pub fn minimal_spec() -> OpenAPI {
    serde_yaml::from_str(MINIMAL_SPEC_YAML).expect("Failed to parse minimal spec")
}

/// Create an OpenAPI spec from YAML string
#[allow(dead_code)]
pub fn spec_from_yaml(yaml: &str) -> OpenAPI {
    serde_yaml::from_str(yaml).expect("Failed to parse YAML spec")
}

/// Minimal valid OpenAPI 3.0 spec
#[allow(dead_code)]
pub const MINIMAL_SPEC_YAML: &str = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /health:
    get:
      responses:
        '200':
          description: OK
"#;

/// OpenAPI spec with all HTTP methods on a single path
#[allow(dead_code)]
pub const ALL_METHODS_SPEC_YAML: &str = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /resources:
    get:
      responses:
        '200':
          description: List resources
    post:
      responses:
        '201':
          description: Create resource
    put:
      responses:
        '200':
          description: Replace resource
    delete:
      responses:
        '204':
          description: Delete resource
    patch:
      responses:
        '200':
          description: Update resource
    head:
      responses:
        '200':
          description: Check resource
    options:
      responses:
        '200':
          description: Get options
    trace:
      responses:
        '200':
          description: Trace request
"#;

/// OpenAPI spec with path parameters
#[allow(dead_code)]
pub const PATH_PARAMS_SPEC_YAML: &str = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      parameters:
        - name: userId
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: OK
  /orgs/{orgId}/users/{userId}:
    get:
      parameters:
        - name: orgId
          in: path
          required: true
          schema:
            type: string
        - name: userId
          in: path
          required: true
          schema:
            type: integer
      responses:
        '200':
          description: OK
"#;

/// OpenAPI spec with examples for mocking
#[allow(dead_code)]
pub const MOCK_EXAMPLES_SPEC_YAML: &str = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: List of users
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    id:
                      type: integer
                    name:
                      type: string
              example:
                - id: 1
                  name: "John Doe"
                - id: 2
                  name: "Jane Smith"
"#;

// =============================================================================
// Schema Builders
// =============================================================================

/// Create a string schema
#[allow(dead_code)]
pub fn string_schema() -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::String(StringType::default())),
    }
}

/// Create an integer schema
#[allow(dead_code)]
pub fn integer_schema() -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::Integer(Default::default())),
    }
}

/// Create a number schema
#[allow(dead_code)]
pub fn number_schema() -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::Number(Default::default())),
    }
}

/// Create a boolean schema
#[allow(dead_code)]
pub fn boolean_schema() -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::Boolean(Default::default())),
    }
}

/// Create a string schema with enum values
#[allow(dead_code)]
pub fn enum_schema(values: Vec<&str>) -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::String(StringType {
            enumeration: values.into_iter().map(|v| Some(v.to_string())).collect(),
            ..Default::default()
        })),
    }
}

/// Create a string schema with pattern
#[allow(dead_code)]
pub fn pattern_schema(pattern: &str) -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::String(StringType {
            pattern: Some(pattern.to_string()),
            ..Default::default()
        })),
    }
}

/// Create a string schema with min/max length
#[allow(dead_code)]
pub fn length_constrained_schema(min: Option<usize>, max: Option<usize>) -> Schema {
    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::String(StringType {
            min_length: min,
            max_length: max,
            ..Default::default()
        })),
    }
}

/// Create an object schema with properties
#[allow(dead_code)]
pub fn object_schema(properties: Vec<(&str, Schema)>, required: Vec<&str>) -> Schema {
    let mut props = BTreeMap::new();
    for (name, schema) in properties {
        props.insert(name.to_string(), ReferenceOr::Item(Box::new(schema)));
    }

    Schema {
        schema_data: SchemaData::default(),
        schema_kind: SchemaKind::Type(Type::Object(ObjectType {
            properties: props,
            required: required.into_iter().map(String::from).collect(),
            ..Default::default()
        })),
    }
}

/// Create an array schema with item type
#[allow(dead_code)]
pub fn array_schema(items: Schema) -> Schema {
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

// =============================================================================
// Parameter Builders
// =============================================================================

/// Create a query parameter
#[allow(dead_code)]
pub fn query_param(name: &str, required: bool, schema: Schema) -> ReferenceOr<Parameter> {
    ReferenceOr::Item(Parameter::Query {
        parameter_data: ParameterData {
            name: name.to_string(),
            description: None,
            required,
            deprecated: None,
            format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)),
            example: None,
            examples: Default::default(),
            explode: None,
            extensions: Default::default(),
        },
        allow_reserved: false,
        style: Default::default(),
        allow_empty_value: None,
    })
}

/// Create a header parameter
#[allow(dead_code)]
pub fn header_param(name: &str, required: bool, schema: Schema) -> ReferenceOr<Parameter> {
    ReferenceOr::Item(Parameter::Header {
        parameter_data: ParameterData {
            name: name.to_string(),
            description: None,
            required,
            deprecated: None,
            format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)),
            example: None,
            examples: Default::default(),
            explode: None,
            extensions: Default::default(),
        },
        style: Default::default(),
    })
}

/// Create a path parameter
#[allow(dead_code)]
pub fn path_param(name: &str, schema: Schema) -> ReferenceOr<Parameter> {
    ReferenceOr::Item(Parameter::Path {
        parameter_data: ParameterData {
            name: name.to_string(),
            description: None,
            required: true, // Path params are always required
            deprecated: None,
            format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)),
            example: None,
            examples: Default::default(),
            explode: None,
            extensions: Default::default(),
        },
        style: Default::default(),
    })
}

// =============================================================================
// Operation Builders
// =============================================================================

/// Create a minimal operation with a 200 response
#[allow(dead_code)]
pub fn minimal_operation() -> Operation {
    let mut responses = openapiv3::Responses::default();
    responses.responses.insert(
        StatusCode::Code(200),
        ReferenceOr::Item(Response {
            description: "OK".to_string(),
            ..Default::default()
        }),
    );

    Operation {
        responses,
        ..Default::default()
    }
}

/// Create an operation with query parameters
#[allow(dead_code)]
pub fn operation_with_query_params(params: Vec<ReferenceOr<Parameter>>) -> Operation {
    let mut op = minimal_operation();
    op.parameters = params;
    op
}

/// Create an operation with header parameters
#[allow(dead_code)]
pub fn operation_with_header_params(params: Vec<ReferenceOr<Parameter>>) -> Operation {
    let mut op = minimal_operation();
    op.parameters = params;
    op
}

/// Create an operation with a JSON response schema
#[allow(dead_code)]
pub fn operation_with_response_schema(status: u16, schema: Schema) -> Operation {
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
        StatusCode::Code(status),
        ReferenceOr::Item(Response {
            description: "Response".to_string(),
            content,
            ..Default::default()
        }),
    );

    Operation {
        responses,
        ..Default::default()
    }
}

/// Create an operation with response example
#[allow(dead_code)]
pub fn operation_with_example(status: u16, example: serde_json::Value) -> Operation {
    let mut content = indexmap::IndexMap::new();
    content.insert(
        "application/json".to_string(),
        MediaType {
            schema: Some(ReferenceOr::Item(object_schema(vec![], vec![]))),
            example: Some(example),
            ..Default::default()
        },
    );

    let mut responses = openapiv3::Responses::default();
    responses.responses.insert(
        StatusCode::Code(status),
        ReferenceOr::Item(Response {
            description: "Response".to_string(),
            content,
            ..Default::default()
        }),
    );

    Operation {
        responses,
        ..Default::default()
    }
}

// =============================================================================
// Response Builders
// =============================================================================

/// Create a JSON response with schema
#[allow(dead_code)]
pub fn json_response(schema: Schema) -> Response {
    let mut content = indexmap::IndexMap::new();
    content.insert(
        "application/json".to_string(),
        MediaType {
            schema: Some(ReferenceOr::Item(schema)),
            ..Default::default()
        },
    );

    Response {
        description: "Response".to_string(),
        content,
        ..Default::default()
    }
}

/// Create a response with required headers
#[allow(dead_code)]
pub fn response_with_headers(headers: Vec<(&str, bool, Schema)>) -> Response {
    let mut header_map = indexmap::IndexMap::new();
    for (name, required, schema) in headers {
        header_map.insert(
            name.to_string(),
            ReferenceOr::Item(Header {
                description: None,
                style: Default::default(),
                required,
                deprecated: None,
                format: ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)),
                example: None,
                examples: Default::default(),
                extensions: Default::default(),
            }),
        );
    }

    Response {
        description: "Response".to_string(),
        headers: header_map,
        ..Default::default()
    }
}
