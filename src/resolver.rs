//! OpenAPI $ref resolution
//!
//! This module handles resolution of `$ref` references in OpenAPI specifications,
//! enabling validation against schemas defined in `#/components/schemas/*` and other
//! component types.
//!
//! ## Supported Reference Types
//!
//! - Internal references: `#/components/schemas/User`, `#/components/parameters/PageSize`, etc.
//! - External file references are NOT supported (security concern)
//! - URL references are NOT supported (security concern)
//!
//! ## Cycle Detection
//!
//! The resolver tracks which references are currently being resolved to detect
//! circular references and avoid infinite loops.

use openapiv3::{Header, OpenAPI, Parameter, ReferenceOr, RequestBody, Response, Schema};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Result type for reference resolution operations
pub type RefResult<T> = std::result::Result<T, RefError>;

/// Errors that can occur during reference resolution
#[derive(Error, Debug, Clone)]
pub enum RefError {
    /// Reference target was not found in the specification
    #[error("Reference not found: {reference}")]
    NotFound { reference: String },

    /// Circular reference detected during resolution
    #[error("Circular reference detected: {}", path.join(" -> "))]
    CircularReference { path: Vec<String> },

    /// Invalid reference format
    #[error("Invalid reference format: {reference}")]
    InvalidFormat { reference: String },

    /// External URL references are not supported (security concern)
    #[error("External URL references not supported: {url}")]
    ExternalUrlNotSupported { url: String },

    /// Reference type not supported
    #[error("Unsupported reference type: {ref_type}")]
    UnsupportedRefType { ref_type: String },
}

/// Type of reference target in OpenAPI components
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefTarget {
    /// Reference to `#/components/schemas/{name}`
    Schema(String),
    /// Reference to `#/components/parameters/{name}`
    Parameter(String),
    /// Reference to `#/components/responses/{name}`
    Response(String),
    /// Reference to `#/components/requestBodies/{name}`
    RequestBody(String),
    /// Reference to `#/components/headers/{name}`
    Header(String),
}

/// Reference resolver for OpenAPI specifications
///
/// The resolver caches the OpenAPI specification and provides methods
/// to resolve `$ref` references to their target schemas, parameters,
/// responses, and request bodies.
///
/// ## Example
///
/// ```ignore
/// let spec: OpenAPI = serde_yaml::from_str(spec_yaml)?;
/// let resolver = RefResolver::new(Arc::new(spec));
///
/// // Resolve a schema reference
/// let schema = resolver.resolve_schema(&ReferenceOr::Reference {
///     reference: "#/components/schemas/User".to_string()
/// })?;
/// ```
pub struct RefResolver {
    /// The OpenAPI specification
    spec: Arc<OpenAPI>,
    /// Currently resolving references (for cycle detection)
    /// Uses Mutex for thread-safe interior mutability during resolution
    resolving: Mutex<HashSet<String>>,
}

impl RefResolver {
    /// Create a new reference resolver for the given OpenAPI specification
    pub fn new(spec: Arc<OpenAPI>) -> Self {
        Self {
            spec,
            resolving: Mutex::new(HashSet::new()),
        }
    }

    /// Get a reference to the underlying OpenAPI specification
    pub fn spec(&self) -> &OpenAPI {
        &self.spec
    }

    /// Parse a reference string into a RefTarget
    ///
    /// Supports internal references like:
    /// - `#/components/schemas/User`
    /// - `#/components/parameters/PageSize`
    /// - `#/components/responses/NotFound`
    /// - `#/components/requestBodies/UserInput`
    /// - `#/components/headers/X-Rate-Limit`
    ///
    /// Returns an error for external URL references (security concern).
    pub fn parse_ref(reference: &str) -> RefResult<RefTarget> {
        // Check for external URL references first (not supported)
        if reference.starts_with("http://") || reference.starts_with("https://") {
            return Err(RefError::ExternalUrlNotSupported {
                url: reference.to_string(),
            });
        }

        // Check for external file references (not supported in this version)
        if !reference.starts_with('#') {
            return Err(RefError::InvalidFormat {
                reference: reference.to_string(),
            });
        }

        // Parse internal reference
        if !reference.starts_with("#/") {
            return Err(RefError::InvalidFormat {
                reference: reference.to_string(),
            });
        }

        let parts: Vec<&str> = reference[2..].split('/').collect();

        match parts.as_slice() {
            ["components", "schemas", name] => Ok(RefTarget::Schema(name.to_string())),
            ["components", "parameters", name] => Ok(RefTarget::Parameter(name.to_string())),
            ["components", "responses", name] => Ok(RefTarget::Response(name.to_string())),
            ["components", "requestBodies", name] => Ok(RefTarget::RequestBody(name.to_string())),
            ["components", "headers", name] => Ok(RefTarget::Header(name.to_string())),
            _ => Err(RefError::InvalidFormat {
                reference: reference.to_string(),
            }),
        }
    }

    /// Resolve a schema reference to its target schema
    ///
    /// If the input is already an inline schema (Item), returns it directly.
    /// If it's a reference, looks up the target in `#/components/schemas/`.
    ///
    /// Handles nested references (schema A refs schema B refs schema C).
    /// Detects and reports circular references.
    pub fn resolve_schema(&self, ref_or_schema: &ReferenceOr<Schema>) -> RefResult<Arc<Schema>> {
        match ref_or_schema {
            ReferenceOr::Item(schema) => Ok(Arc::new(schema.clone())),
            ReferenceOr::Reference { reference } => self.resolve_schema_by_ref(reference),
        }
    }

    /// Resolve a boxed schema reference to its target schema
    ///
    /// This is a convenience method for handling `ReferenceOr<Box<Schema>>` which is
    /// used in array items and object properties.
    pub fn resolve_boxed_schema(
        &self,
        ref_or_schema: &ReferenceOr<Box<Schema>>,
    ) -> RefResult<Arc<Schema>> {
        match ref_or_schema {
            ReferenceOr::Item(schema) => Ok(Arc::new((**schema).clone())),
            ReferenceOr::Reference { reference } => self.resolve_schema_by_ref(reference),
        }
    }

    /// Resolve a schema by its reference string
    fn resolve_schema_by_ref(&self, reference: &str) -> RefResult<Arc<Schema>> {
        // Check for circular reference
        {
            let resolving = self.resolving.lock().expect("resolver lock poisoned");
            if resolving.contains(reference) {
                return Err(RefError::CircularReference {
                    path: resolving.iter().cloned().collect(),
                });
            }
        }

        // Parse the reference
        let target = Self::parse_ref(reference)?;

        // Must be a schema reference
        let name = match target {
            RefTarget::Schema(name) => name,
            _ => {
                return Err(RefError::UnsupportedRefType {
                    ref_type: format!("Expected schema reference, got {:?}", target),
                })
            }
        };

        // Look up the schema in components
        let schema_ref = self
            .spec
            .components
            .as_ref()
            .and_then(|c| c.schemas.get(&name))
            .ok_or_else(|| RefError::NotFound {
                reference: reference.to_string(),
            })?;

        // Track that we're resolving this reference (for cycle detection)
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.insert(reference.to_string());
        }

        // Recursively resolve if it's another reference
        let result = match schema_ref {
            ReferenceOr::Item(schema) => Ok(Arc::new(schema.clone())),
            ReferenceOr::Reference {
                reference: nested_ref,
            } => self.resolve_schema_by_ref(nested_ref),
        };

        // Clean up tracking
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.remove(reference);
        }

        result
    }

    /// Resolve a parameter reference to its target parameter
    ///
    /// If the input is already an inline parameter (Item), returns it directly.
    /// If it's a reference, looks up the target in `#/components/parameters/`.
    pub fn resolve_parameter(
        &self,
        ref_or_param: &ReferenceOr<Parameter>,
    ) -> RefResult<Arc<Parameter>> {
        match ref_or_param {
            ReferenceOr::Item(param) => Ok(Arc::new(param.clone())),
            ReferenceOr::Reference { reference } => self.resolve_parameter_by_ref(reference),
        }
    }

    /// Resolve a parameter by its reference string
    fn resolve_parameter_by_ref(&self, reference: &str) -> RefResult<Arc<Parameter>> {
        // Check for circular reference
        {
            let resolving = self.resolving.lock().expect("resolver lock poisoned");
            if resolving.contains(reference) {
                return Err(RefError::CircularReference {
                    path: resolving.iter().cloned().collect(),
                });
            }
        }

        // Parse the reference
        let target = Self::parse_ref(reference)?;

        // Must be a parameter reference
        let name = match target {
            RefTarget::Parameter(name) => name,
            _ => {
                return Err(RefError::UnsupportedRefType {
                    ref_type: format!("Expected parameter reference, got {:?}", target),
                })
            }
        };

        // Look up the parameter in components
        let param_ref = self
            .spec
            .components
            .as_ref()
            .and_then(|c| c.parameters.get(&name))
            .ok_or_else(|| RefError::NotFound {
                reference: reference.to_string(),
            })?;

        // Track that we're resolving this reference (for cycle detection)
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.insert(reference.to_string());
        }

        // Recursively resolve if it's another reference
        let result = match param_ref {
            ReferenceOr::Item(param) => Ok(Arc::new(param.clone())),
            ReferenceOr::Reference {
                reference: nested_ref,
            } => self.resolve_parameter_by_ref(nested_ref),
        };

        // Clean up tracking
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.remove(reference);
        }

        result
    }

    /// Resolve a response reference to its target response
    ///
    /// If the input is already an inline response (Item), returns it directly.
    /// If it's a reference, looks up the target in `#/components/responses/`.
    pub fn resolve_response(
        &self,
        ref_or_response: &ReferenceOr<Response>,
    ) -> RefResult<Arc<Response>> {
        match ref_or_response {
            ReferenceOr::Item(response) => Ok(Arc::new(response.clone())),
            ReferenceOr::Reference { reference } => self.resolve_response_by_ref(reference),
        }
    }

    /// Resolve a response by its reference string
    fn resolve_response_by_ref(&self, reference: &str) -> RefResult<Arc<Response>> {
        // Check for circular reference
        {
            let resolving = self.resolving.lock().expect("resolver lock poisoned");
            if resolving.contains(reference) {
                return Err(RefError::CircularReference {
                    path: resolving.iter().cloned().collect(),
                });
            }
        }

        // Parse the reference
        let target = Self::parse_ref(reference)?;

        // Must be a response reference
        let name = match target {
            RefTarget::Response(name) => name,
            _ => {
                return Err(RefError::UnsupportedRefType {
                    ref_type: format!("Expected response reference, got {:?}", target),
                })
            }
        };

        // Look up the response in components
        let response_ref = self
            .spec
            .components
            .as_ref()
            .and_then(|c| c.responses.get(&name))
            .ok_or_else(|| RefError::NotFound {
                reference: reference.to_string(),
            })?;

        // Track that we're resolving this reference (for cycle detection)
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.insert(reference.to_string());
        }

        // Recursively resolve if it's another reference
        let result = match response_ref {
            ReferenceOr::Item(response) => Ok(Arc::new(response.clone())),
            ReferenceOr::Reference {
                reference: nested_ref,
            } => self.resolve_response_by_ref(nested_ref),
        };

        // Clean up tracking
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.remove(reference);
        }

        result
    }

    /// Resolve a request body reference to its target request body
    ///
    /// If the input is already an inline request body (Item), returns it directly.
    /// If it's a reference, looks up the target in `#/components/requestBodies/`.
    pub fn resolve_request_body(
        &self,
        ref_or_body: &ReferenceOr<RequestBody>,
    ) -> RefResult<Arc<RequestBody>> {
        match ref_or_body {
            ReferenceOr::Item(body) => Ok(Arc::new(body.clone())),
            ReferenceOr::Reference { reference } => self.resolve_request_body_by_ref(reference),
        }
    }

    /// Resolve a request body by its reference string
    fn resolve_request_body_by_ref(&self, reference: &str) -> RefResult<Arc<RequestBody>> {
        // Check for circular reference
        {
            let resolving = self.resolving.lock().expect("resolver lock poisoned");
            if resolving.contains(reference) {
                return Err(RefError::CircularReference {
                    path: resolving.iter().cloned().collect(),
                });
            }
        }

        // Parse the reference
        let target = Self::parse_ref(reference)?;

        // Must be a request body reference
        let name = match target {
            RefTarget::RequestBody(name) => name,
            _ => {
                return Err(RefError::UnsupportedRefType {
                    ref_type: format!("Expected requestBody reference, got {:?}", target),
                })
            }
        };

        // Look up the request body in components
        let body_ref = self
            .spec
            .components
            .as_ref()
            .and_then(|c| c.request_bodies.get(&name))
            .ok_or_else(|| RefError::NotFound {
                reference: reference.to_string(),
            })?;

        // Track that we're resolving this reference (for cycle detection)
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.insert(reference.to_string());
        }

        // Recursively resolve if it's another reference
        let result = match body_ref {
            ReferenceOr::Item(body) => Ok(Arc::new(body.clone())),
            ReferenceOr::Reference {
                reference: nested_ref,
            } => self.resolve_request_body_by_ref(nested_ref),
        };

        // Clean up tracking
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.remove(reference);
        }

        result
    }

    /// Resolve a header reference to its target header
    ///
    /// If the input is already an inline header (Item), returns it directly.
    /// If it's a reference, looks up the target in `#/components/headers/`.
    pub fn resolve_header(&self, ref_or_header: &ReferenceOr<Header>) -> RefResult<Arc<Header>> {
        match ref_or_header {
            ReferenceOr::Item(header) => Ok(Arc::new(header.clone())),
            ReferenceOr::Reference { reference } => self.resolve_header_by_ref(reference),
        }
    }

    /// Resolve a header by its reference string
    fn resolve_header_by_ref(&self, reference: &str) -> RefResult<Arc<Header>> {
        // Check for circular reference
        {
            let resolving = self.resolving.lock().expect("resolver lock poisoned");
            if resolving.contains(reference) {
                return Err(RefError::CircularReference {
                    path: resolving.iter().cloned().collect(),
                });
            }
        }

        // Parse the reference
        let target = Self::parse_ref(reference)?;

        // Must be a header reference
        let name = match target {
            RefTarget::Header(name) => name,
            _ => {
                return Err(RefError::UnsupportedRefType {
                    ref_type: format!("Expected header reference, got {:?}", target),
                })
            }
        };

        // Look up the header in components
        let header_ref = self
            .spec
            .components
            .as_ref()
            .and_then(|c| c.headers.get(&name))
            .ok_or_else(|| RefError::NotFound {
                reference: reference.to_string(),
            })?;

        // Track that we're resolving this reference (for cycle detection)
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.insert(reference.to_string());
        }

        // Recursively resolve if it's another reference
        let result = match header_ref {
            ReferenceOr::Item(header) => Ok(Arc::new(header.clone())),
            ReferenceOr::Reference {
                reference: nested_ref,
            } => self.resolve_header_by_ref(nested_ref),
        };

        // Clean up tracking
        {
            let mut resolving = self.resolving.lock().expect("resolver lock poisoned");
            resolving.remove(reference);
        }

        result
    }

    /// Resolve a schema reference deeply, inlining all nested `$ref` references
    ///
    /// This function resolves the top-level reference (if any) and then recursively
    /// resolves all nested `$ref` references within the schema, inlining them directly.
    /// This is necessary for JSON Schema validation because the jsonschema crate
    /// cannot resolve OpenAPI component references.
    ///
    /// Note: This function does NOT handle circular references - those will cause
    /// a stack overflow. Use `resolve_schema` for schemas that may be circular.
    pub fn resolve_schema_deep(&self, ref_or_schema: &ReferenceOr<Schema>) -> RefResult<Schema> {
        // First, resolve the top-level reference
        let schema = self.resolve_schema(ref_or_schema)?;

        // Then recursively resolve nested references
        self.resolve_schema_nested(&schema)
    }

    /// Resolve a boxed schema reference deeply
    pub fn resolve_boxed_schema_deep(
        &self,
        ref_or_schema: &ReferenceOr<Box<Schema>>,
    ) -> RefResult<Schema> {
        let schema = self.resolve_boxed_schema(ref_or_schema)?;
        self.resolve_schema_nested(&schema)
    }

    /// Recursively resolve all nested `$ref` in a schema
    fn resolve_schema_nested(&self, schema: &Schema) -> RefResult<Schema> {
        use openapiv3::SchemaKind;

        let resolved_kind = match &schema.schema_kind {
            SchemaKind::Type(typ) => SchemaKind::Type(self.resolve_type_nested(typ)?),
            SchemaKind::OneOf { one_of } => SchemaKind::OneOf {
                one_of: self.resolve_schema_vec(one_of)?,
            },
            SchemaKind::AllOf { all_of } => SchemaKind::AllOf {
                all_of: self.resolve_schema_vec(all_of)?,
            },
            SchemaKind::AnyOf { any_of } => SchemaKind::AnyOf {
                any_of: self.resolve_schema_vec(any_of)?,
            },
            SchemaKind::Not { not } => {
                let resolved = self.resolve_schema_deep(not)?;
                SchemaKind::Not {
                    not: Box::new(ReferenceOr::Item(resolved)),
                }
            }
            SchemaKind::Any(any_schema) => {
                SchemaKind::Any(self.resolve_any_schema_nested(any_schema)?)
            }
        };

        Ok(Schema {
            schema_data: schema.schema_data.clone(),
            schema_kind: resolved_kind,
        })
    }

    /// Resolve nested references in a Type
    fn resolve_type_nested(&self, typ: &openapiv3::Type) -> RefResult<openapiv3::Type> {
        use openapiv3::Type;

        match typ {
            Type::Object(obj) => {
                let resolved_properties = self.resolve_properties(&obj.properties)?;
                let resolved_additional =
                    self.resolve_additional_properties(&obj.additional_properties)?;

                Ok(Type::Object(openapiv3::ObjectType {
                    properties: resolved_properties,
                    required: obj.required.clone(),
                    additional_properties: resolved_additional,
                    min_properties: obj.min_properties,
                    max_properties: obj.max_properties,
                }))
            }
            Type::Array(arr) => {
                let resolved_items = match &arr.items {
                    Some(items) => Some(self.resolve_boxed_schema_to_ref(items)?),
                    None => None,
                };

                Ok(Type::Array(openapiv3::ArrayType {
                    items: resolved_items,
                    min_items: arr.min_items,
                    max_items: arr.max_items,
                    unique_items: arr.unique_items,
                }))
            }
            // Other types don't have nested schemas
            Type::String(s) => Ok(Type::String(s.clone())),
            Type::Number(n) => Ok(Type::Number(n.clone())),
            Type::Integer(i) => Ok(Type::Integer(i.clone())),
            Type::Boolean(b) => Ok(Type::Boolean(b.clone())),
        }
    }

    /// Resolve nested references in an AnySchema
    fn resolve_any_schema_nested(
        &self,
        any: &openapiv3::AnySchema,
    ) -> RefResult<openapiv3::AnySchema> {
        let resolved_properties = self.resolve_properties(&any.properties)?;
        let resolved_items = match &any.items {
            Some(items) => Some(self.resolve_boxed_schema_to_ref(items)?),
            None => None,
        };
        let resolved_additional = self.resolve_additional_properties(&any.additional_properties)?;
        let resolved_one_of = self.resolve_schema_vec(&any.one_of)?;
        let resolved_all_of = self.resolve_schema_vec(&any.all_of)?;
        let resolved_any_of = self.resolve_schema_vec(&any.any_of)?;
        let resolved_not = match &any.not {
            Some(not) => {
                let resolved = self.resolve_schema_deep(not)?;
                Some(Box::new(ReferenceOr::Item(resolved)))
            }
            None => None,
        };

        Ok(openapiv3::AnySchema {
            typ: any.typ.clone(),
            pattern: any.pattern.clone(),
            multiple_of: any.multiple_of,
            exclusive_minimum: any.exclusive_minimum,
            exclusive_maximum: any.exclusive_maximum,
            minimum: any.minimum,
            maximum: any.maximum,
            properties: resolved_properties,
            required: any.required.clone(),
            additional_properties: resolved_additional,
            min_properties: any.min_properties,
            max_properties: any.max_properties,
            items: resolved_items,
            min_items: any.min_items,
            max_items: any.max_items,
            unique_items: any.unique_items,
            enumeration: any.enumeration.clone(),
            format: any.format.clone(),
            min_length: any.min_length,
            max_length: any.max_length,
            one_of: resolved_one_of,
            all_of: resolved_all_of,
            any_of: resolved_any_of,
            not: resolved_not,
        })
    }

    /// Resolve a Vec of schema references
    fn resolve_schema_vec(
        &self,
        schemas: &[ReferenceOr<Schema>],
    ) -> RefResult<Vec<ReferenceOr<Schema>>> {
        schemas
            .iter()
            .map(|s| {
                let resolved = self.resolve_schema_deep(s)?;
                Ok(ReferenceOr::Item(resolved))
            })
            .collect()
    }

    /// Resolve properties map
    fn resolve_properties(
        &self,
        properties: &indexmap::IndexMap<String, ReferenceOr<Box<Schema>>>,
    ) -> RefResult<indexmap::IndexMap<String, ReferenceOr<Box<Schema>>>> {
        properties
            .iter()
            .map(|(k, v)| {
                let resolved = self.resolve_boxed_schema_deep(v)?;
                Ok((k.clone(), ReferenceOr::Item(Box::new(resolved))))
            })
            .collect()
    }

    /// Resolve a boxed schema reference to a ReferenceOr<Box<Schema>>
    fn resolve_boxed_schema_to_ref(
        &self,
        ref_or_schema: &ReferenceOr<Box<Schema>>,
    ) -> RefResult<ReferenceOr<Box<Schema>>> {
        let resolved = self.resolve_boxed_schema_deep(ref_or_schema)?;
        Ok(ReferenceOr::Item(Box::new(resolved)))
    }

    /// Resolve additional_properties
    fn resolve_additional_properties(
        &self,
        additional: &Option<openapiv3::AdditionalProperties>,
    ) -> RefResult<Option<openapiv3::AdditionalProperties>> {
        use openapiv3::AdditionalProperties;

        match additional {
            Some(AdditionalProperties::Schema(boxed_ref)) => {
                let resolved = self.resolve_schema_deep(boxed_ref)?;
                Ok(Some(AdditionalProperties::Schema(Box::new(
                    ReferenceOr::Item(resolved),
                ))))
            }
            Some(AdditionalProperties::Any(b)) => Ok(Some(AdditionalProperties::Any(*b))),
            None => Ok(None),
        }
    }
}

impl Clone for RefResolver {
    fn clone(&self) -> Self {
        Self {
            spec: self.spec.clone(),
            // Each clone gets a fresh resolving set
            resolving: Mutex::new(HashSet::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_spec_with_schemas() -> OpenAPI {
        let yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths: {}
components:
  schemas:
    User:
      type: object
      properties:
        id:
          type: integer
        name:
          type: string
    Address:
      $ref: '#/components/schemas/Location'
    Location:
      type: object
      properties:
        city:
          type: string
    CircularA:
      $ref: '#/components/schemas/CircularB'
    CircularB:
      $ref: '#/components/schemas/CircularA'
  parameters:
    PageSize:
      name: pageSize
      in: query
      schema:
        type: integer
        minimum: 1
        maximum: 100
  responses:
    NotFound:
      description: Resource not found
  requestBodies:
    UserInput:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/User'
  headers:
    X-Rate-Limit:
      description: Rate limit remaining
      schema:
        type: integer
"#;
        serde_yaml::from_str(yaml).expect("Failed to parse test spec")
    }

    #[test]
    fn test_parse_ref_schema() {
        let result = RefResolver::parse_ref("#/components/schemas/User");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), RefTarget::Schema("User".to_string()));
    }

    #[test]
    fn test_parse_ref_parameter() {
        let result = RefResolver::parse_ref("#/components/parameters/PageSize");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            RefTarget::Parameter("PageSize".to_string())
        );
    }

    #[test]
    fn test_parse_ref_response() {
        let result = RefResolver::parse_ref("#/components/responses/NotFound");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), RefTarget::Response("NotFound".to_string()));
    }

    #[test]
    fn test_parse_ref_request_body() {
        let result = RefResolver::parse_ref("#/components/requestBodies/UserInput");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            RefTarget::RequestBody("UserInput".to_string())
        );
    }

    #[test]
    fn test_parse_ref_header() {
        let result = RefResolver::parse_ref("#/components/headers/X-Rate-Limit");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            RefTarget::Header("X-Rate-Limit".to_string())
        );
    }

    #[test]
    fn test_parse_ref_external_url_rejected() {
        let result = RefResolver::parse_ref("https://example.com/schemas/User.json");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RefError::ExternalUrlNotSupported { .. }
        ));

        let result = RefResolver::parse_ref("http://example.com/schemas/User.json");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RefError::ExternalUrlNotSupported { .. }
        ));
    }

    #[test]
    fn test_parse_ref_external_file_rejected() {
        let result = RefResolver::parse_ref("./schemas/user.yaml#/User");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RefError::InvalidFormat { .. }
        ));
    }

    #[test]
    fn test_parse_ref_invalid_format() {
        let result = RefResolver::parse_ref("#invalid");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RefError::InvalidFormat { .. }
        ));

        let result = RefResolver::parse_ref("#/unknown/path/User");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RefError::InvalidFormat { .. }
        ));
    }

    #[test]
    fn test_resolve_schema_inline() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        // Test with inline schema
        let inline_schema = ReferenceOr::Item(Schema {
            schema_data: Default::default(),
            schema_kind: openapiv3::SchemaKind::Type(openapiv3::Type::String(Default::default())),
        });

        let result = resolver.resolve_schema(&inline_schema);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_schema_ref() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let schema_ref = ReferenceOr::Reference {
            reference: "#/components/schemas/User".to_string(),
        };

        let result = resolver.resolve_schema(&schema_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_schema_nested_ref() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        // Address refs Location, so resolving Address should give Location
        let schema_ref = ReferenceOr::Reference {
            reference: "#/components/schemas/Address".to_string(),
        };

        let result = resolver.resolve_schema(&schema_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_schema_not_found() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let schema_ref = ReferenceOr::Reference {
            reference: "#/components/schemas/NonExistent".to_string(),
        };

        let result = resolver.resolve_schema(&schema_ref);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RefError::NotFound { .. }));
    }

    #[test]
    fn test_resolve_schema_circular_ref() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let schema_ref = ReferenceOr::Reference {
            reference: "#/components/schemas/CircularA".to_string(),
        };

        let result = resolver.resolve_schema(&schema_ref);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RefError::CircularReference { .. }
        ));
    }

    #[test]
    fn test_resolve_parameter() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let param_ref = ReferenceOr::Reference {
            reference: "#/components/parameters/PageSize".to_string(),
        };

        let result = resolver.resolve_parameter(&param_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_parameter_not_found() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let param_ref = ReferenceOr::Reference {
            reference: "#/components/parameters/NonExistent".to_string(),
        };

        let result = resolver.resolve_parameter(&param_ref);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RefError::NotFound { .. }));
    }

    #[test]
    fn test_resolve_response() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let response_ref = ReferenceOr::Reference {
            reference: "#/components/responses/NotFound".to_string(),
        };

        let result = resolver.resolve_response(&response_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_request_body() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let body_ref = ReferenceOr::Reference {
            reference: "#/components/requestBodies/UserInput".to_string(),
        };

        let result = resolver.resolve_request_body(&body_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_header() {
        let spec = make_spec_with_schemas();
        let resolver = RefResolver::new(Arc::new(spec));

        let header_ref = ReferenceOr::Reference {
            reference: "#/components/headers/X-Rate-Limit".to_string(),
        };

        let result = resolver.resolve_header(&header_ref);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolver_clone() {
        let spec = make_spec_with_schemas();
        let resolver1 = RefResolver::new(Arc::new(spec));
        let resolver2 = resolver1.clone();

        // Both resolvers should work independently
        let schema_ref = ReferenceOr::Reference {
            reference: "#/components/schemas/User".to_string(),
        };

        assert!(resolver1.resolve_schema(&schema_ref).is_ok());
        assert!(resolver2.resolve_schema(&schema_ref).is_ok());
    }

    #[test]
    fn test_ref_error_display() {
        let err = RefError::NotFound {
            reference: "#/components/schemas/User".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Reference not found: #/components/schemas/User"
        );

        let err = RefError::CircularReference {
            path: vec![
                "#/components/schemas/A".to_string(),
                "#/components/schemas/B".to_string(),
            ],
        };
        assert!(err.to_string().contains("Circular reference detected"));

        let err = RefError::ExternalUrlNotSupported {
            url: "https://example.com".to_string(),
        };
        assert!(err
            .to_string()
            .contains("External URL references not supported"));
    }
}
