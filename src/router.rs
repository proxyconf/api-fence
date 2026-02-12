//! Path routing for OpenAPI operations
//!
//! This module handles efficient path matching using the matchit router,
//! converting OpenAPI path templates to matchit format.

use crate::error::RoutingError;
use crate::validation::ParamSchema;
use openapiv3::{OpenAPI, Operation, ParameterSchemaOrContent, ReferenceOr};
use std::collections::HashMap;
use std::sync::Arc;

/// Route data stored in the matchit router
#[derive(Clone, Debug)]
pub struct RouteData {
    /// Original OpenAPI path template (e.g., "/users/{userId}")
    pub path_template: String,
    /// Map of HTTP method to operation
    pub operations: HashMap<String, Arc<Operation>>,
    /// Path parameter schemas for type validation
    pub param_schemas: HashMap<String, ParamSchema>,
}

/// Result of a successful route match
pub struct RouteMatch<'a> {
    /// The matched route data
    pub route: &'a RouteData,
    /// The matched operation
    pub operation: Arc<Operation>,
    /// Extracted path parameters
    pub path_params: HashMap<String, String>,
}

/// OpenAPI path router
///
/// Provides efficient O(log n) path matching for OpenAPI operations.
pub struct Router {
    inner: matchit::Router<RouteData>,
}

impl Router {
    /// Build a new router from an OpenAPI spec
    pub fn from_spec(spec: &OpenAPI) -> Self {
        let mut router = matchit::Router::new();

        for (path_template, path_item) in &spec.paths.paths {
            // Convert OpenAPI path template to matchit format
            // OpenAPI: /users/{userId} -> matchit: /users/:userId
            let matchit_path = convert_openapi_path_to_matchit(path_template);

            // Collect operations for this path
            let mut operations = HashMap::new();
            let mut param_schemas = HashMap::new();

            if let ReferenceOr::Item(item) = path_item {
                // Extract path parameter schemas from parameters
                for param_or_ref in &item.parameters {
                    if let ReferenceOr::Item(openapiv3::Parameter::Path {
                        parameter_data,
                        style: _,
                    }) = param_or_ref
                    {
                        if let ParameterSchemaOrContent::Schema(ReferenceOr::Item(schema)) =
                            &parameter_data.format
                        {
                            param_schemas.insert(
                                parameter_data.name.clone(),
                                ParamSchema {
                                    name: parameter_data.name.clone(),
                                    schema: Arc::new(schema.clone()),
                                    required: parameter_data.required,
                                },
                            );
                        }
                    }
                }

                // Collect HTTP methods
                if let Some(op) = &item.get {
                    operations.insert("GET".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.post {
                    operations.insert("POST".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.put {
                    operations.insert("PUT".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.delete {
                    operations.insert("DELETE".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.patch {
                    operations.insert("PATCH".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.head {
                    operations.insert("HEAD".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.options {
                    operations.insert("OPTIONS".to_string(), Arc::new(op.clone()));
                }
                if let Some(op) = &item.trace {
                    operations.insert("TRACE".to_string(), Arc::new(op.clone()));
                }
            }

            if !operations.is_empty() {
                let route_data = RouteData {
                    path_template: path_template.clone(),
                    operations,
                    param_schemas,
                };

                if let Err(e) = router.insert(matchit_path, route_data) {
                    // Log but don't fail - some paths may conflict
                    eprintln!("Warning: Failed to insert route {}: {}", path_template, e);
                }
            }
        }

        Self { inner: router }
    }

    /// Find a matching operation for a given method and path
    ///
    /// Returns the operation and extracted path parameters, or a routing error.
    pub fn find_operation(&self, method: &str, path: &str) -> Result<RouteMatch<'_>, RoutingError> {
        match self.inner.at(path) {
            Ok(matched) => {
                let route_data = matched.value;

                // Extract path parameters from matchit
                let mut path_params = HashMap::new();
                for (key, value) in matched.params.iter() {
                    path_params.insert(key.to_string(), value.to_string());
                }

                // Check if method is allowed
                if let Some(operation) = route_data.operations.get(method) {
                    Ok(RouteMatch {
                        route: route_data,
                        operation: operation.clone(),
                        path_params,
                    })
                } else {
                    // Path matches but method doesn't - 405 Method Not Allowed
                    Err(RoutingError::MethodNotAllowed {
                        method: method.to_string(),
                        path: path.to_string(),
                        allowed: route_data.operations.keys().cloned().collect(),
                    })
                }
            }
            Err(_) => {
                // No path matched - 404 Not Found
                Err(RoutingError::PathNotFound {
                    path: path.to_string(),
                })
            }
        }
    }
}

impl Clone for Router {
    fn clone(&self) -> Self {
        // matchit::Router is Clone
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Convert OpenAPI path template to matchit format
///
/// As of matchit 0.8, OpenAPI and matchit use the same `{param}` syntax,
/// so no conversion is needed.
///
/// # Examples
///
/// ```
/// use api_fence::router::convert_openapi_path_to_matchit;
///
/// assert_eq!(convert_openapi_path_to_matchit("/users/{userId}"), "/users/{userId}");
/// assert_eq!(convert_openapi_path_to_matchit("/items/{id}/details"), "/items/{id}/details");
/// ```
pub fn convert_openapi_path_to_matchit(openapi_path: &str) -> String {
    // matchit 0.8+ uses {param} syntax, same as OpenAPI
    openapi_path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_simple_param() {
        // matchit 0.8+ uses same {param} syntax as OpenAPI
        assert_eq!(
            convert_openapi_path_to_matchit("/users/{userId}"),
            "/users/{userId}"
        );
    }

    #[test]
    fn test_convert_multiple_params() {
        assert_eq!(
            convert_openapi_path_to_matchit("/orgs/{orgId}/users/{userId}"),
            "/orgs/{orgId}/users/{userId}"
        );
    }

    #[test]
    fn test_convert_no_params() {
        assert_eq!(convert_openapi_path_to_matchit("/users"), "/users");
    }

    #[test]
    fn test_router_from_minimal_spec() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: OK
  /users/{id}:
    get:
      responses:
        '200':
          description: OK
    delete:
      responses:
        '204':
          description: Deleted
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // Test exact path match
        let result = router.find_operation("GET", "/users");
        assert!(result.is_ok());

        // Test param path match
        let result = router.find_operation("GET", "/users/123");
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap().path_params.get("id"),
            Some(&"123".to_string())
        );

        // Test method not allowed
        let result = router.find_operation("POST", "/users/123");
        assert!(matches!(result, Err(RoutingError::MethodNotAllowed { .. })));

        // Test path not found
        let result = router.find_operation("GET", "/unknown");
        assert!(matches!(result, Err(RoutingError::PathNotFound { .. })));
    }

    #[test]
    fn test_router_extracts_multiple_params() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /orgs/{orgId}/users/{userId}:
    get:
      responses:
        '200':
          description: OK
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        let result = router.find_operation("GET", "/orgs/acme/users/123");
        assert!(result.is_ok());

        let route_match = result.unwrap();
        assert_eq!(
            route_match.path_params.get("orgId"),
            Some(&"acme".to_string())
        );
        assert_eq!(
            route_match.path_params.get("userId"),
            Some(&"123".to_string())
        );
    }

    #[test]
    fn test_router_clone() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /test:
    get:
      responses:
        '200':
          description: OK
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router1 = Router::from_spec(&spec);
        let router2 = router1.clone();

        // Both should work
        assert!(router1.find_operation("GET", "/test").is_ok());
        assert!(router2.find_operation("GET", "/test").is_ok());
    }

    #[test]
    fn test_path_not_found_returns_error() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: OK
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        let result = router.find_operation("GET", "/nonexistent");
        match result {
            Err(RoutingError::PathNotFound { path }) => {
                assert_eq!(path, "/nonexistent");
            }
            _ => panic!("Expected PathNotFound error"),
        }
    }

    #[test]
    fn test_method_not_allowed_returns_allowed_methods() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: OK
    post:
      responses:
        '201':
          description: Created
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        let result = router.find_operation("DELETE", "/users");
        match result {
            Err(RoutingError::MethodNotAllowed {
                method,
                path,
                allowed,
            }) => {
                assert_eq!(method, "DELETE");
                assert_eq!(path, "/users");
                assert!(allowed.contains(&"GET".to_string()));
                assert!(allowed.contains(&"POST".to_string()));
                assert_eq!(allowed.len(), 2);
            }
            _ => panic!("Expected MethodNotAllowed error"),
        }
    }

    #[test]
    fn test_all_http_methods() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /resource:
    get:
      responses:
        '200':
          description: OK
    post:
      responses:
        '201':
          description: Created
    put:
      responses:
        '200':
          description: Updated
    delete:
      responses:
        '204':
          description: Deleted
    patch:
      responses:
        '200':
          description: Patched
    head:
      responses:
        '200':
          description: Head
    options:
      responses:
        '200':
          description: Options
    trace:
      responses:
        '200':
          description: Trace
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // Test all 8 HTTP methods
        for method in [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE",
        ] {
            let result = router.find_operation(method, "/resource");
            assert!(result.is_ok(), "Method {} should be allowed", method);
        }
    }

    #[test]
    fn test_empty_paths_spec() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths: {}
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // Empty spec should return PathNotFound for any path
        let result = router.find_operation("GET", "/anything");
        assert!(matches!(result, Err(RoutingError::PathNotFound { .. })));
    }

    #[test]
    fn test_trailing_slash_handling() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        '200':
          description: List users
  /users/:
    get:
      responses:
        '200':
          description: List users with trailing slash
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // Both paths should be distinct (if both defined)
        let result_no_slash = router.find_operation("GET", "/users");
        let _result_with_slash = router.find_operation("GET", "/users/");

        // At least the no-slash version should work
        assert!(result_no_slash.is_ok());
        // Note: matchit may or may not support both - we just verify no crash
        // The behavior depends on matchit's handling
    }

    #[test]
    fn test_path_with_dots() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /api/v1.0/users:
    get:
      responses:
        '200':
          description: OK
  /files/{filename}.json:
    get:
      responses:
        '200':
          description: OK
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // Path with dots in static segment
        let result = router.find_operation("GET", "/api/v1.0/users");
        assert!(result.is_ok());

        // Note: {filename}.json pattern may not work with matchit as it
        // expects the entire segment to be a parameter. This tests that
        // such patterns don't crash the router.
    }

    #[test]
    fn test_param_schemas_extracted() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users/{userId}:
    parameters:
      - name: userId
        in: path
        required: true
        schema:
          type: integer
          minimum: 1
    get:
      responses:
        '200':
          description: OK
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        let result = router.find_operation("GET", "/users/123");
        assert!(result.is_ok());

        let route_match = result.unwrap();
        // Check that param schema was extracted
        assert!(route_match.route.param_schemas.contains_key("userId"));
        let param_schema = route_match.route.param_schemas.get("userId").unwrap();
        assert_eq!(param_schema.name, "userId");
        assert!(param_schema.required);
    }

    #[test]
    fn test_operations_extracted() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /users:
    get:
      operationId: listUsers
      summary: List all users
      responses:
        '200':
          description: OK
    post:
      operationId: createUser
      summary: Create a user
      responses:
        '201':
          description: Created
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // Check GET operation
        let get_result = router.find_operation("GET", "/users");
        assert!(get_result.is_ok());
        let get_match = get_result.unwrap();
        assert_eq!(
            get_match.operation.operation_id,
            Some("listUsers".to_string())
        );
        assert_eq!(
            get_match.operation.summary,
            Some("List all users".to_string())
        );

        // Check POST operation
        let post_result = router.find_operation("POST", "/users");
        assert!(post_result.is_ok());
        let post_match = post_result.unwrap();
        assert_eq!(
            post_match.operation.operation_id,
            Some("createUser".to_string())
        );

        // Check route data has both operations
        assert_eq!(get_match.route.operations.len(), 2);
        assert!(get_match.route.operations.contains_key("GET"));
        assert!(get_match.route.operations.contains_key("POST"));
    }

    #[test]
    fn test_encoded_path_params() {
        let spec_yaml = r#"
openapi: 3.0.0
info:
  title: Test API
  version: 1.0.0
paths:
  /files/{filename}:
    get:
      responses:
        '200':
          description: OK
"#;
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
        let router = Router::from_spec(&spec);

        // URL-encoded path param (space = %20)
        let result = router.find_operation("GET", "/files/my%20file.txt");
        assert!(result.is_ok());

        let route_match = result.unwrap();
        // matchit returns the raw (encoded) value
        assert_eq!(
            route_match.path_params.get("filename"),
            Some(&"my%20file.txt".to_string())
        );
    }
}
