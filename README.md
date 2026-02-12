# API Fence for Envoy [WIP / Experimental]

An HTTP filter for Envoy Proxy that validates requests against OpenAPI specifications, built as a dynamic module using Rust.

## Quick Start

```bash
# Enter development environment
nix develop

# Build the filter
cargo build --release

# Run tests
cargo test

# The compiled filter is at:
# target/release/libapi_fence.so
```

## Features

- **OpenAPI Validation**: Validates HTTP requests and responses against OpenAPI 3.x specifications
  - Path parameter validation with JSON Schema
  - Query parameter validation with JSON Schema
  - Request header validation (required, pattern, format, etc.)
  - Request body validation (JSON with schema)
  - Response header validation (required, pattern, format, etc.)
  - Response body validation (JSON with schema)
- **Mock Response Generation**: Generate mock responses for API testing without a backend
  - Example-based: Use examples from OpenAPI response definitions
  - Schema-based: Generate realistic fake data matching response schemas
  - Random selection: Automatically chooses from multiple possible response codes (200, 201, 206, etc.)
  - Validation-first: Requests are validated before mocking (useful for contract testing)
  - Works with all request types (GET, POST, PUT, etc.)
- **Dynamic Module**: Loads into Envoy without recompilation
- **Schema Caching**: Compiled JSON schemas are cached with configurable TTL for optimal performance
- **Flexible Validation**: Configure request/response validation independently
- **Error Handling**: Choose to fail requests on validation errors or pass them through with metadata
- **Rich Metrics**: Track cache hits/misses, schema compilation time, and validation errors (scoped per API)
- **Dynamic Metadata**: Validation results and errors are exposed as Envoy dynamic metadata for logging
- **Production Ready**: Optimized builds with LTO and stripping

## Metrics

The filter exposes the following metrics, scoped under your configured `api_name`:

- `api_fence.<api_name>.cache.hits` - Number of schema cache hits
- `api_fence.<api_name>.cache.misses` - Number of schema cache misses  
- `api_fence.<api_name>.schema.compile_time_ms` - Histogram of schema compilation times
- `api_fence.<api_name>.request.validation_errors` - Count of request validation errors
- `api_fence.<api_name>.response.validation_errors` - Count of response validation errors

For example, with `api_name: "users_api"`, metrics will appear as:
- `api_fence.users_api.cache.hits`
- `api_fence.users_api.request.validation_errors`

This allows multiple filter instances to track metrics independently.

Access metrics at `http://localhost:9901/stats/prometheus`

## Dynamic Metadata

Validation results are exposed as dynamic metadata in the `api_fence` namespace:

**Request Validation:**
- `request.verdict` - "valid" or "invalid"
- `request.error_count` - Number of validation errors
- `request.errors` - Pipe-separated list of error messages

**Response Validation:**
- `response.verdict` - "valid" or "invalid"
- `response.error_count` - Number of validation errors
- `response.errors` - Pipe-separated list of error messages

Use these in access logs to track validation issues:
```
%DYNAMIC_METADATA(api_fence:request.verdict)%
%DYNAMIC_METADATA(api_fence:request.errors)%
```

## Development

This project uses Nix for reproducible development environments. See [Agent.md](./Agent.md) for detailed documentation.

### Requirements

- Nix with flakes enabled
- (Optional) direnv for automatic environment loading

### Building

```bash
cargo build --release
```

The compiled shared library will be at `target/release/libapi_fence.so`.

### Testing

```bash
# Unit tests
cargo test

# Integration tests with Envoy
cargo test --test integration -- --ignored --nocapture

# OpenAPI fuzzing tests
cargo test --test fuzzing -- --ignored --nocapture
```

See [TESTING.md](./TESTING.md) and [tests/README.md](./tests/README.md) for details.

## Configuration

The filter supports comprehensive configuration options:

```yaml
http_filters:
  - name: envoy.filters.http.dynamic_module
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
      dynamic_module_config:
        name: api_fence
        do_not_close: true
      filter_name: api_fence
      filter_config:
        "@type": "type.googleapis.com/google.protobuf.StringValue"
        value: |
          {
            "api_name": "my_api",
            "openapi_spec_path": "/path/to/openapi.yaml",
            "cache": {
              "max_capacity": 1000,
              "ttl_seconds": 3600
            },
            "validation": {
              "validate_request": true,
              "validate_response": false,
              "fail_on_request_error": true,
              "fail_on_response_error": false
            }
          }
```

### Configuration Options

**API Name (required):**
- `api_name` - Unique identifier for this API/filter instance. Used for metric scoping to allow multiple filter instances to have separate metrics. Example: "users_api", "orders_api"

**OpenAPI Spec (required, one of):**
- `openapi_spec_path` - Path to OpenAPI spec file (YAML or JSON)
- `openapi_spec_inline` - Inline OpenAPI spec as YAML/JSON string

**Cache Configuration (optional):**
- `cache.max_capacity` - Maximum cached schemas (default: 1000)
- `cache.ttl_seconds` - Cache time-to-live in seconds (default: 3600)

**Validation Configuration (optional):**
- `validation.validate_request` - Enable request validation (default: true)
- `validation.validate_response` - Enable response validation (default: false)
- `validation.fail_on_request_error` - Reject invalid requests (default: true)
- `validation.fail_on_response_error` - Reject invalid responses (default: false)

When `fail_on_*_error` is false, validation errors are recorded in metrics and metadata but the request/response continues.

**Mocking Configuration (optional):**
- `mocking.enabled` - Enable mock response generation (default: false)
- `mocking.prefer_examples` - Use OpenAPI examples before schema-based generation (default: true)
- `mocking.default_status_code` - Override default status code for mocking (default: first 2xx response)
- `mocking.add_mock_header` - Include `x-mock-response: true` header in mock responses (default: true)

When mocking is enabled, requests are still validated (if configured), but instead of forwarding to the backend, the filter generates and returns a mock response. This is useful for:
- **Contract testing**: Validate requests without needing a backend
- **Frontend development**: Test UI against API contracts
- **Integration testing**: Test API consumers with realistic responses
- **Load testing**: Test proxy/middleware performance without backend load

### Example Configurations

See `examples/` directory:
- `envoy-config.yaml` - Basic configuration with request validation
- `envoy-config-advanced.yaml` - Advanced config with response validation, pass-through mode, and full access logging
- `envoy-config-mock.yaml` - Mock response generation for API testing (no backend required)
- `sample-openapi.yaml` - Example OpenAPI spec with header validation
- `header-validation-example.yaml` - Comprehensive header validation examples (required/optional, patterns, formats, enums)
- `mock-example-openapi.yaml` - OpenAPI spec with response examples for mocking

### Mock Response Generation Example

Enable mocking to test API contracts without a backend:

```yaml
filter_config:
  value: |
    {
      "api_name": "mock_api",
      "openapi_spec_path": "./examples/mock-example-openapi.yaml",
      "validation": {
        "validate_request": true,
        "fail_on_request_error": false
      },
      "mocking": {
        "enabled": true,
        "prefer_examples": true,
        "add_mock_header": true
      }
    }
```

Test with curl:
```bash
# GET request - returns mock data from OpenAPI examples
curl -v http://localhost:10000/users

# POST request - validates body, then returns mock response
curl -v http://localhost:10000/users/1 \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@example.com"}'

# Mock response includes indicator header
# x-mock-response: true
```

Mock responses are generated using:
1. **Examples first** (if `prefer_examples: true`): Uses `example` fields from OpenAPI responses
2. **Schema-based fallback**: Generates realistic fake data matching the schema (emails, UUIDs, dates, etc.)
3. **Random selection**: For operations with multiple 2xx responses (200, 201, 206), randomly chooses one

**Supported schema types for generation:**
- Strings: Supports formats (email, uri, uuid, date, date-time) and enums
- Numbers/Integers: Respects min/max constraints
- Booleans: Random true/false
- Arrays: Generates 1-5 items
- Objects: Generates all properties
- **Limitations**: OneOf/AllOf/AnyOf schemas not yet supported

## Project Status

🚧 **Early Development** - This project is in active development.

## License

Apache-2.0

## Resources

- [Envoy Dynamic Modules Documentation](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules)
- [Dynamic Modules Examples](https://github.com/envoyproxy/dynamic-modules-examples)
