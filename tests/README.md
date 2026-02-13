# Integration Tests

This directory contains integration tests for the API Fence.

## Test Structure

- `integration.rs` - Core integration test infrastructure, including `EnvoyTestServer`
- `integration_tests/` - Modular integration test suite:
  - `test_modsecurity.rs` - ModSecurity WAF integration tests
  - `test_path_validation.rs` - Path parameter validation tests
  - `test_query_validation.rs` - Query parameter validation tests
  - `test_body_validation.rs` - Request body validation tests
  - `test_header_validation.rs` - Header validation tests
  - `test_security_limits.rs` - Security limits and DoS protection tests
  - `test_mock_responses.rs` - Mock response generation tests
  - `test_error_responses.rs` - Error response format tests
- `fuzzing.rs` - OpenAPI fuzzing tests

## Running Tests

### Quick Test (Unit Tests Only)

```bash
mise run test-unit
```

### Integration Tests (with Envoy)

Integration tests are marked with `#[ignore]` because they require:
1. Building the filter
2. Starting Envoy
3. External dependencies (envoy binary, libmodsecurity)

Run them explicitly:

```bash
# Run all integration tests
mise run test-integration

# Or manually:
cargo test --test integration -- --ignored --nocapture

# Run specific integration test
cargo test --test integration test_modsecurity -- --ignored --test-threads=1
```

### ModSecurity WAF Tests

```bash
# Run ModSecurity integration tests
SKIP_FILTER_BUILD=1 cargo test --test integration test_modsecurity -- --ignored --test-threads=1
```

### OpenAPI Fuzzing Tests

The fuzzing tests use `openapi-fuzzer` to comprehensively test the filter:

```bash
# Check if openapi-fuzzer is available
cargo test --test fuzzing test_fuzzer_available -- --ignored

# Run the full fuzzing test suite
cargo test --test fuzzing test_openapi_fuzzer_integration -- --ignored --nocapture
```

**Note**: The fuzzing test may take several minutes depending on the `--max-test-case-count`.

## Test Infrastructure

### EnvoyTestServer

The `EnvoyTestServer` struct in `integration.rs` provides:

1. **Automatic build** - Builds the filter before starting Envoy
2. **Dynamic configuration** - Generates Envoy config with the filter loaded
3. **Readiness checking** - Waits for Envoy to be ready
4. **Automatic cleanup** - Stops Envoy when dropped

Example usage:

```rust
use integration::EnvoyTestServer;

#[test]
fn my_test() {
    let server = EnvoyTestServer::start().expect("Failed to start Envoy");
    
    // Make requests to server.url("/path")
    // ...
    
    // Envoy automatically stopped when server goes out of scope
}
```

### OpenAPI Fuzzer Integration

The fuzzing test (`fuzzing.rs`) integrates `openapi-fuzzer` as follows:

1. **Start Envoy** with the OpenAPI filter loaded
2. **Run fuzzer** against the Envoy instance using `examples/sample-openapi.yaml`
3. **Collect results** in `target/fuzzer-results/`
4. **Report findings** - Currently logs findings (development mode)

The fuzzer tests various scenarios:
- Valid requests (should pass through)
- Invalid parameters (out of range, wrong types)
- Missing required fields
- Invalid formats (email, date-time, etc.)
- Malformed JSON/payloads

## Fuzzer Results

When the fuzzer finds issues, it creates JSON files in `target/fuzzer-results/`:

```
target/fuzzer-results/
├── api-users-GET-500.json
├── api-users-{id}-POST-400.json
└── ...
```

Each file contains:
- The request that triggered the issue
- HTTP method, path, headers
- Request body
- Received status code

### Replaying Findings

To replay a specific finding:

```bash
openapi-fuzzer resend \
  --url http://127.0.0.1:10000 \
  target/fuzzer-results/api-users-GET-500.json
```

## Development Workflow

1. **Implement filter logic** in `src/lib.rs`
2. **Run unit tests**: `cargo test`
3. **Run integration tests**: `cargo test --test integration -- --ignored`
4. **Run fuzzing tests**: `cargo test --test fuzzing -- --ignored --nocapture`
5. **Fix any findings** reported by the fuzzer
6. **Repeat** until fuzzer finds no issues

## Current Test Status

As of now:
- ✅ Filter builds successfully
- ✅ Envoy loads the filter
- ✅ Basic request/response flow works
- 🚧 OpenAPI validation logic (in progress)

The fuzzing test currently runs in "development mode" - it reports findings but doesn't fail the test. Once the filter implementation is complete, uncomment the assertion in `fuzzing.rs`:

```rust
// Change from:
if findings_count > 0 {
    println!("⚠️  Found {} issues - filter implementation in progress", findings_count);
}

// To:
assert_eq!(findings_count, 0, "Fuzzer found {} issues", findings_count);
```

## Troubleshooting

### "Failed to start Envoy"

- Ensure `envoy` is in PATH or available locally
- Check that port 10000 and 9901 are not in use
- Review Envoy logs in test output

### "openapi-fuzzer: command not found"

- Install: `cargo install openapi-fuzzer`

### "Filter not found"

- Build the filter first: `mise run build`
- Check that `target/release/libapi_fence.so` exists

### Tests hang

- Envoy might not be starting correctly
- Check logs with `--nocapture` flag
- Verify the filter builds without errors
- Kill any stuck processes: `pkill -9 envoy`

## Adding New Tests

To add a new integration test:

1. **Create test function** in `integration.rs` or a new test file
2. **Mark as ignored**: `#[test] #[ignore]`
3. **Start Envoy**: `let server = EnvoyTestServer::start()?;`
4. **Make requests**: Use `reqwest`, `curl`, or `openapi-fuzzer`
5. **Assert expectations**

Example:

```rust
#[test]
#[ignore]
fn test_my_feature() {
    let server = EnvoyTestServer::start().unwrap();
    
    let response = reqwest::blocking::get(server.url("/api/users"))
        .unwrap();
    
    assert_eq!(response.status(), 200);
}
```
