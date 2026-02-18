# API Fence Architecture

## Overview

This document describes the modular architecture for the Envoy API Fence - a high-performance, Envoy-native API request and response validation and security system. 

**API Fence** provides dual protection layers:
1. **OpenAPI Validation**: Ensures API requests/responses conform to OpenAPI 3.x specifications
2. **ModSecurity WAF**: Protects against common web attacks (SQLi, XSS, RCE, etc.) using OWASP CoreRuleSet v4.0.0

The architecture is designed to support banking, insurance, and cloud environments where correctness, security, auditability, and throughput are non-negotiable.

---

## System Architecture Diagram

```
                                    CONTROL PLANE
    +------------------------------------------------------------------------+
    |                                                                        |
    |   +------------------+    +------------------+    +------------------+ |
    |   |  Config Manager  |    |   Spec Loader    |    |  Schema Registry | |
    |   |  (Envoy xDS or   |    |  (File/Remote)   |    |  (Compiled JSON  | |
    |   |   static YAML)   |    |                  |    |   Schema Cache)  | |
    |   +--------+---------+    +--------+---------+    +--------+---------+ |
    |            |                       |                       |           |
    +------------|-----------------------|-----------------------|-----------+
                 |                       |                       |
                 v                       v                       v
    +------------------------------------------------------------------------+
    |                         FILTER INITIALIZATION                          |
    |                                                                        |
    |   +------------------+    +------------------+    +------------------+ |
    |   |  FilterConfig    |--->|   Path Router    |--->|   Schema Cache   | |
    |   |  (per listener)  |    |   (matchit)      |    |   (moka TTL)     | |
    |   +------------------+    +------------------+    +------------------+ |
    |                                                                        |
    +------------------------------------------------------------------------+
                                        |
                                        | new_http_filter() per stream
                                        v
    +========================================================================+
    ||                        DATA PLANE (per request)                      ||
    ||                                                                      ||
    ||  +----------------+     +----------------+     +----------------+    ||
    ||  |  HTTP Request  |---->|  OpenApiFilter |---->|  Backend or    |    ||
    ||  |  (from client) |     |  (per stream)  |     |  Mock Response |    ||
    ||  +----------------+     +-------+--------+     +----------------+    ||
    ||                                 |                                    ||
    ||                                 v                                    ||
     ||  +--------------------------------------------------------------+   ||
     ||  |                    VALIDATION PIPELINE                        |   ||
     ||  |                                                               |   ||
     ||  |  on_request_headers()                                         |   ||
     ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
     ||  |  | Route    |->| Path     |->| Query    |->| Header   |       |   ||
     ||  |  | Match    |  | Params   |  | Params   |  | Validate |       |   ||
     ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
     ||  |                                                               |   ||
     ||  |  on_request_body()                                            |   ||
     ||  |  +----------+  +----------+  +----------+                     |   ||
     ||  |  | Buffer   |->| Parse    |->| Schema   |                     |   ||
     ||  |  | Body     |  | Content  |  | Validate |                     |   ||
     ||  |  +----------+  +----------+  +----------+                     |   ||
     ||  |       |                           |                           |   ||
     ||  |       v                           v                           |   ||
     ||  |  +----------+              +----------+                       |   ||
     ||  |  | Mock Gen |              | Forward  |                       |   ||
     ||  |  | (if on)  |              | Request  |                       |   ||
     ||  |  +----------+              +----------+                       |   ||
     ||  +--------------------------------------------------------------+   ||
     ||                                 |                                    ||
     ||                                 v                                    ||
     ||  +--------------------------------------------------------------+   ||
     ||  |                    MODSECURITY WAF SCAN                       |   ||
     ||  |                      (async thread pool)                      |   ||
     ||  |                                                               |   ||
     ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
     ||  |  | Extract  |->| Scan     |->| Verdict  |->| Block or |       |   ||
     ||  |  | Strings  |  | Rules    |  | (OWASP)  |  | Allow    |       |   ||
     ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
     ||  |                                                               |   ||
     ||  |  Scans: Headers, Query, Path, Body (JSON strings extracted)  |   ||
     ||  |  Rules: Bundled CRS v4.0.0 or custom (inline/file/URL)       |   ||
     ||  |  Action: Block (403) or Alert (log + continue)               |   ||
     ||  +--------------------------------------------------------------+   ||
     ||                                 |                                    ||
     ||                                 v                                    ||
     ||  +--------------------------------------------------------------+   ||
    ||  |                 RESPONSE VALIDATION (optional)                |   ||
    ||  |                                                               |   ||
    ||  |  on_response_headers()       on_response_body()               |   ||
    ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
    ||  |  | Status   |->| Header   |->| Buffer   |->| Schema   |       |   ||
    ||  |  | Match    |  | Validate |  | Body     |  | Validate |       |   ||
    ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
    ||  +--------------------------------------------------------------+   ||
    ||                                 |                                    ||
    ||                                 v                                    ||
    ||  +--------------------------------------------------------------+   ||
    ||  |                      OBSERVABILITY                            |   ||
    ||  |                                                               |   ||
    ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
    ||  |  | Metrics  |  | Dynamic  |  | Access   |  | Audit    |       |   ||
    ||  |  | (Envoy)  |  | Metadata |  | Logs     |  | Trail    |       |   ||
    ||  |  +----------+  +----------+  +----------+  +----------+       |   ||
    ||  +--------------------------------------------------------------+   ||
    ||                                                                      ||
    +========================================================================+
                                        |
                                        v
    +------------------------------------------------------------------------+
    |                          EXTERNAL SYSTEMS                              |
    |                                                                        |
    |   +------------------+    +------------------+    +------------------+ |
    |   |   Prometheus     |    |   Log Aggregator |    |   SIEM / Audit   | |
    |   |   (metrics)      |    |   (ELK, etc.)    |    |   (compliance)   | |
    |   +------------------+    +------------------+    +------------------+ |
    +------------------------------------------------------------------------+
```

---

## Modules and Components

### 1. Core Filter Module (`src/lib.rs`)

**Responsibility**: Main entry point and HTTP filter lifecycle management.

| Component | Description |
|-----------|-------------|
| `init()` | Module initialization, called once when loaded by Envoy |
| `new_http_filter_config_fn()` | Factory for creating filter configurations per listener |
| `FilterConfig` | Holds parsed OpenAPI spec, path router, schema cache, and metrics handles |
| `OpenApiFilter` | Per-stream filter instance handling request/response lifecycle |

**Key Data Structures**:
- `FilterConfig`: Shared across all streams, contains immutable spec and cache
- `OpenApiFilter`: Per-request state including current operation, path params, validation errors
- `RouteData`: Path template with associated operations and parameter schemas

### 2. Path Router Module (embedded in `lib.rs`)

**Responsibility**: Efficient O(1) path matching using radix tree.

| Component | Description |
|-----------|-------------|
| `matchit::Router<RouteData>` | Radix tree router for path matching |
| `build_path_router()` | Converts OpenAPI paths to matchit format |
| `find_operation()` | Matches request path/method to OpenAPI operation |

**Path Conversion**:
```
OpenAPI:  /users/{userId}/orders/{orderId}
matchit:  /users/:userId/orders/:orderId
```

### 3. Validation Module (embedded in `lib.rs`)

**Responsibility**: Request and response validation against OpenAPI schemas.

| Component | Description |
|-----------|-------------|
| `validate_path_param_types()` | Early type checking for path parameters |
| `validate_path_params()` | Full JSON Schema validation of path params |
| `validate_query_params()` | Query string parameter validation |
| `validate_request_headers()` | Request header validation (required, format, pattern) |
| `validate_body_with_schema()` | Request body validation with content-type handling |
| `validate_response_headers()` | Response header validation |
| `validate_response_body_with_schema()` | Response body validation |

**Content Type Support**:
- `application/json` and vendored JSON types (`+json` suffix)
- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `application/xml`, `text/xml`

### 4. Schema Cache Module (embedded in `lib.rs`)

**Responsibility**: Compiled JSON schema caching for performance.

| Component | Description |
|-----------|-------------|
| `moka::sync::Cache` | TTL-based cache with configurable capacity |
| `schema_cache_key()` | Deterministic hash of schema for cache lookup |
| `get_or_compile_schema()` | Cache-through schema compilation |

**Cache Metrics**:
- `cache.hits` - Schema found in cache
- `cache.misses` - Schema compiled and cached
- `schema.compile_time_ms` - Compilation latency histogram

### 5. Mock Generation Module (`src/mock.rs`)

**Responsibility**: Generate mock responses for API testing.

| Component | Description |
|-----------|-------------|
| `MockConfig` | Configuration for mocking behavior |
| `MockResponse` | Generated response (status, headers, body) |
| `generate_mock_response()` | Main entry point for mock generation |
| `generate_from_example()` | Use OpenAPI examples when available |
| `generate_from_schema()` | Schema-based fake data generation |

**Generation Strategies**:
1. **Examples first** (default): Use inline `example` or named `examples`
2. **Schema fallback**: Generate realistic data using `fake` crate
3. **Random selection**: Choose randomly from multiple 2xx responses

### 6. Observability Module (embedded in `lib.rs`)

**Responsibility**: Metrics, metadata, and audit trail.

| Component | Description |
|-----------|-------------|
| `EnvoyCounterId` / `EnvoyHistogramId` | Metric handles |
| `set_request_metadata()` | Write validation results to dynamic metadata |
| `set_response_metadata()` | Write response validation to metadata |

**Metrics Exposed**:
```
# OpenAPI Validation
api_fence.<api_name>.cache.hits
api_fence.<api_name>.cache.misses
api_fence.<api_name>.schema.compile_time_ms
api_fence.<api_name>.request.validation_errors
api_fence.<api_name>.response.validation_errors

# ModSecurity WAF
api_fence.<api_name>.modsec.request.scans
api_fence.<api_name>.modsec.request.blocked
api_fence.<api_name>.modsec.request.alerts
api_fence.<api_name>.modsec.request.timeouts
api_fence.<api_name>.modsec.request.scan_time_ms
api_fence.<api_name>.modsec.response.scans
api_fence.<api_name>.modsec.response.blocked
api_fence.<api_name>.modsec.response.alerts
api_fence.<api_name>.modsec.response.timeouts
api_fence.<api_name>.modsec.response.scan_time_ms
```

**Dynamic Metadata** (for access logs):
```
# OpenAPI Validation
api_fence:request.verdict   -> "valid" | "invalid"
api_fence:request.error_count
api_fence:request.errors    -> pipe-separated error list
api_fence:response.verdict
api_fence:response.error_count
api_fence:response.errors

# ModSecurity WAF
api_fence:modsec.request.verdict          -> "blocked" | "allowed" | "alert"
api_fence:modsec.request.ruleset          -> Name of ruleset used
api_fence:modsec.request.matched_rules    -> JSON array of rule IDs
api_fence:modsec.request.matched_messages -> Pipe-separated messages
api_fence:modsec.request.scan_time_ms     -> Scan duration
api_fence:modsec.request.timed_out        -> Boolean timeout indicator
api_fence:modsec.response.verdict
api_fence:modsec.response.ruleset
api_fence:modsec.response.matched_rules
api_fence:modsec.response.matched_messages
api_fence:modsec.response.scan_time_ms
api_fence:modsec.response.timed_out
```

### 7. ModSecurity WAF Module (`src/modsec/`)

**Responsibility**: Web Application Firewall protection against common attacks.

| Component | Description |
|-----------|-------------|
| `ModSecConfig` | WAF configuration (rulesets, action, pool size) |
| `ModSecEngine` | Thread-safe wrapper around libmodsecurity3 |
| `ModSecScanner` | Request/response scanning logic |
| `ModSecPool` | Thread pool for async scanning with timeout |
| `ModSecObservability` | Metrics and metadata emission |
| `bundled_crs` | Embedded OWASP CoreRuleSet v4.0.0 files |

**Attack Detection**:
- **SQL Injection (SQLi)**: Detect and block SQL injection attempts
- **Cross-Site Scripting (XSS)**: Prevent XSS attacks in requests/responses
- **Remote Code Execution (RCE)**: Block command injection and code execution
- **Local/Remote File Inclusion (LFI/RFI)**: Detect path traversal attacks
- **Protocol Attacks**: HTTP protocol violations and anomalies
- **Scanner/Bot Detection**: Identify and block automated scanners

**Ruleset Profiles** (OWASP CRS):
1. **Full**: Complete protection (all CRS rules)
2. **Request-only**: Only request scanning (no response rules)
3. **Minimal**: Essential protection only (critical severity)

**Configuration Options**:
- **Dual Ruleset Support**: Run two rulesets simultaneously for safe migration
- **Block vs Alert Mode**: Block malicious requests or log alerts only
- **Async Scanning**: Non-blocking scan with configurable timeout (default: 100ms)
- **Fail-Open/Fail-Closed**: Behavior on timeout or scan error
- **Custom Rules**: Inline rules, file paths, or remote URLs
- **JSON String Extraction**: Smart extraction of strings from JSON bodies
- **Base64 Detection**: Skip scanning base64-encoded data to reduce false positives

---

## Data Flow

### Request Path

```
1. Client Request
       |
2. Envoy receives request
       |
3. on_request_headers() called
       |
       +---> Extract :method, :path
       |
       +---> Path Router lookup (matchit)
       |          |
       |          +---> 404 if no path match
       |          +---> 405 if method not allowed
       |
       +---> Validate path parameter types (early fail)
       |
       +---> Validate path parameters (JSON Schema)
       |
       +---> Validate query parameters
       |
       +---> Validate request headers
       |
       +---> If validation errors AND fail_on_request_error:
       |          Send 400 with error JSON
       |
       +---> If body expected: StopAllIterationAndBuffer
       |          else: Continue
       |
4. on_request_body() called (if buffered)
       |
       +---> Parse body based on Content-Type
       |
       +---> Validate against request body schema
       |
       +---> If ModSecurity WAF enabled:
       |          Async scan request (headers + body)
       |          If blocked: Return 403 Forbidden
       |
       +---> If mocking enabled:
       |          Generate and return mock response
       |
       +---> Continue to backend
       |
5. Backend processes request
       |
6. on_response_headers() / on_response_body() (if enabled)
       |
       +---> Validate response headers
       +---> Validate response body
       +---> If ModSecurity WAF response scan enabled:
       |          Async scan response
       |          Log violations (no blocking)
       +---> Set metadata
       |
7. Response to client
```

### Mock Response Path

```
Request validated successfully
       |
       +---> Mock enabled?
                |
                +---> No: Forward to backend
                |
                +---> Yes: generate_mock_response()
                            |
                            +---> determine_status_code()
                            |        (random from 2xx options)
                            |
                            +---> get_response_for_status()
                            |
                            +---> Try examples first (if prefer_examples)
                            |
                            +---> Fall back to schema generation
                            |
                            +---> Serialize (JSON/XML)
                            |
                            +---> Send mock response headers
                            +---> Send mock response body
                            +---> StopIteration (don't forward)
```

---

## Failure Modes and Handling

### 1. Configuration Failures (Startup)

| Failure | Cause | Handling |
|---------|-------|----------|
| Config parse error | Invalid JSON in filter_config | `panic!` - Envoy won't start with bad config |
| Spec file not found | Bad `openapi_spec_path` | `panic!` - Envoy won't start |
| Spec parse error | Invalid OpenAPI YAML/JSON | `panic!` - Envoy won't start |
| Route conflict | Duplicate paths in matchit | `panic!` - Envoy won't start |

**Rationale**: Fail-fast at startup ensures misconfigurations are caught immediately, not at runtime.

### 2. Request Validation Failures (Runtime)

| Failure | HTTP Code | Behavior |
|---------|-----------|----------|
| Path not found in spec | 404 | Local reply, request blocked |
| Method not allowed | 405 | Local reply, request blocked |
| Path param type error | 400 | Local reply (if `fail_on_request_error`) |
| Required param missing | 400 | Local reply (if `fail_on_request_error`) |
| Schema validation error | 400 | Local reply (if `fail_on_request_error`) |
| Body parse error | 400 | Local reply (if `fail_on_request_error`) |

**Pass-through Mode** (`fail_on_request_error: false`):
- Validation errors recorded in metrics and metadata
- Request continues to backend
- Access logs can capture validation failures

### 3. Response Validation Failures (Runtime)

| Failure | Behavior |
|---------|----------|
| Response body invalid | Error in metadata, metrics incremented |
| Missing required header | Error in metadata, metrics incremented |

**Note**: Response validation failures currently don't block responses (would require response rewriting).

### 4. Schema Compilation Failures

| Failure | Cause | Handling |
|---------|-------|----------|
| Invalid schema | Malformed JSON Schema in spec | Error returned, validation skipped for this field |

### 5. Mock Generation Failures

| Failure | Cause | Handling |
|---------|-------|----------|
| No suitable response | No 2xx response defined | Log error, forward to backend |
| Schema generation failed | Unsupported schema (OneOf/AllOf) | Log error, forward to backend |

**Mocking is best-effort**: If mock generation fails, request continues to backend.

### 6. Resource Exhaustion

| Resource | Protection |
|----------|------------|
| Schema cache | LRU eviction with `max_capacity` |
| Body buffering | Envoy's buffer limits apply |
| Request memory | Per-stream filter is short-lived |

---

## Security Model

### 1. Trust Boundaries

```
+------------------+     +------------------+     +------------------+
|     Client       |     |  Envoy + Filter  |     |     Backend      |
|   (untrusted)    |---->|   (trust zone)   |---->|    (trusted)     |
+------------------+     +------------------+     +------------------+
         |                       |                        |
         |  Untrusted input      |  Validated input       |
         |  - Headers            |  - Conforms to spec    |
         |  - Path               |  - Type-safe           |
         |  - Query              |  - Sanitized           |
         |  - Body               |                        |
```

### 2. Input Validation

| Input | Validation |
|-------|------------|
| Path | Matched against spec, parameters type-checked |
| Query params | Type validation, required checks, pattern matching |
| Headers | Required checks, format validation, enum validation |
| Body | JSON Schema validation (properties, types, formats) |
| **All Inputs** | **ModSecurity WAF scans for SQLi, XSS, RCE, protocol attacks** |

### 3. Denial of Service Protection

| Attack Vector | Mitigation |
|---------------|------------|
| Large request body | Envoy buffer limits (configurable) |
| Complex regex in spec | Regex compilation at startup, not per-request |
| Schema cache flooding | LRU eviction with max capacity |
| Slow schema compilation | One-time compilation, cached thereafter |
| **WAF scan timeout** | **Configurable timeout (default: 100ms), fail-open option** |
| **WAF rule complexity** | **OWASP CRS optimized for performance, profile options** |

### 4. Information Disclosure

| Concern | Mitigation |
|---------|------------|
| Error messages | Validation errors are informative but don't leak internal state |
| Stack traces | Not exposed (Rust panics are caught by Envoy) |
| Spec contents | Not echoed back in responses |

### 5. Filter Isolation

- Filter runs in Envoy's process space
- No network calls from filter (spec loaded at startup)
- No file writes (read-only after init)
- No external dependencies at runtime

### 6. Secrets

- Filter does not handle authentication/authorization
- No secrets stored in filter configuration
- OpenAPI spec should not contain secrets

---

## Operational Model

### Deployment Strategy

#### 1. Build Artifact

```bash
# Build release binary with optimizations
cargo build --release

# Output: target/release/libapi_fence.so
# - LTO enabled for size/performance
# - Strip symbols for smaller binary
# - Single codegen unit for optimization
```

#### 2. Deployment Methods

**A. Sidecar Pattern** (Kubernetes)
```yaml
containers:
  - name: envoy
    image: envoyproxy/envoy:v1.28-latest
    volumeMounts:
      - name: filter
        mountPath: /etc/envoy/filters
      - name: config
        mountPath: /etc/envoy
      - name: specs
        mountPath: /etc/openapi

volumes:
  - name: filter
    configMap:
      name: api-fence-so  # or use initContainer to fetch
  - name: specs
    configMap:
      name: openapi-specs
```

**B. Edge Gateway Pattern**
- Single Envoy deployment at ingress
- Multiple filter instances (per-route or per-listener)
- Centralized spec management

**C. Service Mesh Pattern**
- Filter deployed to all sidecar proxies
- Specs distributed via xDS or ConfigMaps
- Consistent validation across mesh

#### 3. Rolling Updates

1. Build new filter version
2. Update ConfigMap/volume with new `.so`
3. Rolling restart of Envoy pods
4. Envoy reloads filter on startup

**Zero-downtime**: Kubernetes rolling update ensures no service interruption.

### Configuration Management

#### 1. Static Configuration
```yaml
# envoy.yaml
http_filters:
  - name: envoy.filters.http.dynamic_module
    typed_config:
      filter_config:
        value: |
          {
            "api_name": "my_api",
            "openapi_spec_path": "/etc/openapi/spec.yaml"
          }
```

#### 2. Dynamic Configuration (xDS)
- Filter config can be updated via ECDS (Extension Config Discovery Service)
- Spec can be reloaded by pointing to new file

### Monitoring

#### 1. Metrics (Prometheus)

**Collection**:
```
http://envoy:9901/stats/prometheus
```

**Key Metrics**:
```promql
# Cache efficiency
rate(api_fence_my_api_cache_hits[5m]) /
  (rate(api_fence_my_api_cache_hits[5m]) +
   rate(api_fence_my_api_cache_misses[5m]))

# Validation error rate
rate(api_fence_my_api_request_validation_errors[5m])

# Schema compilation latency (p99)
histogram_quantile(0.99,
  rate(api_fence_my_api_schema_compile_time_ms_bucket[5m]))
```

**Dashboards**:
- Cache hit rate over time
- Validation errors by API
- Schema compilation latency distribution

#### 2. Logging

**Access Log Format** (include validation metadata):
```yaml
access_log:
  - name: envoy.access_loggers.file
    typed_config:
      log_format:
        json_format:
          request_id: "%REQ(X-REQUEST-ID)%"
          method: "%REQ(:METHOD)%"
          path: "%REQ(:PATH)%"
          response_code: "%RESPONSE_CODE%"
          validation_verdict: "%DYNAMIC_METADATA(api_fence:request.verdict)%"
          validation_errors: "%DYNAMIC_METADATA(api_fence:request.errors)%"
```

#### 3. Tracing

- Standard Envoy tracing headers preserved
- Validation latency visible in spans (filter processing time)

### Alerting

| Alert | Condition | Severity |
|-------|-----------|----------|
| High validation error rate | `rate(validation_errors[5m]) > threshold` | Warning |
| Cache hit rate degraded | `cache_hits / (hits + misses) < 0.8` | Warning |
| Schema compilation spike | `p99(compile_time_ms) > 100ms` | Warning |
| Filter crash | Envoy logs show dynamic module errors | Critical |

### Health Checks

```bash
# Envoy readiness (includes filter health)
curl http://envoy:9901/ready

# Metrics endpoint
curl http://envoy:9901/stats?filter=api_fence
```

---

## CI/Testing Strategy

### Test Pyramid

```
                    /\
                   /  \
                  / E2E \          ~10% of tests
                 /  Tests \        Real Envoy + real traffic
                /----------\
               /            \
              / Integration  \     ~20% of tests
             /    Tests       \    Envoy with filter loaded
            /------------------\
           /                    \
          /     Unit Tests       \  ~70% of tests
         /    (Rust + Mocks)      \ Pure Rust, no Envoy
        /--------------------------\
```

### Unit Tests

**Location**: `src/lib.rs` (inline), future `src/` submodules

**Coverage**:
- Path template conversion (OpenAPI -> matchit)
- Query string parsing
- Content-type detection
- JSON/form/multipart parsing
- Schema cache key generation
- Mock data generation

**Tooling**:
```bash
# Run unit tests
cargo test

# With coverage
cargo tarpaulin --out Html
```

**Mocking Strategy**:
- Envoy SDK traits require mock implementations
- Current tests are mostly integration-focused
- Plan: Extract pure logic into testable functions

### Integration Tests

**Location**: `tests/integration.rs`

**What They Test**:
- Filter loads into Envoy successfully
- Basic request/response flow
- Validation rejects invalid requests
- Valid requests pass through

**How They Work**:
1. Build filter (`cargo build --release`)
2. Generate Envoy config with filter
3. Start Envoy in subprocess
4. Wait for readiness (poll admin endpoint)
5. Send HTTP requests via curl/reqwest
6. Assert response codes and bodies
7. Teardown Envoy

**Running**:
```bash
# Integration tests (require Envoy binary)
cargo test --test integration -- --ignored --nocapture
```

### Fuzzing Tests

**Location**: `tests/fuzzing.rs`

**Purpose**:
- Generate random valid/invalid requests from OpenAPI spec
- Verify filter handles edge cases gracefully
- Find crash bugs and panics

**Tooling**: `openapi-fuzzer` crate

**Running**:
```bash
cargo test --test fuzzing -- --ignored --nocapture
```

### End-to-End Tests

**Environment**: Kubernetes cluster or docker-compose

**What They Test**:
- Full deployment flow
- Config reload behavior
- Multi-instance consistency
- Performance under load

**Example Test Scenarios**:
1. Deploy filter to Kubernetes
2. Apply OpenAPI spec ConfigMap
3. Send traffic from external client
4. Verify validation, metrics, logs
5. Update spec, verify behavior changes

### CI Pipeline

```yaml
# .github/workflows/ci.yml (conceptual)
name: CI

on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings

  test-unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test

  test-integration:
    runs-on: ubuntu-latest
    needs: test-unit
    steps:
      - uses: actions/checkout@v4
      - name: Install Envoy
        run: |
          # Install Envoy with dynamic module support
      - run: cargo build --release
      - run: cargo test --test integration -- --ignored

  build-release:
    runs-on: ubuntu-latest
    needs: [test-unit, test-integration]
    steps:
      - uses: actions/checkout@v4
      - run: cargo build --release
      - uses: actions/upload-artifact@v4
        with:
          name: libapi_fence.so
          path: target/release/libapi_fence.so
```

### Test Coverage Goals

| Test Type | Current | Target |
|-----------|---------|--------|
| Unit | ~20% | 70% |
| Integration | ~10% | 20% |
| E2E | 0% | 10% |

### Development Workflow

```bash
# 1. Set up development environment
mise install && mise trust

# 2. Watch mode for development
bacon

# 3. Run tests continuously
cargo watch -x test

# 4. Full integration test before PR
mise run quality
```

---

## Future Considerations

### Planned Enhancements

1. **~~libmodsecurity Integration~~** ✅ **COMPLETED**
   - ~~WAF rules evaluation~~
   - ~~Request body scanning~~
   - ~~Separate module to avoid fast-path pollution~~
   - **Status**: Fully implemented in `src/modsec/` with OWASP CRS v4.0.0

2. **XML Schema / WSDL Support** (from vision)
   - SOAP API validation
   - XSD schema compilation and caching

3. **Schema Reference Resolution**
   - Support `$ref` in OpenAPI specs
   - Remote schema fetching (with caching)

4. **Rate Limiting Integration**
   - Per-operation rate limits from OpenAPI `x-rate-limit`
   - Integration with Envoy rate limit service

5. **Advanced WAF Features**
   - Custom rule development and testing tools
   - Rule performance profiling
   - False positive tuning assistance
   - Integration with threat intelligence feeds

### Architectural Decisions Record (ADR)

| Decision | Rationale |
|----------|-----------|
| Rust for filter | Safety, performance, Envoy SDK support |
| matchit for routing | O(1) routing, radix tree efficiency |
| moka for caching | TTL support, thread-safe, configurable |
| jsonschema crate | Full JSON Schema draft support |
| No external runtime deps | Latency, reliability, security |
| Fail-fast on bad config | Prevent silent failures in production |
| **libmodsecurity3 for WAF** | **Industry-standard WAF engine, proven OWASP CRS** |
| **Async WAF scanning** | **Non-blocking with timeout, maintains throughput** |
| **Bundled OWASP CRS v4.0.0** | **Zero-config security, downloaded at build time** |

---

## References

- [Envoy Dynamic Modules](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules)
- [OpenAPI 3.0 Specification](https://spec.openapis.org/oas/v3.0.3)
- [JSON Schema Draft-07](https://json-schema.org/draft-07/json-schema-release-notes.html)
- [Project Vision](../vision.md)
