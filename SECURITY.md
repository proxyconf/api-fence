# Security Policy

This document describes the security controls implemented in the OpenAPI Filter, the threat model it addresses, and how to configure security settings.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email security concerns to the maintainers directly
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will work with you to understand and address the issue.

## Threat Model

### Threat Actors

| Actor | Capability | Goal |
|-------|------------|------|
| External Attacker | Crafted HTTP requests | DoS, bypass validation, information disclosure |
| Malicious API Consumer | Valid credentials, crafted payloads | Exploit edge cases, resource exhaustion |
| Malicious Spec Author | Control over OpenAPI spec | Backdoor validation, regex DoS, resource exhaustion |

### Attack Surfaces

| Surface | Description | Risk | Mitigation |
|---------|-------------|------|------------|
| Request Path | URL path from client | Path traversal, regex DoS | Path length limits, input sanitization |
| Request Headers | HTTP headers from client | Header injection, overflow | Header value length limits |
| Request Body | JSON/form data from client | Schema bypass, parsing DoS | Body size limits, JSON depth limits |
| Query Parameters | URL query string | Injection, overflow | Query string length limits |
| OpenAPI Spec | Spec file content | Regex DoS, circular refs | Schema complexity limits, pattern length limits |

## Security Controls

### 1. Input Length Limits

All inputs are bounded to prevent resource exhaustion:

| Input Type | Default Limit | Config Key | HTTP Status on Violation |
|------------|---------------|------------|-------------------------|
| URL Path | 2,048 bytes | `max_path_length` | 414 URI Too Long |
| Header Value | 8,192 bytes | `max_header_value_length` | 400 Bad Request |
| Query String | 8,192 bytes | `max_query_string_length` | 400 Bad Request |
| Request Body | 10 MB | `max_body_size` | 413 Payload Too Large |
| Regex Input | 64 KB | (hardcoded) | 400 Bad Request |

### 2. JSON Parsing Safety

- **Depth Limiting**: JSON documents with nesting deeper than `max_json_depth` (default: 32) are rejected
- **Fast Detection**: Uses a byte-scanning heuristic to detect deep nesting before full parsing
- **Stack Overflow Protection**: Prevents stack overflow from deeply nested structures

### 3. Regex Safety

The Rust `regex` crate provides inherent protection against ReDoS (Regular Expression Denial of Service):

- **Linear Time Guarantee**: The regex engine runs in O(n) time relative to input size
- **No Backtracking**: Uses Thompson NFA-based matching, immune to catastrophic backtracking
- **Pattern Length Limits**: Regex patterns from OpenAPI schemas are limited to `max_regex_pattern_length` (default: 1024 bytes)
- **Input Length Limits**: Inputs to regex matching are limited to 64KB

### 4. Schema Complexity Protection

- **Complexity Estimation**: Schemas are analyzed before compilation
- **Node Count Limit**: Schemas with more than 1,000 nodes are rejected
- **Depth Limit**: Schema nesting is limited to `max_schema_depth` (default: 32)

### 5. Error Message Sanitization

All error messages returned to clients are sanitized to prevent information disclosure:

- **Path Removal**: Internal file paths (Unix and Windows) are replaced with `[path]`
- **Stack Trace Removal**: Stack trace patterns are stripped
- **Line Number Removal**: Line:column patterns are removed
- **Length Truncation**: Messages are truncated to 1,024 characters maximum

### 6. Response Validation

Response bodies are validated against OpenAPI schemas with the same security controls:

- Body size limits apply
- JSON depth limits apply
- Error messages are sanitized before being sent to clients

## Configuration

All security limits are configurable via the filter configuration JSON:

```json
{
  "openapi_spec": "...",
  "security": {
    "max_path_length": 2048,
    "max_header_value_length": 8192,
    "max_query_string_length": 8192,
    "max_body_size": 10485760,
    "max_json_depth": 32,
    "max_array_items": 1000,
    "max_object_properties": 100,
    "max_schema_depth": 32,
    "max_regex_pattern_length": 1024
  }
}
```

### Tuning Guidelines

**For High-Security Environments (Banking, Healthcare):**
```json
{
  "security": {
    "max_path_length": 1024,
    "max_header_value_length": 4096,
    "max_body_size": 1048576,
    "max_json_depth": 16,
    "max_array_items": 100,
    "max_object_properties": 50
  }
}
```

**For Large Payload APIs (File Upload, Batch Processing):**
```json
{
  "security": {
    "max_body_size": 104857600,
    "max_array_items": 10000,
    "max_object_properties": 500
  }
}
```

### Minimum Values

Some limits have minimum values to prevent misconfiguration:

| Config Key | Minimum Value |
|------------|---------------|
| `max_path_length` | 64 |
| `max_json_depth` | 2 |
| `max_schema_depth` | 2 |

## Security Best Practices

### Deployment

1. **Run as Non-Root**: Deploy the filter with minimal privileges
2. **Resource Limits**: Set container memory and CPU limits
3. **Network Isolation**: Restrict network access to required endpoints only
4. **Logging**: Enable audit logging for security-relevant events

### OpenAPI Specification

1. **Validate Specs**: Review OpenAPI specifications before deployment
2. **Limit Regex Patterns**: Avoid complex regex patterns in schemas
3. **Use References**: Use `$ref` instead of inline schemas to reduce complexity
4. **Version Control**: Keep specs in version control with change review

### Monitoring

1. **Monitor 4xx/5xx Rates**: Sudden increases may indicate attacks
2. **Track Latency**: Spikes may indicate DoS attempts
3. **Log Security Violations**: Log rejected requests for analysis
4. **Alert on Anomalies**: Set up alerts for unusual patterns

## Security Testing

The filter undergoes the following security testing:

1. **Unit Tests**: Each security control has dedicated tests
2. **Fuzzing**: Security-focused fuzzing with cargo-fuzz (planned)
3. **Static Analysis**: Rust's type system prevents many vulnerability classes
4. **Dependency Audit**: Regular `cargo audit` to check for vulnerable dependencies

## OWASP API Security Top 10 Coverage

| OWASP Risk | Mitigation |
|------------|------------|
| API1: Broken Object Level Authorization | N/A (filter validates format, not authorization) |
| API2: Broken Authentication | N/A (filter validates format, not authentication) |
| API3: Broken Object Property Level Authorization | Schema validation enforces allowed properties |
| API4: Unrestricted Resource Consumption | Input size limits, complexity limits |
| API5: Broken Function Level Authorization | N/A (filter validates format, not authorization) |
| API6: Unrestricted Access to Sensitive Business Flows | N/A (business logic not in scope) |
| API7: Server Side Request Forgery | N/A (filter doesn't make outbound requests) |
| API8: Security Misconfiguration | Secure defaults, configuration validation |
| API9: Improper Inventory Management | N/A (filter validates against provided spec) |
| API10: Unsafe Consumption of APIs | Input validation, sanitization |

## Changelog

### Security Hardening (2026-02-11)

- Added configurable security limits for all input types
- Implemented JSON depth limiting to prevent stack overflow
- Added regex pattern and input length limits
- Implemented error message sanitization to prevent information disclosure
- Added schema complexity limits to prevent resource exhaustion
- All error responses now use sanitized messages
