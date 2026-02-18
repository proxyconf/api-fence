# Security Policy

This document describes the security controls implemented in API Fence, including OpenAPI validation and ModSecurity WAF protection, the threat model it addresses, and how to configure security settings.

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
| External Attacker | Crafted HTTP requests | DoS, bypass validation, SQLi/XSS/RCE attacks, information disclosure |
| Malicious API Consumer | Valid credentials, crafted payloads | Exploit edge cases, inject malicious content, resource exhaustion |
| Malicious Spec Author | Control over OpenAPI spec | Backdoor validation, regex DoS, resource exhaustion |
| Bot/Scanner | Automated attack tools | Vulnerability scanning, exploit attempts, WAF bypass |

### Attack Surfaces

| Surface | Description | Risk | Mitigation |
|---------|-------------|------|------------|
| Request Path | URL path from client | Path traversal, regex DoS | Path length limits, input sanitization |
| Request Headers | HTTP headers from client | Header injection, overflow | Header value length limits |
| Request Body | JSON/form data from client | Schema bypass, SQLi, XSS, RCE, parsing DoS | Body size limits, JSON depth limits, WAF scanning |
| Query Parameters | URL query string | SQLi injection, XSS, overflow | Query string length limits, WAF scanning |
| Response Body | Data from backend | Information disclosure, XSS | Response validation, WAF scanning |
| OpenAPI Spec | Spec file content | Regex DoS, circular refs | Schema complexity limits, pattern length limits |
| WAF Rules | ModSecurity rule files | Rule bypass, performance issues | Bundled CRS validation, timeout limits |

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

### 7. ModSecurity WAF Protection

The filter integrates libmodsecurity3 for Web Application Firewall protection:

**Request/Response Body Scanning:**
- Scans request and response bodies for attack patterns
- Supports OWASP CoreRuleSet (CRS) v4.0.0 with bundled rules
- Detects SQLi, XSS, RCE, LFI/RFI, and protocol attacks

**Performance & Safety:**
- Async scanning via thread pool to prevent blocking
- Configurable scan timeouts (default: 100ms)
- Fail-open or fail-closed behavior on timeout
- JSON string extraction optimization to reduce false positives
- Base64 detection to skip encoded data and reduce noise

**Attack Detection:**
- SQL Injection (942xxx rules)
- Cross-Site Scripting (941xxx rules)
- Remote Code Execution (932xxx rules)
- Local/Remote File Inclusion (930xxx, 931xxx rules)
- Protocol violations (920xxx, 921xxx rules)

**Configuration Modes:**
- **Block mode**: Reject requests that match WAF rules
- **Alert mode**: Log matches but allow traffic through
- **Dual ruleset**: Run OLD and NEW rules simultaneously for safe migration

**Resource Limits:**
- Scan timeout prevents DoS via slow scanning
- Queue capacity limits prevent memory exhaustion
- String extraction limits prevent over-processing of large payloads

## Configuration

All security limits are configurable via the filter configuration JSON:

```json
{
  "api_name": "secure_api",
  "openapi_spec_path": "...",
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
  },
  "modsecurity": {
    "scan_request": true,
    "scan_response": false,
    "request_action": "block",
    "response_action": "alert",
    "pool": {
      "timeout_ms": 100,
      "timeout_action": "allow",
      "queue_capacity": 1000
    },
    "primary_ruleset": {
      "name": "crs_v4",
      "use_bundled_crs": true,
      "bundled_crs_profile": "request"
    }
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
  },
  "modsecurity": {
    "scan_request": true,
    "scan_response": true,
    "request_action": "block",
    "response_action": "block",
    "pool": {
      "timeout_ms": 200,
      "timeout_action": "block"
    },
    "primary_ruleset": {
      "name": "crs_strict",
      "use_bundled_crs": true,
      "bundled_crs_profile": "full"
    }
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
  },
  "modsecurity": {
    "scan_request": true,
    "request_action": "alert",
    "pool": {
      "timeout_ms": 500,
      "timeout_action": "allow"
    },
    "primary_ruleset": {
      "name": "crs_permissive",
      "use_bundled_crs": true,
      "bundled_crs_profile": "minimal"
    }
  }
}
```

**For High-Performance APIs (Low Latency Requirements):**
```json
{
  "modsecurity": {
    "scan_request": true,
    "request_action": "alert",
    "pool": {
      "timeout_ms": 50,
      "timeout_action": "allow"
    },
    "primary_ruleset": {
      "name": "crs_fast",
      "use_bundled_crs": true,
      "bundled_crs_profile": "minimal"
    },
    "string_extraction": {
      "max_unique_strings": 100,
      "skip_base64": true
    }
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
2. **Resource Limits**: Set container memory and CPU limits (especially for WAF scanning)
3. **Network Isolation**: Restrict network access to required endpoints only
4. **Logging**: Enable audit logging for security-relevant events
5. **Thread Pool Sizing**: Configure ModSecurity thread pool based on expected traffic

### OpenAPI Specification

1. **Validate Specs**: Review OpenAPI specifications before deployment
2. **Limit Regex Patterns**: Avoid complex regex patterns in schemas
3. **Use References**: Use `$ref` instead of inline schemas to reduce complexity
4. **Version Control**: Keep specs in version control with change review

### ModSecurity WAF Configuration

1. **Start with Alert Mode**: Test new rules in alert mode before blocking
2. **Use Bundled CRS**: The bundled CRS v4.0.0 is pre-validated and optimized
3. **Monitor False Positives**: Review alerts and tune rules for your application
4. **Dual Ruleset Testing**: Use dual ruleset mode when migrating CRS versions
5. **Timeout Configuration**: Set scan timeouts based on your latency SLA
6. **Fail-Open for Availability**: Use `timeout_action: allow` for high-availability APIs
7. **Fail-Closed for Security**: Use `timeout_action: block` for high-security environments
8. **Profile Selection**:
   - Use `minimal` profile for high-performance APIs (SQLi, XSS, RCE only)
   - Use `request` profile for typical APIs (no response scanning)
   - Use `full` profile for high-security APIs (request + response)

### Monitoring

1. **Monitor 4xx/5xx Rates**: Sudden increases may indicate attacks
2. **Track Latency**: Spikes may indicate DoS attempts or WAF performance issues
3. **Log Security Violations**: Log rejected requests for analysis
4. **Alert on Anomalies**: Set up alerts for unusual patterns
5. **WAF Metrics**: Monitor `modsec.request.blocked` and `modsec.request.timeouts`
6. **False Positive Rate**: Track `modsec.request.alerts` vs `modsec.request.blocked`
7. **Scan Performance**: Monitor `modsec.request.scan_time_ms` histogram

## Security Testing

The filter undergoes the following security testing:

1. **Unit Tests**: Each security control has dedicated tests
2. **Integration Tests**: OpenAPI validation and ModSecurity WAF integration tests
3. **CRS Rule Tests**: Bundled CRS rules are tested against known attack patterns
4. **Fuzzing**: Security-focused fuzzing with cargo-fuzz (planned)
5. **Static Analysis**: Rust's type system prevents many vulnerability classes
6. **Dependency Audit**: Regular `cargo audit` to check for vulnerable dependencies
7. **WAF Bypass Testing**: Test against common WAF bypass techniques

### Testing Attack Patterns

The ModSecurity integration is tested against:
- **SQLi**: `' OR '1'='1`, `UNION SELECT`, etc.
- **XSS**: `<script>alert(1)</script>`, event handlers, etc.
- **RCE**: Shell command patterns, PHP/Java code injection
- **Path Traversal**: `../../../etc/passwd`, URL encoding variants
- **Protocol Attacks**: Malformed headers, HTTP smuggling attempts

## OWASP API Security Top 10 Coverage

| OWASP Risk | OpenAPI Validation | ModSecurity WAF |
|------------|-------------------|-----------------|
| API1: Broken Object Level Authorization | N/A (format validation only) | N/A (authorization not in scope) |
| API2: Broken Authentication | N/A (format validation only) | N/A (authentication not in scope) |
| API3: Broken Object Property Level Authorization | Schema validation enforces allowed properties | Additional property inspection |
| API4: Unrestricted Resource Consumption | Input size limits, complexity limits | Scan timeout, queue limits |
| API5: Broken Function Level Authorization | N/A (format validation only) | N/A (authorization not in scope) |
| API6: Unrestricted Access to Sensitive Business Flows | N/A (business logic not in scope) | Rate limiting detection (CRS) |
| API7: Server Side Request Forgery | N/A (no outbound requests) | SSRF pattern detection (CRS) |
| API8: Security Misconfiguration | Secure defaults, config validation | Bundled CRS best practices |
| API9: Improper Inventory Management | Validates against provided spec | N/A (inventory not in scope) |
| API10: Unsafe Consumption of APIs | Input validation, sanitization | SQLi, XSS, RCE detection |

### Additional Security Coverage

**OWASP Top 10 Web Application Risks (via ModSecurity):**
- **A03:2021 - Injection**: SQLi (942), Command Injection (932), LDAP, XPath
- **A07:2021 - XSS**: Cross-Site Scripting (941)
- **A05:2021 - Security Misconfiguration**: Protocol enforcement (920, 921)
- **A06:2021 - Vulnerable Components**: Known attack pattern detection
- **A04:2021 - Insecure Design**: Request/response anomaly detection

## Changelog

### ModSecurity WAF Integration (2026-02-14)

- Integrated libmodsecurity3 for Web Application Firewall protection
- Added bundled OWASP CoreRuleSet (CRS) v4.0.0
- Implemented async scanning with thread pool for non-blocking operation
- Added configurable scan timeouts and fail-open/fail-closed modes
- JSON string extraction optimization to reduce false positives
- Base64 detection to skip encoded data scanning
- Dual ruleset support for safe CRS version migration
- Block and alert modes for flexible security policies

### Security Hardening (2026-02-11)

- Added configurable security limits for all input types
- Implemented JSON depth limiting to prevent stack overflow
- Added regex pattern and input length limits
- Implemented error message sanitization to prevent information disclosure
- Added schema complexity limits to prevent resource exhaustion
- All error responses now use sanitized messages
