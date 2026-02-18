# API Fence - Envoy Dynamic Module

## Project Overview

This project implements an HTTP filter for Envoy Proxy using Rust and the Envoy Dynamic Modules feature. The filter provides dual functionality:

1. **OpenAPI Validation**: Validates incoming HTTP requests and responses against OpenAPI 3.x specifications
2. **ModSecurity WAF**: Web Application Firewall protection with bundled OWASP CoreRuleSet v4.0.0 for defense against SQLi, XSS, RCE, and other attacks

### Technology Stack

- **Language**: Rust (stable)
- **Build System**: Cargo
- **Dev Environment**: Mise (https://mise.jdx.dev/)
- **Target**: Envoy Dynamic Module (shared library)
- **Envoy Version**: v1.37.0 (commit: 6d9bb7d9a85d616b220d1f8fe67b61f82bbdb8d3)
- **Testing Strategy**: Integration-test driven development with OpenAPI fuzzing

## Architecture

### Envoy Dynamic Modules

Dynamic modules are shared libraries (`.so` files on Linux) that extend Envoy's functionality at runtime without recompiling Envoy itself. This project uses the official Rust SDK from the Envoy repository.

**Key Characteristics:**
- Compiled as `cdylib` (C-compatible dynamic library)
- Loaded by Envoy at runtime via configuration
- Must match the exact Envoy version (strict ABI compatibility)
- Implements HTTP filter lifecycle callbacks

### Filter Lifecycle

The filter implements the following callback methods:
1. `on_request_headers` - Process request headers
2. `on_request_body` - Process request body chunks
3. `on_response_headers` - Process response headers
4. `on_response_body` - Process response body chunks

## Development Setup

### Prerequisites

- Mise (https://mise.jdx.dev/) for development environment
- Envoy binary with dynamic module support (v1.37.0+)
- System LLVM/Clang for bindgen

### Getting Started

```bash
# Clone the repository
git clone <repo-url>
cd api_fence

# Install mise tools
mise install
mise trust

# Build the project
mise run build

# Or using cargo directly
cargo build --release

# Run tests
mise run test

# Run linter
mise run clippy
```

### Project Structure

```
api_fence/
├── src/
│   ├── lib.rs              # Main filter and OpenAPI validation
│   └── modsec/             # ModSecurity WAF integration
│       ├── mod.rs          # Public API exports
│       ├── config.rs       # WAF configuration types
│       ├── engine.rs       # ModSecurity engine wrapper
│       ├── pool.rs         # Thread pool for async scanning
│       ├── scanner.rs      # Request/response scanning logic
│       ├── observability.rs # Metrics and metadata
│       ├── crs.rs          # Bundled OWASP CRS
│       └── util.rs         # Helper utilities
├── tests/                  # Integration and WAF tests
│   └── integration_tests/  # Test modules
├── build.rs                # Build script (downloads OWASP CRS v4.0.0)
├── Cargo.toml              # Rust dependencies and build config
├── mise.toml               # Mise development environment
├── bacon.toml              # Bacon watcher config
├── rustfmt.toml            # Rust formatting config
├── .clippy.toml            # Clippy linter config
└── .rust-analyzer.toml     # IDE configuration
```

## Testing Strategy

### Integration-Test Driven Development

This project follows an integration-test driven approach:

1. **Envoy Integration Tests**: Tests start a real Envoy instance with the compiled filter
2. **OpenAPI Fuzzing**: An OpenAPI fuzzer (Rust-based) sends various requests to test all edge cases
3. **Coverage Goal**: When the fuzzer finds no issues, we can be confident most cases are covered

### Running Integration Tests

```bash
# Build the filter
cargo build --release

# Run integration tests (starts Envoy + fuzzer)
cargo test --test integration

# Watch mode
cargo watch -x "test --test integration"
```

## Dependencies

### Main Dependencies

- `envoy-proxy-dynamic-modules-rust-sdk`: Official Envoy Rust SDK (git dependency, must match Envoy version)
- `serde`, `serde_json`: Configuration parsing and JSON handling
- `modsecurity-sys`: Rust bindings to libmodsecurity3 (WAF engine)
- `jsonschema`: JSON Schema validation for OpenAPI
- `matchit`: Fast path routing for API endpoints

### Development Dependencies

- `tempfile`: Temporary file management for tests
- `tokio`: Async runtime for integration tests
- `reqwest`: HTTP client for testing

## Building for Production

```bash
# Build optimized release binary
cargo build --release

# The shared library will be at:
# target/release/libapi_fence.so
```

### Build Configuration

The release profile is optimized for size and performance:
- LTO (Link-Time Optimization) enabled
- Single codegen unit for maximum optimization
- Symbols stripped

## Envoy Configuration

The filter is loaded into Envoy via configuration:

```yaml
http_filters:
  - name: envoy.filters.http.dynamic_module
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_module.v3.DynamicModuleFilter
      dynamic_module_config:
        name: api_fence
        do_not_close: true
      filter_name: api_fence
      filter_config:
        # Your filter-specific configuration here
```

## Code Guidelines

### License Headers

**CRITICAL**: Every Rust source file (`.rs`) MUST begin with:

```rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 ProxyConf Authors

```

- See `.opencode/rules/rust.md` for complete requirements
- Templates are available in `.opencode/templates/`
- This project is licensed under **Mozilla Public License 2.0 (MPL-2.0)**

### Rust Style

- Follow standard Rust conventions (enforced by rustfmt)
- Enable all Clippy lints (clippy::all, clippy::pedantic, clippy::cargo)
- Prefer explicit types over type inference in public APIs
- Document all public APIs with rustdoc comments

### Error Handling

- Use `Result<T, E>` for fallible operations
- Avoid panics in filter code (Envoy will crash)
- Log errors appropriately using Envoy's logging facilities

### Performance

- Minimize allocations in hot paths
- Use zero-copy operations when possible
- Profile with `perf` or similar tools for bottlenecks

## Common Tasks

### Add a New Dependency

```bash
# Using cargo-edit (included in dev shell)
cargo add <dependency>

# Or manually edit Cargo.toml
```

### Format Code

```bash
cargo fmt
```

### Run Linter

```bash
cargo clippy --all-targets
```

### Background Checking (Bacon)

```bash
# Start bacon for continuous checking
bacon

# Or for tests
bacon test
```

### Update Envoy SDK Version

1. Find the new Envoy commit hash
2. Update `rev` in Cargo.toml for `envoy-proxy-dynamic-modules-rust-sdk`
3. Update the Envoy version comment in this document
4. Run `cargo update` to fetch new dependencies

## Troubleshooting

### Build Errors

- **"cannot find crate"**: Ensure you have run `mise install` to set up the development environment
- **ABI mismatch**: Ensure Envoy SDK version exactly matches your Envoy binary version
- **Linking errors**: Check that LLVM/Clang is installed for bindgen (`apt install llvm-dev libclang-dev` or equivalent)
- **"libclang not found"**: Set `LIBCLANG_PATH` to your system's libclang location

### Runtime Errors

- **Filter not loading**: Check Envoy logs for detailed error messages
- **Segfaults**: Likely ABI mismatch or memory safety issue in filter code
- **Performance issues**: Profile with `perf` and check for excessive allocations

## References

- [Envoy Dynamic Modules Documentation](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules)
- [Dynamic Modules Examples](https://github.com/envoyproxy/dynamic-modules-examples)
- [Envoy Rust SDK Source](https://github.com/envoyproxy/envoy/tree/main/source/extensions/dynamic_modules/sdk/rust)

## Contributing

When working on this project:

1. Keep the Envoy SDK version in sync with your Envoy installation
2. Add tests for all new functionality
3. Run the full test suite before committing
4. Update this documentation as the project evolves

## OpenCode-Specific Notes

This project is optimized for development with OpenCode and similar LLM-assisted development tools:

- **Agent.md**: This file provides context about the project structure and conventions
- **Clear structure**: Code is organized to be easily navigable and understandable
- **Documentation**: Inline comments explain non-obvious decisions
- **Testing**: Comprehensive tests make it easy to verify changes

### Working with OpenCode

When asking OpenCode to make changes:

- Reference specific file paths and line numbers
- Mention if changes should update tests
- Specify if documentation should be updated
- Request integration test runs for verification
