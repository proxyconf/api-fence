# Quick Start Guide

Get up and running with API Fence in minutes.

## Prerequisites

1. **Mise** (https://mise.jdx.dev/)
   ```bash
   # Install mise (if not already installed)
   curl https://mise.run | sh
   
   # Or via package manager
   # macOS: brew install mise
   # Arch: pacman -S mise
   ```

2. **System Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt install build-essential llvm-dev libclang-dev pkg-config libssl-dev
   
   # macOS (via Homebrew)
   brew install llvm pkg-config openssl
   ```

3. **Envoy Binary** (for integration tests)
   ```bash
   # Download from Envoy releases or build from source
   # Ensure it supports dynamic modules (v1.37.0+)
   ```

## Setup

### Quick Setup

```bash
# Clone the repository
git clone <repo-url>
cd api_fence

# Install mise tools and trust the config
mise install
mise trust

# Build the project
mise run build
```

## First Steps

### 1. Verify Setup

```bash
# Show environment info
mise run info

# Check Rust version
rustc --version

# Check Cargo version
cargo --version
```

### 2. Build the Filter

```bash
# Development build
mise run build-dev

# Or release build (optimized)
mise run build
```

The compiled filter will be at:
- Debug: `target/debug/libapi_fence.so`
- Release: `target/release/libapi_fence.so`

### 3. Run Tests

```bash
# Run all tests
mise run test

# Run with verbose output
cargo test -- --nocapture

# Run integration tests
mise run test-integration

# Run ModSecurity WAF tests
mise run test-modsec-verbose
```

### 4. Run Code Checks

```bash
# Format code
mise run fmt

# Run linter
mise run clippy

# Run all quality checks
mise run quality
```

## Development Workflow

### Using Bacon (Background Checker)

```bash
# Start bacon for continuous checking
bacon

# Or for continuous testing
bacon test
```

### Using Cargo Watch

```bash
# Watch for changes and run tests
mise run watch

# Or watch clippy
mise run watch-clippy
```

### Using Mise Tasks

```bash
# See all available tasks
mise tasks

# Common commands
mise run build          # Build release
mise run test           # Run tests
mise run clippy         # Run linter
mise run quality        # Run all checks
```

## Next Steps

1. **Read the documentation**
   - [Agent.md](./Agent.md) - Project overview and architecture
   - [DEVELOPMENT.md](./DEVELOPMENT.md) - Detailed development guide
   - [TESTING.md](./TESTING.md) - Testing strategy

2. **Explore the code**
   - `src/lib.rs` - Main filter implementation
   - `src/modsec/` - ModSecurity WAF integration
   - `examples/` - Example configurations

3. **Start developing**
   - Implement new validation logic
   - Write tests
   - Run integration tests with Envoy

## Common Commands

```bash
# Build
mise run build              # Release build
mise run build-dev          # Debug build

# Test
mise run test               # All tests
mise run test-unit          # Unit tests only
mise run test-integration   # Integration tests
mise run test-modsec        # ModSecurity tests

# Quality
mise run fmt                # Format code
mise run clippy             # Run linter
mise run quality            # All checks

# Documentation
mise run doc                # Generate and open docs

# Clean
mise run clean              # Remove build artifacts
```

## Troubleshooting

### "Command not found"

Make sure mise tools are installed:
```bash
mise install
```

### "libclang not found"

Set the LIBCLANG_PATH environment variable:
```bash
# Find libclang location
find /usr -name "libclang*.so*" 2>/dev/null

# Set in your shell config
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
```

### Build errors

Try cleaning and rebuilding:
```bash
mise run clean
mise run build-dev
```

### "Cannot find crate"

Update dependencies:
```bash
cargo update
```

## IDE Setup

### VSCode

1. Open the project folder
2. Install recommended extensions (prompt will appear)
3. rust-analyzer will start automatically

### Other IDEs

The project includes configurations for:
- Neovim (via rust-analyzer LSP)
- Emacs (via rust-analyzer)
- IntelliJ IDEA (via Rust plugin)

## Getting Help

- Check [Agent.md](./Agent.md) for project documentation
- Check [DEVELOPMENT.md](./DEVELOPMENT.md) for development details
- Check [TESTING.md](./TESTING.md) for testing information
- Review [examples/](./examples/) for configuration examples

## What's Next?

Now that you have the environment set up, you can:

1. **Implement new filter features** in `src/lib.rs`
2. **Add WAF rules** via ModSecurity configuration
3. **Write unit tests** for validation logic
4. **Create integration tests** with Envoy
5. **Profile performance** for optimization

Happy coding!
