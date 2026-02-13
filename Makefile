.PHONY: help build test clean check fmt clippy doc watch run-envoy integration-test

# Default target
help:
	@echo "OpenAPI Filter - Available targets:"
	@echo "  build            - Build the filter in release mode"
	@echo "  build-dev        - Build the filter in debug mode"
	@echo "  test             - Run all tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  check            - Check code without building"
	@echo "  fmt              - Format code"
	@echo "  fmt-check        - Check code formatting"
	@echo "  clippy           - Run clippy linter"
	@echo "  doc              - Generate and open documentation"
	@echo "  watch            - Watch for changes and run tests"
	@echo "  clean            - Clean build artifacts"
	@echo "  run-envoy        - Run Envoy with the filter (requires config)"
	@echo "  audit            - Audit dependencies for security issues"
	@echo ""
	@echo "All commands are executed via mise. Run 'mise tasks' for full list."

# Build targets
build:
	mise run build

build-dev:
	mise run build-dev

# Test targets
test:
	mise run test

test-unit:
	mise run test-unit

test-integration:
	mise run test-integration

# Code quality
check:
	mise run check

fmt:
	mise run fmt

fmt-check:
	mise run fmt-check

clippy:
	mise run clippy

# Documentation
doc:
	mise run doc

# Development
watch:
	mise run watch

watch-clippy:
	mise run watch-clippy

# Run Envoy (requires ENVOY_CONFIG environment variable)
run-envoy:
	mise run run-envoy

# Clean
clean:
	mise run clean

# Security audit
audit:
	mise run audit

# All quality checks
quality:
	mise run quality

# Pre-commit hook
pre-commit:
	mise run pre-commit

# Show environment info
info:
	mise run info
