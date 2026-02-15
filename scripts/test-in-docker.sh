#!/usr/bin/env bash
# Run cargo test inside the Docker builder container.
#
# Uses the same builder image as build-in-docker.sh to ensure libmodsecurity
# is available for linking. Uses host networking so tests can reach Envoy
# running on localhost.
#
# Usage:
#   ./scripts/test-in-docker.sh [cargo test arguments...]
#
# Examples:
#   ./scripts/test-in-docker.sh --test integration -- --ignored
#   ./scripts/test-in-docker.sh --test integration test_modsecurity -- --ignored
#
# Environment variables:
#   BUILDER_IMAGE   - override the builder image name (default: api_fence-builder)
#   CARGO_CACHE_ID  - suffix for cache volume names (default: empty)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDER_IMAGE="${BUILDER_IMAGE:-api_fence-builder}"
CARGO_CACHE_ID="${CARGO_CACHE_ID:-}"

# Volume names for cargo caching (use debug target for tests)
VOL_REGISTRY="api_fence_cargo_registry${CARGO_CACHE_ID:+_${CARGO_CACHE_ID}}"
VOL_GIT="api_fence_cargo_git${CARGO_CACHE_ID:+_${CARGO_CACHE_ID}}"
VOL_TARGET="api_fence_cargo_target_debug${CARGO_CACHE_ID:+_${CARGO_CACHE_ID}}"

# Ensure the builder image exists
if ! docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
    echo "==> Building builder image ($BUILDER_IMAGE)..."
    docker build -f "$PROJECT_ROOT/docker/Dockerfile.builder" -t "$BUILDER_IMAGE" "$PROJECT_ROOT"
fi

echo "==> Running tests in Docker..."
echo "    Builder image : $BUILDER_IMAGE"
echo "    Arguments     : $*"

# Run cargo test inside the builder container
# --network=host allows the container to reach Envoy on localhost:18080/18090
docker run --rm \
    --network=host \
    -v "${VOL_REGISTRY}:/usr/local/cargo/registry" \
    -v "${VOL_GIT}:/usr/local/cargo/git" \
    -v "${VOL_TARGET}:/cargo-target" \
    -v "${PROJECT_ROOT}:/src" \
    -w /src \
    -e CARGO_TARGET_DIR=/cargo-target \
    "$BUILDER_IMAGE" \
    cargo test "$@"
