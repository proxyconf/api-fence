#!/usr/bin/env bash
# Build the api_fence shared library inside Docker.
#
# Produces a .so that is binary-compatible with the Envoy container (Ubuntu 22.04).
# Uses named Docker volumes for cargo registry/git caches so incremental builds
# are fast both locally and in CI.
#
# Usage:
#   ./scripts/build-in-docker.sh [--release] [--rebuild-image]
#
# Output:
#   target/docker-{debug,release}/libapi_fence.so   - the built filter
#   target/docker-{debug,release}/lib/              - runtime shared libraries
#
# Environment variables:
#   BUILDER_IMAGE   - override the builder image name (default: api_fence-builder)
#   CARGO_CACHE_ID  - suffix for cache volume names (default: empty)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILDER_IMAGE="${BUILDER_IMAGE:-api_fence-builder}"
CARGO_CACHE_ID="${CARGO_CACHE_ID:-}"

# Parse arguments
BUILD_MODE="debug"
CARGO_FLAGS=""
REBUILD_IMAGE=false
for arg in "$@"; do
    case "$arg" in
        --release)
            BUILD_MODE="release"
            CARGO_FLAGS="--release"
            ;;
        --rebuild-image)
            REBUILD_IMAGE=true
            ;;
    esac
done

HOST_OUTPUT_DIR="${PROJECT_ROOT}/target/docker-${BUILD_MODE}"

# Volume names for cargo caching
VOL_REGISTRY="api_fence_cargo_registry${CARGO_CACHE_ID:+_${CARGO_CACHE_ID}}"
VOL_GIT="api_fence_cargo_git${CARGO_CACHE_ID:+_${CARGO_CACHE_ID}}"
VOL_TARGET="api_fence_cargo_target_${BUILD_MODE}${CARGO_CACHE_ID:+_${CARGO_CACHE_ID}}"

# Ensure the builder image exists (or rebuild if requested)
if [ "$REBUILD_IMAGE" = true ]; then
    echo "==> Rebuilding builder image ($BUILDER_IMAGE)..."
    docker build -f "$PROJECT_ROOT/docker/Dockerfile.builder" -t "$BUILDER_IMAGE" "$PROJECT_ROOT"
elif ! docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
    echo "==> Building builder image ($BUILDER_IMAGE)..."
    docker build -f "$PROJECT_ROOT/docker/Dockerfile.builder" -t "$BUILDER_IMAGE" "$PROJECT_ROOT"
fi

echo "==> Building api_fence (${BUILD_MODE}) in Docker..."
echo "    Builder image : $BUILDER_IMAGE"
echo "    Cargo caches  : $VOL_REGISTRY, $VOL_GIT"
echo "    Target cache  : $VOL_TARGET"

mkdir -p "$HOST_OUTPUT_DIR/lib"

# Strategy:
#   - Mount the project source read-write (cargo needs to potentially write Cargo.lock)
#   - Use a named volume for the cargo target dir (compiled deps cache)
#   - Use named volumes for cargo registry and git (downloaded crates cache)
#   - After build, copy the .so and needed runtime libs to the host output dir
docker run --rm \
    -v "${VOL_REGISTRY}:/usr/local/cargo/registry" \
    -v "${VOL_GIT}:/usr/local/cargo/git" \
    -v "${VOL_TARGET}:/cargo-target" \
    -v "${PROJECT_ROOT}:/src" \
    -w /src \
    -e CARGO_TARGET_DIR=/cargo-target \
    "$BUILDER_IMAGE" \
    bash -c "
        set -euo pipefail
        cargo build ${CARGO_FLAGS}

        # Copy artifact to output location
        cp /cargo-target/${BUILD_MODE}/libapi_fence.so /src/target/docker-${BUILD_MODE}/libapi_fence.so

        # Collect runtime shared libraries that the Envoy container needs.
        # Both containers are Ubuntu 22.04 so base libs (libc, libm, etc.) match.
        # We only need to copy libs that the Envoy image does NOT ship.
        rm -rf /src/target/docker-${BUILD_MODE}/lib/*
        for lib in \$(ldd /cargo-target/${BUILD_MODE}/libapi_fence.so 2>/dev/null \
                      | grep '=>' | awk '{print \$3}' | sort -u); do
            case \"\$(basename \"\$lib\")\" in
                libc.so*|libm.so*|libgcc_s.so*|libpthread.so*|libdl.so*|librt.so*|ld-linux*)
                    ;; # base libs — present in every Ubuntu container
                *)
                    cp -L \"\$lib\" /src/target/docker-${BUILD_MODE}/lib/ 2>/dev/null || true
                    ;;
            esac
        done

        echo '==> Collected runtime libraries:'
        ls -1 /src/target/docker-${BUILD_MODE}/lib/
    "

echo "==> Build complete: ${HOST_OUTPUT_DIR}/libapi_fence.so"
