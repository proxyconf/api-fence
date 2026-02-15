#!/usr/bin/env bash
# Manage the Envoy Docker container for integration tests.
#
# Uses plain `docker run` -- no docker-compose dependency required.
#
# Usage:
#   ./scripts/envoy-container.sh start <docker_image> [debug|release]
#   ./scripts/envoy-container.sh stop
#   ./scripts/envoy-container.sh logs
#
# The .so and its runtime libraries are expected in:
#   target/docker-{debug,release}/libapi_fence.so
#   target/docker-{debug,release}/lib/
#
# Build these first with: ./scripts/build-in-docker.sh [--release]
#
# The container is named "api_fence_envoy" so concurrent runs are prevented.

set -euo pipefail

CONTAINER_NAME="api_fence_envoy"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cmd_start() {
    local DOCKER_IMAGE="${1:?start requires <docker_image>}"
    local BUILD_MODE="${2:-debug}"

    # Stop any leftover container from a previous run
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    local OUTPUT_DIR="$PROJECT_ROOT/target/docker-${BUILD_MODE}"
    local FILTER_SO="${OUTPUT_DIR}/libapi_fence.so"
    local RUNTIME_LIBS="${OUTPUT_DIR}/lib"

    if [[ ! -f "$FILTER_SO" ]]; then
        echo "ERROR: Filter not found at $FILTER_SO" >&2
        echo "Build it first: ./scripts/build-in-docker.sh${BUILD_MODE:+ --release}" >&2
        exit 1
    fi

    # Build docker run arguments
    local -a DOCKER_ARGS=(
        -d
        --name "$CONTAINER_NAME"
        -v "$FILTER_SO:/filter/libapi_fence.so:ro"
        -v "$PROJECT_ROOT/tests/fixtures:/fixtures:ro"
        -v "$PROJECT_ROOT/docker/envoy-integration-test.yaml:/etc/envoy/envoy.yaml:ro"
        -e "ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/filter"
        -p 18080:18080
        -p 18090:18090
        -p 18081:18081
    )

    # Mount runtime shared libraries if present
    if [[ -d "$RUNTIME_LIBS" ]] && ls "$RUNTIME_LIBS"/*.so* >/dev/null 2>&1; then
        DOCKER_ARGS+=(-v "${RUNTIME_LIBS}:/filter/lib:ro")
        DOCKER_ARGS+=(-e "LD_LIBRARY_PATH=/filter/lib")
    fi

    docker run "${DOCKER_ARGS[@]}" \
        "$DOCKER_IMAGE" \
        envoy -c /etc/envoy/envoy.yaml --log-level warn

    # Wait for Envoy to become ready
    echo "==> Waiting for Envoy (admin on :18081)..."
    for i in $(seq 1 30); do
        if curl -sf http://127.0.0.1:18081/ready >/dev/null 2>&1; then
            echo "==> Envoy is ready."
            return 0
        fi
        if [ "$i" = "30" ]; then
            echo "ERROR: Envoy failed to become ready within 30s" >&2
            echo "--- container logs ---" >&2
            docker logs "$CONTAINER_NAME" 2>&1 | tail -40 >&2
            docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
            exit 1
        fi
        sleep 1
    done
}

cmd_stop() {
    if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
        echo "==> Envoy container stopped."
    fi
}

cmd_logs() {
    docker logs "$CONTAINER_NAME" 2>&1
}

case "${1:-}" in
    start) shift; cmd_start "$@" ;;
    stop)  cmd_stop ;;
    logs)  cmd_logs ;;
    *)
        echo "Usage: $0 {start|stop|logs}" >&2
        exit 1
        ;;
esac
