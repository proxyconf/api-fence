#!/usr/bin/env bash
# Extract the SDK revision (git commit hash) from an Envoy Docker image.
#
# The Envoy version string has the format:
#   envoy  version: <commit>/<semver>/Clean/RELEASE/BoringSSL
#
# Usage:
#   ./scripts/get-envoy-sdk-rev.sh <docker_image>
#
# Example:
#   ./scripts/get-envoy-sdk-rev.sh envoyproxy/envoy:v1.37-latest
#   # => 3909deb175ef358202d6ab4f94d683ffc0fdb477

set -euo pipefail

DOCKER_IMAGE="${1:?Usage: $0 <docker_image>}"

VERSION_OUTPUT=$(docker run --rm "$DOCKER_IMAGE" envoy --version 2>/dev/null)

# Extract the 40-char hex commit hash after "version: "
SDK_REV=$(echo "$VERSION_OUTPUT" | sed -n 's/.*version: \([a-f0-9]\{40\}\).*/\1/p')

if [[ -z "$SDK_REV" ]]; then
    echo "ERROR: Could not extract SDK revision from: $VERSION_OUTPUT" >&2
    exit 1
fi

echo "$SDK_REV"
