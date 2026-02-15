#!/usr/bin/env bash
# Update the envoy-proxy-dynamic-modules-rust-sdk git rev in Cargo.toml.
#
# This replaces the `rev = "..."` value in the SDK dependency line so that
# the build links against the ABI-compatible version of the SDK.
#
# Usage:
#   ./scripts/set-envoy-sdk-rev.sh <sdk_rev>
#
# Example:
#   ./scripts/set-envoy-sdk-rev.sh 3909deb175ef358202d6ab4f94d683ffc0fdb477

set -euo pipefail

SDK_REV="${1:?Usage: $0 <sdk_rev>}"

# Validate that it looks like a git SHA
if ! [[ "$SDK_REV" =~ ^[a-f0-9]{40}$ ]]; then
    echo "ERROR: SDK_REV does not look like a 40-char git commit hash: $SDK_REV" >&2
    exit 1
fi

CARGO_TOML="${2:-Cargo.toml}"

if [[ ! -f "$CARGO_TOML" ]]; then
    echo "ERROR: $CARGO_TOML not found" >&2
    exit 1
fi

# Replace the rev in the active (non-commented) SDK dependency line
sed -i -E \
    '/^[^#]*envoy-proxy-dynamic-modules-rust-sdk/s/rev = "[a-f0-9]+"/rev = "'"$SDK_REV"'"/' \
    "$CARGO_TOML"

# Verify the change
if grep -q "rev = \"$SDK_REV\"" "$CARGO_TOML"; then
    echo "Updated $CARGO_TOML SDK rev to: $SDK_REV"
else
    echo "ERROR: Failed to update SDK rev in $CARGO_TOML" >&2
    exit 1
fi
