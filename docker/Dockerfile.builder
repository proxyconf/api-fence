# Build container for api_fence.
#
# Based on Ubuntu 22.04 to match the Envoy container's glibc version.
# Produces a .so that is binary-compatible with envoyproxy/envoy containers.
#
# Builds libmodsecurity v3.0.14 from source as a static library so that the
# final .so is self-contained and doesn't require libmodsecurity at runtime.
#
# Build:
#   docker build -f docker/Dockerfile.builder -t api_fence-builder .
#
# Usage (via scripts/build-in-docker.sh):
#   docker run --rm \
#     -v cargo-registry:/usr/local/cargo/registry \
#     -v cargo-git:/usr/local/cargo/git \
#     -v "$PWD:/src" \
#     -w /src \
#     api_fence-builder \
#     cargo build [--release]

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ==========================================================================
# Stage 1: System packages
# ==========================================================================
#   - libclang-dev: bindgen (used by envoy-proxy-dynamic-modules-rust-sdk)
#   - pkg-config: dependency resolution
#   - curl, ca-certificates: rustup install + CRS download in build.rs
#   - build-essential: gcc/g++ linker
#   - autoconf/automake/libtool/flex/bison: libmodsecurity autotools build
#   - libpcre2-dev: regex engine (static .a available from Ubuntu package)
#   - libyajl-dev: JSON parser for audit logs
#   - libxml2-dev: XML body parsing
#   - libssl-dev: OpenSSL (required by reqwest in integration tests)
#   - git: clone libmodsecurity source + submodules
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libclang-dev \
        curl \
        ca-certificates \
        git \
        autoconf \
        automake \
        libtool \
        flex \
        bison \
        libpcre2-dev \
        libyajl-dev \
        libxml2-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ==========================================================================
# Stage 2: Build libmodsecurity v3.0.14 as a static library
# ==========================================================================
# We build with a minimal feature set — no optional deps that pull in
# heavy transitive libraries (curl, GeoIP, MaxMind, Lua, LMDB, ssdeep).
# libinjection and mbedTLS are bundled as git submodules.
ARG MODSEC_VERSION=v3.0.14

RUN git clone --depth 1 --branch ${MODSEC_VERSION} \
        https://github.com/owasp-modsecurity/ModSecurity.git \
        /tmp/modsecurity && \
    cd /tmp/modsecurity && \
    git submodule update --init --recursive --depth 1

RUN cd /tmp/modsecurity && \
    ./build.sh && \
    ./configure \
        --prefix=/opt/modsecurity \
        --disable-shared \
        --enable-static \
        --with-pcre2 \
        --without-lmdb \
        --without-ssdeep \
        --without-lua \
        --without-curl \
        --without-geoip \
        --without-maxmind \
        --disable-examples && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf /tmp/modsecurity

# Verify the static lib exists and no .so was produced
RUN ls -la /opt/modsecurity/lib/libmodsecurity.a && \
    ! test -f /opt/modsecurity/lib/libmodsecurity.so

# ==========================================================================
# Stage 3: Install Rust
# ==========================================================================
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal

ENV PATH="/root/.cargo/bin:${PATH}"

# Tell pkg-config and the linker where to find our custom modsecurity build
ENV PKG_CONFIG_PATH="/opt/modsecurity/lib/pkgconfig:${PKG_CONFIG_PATH}"

WORKDIR /src
