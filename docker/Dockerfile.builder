# Build container for api_fence.
#
# Based on Ubuntu 22.04 to match the Envoy container's glibc version.
# Produces a .so that is binary-compatible with envoyproxy/envoy containers.
#
# Builds libmodsecurity v3.0.14 from source as a static library so that the
# final .so is self-contained and doesn't require libmodsecurity at runtime.
#
# All key dependencies (pcre2, yajl, libxml2, zlib) are also built as static
# libraries and bundled into the final .so to minimize runtime dependencies.
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

# Prefix for all statically-built libraries
ENV STATIC_PREFIX=/opt/static

# All static libs must be built with -fPIC so they can be linked into a .so
ENV CFLAGS="-fPIC"
ENV CXXFLAGS="-fPIC"

# ==========================================================================
# Stage 1: System packages
# ==========================================================================
#   - libclang-dev: bindgen (used by envoy-proxy-dynamic-modules-rust-sdk)
#   - pkg-config: dependency resolution
#   - curl, ca-certificates: rustup install + CRS download in build.rs
#   - build-essential: gcc/g++ linker
#   - autoconf/automake/libtool/flex/bison: libmodsecurity autotools build
#   - cmake: required for building pcre2
#   - python3: required for some build scripts
#   - libssl-dev: OpenSSL (required by reqwest in integration tests)
#   - git: clone libmodsecurity source + submodules
#
# NOTE: We no longer install libpcre2-dev, libyajl-dev, libxml2-dev as system
# packages. Instead, we build them from source as static libraries below.
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
        cmake \
        python3 \
        libssl-dev \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# ==========================================================================
# Stage 2: Build zlib as a static library
# ==========================================================================
# zlib is a transitive dependency of libxml2. Building it statically ensures
# we don't pull in the system's shared library.
ARG ZLIB_VERSION=1.3.1

RUN curl -fsSL "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" | tar -xzC /tmp && \
    cd /tmp/zlib-${ZLIB_VERSION} && \
    ./configure \
        --prefix=${STATIC_PREFIX} \
        --static && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf /tmp/zlib-${ZLIB_VERSION}

# Verify static zlib
RUN ls -la ${STATIC_PREFIX}/lib/libz.a && \
    ! test -f ${STATIC_PREFIX}/lib/libz.so

# ==========================================================================
# Stage 3: Build PCRE2 as a static library
# ==========================================================================
# PCRE2 is the regex engine used by libmodsecurity.
ARG PCRE2_VERSION=10.44

RUN curl -fsSL "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz" | tar -xzC /tmp && \
    cd /tmp/pcre2-${PCRE2_VERSION} && \
    ./configure \
        --prefix=${STATIC_PREFIX} \
        --disable-shared \
        --enable-static \
        --enable-jit \
        --enable-unicode && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf /tmp/pcre2-${PCRE2_VERSION}

# Verify static pcre2
RUN ls -la ${STATIC_PREFIX}/lib/libpcre2-8.a && \
    ! test -f ${STATIC_PREFIX}/lib/libpcre2-8.so

# ==========================================================================
# Stage 4: Build YAJL as a static library
# ==========================================================================
# YAJL is the JSON parser used by libmodsecurity for audit logs and JSON
# body processing.
ARG YAJL_VERSION=2.1.0

RUN curl -fsSL "https://github.com/lloyd/yajl/archive/refs/tags/${YAJL_VERSION}.tar.gz" | tar -xzC /tmp && \
    cd /tmp/yajl-${YAJL_VERSION} && \
    mkdir build && cd build && \
    cmake .. \
        -DCMAKE_INSTALL_PREFIX=${STATIC_PREFIX} \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS="-fPIC" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j"$(nproc)" && \
    make install && \
    rm -f ${STATIC_PREFIX}/lib/libyajl.so* && \
    ln -sf libyajl_s.a ${STATIC_PREFIX}/lib/libyajl.a && \
    mkdir -p ${STATIC_PREFIX}/lib/pkgconfig && \
    cp ${STATIC_PREFIX}/share/pkgconfig/yajl.pc ${STATIC_PREFIX}/lib/pkgconfig/ && \
    rm -rf /tmp/yajl-${YAJL_VERSION}

# Verify static yajl (ensure shared libs are removed and symlink created)
RUN ls -la ${STATIC_PREFIX}/lib/libyajl_s.a && \
    ls -la ${STATIC_PREFIX}/lib/libyajl.a && \
    ls -la ${STATIC_PREFIX}/lib/pkgconfig/yajl.pc && \
    ! test -f ${STATIC_PREFIX}/lib/libyajl.so

# ==========================================================================
# Stage 5: Build libxml2 as a static library (minimal, no ICU)
# ==========================================================================
# libxml2 is used by libmodsecurity for XML body parsing.
# We build it WITHOUT ICU support to avoid pulling in the massive ICU libraries.
# Also disable features not needed by ModSecurity.
ARG LIBXML2_VERSION=2.12.9

RUN curl -fsSL "https://download.gnome.org/sources/libxml2/2.12/libxml2-${LIBXML2_VERSION}.tar.xz" | tar -xJC /tmp && \
    cd /tmp/libxml2-${LIBXML2_VERSION} && \
    ./configure \
        --prefix=${STATIC_PREFIX} \
        --disable-shared \
        --enable-static \
        --without-python \
        --without-icu \
        --without-lzma \
        --without-readline \
        --without-history \
        --without-http \
        --without-ftp \
        --without-catalog \
        --without-docbook \
        --without-xinclude \
        --without-xptr \
        --without-c14n \
        --without-debug \
        --without-mem-debug \
        --without-run-debug \
        --with-zlib=${STATIC_PREFIX} \
        --with-threads && \
    make -j"$(nproc)" && \
    make install && \
    rm -rf /tmp/libxml2-${LIBXML2_VERSION}

# Verify static libxml2
RUN ls -la ${STATIC_PREFIX}/lib/libxml2.a && \
    ! test -f ${STATIC_PREFIX}/lib/libxml2.so

# ==========================================================================
# Stage 6: Build libmodsecurity v3.0.14 as a static library
# ==========================================================================
# We build with a minimal feature set — no optional deps that pull in
# heavy transitive libraries (curl, GeoIP, MaxMind, Lua, LMDB, ssdeep).
# libinjection and mbedTLS are bundled as git submodules.
#
# We point libmodsecurity to our static builds of pcre2, yajl, and libxml2.
ARG MODSEC_VERSION=v3.0.14

# Set up PKG_CONFIG to find our static libraries
# Keep -fPIC and add include paths
ENV PKG_CONFIG_PATH="${STATIC_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}"
ENV CFLAGS="-fPIC -I${STATIC_PREFIX}/include"
ENV CXXFLAGS="-fPIC -I${STATIC_PREFIX}/include"
ENV LDFLAGS="-L${STATIC_PREFIX}/lib"

RUN git clone --depth 1 --branch ${MODSEC_VERSION} \
        https://github.com/owasp-modsecurity/ModSecurity.git \
        /tmp/modsecurity && \
    cd /tmp/modsecurity && \
    git submodule update --init --recursive --depth 1

# NOTE: We don't use --with-pcre2=, --with-yajl=, --with-libxml= explicit paths
# because modsecurity's configure macros only search for .so/.la files when a
# path is given, not .a files. Instead, we rely on PKG_CONFIG_PATH being set
# so that pkg-config finds our static libraries correctly.
RUN cd /tmp/modsecurity && \
    ./build.sh && \
    ./configure \
        --prefix=/opt/modsecurity \
        --disable-shared \
        --enable-static \
        --with-pcre2 \
        --with-yajl \
        --with-libxml \
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
# Stage 7: Install Rust
# ==========================================================================
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --profile minimal

ENV PATH="/root/.cargo/bin:${PATH}"

# Tell pkg-config and the linker where to find our custom builds.
# Also set library search paths for the linker.
ENV PKG_CONFIG_PATH="/opt/modsecurity/lib/pkgconfig:${STATIC_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}"
ENV LIBRARY_PATH="${STATIC_PREFIX}/lib:/opt/modsecurity/lib:${LIBRARY_PATH}"

WORKDIR /src
