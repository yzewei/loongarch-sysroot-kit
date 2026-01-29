#!/usr/bin/env bash
set -euo pipefail

# Build source-based library artifacts (OpenSSL/GLib) in a loong64 container.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

SRC_BUILDS="${SRC_BUILDS:-openssl glib}"

OPENSSL_VERSION="${OPENSSL_VERSION:-3.2.2}"
OPENSSL_URL="${OPENSSL_URL:-https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz}"
OPENSSL_ARTIFACTS_DIR="${OPENSSL_ARTIFACTS_DIR:-${SRC_ARTIFACTS_DIR:-$ROOT_DIR/src-libs/openssl-${OPENSSL_VERSION}}}"

GLIB_VERSION="${GLIB_VERSION:-2.78.3}"
GLIB_URL="${GLIB_URL:-https://download.gnome.org/sources/glib/${GLIB_VERSION%.*}/glib-${GLIB_VERSION}.tar.xz}"
GLIB_ARTIFACTS_DIR="${GLIB_ARTIFACTS_DIR:-$ROOT_DIR/src-libs/glib-${GLIB_VERSION}}"

SRC_ARTIFACTS_IMAGE="${SRC_ARTIFACTS_IMAGE:-ghcr.io/loong64/debian:trixie-slim-fix}"
SRC_ARTIFACTS_PLATFORM="${SRC_ARTIFACTS_PLATFORM:-linux/loong64}"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found; cannot build source artifacts."
    exit 1
fi

build_artifacts() {
    local builds="$1"
    local dest_dir="$2"

    mkdir -p "$dest_dir"
    local rel="${dest_dir#$ROOT_DIR/}"
    if [ "$rel" = "$dest_dir" ]; then
        echo "ERROR: artifacts dir must be under repo root ($ROOT_DIR): $dest_dir"
        exit 1
    fi

    docker run --rm --platform="$SRC_ARTIFACTS_PLATFORM" \
        -v "$ROOT_DIR:/work" -w /work \
        -e BASH_ENV=/dev/null \
        -e ENV=/dev/null \
        -e SRC_BUILD_MODE=native \
        -e SYSROOT_DIR="/work/$rel" \
        -e SRC_BUILDS="$builds" \
        -e OPENSSL_VERSION="$OPENSSL_VERSION" \
        -e OPENSSL_URL="$OPENSSL_URL" \
        -e GLIB_VERSION="$GLIB_VERSION" \
        -e GLIB_URL="$GLIB_URL" \
        "$SRC_ARTIFACTS_IMAGE" \
        /bin/bash --noprofile --norc -c "./scripts/build_src_libs.sh"
}

if [[ "$SRC_BUILDS" == *"openssl"* ]]; then
    if [ -f "$OPENSSL_ARTIFACTS_DIR/usr/lib64/libcrypto.so.3" ] && [ -f "$OPENSSL_ARTIFACTS_DIR/usr/lib64/libssl.so.3" ]; then
        echo "✅ OpenSSL artifacts already present: $OPENSSL_ARTIFACTS_DIR"
    else
        echo "=== Building OpenSSL ${OPENSSL_VERSION} artifacts in loong64 container ==="
        build_artifacts "openssl" "$OPENSSL_ARTIFACTS_DIR"
    fi
fi

if [[ "$SRC_BUILDS" == *"glib"* ]]; then
    if [ -f "$GLIB_ARTIFACTS_DIR/usr/lib64/libglib-2.0.so.0" ] || [ -f "$GLIB_ARTIFACTS_DIR/usr/lib64/libglib-2.0.so" ]; then
        echo "✅ GLib artifacts already present: $GLIB_ARTIFACTS_DIR"
    else
        echo "=== Building GLib ${GLIB_VERSION} artifacts in loong64 container ==="
        build_artifacts "glib" "$GLIB_ARTIFACTS_DIR"
    fi
fi
