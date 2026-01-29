#!/bin/bash
set -e

# Build AOSC sysroot by installing runtime packages inside AOSC container.

ARCH="loongarch64"
TARGET_DIR="${TARGET_DIR:-sysroot-aosc-${ARCH}}"
if [[ "$TARGET_DIR" != /* ]]; then
    TARGET_DIR="$(pwd)/$TARGET_DIR"
fi

if [ -z "${SUDO:-}" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        SUDO=""
    fi
fi

# Default package set (override with AOSC_PKGS="...").
# Keep in sync with Debian/OC runtime requirements where possible.
AOSC_PKGS="${AOSC_PKGS:-openssl glib2 libgomp zlib xz zstd bzip2 libgcrypt libgpg-error lz4 p11-kit libffi libidn2 libunistring libtasn1 gnutls systemd libxml2 sqlite libatomic libpsl krb5 keyutils e2fsprogs brotli libevent libgcc libstdc++ glibc libselinux libsepol}"
AOSC_PKGS="$(printf '%s' "$AOSC_PKGS" | tr -s ' ' ' ')"
AOSC_PKGS="${AOSC_PKGS# }"
AOSC_PKGS="${AOSC_PKGS% }"

# Libraries to validate after install (pkg:pattern).
AOSC_LIB_CHECKS=(
    "openssl:libssl.so.*"
    "openssl:libcrypto.so.*"
    "glib2:libglib-2.0.so.*"
    "glib2:libgobject-2.0.so.*"
    "glib2:libgio-2.0.so.*"
    "libgomp:libgomp.so.*"
    "libselinux:libselinux.so.*"
    "libsepol:libsepol.so.*"
)

find_lib_in_sysroot() {
    local pattern="$1"
    find \
        "$TARGET_DIR/usr/lib" \
        "$TARGET_DIR/usr/lib64" \
        "$TARGET_DIR/lib" \
        "$TARGET_DIR/lib64" \
        -name "$pattern" 2>/dev/null | head -n 1
}

check_libs() {
    local entry pkg pattern found
    for entry in "${AOSC_LIB_CHECKS[@]}"; do
        pkg="${entry%%:*}"
        pattern="${entry#*:}"
        found="$(find_lib_in_sysroot "$pattern")"
        if [ -n "$found" ]; then
            echo "✅ Verified: Found $found"
            continue
        fi
        echo "❌ CRITICAL: $pattern not found (missing from $pkg?)"
        return 1
    done
}

echo "=== 0. Prepare Build Env (AOSC) ==="
if command -v oma >/dev/null 2>&1; then
    $SUDO oma refresh
    $SUDO oma install -y ca-certificates ${AOSC_PKGS}
elif command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y ca-certificates ${AOSC_PKGS}
elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -Sy --noconfirm ca-certificates ${AOSC_PKGS}
elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf -y install ca-certificates ${AOSC_PKGS}
else
    echo "ERROR: no supported package manager (oma/apt-get/pacman/dnf) found."
    exit 1
fi

echo "=== 1. Build AOSC Sysroot ==="
$SUDO rm -rf "$TARGET_DIR"
$SUDO mkdir -p "$TARGET_DIR"

$SUDO cp -a /lib "$TARGET_DIR/" 2>/dev/null || true
$SUDO cp -a /lib64 "$TARGET_DIR/" 2>/dev/null || true
$SUDO mkdir -p "$TARGET_DIR/usr"
$SUDO cp -a /usr/lib "$TARGET_DIR/usr/" 2>/dev/null || true
$SUDO cp -a /usr/lib64 "$TARGET_DIR/usr/" 2>/dev/null || true
$SUDO cp -a /etc "$TARGET_DIR/" 2>/dev/null || true

echo ">>> Verifying Runtime Libraries..."
if ! check_libs; then
    exit 1
fi

echo "=== 2. Package Sysroot ==="
SYSROOT_TAR="aosc-${ARCH}-sysroot.tar.gz"
RUNTIME_TAR="aosc-${ARCH}-runtime-libs.tar.gz"

echo "Packaging Sysroot: $SYSROOT_TAR ..."
$SUDO tar -czf "$SYSROOT_TAR" -C "$TARGET_DIR" .
$SUDO chown "$USER:$USER" "$SYSROOT_TAR"

echo "Packaging Runtime Libs: $RUNTIME_TAR ..."
TEMP_RUNTIME="runtime-libs-temp"
$SUDO rm -rf "$TEMP_RUNTIME"
mkdir -p "$TEMP_RUNTIME/usr"
$SUDO cp -a "$TARGET_DIR/lib" "$TEMP_RUNTIME/" 2>/dev/null || true
$SUDO cp -a "$TARGET_DIR/lib64" "$TEMP_RUNTIME/" 2>/dev/null || true
$SUDO cp -a "$TARGET_DIR/usr/lib" "$TEMP_RUNTIME/usr/" 2>/dev/null || true
$SUDO cp -a "$TARGET_DIR/usr/lib64" "$TEMP_RUNTIME/usr/" 2>/dev/null || true
$SUDO cp -a "$TARGET_DIR/etc" "$TEMP_RUNTIME/" 2>/dev/null || true
$SUDO tar -czf "$RUNTIME_TAR" -C "$TEMP_RUNTIME" .
$SUDO chown "$USER:$USER" "$RUNTIME_TAR"

echo "✅ AOSC sysroot build complete."
