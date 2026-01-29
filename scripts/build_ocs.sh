#!/bin/bash
set -e

# ================= Configuration =================
SYSROOT_ID="opencloudos-stream"
OCS_RELEASE="${OCS_RELEASE:-23}"
ARCH="loongarch64"
TARGET_DIR="${TARGET_DIR:-sysroot-ocs-${ARCH}}"
if [[ "$TARGET_DIR" != /* ]]; then
    TARGET_DIR="$(pwd)/$TARGET_DIR"
fi
if [ -z "${SUDO:-}" ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        SUDO=""
    fi
fi
OCS_MIRROR="${OCS_MIRROR:-https://mirrors.opencloudos.org/opencloudos-stream/releases/${OCS_RELEASE}}"
# Repos to use (space-separated). Common choices: BaseOS AppStream EPOL
OCS_REPOS="${OCS_REPOS:-BaseOS AppStream}"
OCS_GPGCHECK="${OCS_GPGCHECK:-0}"

# Source-build controls (space-separated list; currently supports: openssl glib)
OCS_SRC_BUILDS="${OCS_SRC_BUILDS:-openssl glib}"
OCS_OPENSSL_VERSION="${OCS_OPENSSL_VERSION:-3.2.2}"
OCS_OPENSSL_URL="${OCS_OPENSSL_URL:-https://www.openssl.org/source/openssl-${OCS_OPENSSL_VERSION}.tar.gz}"
OCS_GLIB_VERSION="${OCS_GLIB_VERSION:-2.78.3}"
OCS_GLIB_URL="${OCS_GLIB_URL:-https://download.gnome.org/sources/glib/${OCS_GLIB_VERSION%.*}/glib-${OCS_GLIB_VERSION}.tar.xz}"
OCS_SRC_USE_ARTIFACTS="${OCS_SRC_USE_ARTIFACTS:-1}"
OCS_SRC_BUILD_ARTIFACTS="${OCS_SRC_BUILD_ARTIFACTS:-1}"
OCS_SRC_ARTIFACTS_DIR="${OCS_SRC_ARTIFACTS_DIR:-src-libs/openssl-${OCS_OPENSSL_VERSION}}"
OCS_GLIB_ARTIFACTS_DIR="${OCS_GLIB_ARTIFACTS_DIR:-src-libs/glib-${OCS_GLIB_VERSION}}"
if [[ "$OCS_SRC_ARTIFACTS_DIR" != /* ]]; then
    OCS_SRC_ARTIFACTS_DIR="$(pwd)/$OCS_SRC_ARTIFACTS_DIR"
fi
if [[ "$OCS_GLIB_ARTIFACTS_DIR" != /* ]]; then
    OCS_GLIB_ARTIFACTS_DIR="$(pwd)/$OCS_GLIB_ARTIFACTS_DIR"
fi

OCS_GLIBC_FROM_DEBIAN="${OCS_GLIBC_FROM_DEBIAN:-1}"
DEBIAN_SYSROOT_DIR="${DEBIAN_SYSROOT_DIR:-$PWD/sysroot-loong64}"

# Default package set (override with OCS_PKGS="...").
OCS_PKGS="${OCS_PKGS:-ca-certificates wget curl bash coreutils glibc libgcc libstdc++ libgomp openssl-libs zlib xz-libs zstd bzip2-libs libgcrypt libgpg-error lz4-libs p11-kit libffi libidn2 libunistring libtasn1 gnutls systemd-libs glib2 libxml2 sqlite-libs libatomic libpsl krb5-libs keyutils-libs e2fsprogs-libs brotli libevent openssl}"
# filesystem is installed explicitly; remove it if user includes it in OCS_PKGS
OCS_PKGS="${OCS_PKGS//filesystem/}"
OCS_PKGS="$(printf '%s' "$OCS_PKGS" | tr -s ' ' ' ')"
OCS_PKGS="${OCS_PKGS# }"
OCS_PKGS="${OCS_PKGS% }"

# Libraries to validate after install (pkg:pattern).
OCS_LIB_CHECKS=(
    "openssl-libs:libssl.so.*"
    "openssl-libs:libcrypto.so.*"
    "glib2:libglib-2.0.so.*"
    "glib2:libgobject-2.0.so.*"
    "glib2:libgio-2.0.so.*"
    "libxml2:libxml2.so.*"
    "sqlite-libs:libsqlite3.so.*"
    "libatomic:libatomic.so.*"
    "libgomp:libgomp.so.*"
    "libpsl:libpsl.so.*"
    "krb5-libs:libgssapi_krb5.so.*"
    "krb5-libs:libkrb5.so.*"
    "krb5-libs:libkrb5support.so.*"
    "krb5-libs:libk5crypto.so.*"
    "e2fsprogs-libs:libcom_err.so.*"
    "keyutils-libs:libkeyutils.so.*"
    "brotli:libbrotlidec.so.*"
    "libevent:libevent-2.1.so.*"
    "openssl:legacy.so"
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
    for entry in "${OCS_LIB_CHECKS[@]}"; do
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

enable_openssl_legacy_provider() {
    local conf=""
    if [ -f "$TARGET_DIR/etc/ssl/openssl.cnf" ]; then
        conf="$TARGET_DIR/etc/ssl/openssl.cnf"
    elif [ -f "$TARGET_DIR/etc/pki/tls/openssl.cnf" ]; then
        conf="$TARGET_DIR/etc/pki/tls/openssl.cnf"
    else
        echo "WARNING: openssl.cnf not found; skipping legacy provider enable."
        return 0
    fi

    $SUDO python3 - "$conf" <<'PY'
import re
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = f.read()

def has_section(name: str) -> bool:
    return re.search(rf"^\s*\[{re.escape(name)}\]\s*$", data, re.M) is not None

def has_key(section: str, key: str) -> bool:
    pattern = rf"^\s*\[{re.escape(section)}\]\s*$"
    lines = data.splitlines()
    in_section = False
    for line in lines:
        if re.match(r"^\s*\[.*\]\s*$", line):
            in_section = re.match(pattern, line) is not None
            continue
        if in_section and re.match(rf"^\s*{re.escape(key)}\s*=", line):
            return True
    return False

if not re.search(r"^\s*openssl_conf\s*=", data, re.M):
    data = "openssl_conf = openssl_init\n\n" + data

if has_section("provider_sect"):
    if not has_key("provider_sect", "legacy"):
        lines = data.splitlines()
        out = []
        in_section = False
        inserted = False
        for line in lines:
            if re.match(r"^\s*\[.*\]\s*$", line):
                if in_section and not inserted:
                    out.append("legacy = legacy_sect")
                    inserted = True
                in_section = line.strip().lower() == "[provider_sect]"
            out.append(line)
        if in_section and not inserted:
            out.append("legacy = legacy_sect")
        data = "\n".join(out)
else:
    data += (
        "\n\n[openssl_init]\n"
        "providers = provider_sect\n"
        "\n[provider_sect]\n"
        "default = default_sect\n"
        "legacy = legacy_sect\n"
        "\n[default_sect]\n"
        "activate = 1\n"
        "\n[legacy_sect]\n"
        "activate = 1\n"
    )

if not has_section("legacy_sect"):
    data += "\n\n[legacy_sect]\nactivate = 1\n"

with open(path, "w", encoding="utf-8") as f:
    f.write(data)
PY
}

ensure_build_tools() {
    if [[ "$OCS_SRC_BUILDS" == *"openssl"* ]]; then
        if command -v dnf >/dev/null 2>&1; then
            if ! $SUDO dnf -y install gcc make perl tar findutils binutils; then
                $SUDO dnf -y install gcc make perl tar findutils || true
            fi
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO apt-get update
            $SUDO apt-get install -y build-essential perl tar binutils
        fi
    fi

    if [[ "$OCS_SRC_BUILDS" == *"glib"* ]]; then
        if command -v dnf >/dev/null 2>&1; then
            if ! $SUDO dnf -y install gcc meson ninja-build pkgconf-pkg-config python3 tar xz \
                libffi-devel pcre2-devel zlib-devel gettext; then
                $SUDO dnf -y install gcc meson ninja-build pkgconf-pkg-config python3 tar xz \
                    libffi-devel pcre2-devel zlib-devel || true
            fi
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO apt-get update
            $SUDO apt-get install -y build-essential meson ninja-build pkg-config python3 \
                tar xz-utils libffi-dev libpcre2-dev zlib1g-dev gettext
        fi
    fi
}

verify_openssl_symbols() {
    local libcrypto libssl
    libcrypto="$(find "$TARGET_DIR/usr/lib64" "$TARGET_DIR/lib64" "$TARGET_DIR/usr/lib" "$TARGET_DIR/lib" -name 'libcrypto.so.3' 2>/dev/null | head -n 1)"
    libssl="$(find "$TARGET_DIR/usr/lib64" "$TARGET_DIR/lib64" "$TARGET_DIR/usr/lib" "$TARGET_DIR/lib" -name 'libssl.so.3' 2>/dev/null | head -n 1)"
    if [ -z "$libcrypto" ] || [ -z "$libssl" ]; then
        echo "❌ CRITICAL: OpenSSL libs not found for symbol verification."
        return 1
    fi

    local crypto_syms=(
        EVP_PKEY_get_bn_param
        EVP_PKEY_get_utf8_string_param
        EVP_PKEY_get_security_bits
        EVP_PKEY_get_id
        EVP_PKEY_get0_type_name
        EVP_PKEY_get_group_name
        EVP_PKEY_generate
        EVP_PKEY_fromdata_init
        EVP_PKEY_fromdata
        EVP_PKEY_todata
        EVP_PKEY_eq
        EVP_PKEY_CTX_new_from_name
        EVP_PKEY_CTX_new_from_pkey
        EVP_PKEY_CTX_set_params
        EVP_PKEY_Q_keygen
        EVP_KDF_fetch
        EVP_KDF_derive
        EVP_KDF_CTX_new
        EVP_KDF_CTX_free
        EVP_KDF_free
        OSSL_LIB_CTX_new
        OSSL_LIB_CTX_free
        OSSL_LIB_CTX_load_config
        OSSL_PROVIDER_load
        OSSL_PROVIDER_unload
        OSSL_PROVIDER_available
        OSSL_PARAM_construct_end
        OSSL_PARAM_construct_int
        OSSL_PARAM_construct_uint
        OSSL_PARAM_construct_octet_string
        OSSL_PARAM_construct_utf8_string
        OSSL_PARAM_get_BN
        OSSL_PARAM_get_octet_string_ptr
        OSSL_PARAM_locate
        OSSL_PARAM_locate_const
        OSSL_PARAM_merge
        OSSL_PARAM_free
        OSSL_PARAM_BLD_new
        OSSL_PARAM_BLD_free
        OSSL_PARAM_BLD_push_BN
        OSSL_PARAM_BLD_push_utf8_string
        OSSL_PARAM_BLD_push_octet_string
        OSSL_PARAM_BLD_to_param
        OSSL_STORE_open
        OSSL_STORE_open_ex
        OSSL_STORE_load
        OSSL_STORE_close
        OSSL_STORE_expect
        OSSL_STORE_INFO_get_type
        OSSL_STORE_INFO_get1_CERT
        OSSL_STORE_INFO_get1_PKEY
        OSSL_STORE_INFO_get1_PUBKEY
        OSSL_STORE_INFO_free
        EVP_CipherInit_ex2
        EVP_CIPHER_fetch
        EVP_CIPHER_free
        EVP_CIPHER_get_iv_length
        EVP_CIPHER_get_key_length
        EVP_CIPHER_CTX_get0_cipher
        EVP_CIPHER_CTX_get_iv_length
        EVP_CIPHER_CTX_get_key_length
        EVP_CIPHER_CTX_get_block_size
        EVP_aes_128_ocb
        EVP_aes_192_ocb
        EVP_aes_256_ocb
        EVP_sha512_256
        EVP_idea_cfb64
        EC_GROUP_new_by_curve_name_ex
        EC_POINT_oct2point
        EC_POINT_point2oct
        i2d_DSA_SIG
        DSA_SIG_new
        DSA_SIG_free
        DSA_SIG_set0
        i2d_ECDSA_SIG
        d2i_ECDSA_SIG
        X509_NAME_dup
        X509_LOOKUP_ctrl
        X509V3_add_standard_extensions
        X509_get_signature_nid
        X509_get0_signature
        X509_get0_extensions
        X509_ALGOR_get0
        X509_STORE_up_ref
        OCSP_cert_status_str
        OCSP_crl_reason_str
        OCSP_response_status_str
        ERR_get_error_all
        CRYPTO_clear_free
        BN_set_flags
        BIO_meth_set_gets
        PEM_read_bio_Parameters
        PEM_X509_INFO_read_bio
        UI_create_method
        UI_destroy_method
        UI_method_get_opener
        UI_method_get_reader
        UI_method_get_writer
        UI_method_get_closer
        UI_method_set_opener
        UI_method_set_reader
        UI_method_set_writer
        UI_method_set_closer
        UI_get_input_flags
        UI_get_string_type
        UI_set_result
    )

    local ssl_syms=(
        SSL_CTX_new_ex
        SSL_CTX_set0_tmp_dh_pkey
        SSL_CTX_up_ref
        SSL_CTX_set_info_callback
        SSL_CTX_set_default_read_buffer_len
        SSL_set_ciphersuites
        SSL_write_early_data
        SSL_SESSION_get_max_early_data
        SSL_get_early_data_status
        SSL_get_peer_signature_type_nid
        SSL_get0_group_name
    )

    local missing=0
    for sym in "${crypto_syms[@]}"; do
        if ! readelf -Ws "$libcrypto" | awk '{print $8}' | grep -qx "$sym"; then
            echo "❌ Missing libcrypto symbol: $sym"
            missing=1
        fi
    done
    for sym in "${ssl_syms[@]}"; do
        if ! readelf -Ws "$libssl" | awk '{print $8}' | grep -qx "$sym"; then
            echo "❌ Missing libssl symbol: $sym"
            missing=1
        fi
    done

    if [ "$missing" -ne 0 ]; then
        echo "❌ OpenSSL symbol verification failed."
        return 1
    fi
    echo "✅ OpenSSL symbol verification passed."
}

verify_glib_symbols() {
    local libglib
    libglib="$(find "$TARGET_DIR/usr/lib64" "$TARGET_DIR/lib64" "$TARGET_DIR/usr/lib" "$TARGET_DIR/lib" -name 'libglib-2.0.so.*' 2>/dev/null | head -n 1)"
    if [ -z "$libglib" ]; then
        echo "❌ CRITICAL: libglib-2.0 not found for symbol verification."
        return 1
    fi

    local glib_syms=(
        g_uri_get_port
        g_uri_get_scheme
        g_uri_get_host
        g_once_init_enter_pointer
        g_once_init_leave_pointer
    )

    local missing=0
    for sym in "${glib_syms[@]}"; do
        if ! readelf -Ws "$libglib" | awk '{print $8}' | grep -qx "$sym"; then
            echo "❌ Missing libglib symbol: $sym"
            missing=1
        fi
    done

    if [ "$missing" -ne 0 ]; then
        echo "❌ GLib symbol verification failed."
        return 1
    fi
    echo "✅ GLib symbol verification passed."
}

build_openssl_from_source() {
    if [[ "$OCS_SRC_BUILDS" != *"openssl"* ]]; then
        return 0
    fi

    echo "=== Building OpenSSL ${OCS_OPENSSL_VERSION} from source ==="
    ensure_build_tools

    local workdir
    workdir="$(mktemp -d)"
    (
        cd "$workdir"
        echo "Downloading ${OCS_OPENSSL_URL}..."
        curl -fsSL "$OCS_OPENSSL_URL" -o openssl.tar.gz
        tar -xzf openssl.tar.gz
        cd "openssl-${OCS_OPENSSL_VERSION}"
        ./Configure linux64-loongarch64             --prefix=/usr             --openssldir=/etc/ssl             --libdir=lib64             shared
        make -j"$(nproc)"
        make DESTDIR="$TARGET_DIR" install_sw install_ssldirs
    )
    rm -rf "$workdir"

    echo "✅ OpenSSL ${OCS_OPENSSL_VERSION} installed into sysroot."
    verify_openssl_symbols
}

build_openssl_artifacts() {
    if [[ "$OCS_SRC_BUILDS" != *"openssl"* ]]; then
        return 0
    fi
    if [ "$OCS_SRC_USE_ARTIFACTS" != "1" ]; then
        build_openssl_from_source
        return 0
    fi

    if [ -f "$OCS_SRC_ARTIFACTS_DIR/usr/lib64/libcrypto.so.3" ] && [ -f "$OCS_SRC_ARTIFACTS_DIR/usr/lib64/libssl.so.3" ]; then
        echo "✅ OpenSSL artifacts already present: $OCS_SRC_ARTIFACTS_DIR"
        return 0
    fi

    echo "=== Building OpenSSL ${OCS_OPENSSL_VERSION} into artifacts ==="
    ensure_build_tools
    $SUDO mkdir -p "$OCS_SRC_ARTIFACTS_DIR"
    SRC_BUILD_MODE=native SYSROOT_DIR="$OCS_SRC_ARTIFACTS_DIR" \
        SRC_BUILDS="openssl" \
        OPENSSL_VERSION="$OCS_OPENSSL_VERSION" \
        OPENSSL_URL="$OCS_OPENSSL_URL" \
        SUDO="$SUDO" \
        bash scripts/build_src_libs.sh
}

install_openssl_artifacts_into_sysroot() {
    if [[ "$OCS_SRC_BUILDS" != *"openssl"* ]]; then
        return 0
    fi
    if [ "$OCS_SRC_USE_ARTIFACTS" != "1" ]; then
        return 0
    fi

    if [ ! -d "$OCS_SRC_ARTIFACTS_DIR/usr/lib64" ]; then
        echo "ERROR: OpenSSL artifacts not found at $OCS_SRC_ARTIFACTS_DIR"
        exit 1
    fi

    echo "=== Installing OpenSSL artifacts into sysroot ==="
    $SUDO mkdir -p "$TARGET_DIR/usr/lib64" "$TARGET_DIR/usr/bin" "$TARGET_DIR/etc"
    $SUDO cp -a "$OCS_SRC_ARTIFACTS_DIR/usr/lib64/." "$TARGET_DIR/usr/lib64/"
    if [ -f "$OCS_SRC_ARTIFACTS_DIR/usr/bin/openssl" ]; then
        $SUDO cp -a "$OCS_SRC_ARTIFACTS_DIR/usr/bin/openssl" "$TARGET_DIR/usr/bin/"
    fi
    if [ -d "$OCS_SRC_ARTIFACTS_DIR/etc/ssl" ]; then
        $SUDO cp -a "$OCS_SRC_ARTIFACTS_DIR/etc/ssl" "$TARGET_DIR/etc/"
    fi

    enable_openssl_legacy_provider
    verify_openssl_symbols
}

build_glib_from_source() {
    if [[ "$OCS_SRC_BUILDS" != *"glib"* ]]; then
        return 0
    fi

    echo "=== Building GLib ${OCS_GLIB_VERSION} from source ==="
    ensure_build_tools
    SRC_BUILD_MODE=native SYSROOT_DIR="$TARGET_DIR" \
        SRC_BUILDS="glib" \
        GLIB_VERSION="$OCS_GLIB_VERSION" \
        GLIB_URL="$OCS_GLIB_URL" \
        SUDO="$SUDO" \
        bash scripts/build_src_libs.sh

    verify_glib_symbols
}

build_glib_artifacts() {
    if [[ "$OCS_SRC_BUILDS" != *"glib"* ]]; then
        return 0
    fi
    if [ "$OCS_SRC_USE_ARTIFACTS" != "1" ]; then
        build_glib_from_source
        return 0
    fi

    if [ -f "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/libglib-2.0.so.0" ] || [ -f "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/libglib-2.0.so" ]; then
        echo "✅ GLib artifacts already present: $OCS_GLIB_ARTIFACTS_DIR"
        return 0
    fi

    echo "=== Building GLib ${OCS_GLIB_VERSION} into artifacts ==="
    ensure_build_tools
    $SUDO mkdir -p "$OCS_GLIB_ARTIFACTS_DIR"
    SRC_BUILD_MODE=native SYSROOT_DIR="$OCS_GLIB_ARTIFACTS_DIR" \
        SRC_BUILDS="glib" \
        GLIB_VERSION="$OCS_GLIB_VERSION" \
        GLIB_URL="$OCS_GLIB_URL" \
        SUDO="$SUDO" \
        bash scripts/build_src_libs.sh
}

install_glib_artifacts_into_sysroot() {
    if [[ "$OCS_SRC_BUILDS" != *"glib"* ]]; then
        return 0
    fi
    if [ "$OCS_SRC_USE_ARTIFACTS" != "1" ]; then
        return 0
    fi

    if [ ! -d "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64" ]; then
        echo "ERROR: GLib artifacts not found at $OCS_GLIB_ARTIFACTS_DIR"
        exit 1
    fi

    echo "=== Installing GLib artifacts into sysroot ==="
    $SUDO mkdir -p "$TARGET_DIR/usr/lib64"
    for lib in libglib-2.0 libgobject-2.0 libgio-2.0 libgmodule-2.0 libgthread-2.0; do
        $SUDO cp -a "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/${lib}.so"* "$TARGET_DIR/usr/lib64/" 2>/dev/null || true
    done
    if [ -d "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/glib-2.0" ]; then
        $SUDO cp -a "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/glib-2.0" "$TARGET_DIR/usr/lib64/"
    fi
    if [ -d "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/gio" ]; then
        $SUDO cp -a "$OCS_GLIB_ARTIFACTS_DIR/usr/lib64/gio" "$TARGET_DIR/usr/lib64/"
    fi
    if [ -d "$OCS_GLIB_ARTIFACTS_DIR/usr/share/glib-2.0" ]; then
        $SUDO mkdir -p "$TARGET_DIR/usr/share"
        $SUDO cp -a "$OCS_GLIB_ARTIFACTS_DIR/usr/share/glib-2.0" "$TARGET_DIR/usr/share/"
    fi

    verify_glib_symbols
}

copy_debian_glibc() {
    if [ "${OCS_GLIBC_FROM_DEBIAN}" != "1" ]; then
        return 0
    fi

    if [ ! -d "$DEBIAN_SYSROOT_DIR" ]; then
        echo "ERROR: DEBIAN_SYSROOT_DIR not found: $DEBIAN_SYSROOT_DIR"
        echo "Set DEBIAN_SYSROOT_DIR to an existing Debian sysroot before building OCS."
        exit 1
    fi

    echo "=== Replacing OpenCloudOS glibc with Debian glibc from $DEBIAN_SYSROOT_DIR ==="
    $SUDO mkdir -p "$TARGET_DIR/lib64"

    local src_dirs=(
        "$DEBIAN_SYSROOT_DIR/lib/loongarch64-linux-gnu"
        "$DEBIAN_SYSROOT_DIR/usr/lib/loongarch64-linux-gnu"
        "$DEBIAN_SYSROOT_DIR/lib64"
        "$DEBIAN_SYSROOT_DIR/usr/lib64"
    )

    local patterns=(
        "ld-linux-loongarch-lp64d.so.1"
        "libc.so.6" "libc-*.so"
        "libpthread.so.0" "libpthread-*.so"
        "libm.so.6" "libm-*.so"
        "librt.so.1" "librt-*.so"
        "libdl.so.2" "libdl-*.so"
        "libutil.so.1" "libutil-*.so"
        "libresolv.so.2" "libresolv-*.so"
        "libnss_*.so.2" "libnss_*.so"
        "libanl.so.1" "libanl-*.so"
    )

    for dir in "${src_dirs[@]}"; do
        if [ -d "$dir" ]; then
            for pat in "${patterns[@]}"; do
                find "$dir" -maxdepth 1 -name "$pat" -print0 2>/dev/null | while IFS= read -r -d '' f; do
                    $SUDO cp -a "$f" "$TARGET_DIR/lib64/" || true
                done
            done
        fi
    done

    if [ ! -e "$TARGET_DIR/lib64/ld-linux-loongarch-lp64d.so.1" ]; then
        echo "ERROR: Failed to copy ld-linux-loongarch-lp64d.so.1 from Debian sysroot."
        exit 1
    fi
}

build_repo_args() {
    local repo name base args=()
    for repo in $OCS_REPOS; do
        name="ocs-$(echo "$repo" | tr '[:upper:]' '[:lower:]')"
        base="${OCS_MIRROR}/${repo}/${ARCH}/Packages"
        if curl -fsI "${base}/repodata/repomd.xml" >/dev/null; then
            args+=("--repofrompath=${name},${base}/")
            args+=("--repo=${name}")
            args+=("--setopt=${name}.gpgcheck=${OCS_GPGCHECK}")
        else
            echo "WARNING: ${base}/repodata/repomd.xml not reachable; skipping ${repo}"
        fi
    done
    echo "${args[@]}"
}

echo "=== 0. Prepare Build Env ==="
if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y wget curl dnf rpm python3
elif command -v dnf >/dev/null 2>&1; then
    if ! $SUDO dnf -y install wget curl-minimal python3; then
        $SUDO dnf -y install wget curl python3 --allowerasing
    fi
else
    echo "ERROR: no apt-get or dnf available to install host deps."
    exit 1
fi

if [ -n "$OCS_SRC_BUILDS" ] && [ "$OCS_SRC_USE_ARTIFACTS" = "1" ] && [ "$OCS_SRC_BUILD_ARTIFACTS" = "1" ]; then
    echo "=== 0.5 Build Source Artifacts (before sysroot) ==="
    build_openssl_artifacts
    build_glib_artifacts
fi

echo "=== 1. Start Build OpenCloudOS Sysroot ==="
if [ -d "$TARGET_DIR" ]; then $SUDO rm -rf "$TARGET_DIR"; fi
$SUDO mkdir -p "$TARGET_DIR"

# Clean up any pre-existing lib dirs to avoid filesystem conflicts
$SUDO rm -rf "$TARGET_DIR/lib" "$TARGET_DIR/lib64"
# Pre-create usr-merged layout to prevent filesystem conflicts
$SUDO mkdir -p "$TARGET_DIR/usr/lib" "$TARGET_DIR/usr/lib64"
$SUDO ln -sfn usr/lib "$TARGET_DIR/lib"
$SUDO ln -sfn usr/lib64 "$TARGET_DIR/lib64"

REPO_ARGS="$(build_repo_args)"
if [ -z "$REPO_ARGS" ]; then
    echo "ERROR: No valid OpenCloudOS repos found. Check OCS_MIRROR/OCS_REPOS."
    exit 1
fi

DNF_FORCEARCH="--forcearch=$ARCH"
DNF_IGNOREARCH=""
if ! command -v dnf >/dev/null 2>&1; then
    if [ -z "${OCS_IN_CONTAINER:-}" ] && [ "${OCS_USE_DOCKER:-1}" != "0" ] && command -v docker >/dev/null 2>&1; then
        OCS_DOCKER_IMAGE="${OCS_DOCKER_IMAGE:-ghcr.io/loong64/opencloudos:9.4-toolbox-20251019}"
        OCS_DOCKER_PLATFORM="${OCS_DOCKER_PLATFORM:-linux/loong64}"
        echo "INFO: Host dnf/rpm does not recognize arch '$ARCH'; running in container ${OCS_DOCKER_IMAGE} (${OCS_DOCKER_PLATFORM})..."
        if docker buildx version >/dev/null 2>&1; then
            echo "INFO: buildx detected; bootstrapping builder for ${OCS_DOCKER_PLATFORM}"
            docker buildx inspect --bootstrap >/dev/null 2>&1 || true
        fi
        docker run --rm --platform="$OCS_DOCKER_PLATFORM" --entrypoint /bin/bash \
            -e BASH_ENV=/dev/null \
            -e ENV=/dev/null \
            -v "$PWD:/work" -w /work \
            -e OCS_IN_CONTAINER=1 \
            -e OCS_USE_DOCKER=0 \
            -e OCS_RELEASE="$OCS_RELEASE" \
            -e ARCH="$ARCH" \
            -e TARGET_DIR="sysroot-ocs-${ARCH}" \
            -e OCS_MIRROR="$OCS_MIRROR" \
            -e OCS_REPOS="$OCS_REPOS" \
            -e OCS_GPGCHECK="$OCS_GPGCHECK" \
            -e OCS_PKGS="$OCS_PKGS" \
            -e OCS_SRC_BUILDS="$OCS_SRC_BUILDS" \
            -e OCS_OPENSSL_VERSION="$OCS_OPENSSL_VERSION" \
            -e OCS_OPENSSL_URL="$OCS_OPENSSL_URL" \
            -e OCS_GLIB_VERSION="$OCS_GLIB_VERSION" \
            -e OCS_GLIB_URL="$OCS_GLIB_URL" \
            -e OCS_SRC_USE_ARTIFACTS="$OCS_SRC_USE_ARTIFACTS" \
            -e OCS_SRC_BUILD_ARTIFACTS="$OCS_SRC_BUILD_ARTIFACTS" \
            -e OCS_SRC_ARTIFACTS_DIR="$OCS_SRC_ARTIFACTS_DIR" \
            -e OCS_GLIB_ARTIFACTS_DIR="$OCS_GLIB_ARTIFACTS_DIR" \
            -e OCS_GLIBC_FROM_DEBIAN="$OCS_GLIBC_FROM_DEBIAN" \
            -e DEBIAN_SYSROOT_DIR="$DEBIAN_SYSROOT_DIR" \
            "$OCS_DOCKER_IMAGE" \
            --noprofile --norc -c "./scripts/build_ocs.sh"
        exit $?
    fi
    echo "ERROR: dnf not available on host and docker fallback disabled/unavailable."
    exit 1
fi
if ! dnf --forcearch="$ARCH" --version >/dev/null 2>&1; then
    if [ -z "${OCS_IN_CONTAINER:-}" ] && [ "${OCS_USE_DOCKER:-1}" != "0" ] && command -v docker >/dev/null 2>&1; then
        OCS_DOCKER_IMAGE="${OCS_DOCKER_IMAGE:-ghcr.io/loong64/opencloudos:9.4-toolbox-20251019}"
        OCS_DOCKER_PLATFORM="${OCS_DOCKER_PLATFORM:-linux/loong64}"
        echo "INFO: Host dnf/rpm does not recognize arch '$ARCH'; running in container ${OCS_DOCKER_IMAGE} (${OCS_DOCKER_PLATFORM})..."
        if docker buildx version >/dev/null 2>&1; then
            echo "INFO: buildx detected; bootstrapping builder for ${OCS_DOCKER_PLATFORM}"
            docker buildx inspect --bootstrap >/dev/null 2>&1 || true
        fi
        docker run --rm --platform="$OCS_DOCKER_PLATFORM" --entrypoint /bin/bash \
            -e BASH_ENV=/dev/null \
            -e ENV=/dev/null \
            -v "$PWD:/work" -w /work \
            -e OCS_IN_CONTAINER=1 \
            -e OCS_USE_DOCKER=0 \
            -e OCS_RELEASE="$OCS_RELEASE" \
            -e ARCH="$ARCH" \
            -e TARGET_DIR="sysroot-ocs-${ARCH}" \
            -e OCS_MIRROR="$OCS_MIRROR" \
            -e OCS_REPOS="$OCS_REPOS" \
            -e OCS_GPGCHECK="$OCS_GPGCHECK" \
            -e OCS_PKGS="$OCS_PKGS" \
            -e OCS_SRC_BUILDS="$OCS_SRC_BUILDS" \
            -e OCS_OPENSSL_VERSION="$OCS_OPENSSL_VERSION" \
            -e OCS_OPENSSL_URL="$OCS_OPENSSL_URL" \
            -e OCS_GLIB_VERSION="$OCS_GLIB_VERSION" \
            -e OCS_GLIB_URL="$OCS_GLIB_URL" \
            -e OCS_SRC_USE_ARTIFACTS="$OCS_SRC_USE_ARTIFACTS" \
            -e OCS_SRC_BUILD_ARTIFACTS="$OCS_SRC_BUILD_ARTIFACTS" \
            -e OCS_SRC_ARTIFACTS_DIR="$OCS_SRC_ARTIFACTS_DIR" \
            -e OCS_GLIB_ARTIFACTS_DIR="$OCS_GLIB_ARTIFACTS_DIR" \
            -e OCS_GLIBC_FROM_DEBIAN="$OCS_GLIBC_FROM_DEBIAN" \
            -e DEBIAN_SYSROOT_DIR="$DEBIAN_SYSROOT_DIR" \
            "$OCS_DOCKER_IMAGE" \
            --noprofile --norc -c "./scripts/build_ocs.sh"
        exit $?
    fi
    echo "WARNING: Host dnf/rpm does not recognize arch '$ARCH'; falling back to ignorearch."
    DNF_FORCEARCH=""
    DNF_IGNOREARCH="--setopt=ignorearch=1"
fi

# Install filesystem first to lay down base filesystem layout
$SUDO dnf -y --installroot="$TARGET_DIR" \
    --releasever="$OCS_RELEASE" \
    $DNF_FORCEARCH \
    --setopt=reposdir=/dev/null \
    --setopt=varsdir=/dev/null \
    --setopt=install_weak_deps=False \
    --setopt=tsflags=nodocs \
    --setopt=keepcache=0 \
    --setopt=cachedir="$TARGET_DIR/var/cache/dnf" \
    $DNF_IGNOREARCH \
    $REPO_ARGS \
    --allowerasing \
    install filesystem

echo "Installing packages into $TARGET_DIR..."
$SUDO dnf -y --installroot="$TARGET_DIR" \
    --releasever="$OCS_RELEASE" \
    $DNF_FORCEARCH \
    --setopt=reposdir=/dev/null \
    --setopt=varsdir=/dev/null \
    --setopt=install_weak_deps=False \
    --setopt=tsflags=nodocs,noscripts \
    --setopt=keepcache=0 \
    --setopt=cachedir="$TARGET_DIR/var/cache/dnf" \
    $DNF_IGNOREARCH \
    $REPO_ARGS \
    --allowerasing \
    install $OCS_PKGS

if [ -n "$OCS_SRC_BUILDS" ]; then
    if [ "$OCS_SRC_USE_ARTIFACTS" = "1" ]; then
        install_openssl_artifacts_into_sysroot
        install_glib_artifacts_into_sysroot
    else
        build_openssl_from_source
        build_glib_from_source
    fi
fi

copy_debian_glibc

echo ">>> Verifying Runtime Libraries..."
if ! check_libs; then
    exit 1
fi

echo ">>> Enabling OpenSSL legacy provider..."
enable_openssl_legacy_provider

echo "=== 2. Clean & Fix ==="
$SUDO rm -rf "$TARGET_DIR/var/cache/dnf"

echo "Fixing symlinks..."
# Add Debian-compatible multiarch libdir for consumers
if [ ! -e "$TARGET_DIR/usr/lib/loongarch64-linux-gnu" ]; then
    $SUDO ln -s ../lib64 "$TARGET_DIR/usr/lib/loongarch64-linux-gnu"
fi
if [ -f "scripts/fix_links.py" ]; then $SUDO python3 scripts/fix_links.py "$TARGET_DIR"; fi

# ==========================================
# 3. Package Runtime Libs
# ==========================================
echo "=== 3. Package Runtime Libs (For Box64) ==="
RUNTIME_TAR="${SYSROOT_ID}-${OCS_RELEASE}-${ARCH}-runtime-libs.tar.gz"
TEMP_RUNTIME="runtime-libs-temp"
rm -rf "$TEMP_RUNTIME"
mkdir -p "$TEMP_RUNTIME/usr"

echo "Copying libraries..."
$SUDO cp -a "$TARGET_DIR/lib" "$TEMP_RUNTIME/" || true
$SUDO cp -a "$TARGET_DIR/lib64" "$TEMP_RUNTIME/" || true
$SUDO cp -a "$TARGET_DIR/usr/lib" "$TEMP_RUNTIME/usr/" || true
$SUDO cp -a "$TARGET_DIR/usr/lib64" "$TEMP_RUNTIME/usr/" || true
$SUDO cp -a "$TARGET_DIR/etc" "$TEMP_RUNTIME/" || true

echo "Packaging Runtime Artifact: $RUNTIME_TAR ..."
$SUDO tar -czf "$RUNTIME_TAR" -C "$TEMP_RUNTIME" .
$SUDO chown $USER:$USER "$RUNTIME_TAR"
$SUDO rm -rf "$TEMP_RUNTIME"

# ==========================================
# 4. Package Full Sysroot
# ==========================================
echo "=== 4. Package Full Sysroot ==="
FULL_TAR="${SYSROOT_ID}-${OCS_RELEASE}-${ARCH}-sysroot.tar.gz"
echo "Packaging Full Artifact: $FULL_TAR ..."
$SUDO tar -czf "$FULL_TAR" -C "$TARGET_DIR" .
$SUDO chown $USER:$USER "$FULL_TAR"

echo "Build Success!"
