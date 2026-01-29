#!/bin/bash
set -e

# Support alternate sysroot builders.
SYSROOT_FLAVOR="${SYSROOT_FLAVOR:-debian}"
if [ "$SYSROOT_FLAVOR" = "ocs" ]; then
    exec "$(dirname "$0")/build_ocs.sh"
fi

# Project root (for stable paths)
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ================= Configuration =================
ARCH="loong64"
DISTRO="sid"
TARGET_DIR="sysroot-loong64"
# loong64 使用 debian-ports；可用环境变量 MIRROR 覆盖
MIRROR="${MIRROR:-http://ftp.ports.debian.org/debian-ports}"

DEB_SRC_BUILDS="${DEB_SRC_BUILDS:-openssl glib}"
DEB_OPENSSL_VERSION="${DEB_OPENSSL_VERSION:-3.2.2}"
DEB_OPENSSL_URL="${DEB_OPENSSL_URL:-https://www.openssl.org/source/openssl-${DEB_OPENSSL_VERSION}.tar.gz}"
DEB_GLIB_VERSION="${DEB_GLIB_VERSION:-2.78.3}"
DEB_GLIB_URL="${DEB_GLIB_URL:-https://download.gnome.org/sources/glib/${DEB_GLIB_VERSION%.*}/glib-${DEB_GLIB_VERSION}.tar.xz}"
DEB_SRC_USE_ARTIFACTS="${DEB_SRC_USE_ARTIFACTS:-1}"
DEB_SRC_BUILD_ARTIFACTS="${DEB_SRC_BUILD_ARTIFACTS:-1}"
DEB_SRC_ARTIFACTS_DIR="${DEB_SRC_ARTIFACTS_DIR:-$ROOT_DIR/src-libs/openssl-${DEB_OPENSSL_VERSION}}"
DEB_GLIB_ARTIFACTS_DIR="${DEB_GLIB_ARTIFACTS_DIR:-$ROOT_DIR/src-libs/glib-${DEB_GLIB_VERSION}}"
DEB_SRC_ARTIFACTS_IMAGE="${DEB_SRC_ARTIFACTS_IMAGE:-ghcr.io/loong64/debian:trixie-slim-fix}"
DEB_SRC_ARTIFACTS_PLATFORM="${DEB_SRC_ARTIFACTS_PLATFORM:-linux/loong64}"

# ✅ 包列表 (保持不变)
VERIFIED_PKGS="ca-certificates,wget,curl,perl-base,bash,usr-is-merged,libc6,libstdc++6,libgcc-s1,libgomp1,libssl3t64,zlib1g,liblzma5,libzstd1,libbz2-1.0,libcrypt1,libgcrypt20,libgpg-error0,liblz4-1,libp11-kit0,libffi8,libidn2-0,libunistring5,libtasn1-6,libgnutls30t64,libsystemd0,libglib2.0-0t64,libxml2,libsqlite3-0,libatomic1,libpsl5t64,libgssapi-krb5-2,libkrb5-3,libbrotli1,libevent-2.1-7t64,libkeyutils1,libcom-err2,libkrb5support0,libk5crypto3"
# =================================================

# Packages in VERIFIED_PKGS that are libraries (excluding libc6/libstdc++6/libgcc-s1).
NONSTANDARD_LIB_CHECKS=(
    "libssl3t64:libssl.so.*"
    "zlib1g:libz.so.*"
    "liblzma5:liblzma.so.*"
    "libzstd1:libzstd.so.*"
    "libbz2-1.0:libbz2.so.*"
    "libcrypt1:libcrypt.so.*"
    "libgcrypt20:libgcrypt.so.*"
    "libgpg-error0:libgpg-error.so.*"
    "liblz4-1:liblz4.so.*"
    "libp11-kit0:libp11-kit.so.*"
    "libffi8:libffi.so.*"
    "libidn2-0:libidn2.so.*"
    "libunistring5:libunistring.so.*"
    "libtasn1-6:libtasn1.so.*"
    "libgnutls30t64:libgnutls.so.*"
    "libsystemd0:libsystemd.so.*"
    "libglib2.0-0t64:libglib-2.0.so.*"
    "libglib2.0-0t64:libgobject-2.0.so.*"
    "libglib2.0-0t64:libgio-2.0.so.*"
    "libxml2:libxml2.so.*"
    "libsqlite3-0:libsqlite3.so.*"
    "libatomic1:libatomic.so.*"
    "libgomp1:libgomp.so.*"
    "libpsl5t64:libpsl.so.*"
    "libgssapi-krb5-2:libgssapi_krb5.so.*"
    "libkrb5-3:libkrb5.so.*"
    "libbrotli1:libbrotlidec.so.*"
    "libevent-2.1-7t64:libevent-2.1.so.*"
    "libkeyutils1:libkeyutils.so.*"
    "libcom-err2:libcom_err.so.*"
    "libkrb5support0:libkrb5support.so.*"
    "libk5crypto3:libk5crypto.so.*"
)

enable_openssl_legacy_provider_deb() {
    local conf=""
    if [ -f "$TARGET_DIR/etc/ssl/openssl.cnf" ]; then
        conf="$TARGET_DIR/etc/ssl/openssl.cnf"
    elif [ -f "$TARGET_DIR/etc/pki/tls/openssl.cnf" ]; then
        conf="$TARGET_DIR/etc/pki/tls/openssl.cnf"
    else
        echo "WARNING: openssl.cnf not found; skipping legacy provider enable."
        return 0
    fi

    sudo python3 - "$conf" <<'PY'
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

verify_openssl_symbols_deb() {
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

verify_glib_symbols_deb() {
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

build_openssl_artifacts_container() {
    if [[ "$DEB_SRC_BUILDS" != *"openssl"* ]]; then
        return 0
    fi
    if [ "$DEB_SRC_USE_ARTIFACTS" != "1" ]; then
        return 0
    fi

    if [ -f "$DEB_SRC_ARTIFACTS_DIR/usr/lib64/libcrypto.so.3" ] &&        [ -f "$DEB_SRC_ARTIFACTS_DIR/usr/lib64/libssl.so.3" ]; then
        echo "✅ OpenSSL artifacts already present: $DEB_SRC_ARTIFACTS_DIR"
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: docker not found; cannot build OpenSSL artifacts."
        exit 1
    fi

    mkdir -p "$DEB_SRC_ARTIFACTS_DIR"
    local rel
    rel="${DEB_SRC_ARTIFACTS_DIR#$ROOT_DIR/}"
    if [ "$rel" = "$DEB_SRC_ARTIFACTS_DIR" ]; then
        echo "ERROR: DEB_SRC_ARTIFACTS_DIR must be under repo root ($ROOT_DIR) for container build."
        exit 1
    fi

    echo "=== Building OpenSSL ${DEB_OPENSSL_VERSION} artifacts in loong64 container ==="
    docker run --rm --platform="$DEB_SRC_ARTIFACTS_PLATFORM" \
        --entrypoint /usr/bin/env \
        -v "$ROOT_DIR:/work" -w /work \
        -e SRC_BUILD_MODE=native \
        -e SYSROOT_DIR="/work/$rel" \
        -e SRC_BUILDS="openssl" \
        -e OPENSSL_VERSION="$DEB_OPENSSL_VERSION" \
        -e OPENSSL_URL="$DEB_OPENSSL_URL" \
        "$DEB_SRC_ARTIFACTS_IMAGE" \
        -i \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME=/root \
        LANG=C \
        LC_ALL=C \
        /bin/bash --noprofile --norc -c "./scripts/build_src_libs.sh"
}

build_glib_artifacts_container() {
    if [[ "$DEB_SRC_BUILDS" != *"glib"* ]]; then
        return 0
    fi
    if [ "$DEB_SRC_USE_ARTIFACTS" != "1" ]; then
        return 0
    fi

    if [ -f "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/libglib-2.0.so.0" ] || [ -f "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/libglib-2.0.so" ]; then
        echo "✅ GLib artifacts already present: $DEB_GLIB_ARTIFACTS_DIR"
        return 0
    fi

    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: docker not found; cannot build GLib artifacts."
        exit 1
    fi

    mkdir -p "$DEB_GLIB_ARTIFACTS_DIR"
    local rel
    rel="${DEB_GLIB_ARTIFACTS_DIR#$ROOT_DIR/}"
    if [ "$rel" = "$DEB_GLIB_ARTIFACTS_DIR" ]; then
        echo "ERROR: DEB_GLIB_ARTIFACTS_DIR must be under repo root ($ROOT_DIR) for container build."
        exit 1
    fi

    echo "=== Building GLib ${DEB_GLIB_VERSION} artifacts in loong64 container ==="
    docker run --rm --platform="$DEB_SRC_ARTIFACTS_PLATFORM" \
        --entrypoint /usr/bin/env \
        -v "$ROOT_DIR:/work" -w /work \
        -e SRC_BUILD_MODE=native \
        -e SYSROOT_DIR="/work/$rel" \
        -e SRC_BUILDS="glib" \
        -e GLIB_VERSION="$DEB_GLIB_VERSION" \
        -e GLIB_URL="$DEB_GLIB_URL" \
        "$DEB_SRC_ARTIFACTS_IMAGE" \
        -i \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME=/root \
        LANG=C \
        LC_ALL=C \
        /bin/bash --noprofile --norc -c "./scripts/build_src_libs.sh"
}

install_openssl_artifacts_into_sysroot() {
    if [[ "$DEB_SRC_BUILDS" != *"openssl"* ]]; then
        return 0
    fi
    if [ "$DEB_SRC_USE_ARTIFACTS" != "1" ]; then
        return 0
    fi

    if [ ! -d "$DEB_SRC_ARTIFACTS_DIR/usr/lib64" ]; then
        echo "ERROR: OpenSSL artifacts not found at $DEB_SRC_ARTIFACTS_DIR"
        exit 1
    fi

    echo "=== Installing OpenSSL artifacts into Debian sysroot ==="
    sudo mkdir -p "$TARGET_DIR/usr/lib64" "$TARGET_DIR/usr/bin" "$TARGET_DIR/etc"
    sudo cp -a "$DEB_SRC_ARTIFACTS_DIR/usr/lib64/." "$TARGET_DIR/usr/lib64/"
    if [ -d "$DEB_SRC_ARTIFACTS_DIR/usr/bin" ]; then
        sudo cp -a "$DEB_SRC_ARTIFACTS_DIR/usr/bin/openssl" "$TARGET_DIR/usr/bin/" 2>/dev/null || true
    fi
    if [ -d "$DEB_SRC_ARTIFACTS_DIR/etc/ssl" ]; then
        sudo cp -a "$DEB_SRC_ARTIFACTS_DIR/etc/ssl" "$TARGET_DIR/etc/"
    fi

    enable_openssl_legacy_provider_deb
    verify_openssl_symbols_deb
}

install_glib_artifacts_into_sysroot() {
    if [[ "$DEB_SRC_BUILDS" != *"glib"* ]]; then
        return 0
    fi
    if [ "$DEB_SRC_USE_ARTIFACTS" != "1" ]; then
        return 0
    fi

    if [ ! -d "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64" ]; then
        echo "ERROR: GLib artifacts not found at $DEB_GLIB_ARTIFACTS_DIR"
        exit 1
    fi

    echo "=== Installing GLib artifacts into Debian sysroot ==="
    sudo mkdir -p "$TARGET_DIR/usr/lib64"
    for lib in libglib-2.0 libgobject-2.0 libgio-2.0 libgmodule-2.0 libgthread-2.0; do
        sudo cp -a "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/${lib}.so"* "$TARGET_DIR/usr/lib64/" 2>/dev/null || true
    done
    if [ -d "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/glib-2.0" ]; then
        sudo cp -a "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/glib-2.0" "$TARGET_DIR/usr/lib64/"
    fi
    if [ -d "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/gio" ]; then
        sudo cp -a "$DEB_GLIB_ARTIFACTS_DIR/usr/lib64/gio" "$TARGET_DIR/usr/lib64/"
    fi
    if [ -d "$DEB_GLIB_ARTIFACTS_DIR/usr/share/glib-2.0" ]; then
        sudo mkdir -p "$TARGET_DIR/usr/share"
        sudo cp -a "$DEB_GLIB_ARTIFACTS_DIR/usr/share/glib-2.0" "$TARGET_DIR/usr/share/"
    fi

    verify_glib_symbols_deb
}

find_lib_in_sysroot() {
    local pattern="$1"
    find \
        "$TARGET_DIR/usr/lib" \
        "$TARGET_DIR/usr/lib64" \
        "$TARGET_DIR/lib" \
        "$TARGET_DIR/lib64" \
        -name "$pattern" 2>/dev/null | head -n 1
}

ensure_lib_from_pkg() {
    local pkg="$1"
    local pattern="$2"
    local found
    local deb_path

    found="$(find_lib_in_sysroot "$pattern")"
    if [ -n "$found" ]; then
        echo "✅ Verified: Found $found"
        return 0
    fi

    echo "WARNING: $pattern not found; trying cached .deb for $pkg..."
    deb_path="$(awk -v p="$pkg" '$1==p {print $2; exit}' \
        "$TARGET_DIR/debootstrap/debpaths" 2>/dev/null)"
    if [ -n "$deb_path" ] && [ -f "$TARGET_DIR$deb_path" ]; then
        sudo dpkg-deb -x "$TARGET_DIR$deb_path" "$TARGET_DIR"
    fi

    found="$(find_lib_in_sysroot "$pattern")"
    if [ -n "$found" ]; then
        echo "✅ Verified: Found $found"
        return 0
    fi

    echo "❌ CRITICAL: $pattern not found after fallback."
    echo "Hint: check $TARGET_DIR/debootstrap/debootstrap.log for dpkg errors."
    return 1
}

check_nonstandard_libs() {
    local entry pkg pattern
    for entry in "${NONSTANDARD_LIB_CHECKS[@]}"; do
        pkg="${entry%%:*}"
        pattern="${entry#*:}"
        if ! ensure_lib_from_pkg "$pkg" "$pattern"; then
            return 1
        fi
    done
}

echo "=== 0. Prepare Build Env ==="
sudo apt-get update
sudo apt-get install -y wget curl binfmt-support binutils

# --- 1. 下载并安装 QEMU ---
echo ">>> Installing QEMU v10.0.4..."
rm -f qemu-package.tar.gz
wget -O qemu-package.tar.gz https://github.com/loong64/binfmt/releases/download/deploy%2Fv10.0.4-10/qemu_v10.0.4_linux-amd64.tar.gz
tar -xzvf qemu-package.tar.gz
FOUND_BIN=$(find . -type f -name "qemu-loongarch64*" ! -name "*.tar.gz" | head -n 1)
if [ -z "$FOUND_BIN" ]; then echo "Error: Binary not found!"; exit 1; fi

sudo mv "$FOUND_BIN" /usr/bin/qemu-loongarch64-static
sudo chmod +x /usr/bin/qemu-loongarch64-static
rm qemu-package.tar.gz

# --- 2. 重置 Binfmt ---
echo "=== Registering LoongArch binfmt (Aggressive Mode) ==="
if [ ! -d /proc/sys/fs/binfmt_misc ]; then
    echo "Mounting binfmt_misc..."
    sudo mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
fi
if [ -f /proc/sys/fs/binfmt_misc/qemu-loongarch64 ]; then
    echo -1 | sudo tee /proc/sys/fs/binfmt_misc/qemu-loongarch64 > /dev/null
fi
# 注意：这里我们使用了 F 标志，并指向宿主机的静态 QEMU
echo ':qemu-loongarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\x01:\xff\xff\xff\xff\xff\xff\xff\xfc\x00\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-loongarch64-static:OCF' | sudo tee /proc/sys/fs/binfmt_misc/register > /dev/null

# --- 2.5. Prebuild source libs (artifacts) ---
if [ "$DEB_SRC_USE_ARTIFACTS" = "1" ] && [ "$DEB_SRC_BUILD_ARTIFACTS" = "1" ]; then
    build_openssl_artifacts_container
    build_glib_artifacts_container
fi

# --- 3. 修复 Keyring ---
echo ">>> Fetching latest Debian Ports Keyring..."
KEY_TEMP="temp_keyring_extract"
rm -rf "$KEY_TEMP"
mkdir -p "$KEY_TEMP"
KEYRING_URL="http://ftp.debian.org/debian/pool/main/d/debian-ports-archive-keyring/"
LATEST_KEYRING_DEB=$(curl -s "$KEYRING_URL" | grep -o 'debian-ports-archive-keyring_[0-9.]\+_all.deb' | sort -V | tail -n 1)
wget -q -O "$KEY_TEMP/keyring.deb" "${KEYRING_URL}${LATEST_KEYRING_DEB}"
dpkg-deb -x "$KEY_TEMP/keyring.deb" "$KEY_TEMP/out"
CUSTOM_KEYRING="$(pwd)/$KEY_TEMP/out/usr/share/keyrings/debian-ports-archive-keyring.gpg"
echo "✅ Using fresh keyring: $CUSTOM_KEYRING"

# --- 4. 准备 Debootstrap ---
echo ">>> Preparing Debootstrap..."
rm -rf debootstrap-master
wget -q https://salsa.debian.org/installer-team/debootstrap/-/archive/master/debootstrap-master.tar.gz
tar -xzf debootstrap-master.tar.gz
cd debootstrap-master
sudo make install
DEBOOTSTRAP_BIN="$(command -v debootstrap || true)"
if [ -z "$DEBOOTSTRAP_BIN" ]; then
    for candidate in /usr/local/sbin/debootstrap /usr/sbin/debootstrap; do
        if [ -x "$candidate" ]; then
            DEBOOTSTRAP_BIN="$candidate"
            break
        fi
    done
fi
if [ -z "$DEBOOTSTRAP_BIN" ]; then
    echo "Error: debootstrap not found in PATH after install!"
    exit 1
fi
cd ..

echo "=== 1. Start Build Debootstrap (Download Stage) ==="
if [ -d "$TARGET_DIR" ]; then sudo rm -rf "$TARGET_DIR"; fi
sudo mkdir -p "$TARGET_DIR"

echo "Running debootstrap Stage 1..."
sudo "$DEBOOTSTRAP_BIN" --arch="$ARCH" \
    --foreign \
    --keyring="$CUSTOM_KEYRING" \
    --include="$VERIFIED_PKGS" \
    "$DISTRO" "$TARGET_DIR" "$MIRROR"

# 清理临时密钥
rm -rf "$KEY_TEMP"

echo "=== 2. Config (Install Stage) ==="
sudo cp /usr/bin/qemu-loongarch64-static "$TARGET_DIR/usr/bin/"
sudo ln -sf /bin/bash "$TARGET_DIR/bin/sh"

echo ">>> Pre-flight Check..."
if ! sudo chroot "$TARGET_DIR" /bin/true; then
    echo "❌ FATAL ERROR: Unable to execute binaries inside chroot!"
    exit 1
fi

echo ">>> Running Debootstrap Second Stage (internal runner)..."
cat <<'EOF' | sudo tee "$TARGET_DIR/stage2_runner.sh" > /dev/null
#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "Starting Second Stage inside chroot..."
/debootstrap/debootstrap --second-stage
EOF
sudo chmod +x "$TARGET_DIR/stage2_runner.sh"
sudo chroot "$TARGET_DIR" /stage2_runner.sh
if [ "$DEB_SRC_USE_ARTIFACTS" = "1" ]; then
    install_openssl_artifacts_into_sysroot
    install_glib_artifacts_into_sysroot
else
    if [[ "$DEB_SRC_BUILDS" == *"glib"* ]]; then
        echo "ERROR: GLib source build inside Debian chroot is not supported."
        echo "Hint: set DEB_SRC_USE_ARTIFACTS=1 and build artifacts in loong64 container."
        exit 1
    fi
    SRC_BUILD_MODE=debian SYSROOT_DIR="$TARGET_DIR" \
        SRC_BUILDS="$DEB_SRC_BUILDS" \
        OPENSSL_VERSION="$DEB_OPENSSL_VERSION" \
        OPENSSL_URL="$DEB_OPENSSL_URL" \
        SUDO="sudo" \
        bash scripts/build_src_libs.sh
fi
sudo rm "$TARGET_DIR/stage2_runner.sh"

echo ">>> Verifying Non-Standard Libraries..."
if ! check_nonstandard_libs; then
    exit 1
fi

# ==========================================
# 3. Post-Fixes & Symlinks
# ==========================================
echo "=== 3. Clean & Fix ==="
sudo rm "$TARGET_DIR/usr/bin/qemu-loongarch64-static"
sudo rm -rf "$TARGET_DIR/var/cache/apt/archives/*.deb"

echo "Applying Symlink Hacks..."
LIB_DIR="$TARGET_DIR/usr/lib/loongarch64-linux-gnu"

# 1. libunistring
if [ -f "$LIB_DIR/libunistring.so.5" ]; then
    sudo ln -sf libunistring.so.5 "$LIB_DIR/libunistring.so.2"
fi

# 2. libgnutls
if [ ! -f "$LIB_DIR/libgnutls.so.30" ]; then
    REAL_LIB=$(find "$LIB_DIR" -name "libgnutls.so.30.*" -printf "%f\n" | head -n 1)
    if [ -n "$REAL_LIB" ]; then
        sudo ln -sf "$REAL_LIB" "$LIB_DIR/libgnutls.so.30"
    fi
fi
# Box64 may dlopen libgnutls.so (unversioned).
if [ ! -f "$LIB_DIR/libgnutls.so" ]; then
    REAL_LIB=$(find "$LIB_DIR" -name "libgnutls.so.30.*" -printf "%f\n" | head -n 1)
    if [ -n "$REAL_LIB" ]; then
        sudo ln -sf "$REAL_LIB" "$LIB_DIR/libgnutls.so"
    fi
fi

if [ -f "scripts/fix_links.py" ]; then sudo python3 scripts/fix_links.py "$TARGET_DIR"; fi

# ==========================================
# 3.5 Normalize Debian libs into lib64
# ==========================================
echo "Normalizing Debian libs into lib64 (real files)..."
sudo mkdir -p "$TARGET_DIR/lib64" "$TARGET_DIR/usr/lib64"

COPY_SRC_DIRS=(
    "$TARGET_DIR/lib/loongarch64-linux-gnu"
    "$TARGET_DIR/usr/lib/loongarch64-linux-gnu"
)

for src_dir in "${COPY_SRC_DIRS[@]}"; do
    if [ -d "$src_dir" ]; then
        while IFS= read -r -d '' sofile; do
            base="$(basename "$sofile")"
            for dest in "$TARGET_DIR/lib64/$base" "$TARGET_DIR/usr/lib64/$base"; do
                if [ ! -e "$dest" ] || [ -L "$dest" ]; then
                    sudo rm -f "$dest"
                    sudo cp -aL "$sofile" "$dest"
                fi
            done
        done < <(find "$src_dir" -maxdepth 1 \( -type f -o -type l \) -name "*.so*" -print0)
    fi
done

# Ensure loader exists in /lib64 (copy real file if needed)
if [ ! -f "$TARGET_DIR/lib64/ld-linux-loongarch-lp64d.so.1" ]; then
    for candidate in \
        "$TARGET_DIR/lib/loongarch64-linux-gnu/ld-linux-loongarch-lp64d.so.1" \
        "$TARGET_DIR/usr/lib/loongarch64-linux-gnu/ld-linux-loongarch-lp64d.so.1"; do
        if [ -e "$candidate" ]; then
            sudo cp -aL "$candidate" "$TARGET_DIR/lib64/ld-linux-loongarch-lp64d.so.1"
            break
        fi
    done
fi

# ==========================================
# 4. Package Runtime Libs
# ==========================================
echo "=== 4. Package Runtime Libs (For Box64) ==="
RUNTIME_TAR="debian-${DISTRO}-${ARCH}-runtime-libs.tar.gz"
TEMP_RUNTIME="runtime-libs-temp"
rm -rf "$TEMP_RUNTIME"
mkdir -p "$TEMP_RUNTIME/usr"

echo "Copying libraries..."
sudo cp -a "$TARGET_DIR/lib" "$TEMP_RUNTIME/" || true
sudo cp -a "$TARGET_DIR/lib64" "$TEMP_RUNTIME/" || true
sudo cp -a "$TARGET_DIR/usr/lib" "$TEMP_RUNTIME/usr/" || true
sudo cp -a "$TARGET_DIR/usr/lib64" "$TEMP_RUNTIME/usr/" || true
sudo cp -a "$TARGET_DIR/etc" "$TEMP_RUNTIME/" || true

echo "Packaging Runtime Artifact: $RUNTIME_TAR ..."
sudo tar -czf "$RUNTIME_TAR" -C "$TEMP_RUNTIME" .
sudo chown $USER:$USER "$RUNTIME_TAR"
sudo rm -rf "$TEMP_RUNTIME"

# ==========================================
# 5. Package Full Sysroot
# ==========================================
echo "=== 5. Package Full Sysroot ==="
FULL_TAR="debian-${DISTRO}-${ARCH}-sysroot.tar.gz"
echo "Packaging Full Artifact: $FULL_TAR ..."
sudo tar -czf "$FULL_TAR" -C "$TARGET_DIR" .
sudo chown $USER:$USER "$FULL_TAR"

echo "🎉 Build Success!"
