#!/usr/bin/env bash
set -euo pipefail

# Shared source-build helper for sysroots.
# Supported libs: openssl, glib

SRC_BUILD_MODE="${SRC_BUILD_MODE:-}"
SYSROOT_DIR="${SYSROOT_DIR:-}"
SRC_BUILDS="${SRC_BUILDS:-openssl}"
OPENSSL_VERSION="${OPENSSL_VERSION:-3.2.2}"
OPENSSL_URL="${OPENSSL_URL:-https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz}"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-/usr}"
OPENSSL_DIR="${OPENSSL_DIR:-/etc/ssl}"
OPENSSL_LIBDIR="${OPENSSL_LIBDIR:-lib64}"
SUDO="${SUDO:-}"

GLIB_VERSION="${GLIB_VERSION:-2.78.3}"
GLIB_SERIES="${GLIB_SERIES:-${GLIB_VERSION%.*}}"
GLIB_URL="${GLIB_URL:-https://download.gnome.org/sources/glib/${GLIB_SERIES}/glib-${GLIB_VERSION}.tar.xz}"
GLIB_PREFIX="${GLIB_PREFIX:-/usr}"
GLIB_LIBDIR="${GLIB_LIBDIR:-lib64}"
GLIB_MESON_FLAGS="${GLIB_MESON_FLAGS:--Dtests=false -Dman=false -Dglib_debug=disabled -Ddefault_library=shared -Dgtk_doc=false -Dintrospection=disabled -Dsysprof=disabled -Dsystemtap=disabled -Ddtrace=disabled -Dselinux=disabled -Dlibmount=disabled}"

if [ -z "$SYSROOT_DIR" ]; then
    echo "ERROR: SYSROOT_DIR is required."
    exit 1
fi

if [[ "$SRC_BUILDS" != *"openssl"* && "$SRC_BUILDS" != *"glib"* ]]; then
    echo "No source builds requested (SRC_BUILDS=$SRC_BUILDS)."
    exit 0
fi

if [ -z "$SRC_BUILD_MODE" ]; then
    echo "ERROR: SRC_BUILD_MODE is required (debian|ocs|native)."
    exit 1
fi

enable_openssl_legacy_provider() {
    local conf=""
    if [ -f "$SYSROOT_DIR/etc/ssl/openssl.cnf" ]; then
        conf="$SYSROOT_DIR/etc/ssl/openssl.cnf"
    elif [ -f "$SYSROOT_DIR/etc/pki/tls/openssl.cnf" ]; then
        conf="$SYSROOT_DIR/etc/pki/tls/openssl.cnf"
    else
        echo "WARNING: openssl.cnf not found; skipping legacy provider enable."
        return 0
    fi

    if ! grep -Eq '^[[:space:]]*openssl_conf[[:space:]]*=' "$conf"; then
        local tmp_conf
        tmp_conf="$(mktemp)"
        {
            echo "openssl_conf = openssl_init"
            echo
            cat "$conf"
        } > "$tmp_conf"
        mv "$tmp_conf" "$conf"
    fi

    if ! grep -Eq '^[[:space:]]*\\[openssl_init\\]' "$conf"; then
        {
            echo
            echo "[openssl_init]"
            echo "providers = provider_sect"
            echo
        } >> "$conf"
    fi

    if ! grep -Eq '^[[:space:]]*\\[provider_sect\\]' "$conf"; then
        {
            echo "[provider_sect]"
            echo "default = default_sect"
            echo "legacy = legacy_sect"
            echo
        } >> "$conf"
    fi

    if ! grep -Eq '^[[:space:]]*\\[legacy_sect\\]' "$conf"; then
        {
            echo "[legacy_sect]"
            echo "activate = 1"
            echo
        } >> "$conf"
    fi

    echo "✅ Enabled OpenSSL legacy provider in $conf"
}

verify_openssl_symbols() {
    local libcrypto libssl
    local search_dirs=()
    for d in "$SYSROOT_DIR/usr/lib64" "$SYSROOT_DIR/lib64" "$SYSROOT_DIR/usr/lib" "$SYSROOT_DIR/lib"; do
        if [ -d "$d" ]; then
            search_dirs+=("$d")
        fi
    done
    if [ "${#search_dirs[@]}" -eq 0 ]; then
        echo "❌ CRITICAL: no library directories found under $SYSROOT_DIR."
        return 1
    fi

    libcrypto="$(find "${search_dirs[@]}" -name 'libcrypto.so.3' 2>/dev/null | head -n 1 || true)"
    libssl="$(find "${search_dirs[@]}" -name 'libssl.so.3' 2>/dev/null | head -n 1 || true)"

    if [ -z "$libcrypto" ] || [ -z "$libssl" ]; then
        echo "❌ CRITICAL: OpenSSL libs not found for symbol verification."
        echo "libcrypto: ${libcrypto:-<missing>}"
        echo "libssl: ${libssl:-<missing>}"
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

    list_dyn_syms() {
        local so="$1"
        if command -v nm >/dev/null 2>&1; then
            nm -D --defined-only "$so" 2>/dev/null | awk '{print $3}' | sed 's/@.*//'
        else
            readelf -Ws "$so" 2>/dev/null | awk '{print $8}' | sed 's/@.*//'
        fi
    }

    local crypto_sym_list ssl_sym_list missing=0
    crypto_sym_list="$(list_dyn_syms "$libcrypto")"
    ssl_sym_list="$(list_dyn_syms "$libssl")"

    for sym in "${crypto_syms[@]}"; do
        if ! printf '%s\n' "$crypto_sym_list" | grep -qx "$sym"; then
            echo "❌ Missing libcrypto symbol: $sym"
            missing=1
        fi
    done
    for sym in "${ssl_syms[@]}"; do
        if ! printf '%s\n' "$ssl_sym_list" | grep -qx "$sym"; then
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

build_openssl_native() {
    local fetcher=""
    if command -v curl >/dev/null 2>&1; then
        fetcher="curl"
    elif command -v wget >/dev/null 2>&1; then
        fetcher="wget"
    fi

    if command -v gcc >/dev/null 2>&1 && \
        command -v make >/dev/null 2>&1 && \
        command -v perl >/dev/null 2>&1 && \
        { [ -n "$fetcher" ]; } && \
        command -v tar >/dev/null 2>&1 && \
        command -v readelf >/dev/null 2>&1; then
        echo "✅ Build tools already available; skipping package install."
    else
    if command -v dnf >/dev/null 2>&1; then
        local dnf_bin
        dnf_bin="$(command -v dnf)"
        run_dnf() {
            if [ -n "$SUDO" ]; then
                $SUDO "$dnf_bin" "$@"
            else
                "$dnf_bin" "$@"
            fi
        }
        run_dnf -y install gcc make perl-core perl-IPC-Cmd ca-certificates tar binutils curl-minimal || \
            run_dnf -y install gcc make perl ca-certificates tar binutils curl-minimal || \
            run_dnf -y install gcc make perl-core perl-IPC-Cmd ca-certificates tar binutils wget || \
            run_dnf -y install gcc make perl ca-certificates tar binutils wget || \
            run_dnf --assumeyes install gcc make perl-core perl-IPC-Cmd ca-certificates tar binutils curl-minimal || \
            run_dnf --assumeyes install gcc make perl ca-certificates tar binutils curl-minimal || \
            run_dnf --assumeyes install gcc make perl-core perl-IPC-Cmd ca-certificates tar binutils wget || \
            run_dnf --assumeyes install gcc make perl ca-certificates tar binutils wget
    elif command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update
        $SUDO apt-get install -y build-essential perl curl ca-certificates tar binutils
    else
        echo "ERROR: no package manager available to install build tools."
        exit 1
    fi
        if command -v curl >/dev/null 2>&1; then
            fetcher="curl"
        elif command -v wget >/dev/null 2>&1; then
            fetcher="wget"
        else
            echo "ERROR: curl or wget is required to download OpenSSL."
            exit 1
        fi
    fi

    local workdir
    workdir="$(mktemp -d)"
    (
        cd "$workdir"
        echo "Downloading ${OPENSSL_URL}..."
        if [ "$fetcher" = "curl" ]; then
            curl -fsSL "$OPENSSL_URL" -o openssl.tar.gz
        else
            wget -qO openssl.tar.gz "$OPENSSL_URL"
        fi
        tar -xzf openssl.tar.gz
        cd "openssl-${OPENSSL_VERSION}"
        ./Configure linux64-loongarch64 \
            --prefix="$OPENSSL_PREFIX" \
            --openssldir="$OPENSSL_DIR" \
            --libdir="$OPENSSL_LIBDIR" \
            shared
        make -j"$(nproc)"
        make DESTDIR="$SYSROOT_DIR" install_sw install_ssldirs
    )
    rm -rf "$workdir"
}

build_openssl_debian() {
    $SUDO mkdir -p "$SYSROOT_DIR/tmp"
    cat <<EOD | $SUDO tee "$SYSROOT_DIR/tmp/build_src_libs.sh" >/dev/null
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y build-essential perl curl ca-certificates tar
cd /tmp
curl -fsSL "${OPENSSL_URL}" -o openssl.tar.gz
tar -xzf openssl.tar.gz
cd openssl-${OPENSSL_VERSION}
./Configure linux64-loongarch64 --prefix=${OPENSSL_PREFIX} --openssldir=${OPENSSL_DIR} --libdir=${OPENSSL_LIBDIR} shared
make -j\$(nproc)
make install_sw install_ssldirs
apt-get purge -y build-essential perl curl || true
apt-get autoremove -y || true
rm -rf /var/lib/apt/lists/* /tmp/openssl.tar.gz /tmp/openssl-${OPENSSL_VERSION}
EOD
    $SUDO chmod +x "$SYSROOT_DIR/tmp/build_src_libs.sh"
    $SUDO chroot "$SYSROOT_DIR" /bin/bash /tmp/build_src_libs.sh
    $SUDO rm -f "$SYSROOT_DIR/tmp/build_src_libs.sh"
}

build_glib_native() {
    local fetcher=""
    if command -v curl >/dev/null 2>&1; then
        fetcher="curl"
    elif command -v wget >/dev/null 2>&1; then
        fetcher="wget"
    fi

    if command -v gcc >/dev/null 2>&1 && \
        command -v meson >/dev/null 2>&1 && \
        command -v ninja >/dev/null 2>&1 && \
        command -v pkg-config >/dev/null 2>&1 && \
        command -v python3 >/dev/null 2>&1 && \
        { [ -n "$fetcher" ]; } && \
        command -v tar >/dev/null 2>&1; then
        echo "✅ GLib build tools already available; skipping package install."
    else
        if command -v dnf >/dev/null 2>&1; then
            local dnf_bin
            dnf_bin="$(command -v dnf)"
            run_dnf() {
                if [ -n "$SUDO" ]; then
                    $SUDO "$dnf_bin" "$@"
                else
                    "$dnf_bin" "$@"
                fi
            }
            run_dnf -y install gcc meson ninja-build pkgconf-pkg-config python3 ca-certificates tar xz \
                libffi-devel pcre2-devel zlib-devel gettext || \
            run_dnf -y install gcc meson ninja-build pkgconf-pkg-config python3 ca-certificates tar xz \
                libffi-devel pcre2-devel zlib-devel || \
            run_dnf --assumeyes install gcc meson ninja-build pkgconf-pkg-config python3 ca-certificates tar xz \
                libffi-devel pcre2-devel zlib-devel gettext || \
            run_dnf --assumeyes install gcc meson ninja-build pkgconf-pkg-config python3 ca-certificates tar xz \
                libffi-devel pcre2-devel zlib-devel
        elif command -v apt-get >/dev/null 2>&1; then
            $SUDO apt-get update
            $SUDO apt-get install -y build-essential meson ninja-build pkg-config python3 ca-certificates \
                tar xz-utils libffi-dev libpcre2-dev zlib1g-dev gettext
        else
            echo "ERROR: no package manager available to install GLib build tools."
            exit 1
        fi

        if command -v curl >/dev/null 2>&1; then
            fetcher="curl"
        elif command -v wget >/dev/null 2>&1; then
            fetcher="wget"
        else
            echo "ERROR: curl or wget is required to download GLib."
            exit 1
        fi
    fi

    local workdir
    workdir="$(mktemp -d)"
    (
        cd "$workdir"
        echo "Downloading ${GLIB_URL}..."
        if [ "$fetcher" = "curl" ]; then
            curl -fsSL "$GLIB_URL" -o glib.tar.xz
        else
            wget -qO glib.tar.xz "$GLIB_URL"
        fi
        tar -xJf glib.tar.xz
        cd "glib-${GLIB_VERSION}"
        local meson_flags=()
        if [ -f "meson_options.txt" ]; then
            local raw_flags=()
            read -r -a raw_flags <<< "$GLIB_MESON_FLAGS"
            local flag opt
            for flag in "${raw_flags[@]}"; do
                if [[ "$flag" == -D*=* ]]; then
                    opt="${flag#-D}"
                    opt="${opt%%=*}"
                    if grep -Eq "option\\(['\"]${opt}['\"]" meson_options.txt; then
                        meson_flags+=("$flag")
                    else
                        echo "INFO: GLib option '${opt}' not found; dropping flag ${flag}"
                    fi
                else
                    meson_flags+=("$flag")
                fi
            done
        else
            read -r -a meson_flags <<< "$GLIB_MESON_FLAGS"
        fi
        meson setup build \
            --prefix="$GLIB_PREFIX" \
            --libdir="$GLIB_LIBDIR" \
            "${meson_flags[@]}"
        ninja -C build
        DESTDIR="$SYSROOT_DIR" ninja -C build install
    )
    rm -rf "$workdir"
}

verify_glib_symbols() {
    local libglib
    libglib="$(find "$SYSROOT_DIR/usr/lib64" "$SYSROOT_DIR/lib64" "$SYSROOT_DIR/usr/lib" "$SYSROOT_DIR/lib" -name 'libglib-2.0.so.*' 2>/dev/null | head -n 1 || true)"
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

    local sym_list
    if command -v nm >/dev/null 2>&1; then
        sym_list="$(nm -D --defined-only "$libglib" 2>/dev/null | awk '{print $3}' | sed 's/@.*//')"
    else
        sym_list="$(readelf -Ws "$libglib" 2>/dev/null | awk '{print $8}' | sed 's/@.*//')"
    fi

    local missing=0
    for sym in "${glib_syms[@]}"; do
        if ! printf '%s\n' "$sym_list" | grep -qx "$sym"; then
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

build_glib_debian() {
    echo "ERROR: GLib source build inside Debian chroot is not supported."
    echo "Hint: set SRC_BUILD_MODE=native in a loong64 container and use artifacts."
    exit 1
}

if [[ "$SRC_BUILDS" == *"openssl"* ]]; then
    echo "=== Building OpenSSL ${OPENSSL_VERSION} (mode=${SRC_BUILD_MODE}) ==="
    case "$SRC_BUILD_MODE" in
        debian)
            build_openssl_debian
            ;;
        ocs|native)
            build_openssl_native
            ;;
        *)
            echo "ERROR: Unsupported SRC_BUILD_MODE=$SRC_BUILD_MODE (expected debian|ocs|native)."
            exit 1
            ;;
    esac

    enable_openssl_legacy_provider
    verify_openssl_symbols
fi

if [[ "$SRC_BUILDS" == *"glib"* ]]; then
    echo "=== Building GLib ${GLIB_VERSION} (mode=${SRC_BUILD_MODE}) ==="
    case "$SRC_BUILD_MODE" in
        debian)
            build_glib_debian
            ;;
        ocs|native)
            build_glib_native
            ;;
        *)
            echo "ERROR: Unsupported SRC_BUILD_MODE=$SRC_BUILD_MODE (expected debian|ocs|native)."
            exit 1
            ;;
    esac

    verify_glib_symbols
fi
