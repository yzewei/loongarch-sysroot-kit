#!/bin/bash
set -e

# ================= Configuration =================
ARCH="loong64"
DISTRO="sid"
TARGET_DIR="sysroot-loong64"
# loong64 使用 debian-ports；可用环境变量 MIRROR 覆盖
MIRROR="${MIRROR:-http://ftp.ports.debian.org/debian-ports}"

# ✅ 包列表 (保持不变)
VERIFIED_PKGS="ca-certificates,wget,curl,perl-base,bash,usr-is-merged,libc6,libstdc++6,libgcc-s1,libssl3t64,zlib1g,liblzma5,libzstd1,libbz2-1.0,libcrypt1,libgcrypt20,libgpg-error0,liblz4-1,libp11-kit0,libffi8,libidn2-0,libunistring5,libtasn1-6,libgnutls30t64,libsystemd0,libglib2.0-0t64,libxml2,libsqlite3-0,libatomic1,libpsl5t64,libgssapi-krb5-2,libkrb5-3,libbrotli1,libevent-2.1-7t64,libkeyutils1,libcom-err2,libkrb5support0,libk5crypto3"
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
sudo apt-get install -y wget curl binfmt-support

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
