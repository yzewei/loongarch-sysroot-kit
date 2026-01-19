#!/bin/bash
set -e

# env Larch
ARCH="loong64"
DISTRO="sid"
TARGET_DIR="sysroot-loong64"
MIRROR="http://ftp.ports.debian.org/debian-ports"

echo "=== 0. Prepare Build Env ==="
sudo apt-get update
sudo apt-get install -y wget curl binfmt-support

echo ">>> Installing QEMU v10.0.4 (User Specified)..."
# 使用 v10.0.4 linux-amd64 包 (包含静态二进制文件)
wget -O qemu-package.tar.gz https://github.com/loong64/binfmt/releases/download/deploy%2Fv10.0.4-10/qemu_v10.0.4_linux-amd64.tar.gz

echo "Extracting tarball..."
tar -xzvf qemu-package.tar.gz

echo "Searching for qemu binary..."
# 递归查找 qemu-loongarch64-static
FOUND_BIN=$(find . -type f -name "qemu-loongarch64*" ! -name "*.tar.gz" | head -n 1)

if [ -z "$FOUND_BIN" ]; then
    echo "Error: Could not find qemu-loongarch64 binary!"
    ls -R
    exit 1
fi

echo "Found binary at: $FOUND_BIN"
sudo mv "$FOUND_BIN" /usr/bin/qemu-loongarch64-static
sudo chmod +x /usr/bin/qemu-loongarch64-static
rm qemu-package.tar.gz

echo "QEMU Installed Successfully:"
/usr/bin/qemu-loongarch64-static --version

# === 注册 binfmt (必须保留 OCF 标志) ===
echo ">>> Registering LoongArch binfmt..."
if [ -f /proc/sys/fs/binfmt_misc/register ]; then
    if [ -f /proc/sys/fs/binfmt_misc/qemu-loongarch64 ]; then
        echo -1 | sudo tee /proc/sys/fs/binfmt_misc/qemu-loongarch64 > /dev/null
    fi
    # 注册 Magic Number (保留 OCF 标志以解决 chroot 权限和打开问题)
    echo ':qemu-loongarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\x01:\xff\xff\xff\xff\xff\xff\xff\xfc\x00\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-loongarch64-static:OCF' | sudo tee /proc/sys/fs/binfmt_misc/register > /dev/null
    echo "Binfmt registered with OCF flags."
else
    echo "Warning: binfmt_misc not mounted. Using docker fallback..."
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes || true
fi

echo ">>> Detecting latest Debian Ports Keyring..."
REPO_URL="http://ftp.debian.org/debian/pool/main/d/debian-ports-archive-keyring/"
LATEST_DEB=$(curl -s $REPO_URL | grep -o 'debian-ports-archive-keyring_[0-9.]\+_all.deb' | sort -V | tail -n 1)

if [ -z "$LATEST_DEB" ]; then echo "Error: Keyring not found."; exit 1; fi
wget -q "${REPO_URL}${LATEST_DEB}"
sudo dpkg -i "$LATEST_DEB"
rm "$LATEST_DEB"

echo "Downloading latest debootstrap..."
rm -rf debootstrap-master
wget -q https://salsa.debian.org/installer-team/debootstrap/-/archive/master/debootstrap-master.tar.gz
tar -xzf debootstrap-master.tar.gz
cd debootstrap-master
sudo make install
cd ..

echo "=== 1. Start Build Debootstrap (First Stage) ==="
# 必须包含 bash
PACKAGES="libc6,libstdc++6,libgcc-s1,libssl3t64,zlib1g,liblzma5,libzstd1,libbz2-1.0,libcrypt1,perl-base,bash"
sudo mkdir -p "$TARGET_DIR"

echo "Running debootstrap..."
sudo debootstrap --arch="$ARCH" --foreign --keyring=/usr/share/keyrings/debian-ports-archive-keyring.gpg --include="$PACKAGES" "$DISTRO" "$TARGET_DIR" "$MIRROR"

echo "=== 2. Config (Second Stage) ==="
sudo cp /usr/bin/qemu-loongarch64-static "$TARGET_DIR/usr/bin/"

echo "Running second-stage configuration..."
# !!! 核心修复点 !!!
# 使用 bash -c 将命令包裹起来，避免参数歧义
sudo chroot "$TARGET_DIR" /bin/bash -c "/debootstrap/debootstrap --second-stage"

echo "=== 3. Clean & Fix ==="
sudo rm -rf "$TARGET_DIR/var/cache/apt/archives/*"
sudo rm "$TARGET_DIR/usr/bin/qemu-loongarch64-static"

echo "Fixing symlinks..."
if [ -f "scripts/fix_links.py" ]; then sudo python3 scripts/fix_links.py "$TARGET_DIR"; fi

echo "=== 4. Package ==="
TAR_NAME="debian-${DISTRO}-${ARCH}-sysroot.tar.gz"
sudo tar -czf "$TAR_NAME" -C "$TARGET_DIR" .
sudo chown $USER:$USER "$TAR_NAME"

echo "Build Success! Artifact: $TAR_NAME"
