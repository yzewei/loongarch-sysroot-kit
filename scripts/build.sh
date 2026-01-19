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
wget -O qemu-package.tar.gz https://github.com/loong64/binfmt/releases/download/deploy/v10.0.4-10/qemu_v10.0.4_linux-amd64.tar.gz

echo "Extracting tarball..."
tar -xzvf qemu-package.tar.gz

echo "Searching for qemu binary..."
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

# === 注册 binfmt (OCF 标志是必须的，用于处理 chroot 路径) ===
echo ">>> Registering LoongArch binfmt..."
if [ -f /proc/sys/fs/binfmt_misc/register ]; then
    if [ -f /proc/sys/fs/binfmt_misc/qemu-loongarch64 ]; then
        echo -1 | sudo tee /proc/sys/fs/binfmt_misc/qemu-loongarch64 > /dev/null
    fi
    # 使用 OCF 标志，允许内核在 chroot 内也能根据 Magic Number 找到宿主机的 QEMU
    echo ':qemu-loongarch64:M::\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x02\x01:\xff\xff\xff\xff\xff\xff\xff\xfc\x00\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff:/usr/bin/qemu-loongarch64-static:OCF' | sudo tee /proc/sys/fs/binfmt_misc/register > /dev/null
    echo "Binfmt registered with OCF flags."
else
    # Docker 环境备用方案
    docker run --rm --privileged multiarch/qemu-user-static --reset -p yes || true
fi

echo ">>> Preparing Keyring..."
REPO_URL="http://ftp.debian.org/debian/pool/main/d/debian-ports-archive-keyring/"
LATEST_DEB=$(curl -s $REPO_URL | grep -o 'debian-ports-archive-keyring_[0-9.]\+_all.deb' | sort -V | tail -n 1)
wget -q "${REPO_URL}${LATEST_DEB}"
sudo dpkg -i "$LATEST_DEB"
rm "$LATEST_DEB"

echo ">>> Preparing Debootstrap..."
rm -rf debootstrap-master
wget -q https://salsa.debian.org/installer-team/debootstrap/-/archive/master/debootstrap-master.tar.gz
tar -xzf debootstrap-master.tar.gz
cd debootstrap-master
sudo make install
cd ..

echo "=== 1. Start Build Debootstrap (First Stage) ==="
# 必须包含 bash，它是我们后续救命的稻草
PACKAGES="libc6,libstdc++6,libgcc-s1,libssl3t64,zlib1g,liblzma5,libzstd1,libbz2-1.0,libcrypt1,perl-base,bash"
sudo mkdir -p "$TARGET_DIR"

echo "Running debootstrap (Stage 1)..."
sudo debootstrap --arch="$ARCH" --foreign --keyring=/usr/share/keyrings/debian-ports-archive-keyring.gpg --include="$PACKAGES" "$DISTRO" "$TARGET_DIR" "$MIRROR"

echo "=== 2. Config (Second Stage) ==="
# 复制 QEMU 进去（虽然有 binfmt OCF 可能不需要，但为了保险起见）
sudo cp /usr/bin/qemu-loongarch64-static "$TARGET_DIR/usr/bin/"

# --- 关键修复：手动创建 /bin/sh ---
echo "DEBUG: Fixing /bin/sh symlink..."
# 强制让 /bin/sh 指向 /bin/bash，防止脚本因找不到解释器而报 127 错误
sudo ln -sf /bin/bash "$TARGET_DIR/bin/sh"

# --- 检查文件是否存在 ---
if [ ! -f "$TARGET_DIR/debootstrap/debootstrap" ]; then
    echo "CRITICAL ERROR: /debootstrap/debootstrap script is missing inside target!"
    exit 1
fi

echo "Running second-stage configuration..."
# 这里我们显式指定用 bash 运行，双重保险
# 解释：sudo chroot 目录 /bin/bash 脚本路径 --second-stage
sudo chroot "$TARGET_DIR" /bin/bash /debootstrap/debootstrap --second-stage

echo "=== 3. Clean & Fix ==="
sudo rm -rf "$TARGET_DIR/var/cache/apt/archives/*"
sudo rm "$TARGET_DIR/usr/bin/qemu-loongarch64-static"

echo "Fixing symlinks..."
if [ -f "scripts/fix_links.py" ]; then sudo python3 scripts/fix_links.py "$TARGET_DIR"; fi

echo "=== 4. Package ==="
TAR_NAME="debian-${DISTRO}-${ARCH}-sysroot.tar.gz"
sudo tar -czf "$TAR_NAME" -C "$TARGET_DIR" .
sudo chown $USER:$USER "$TAR_NAME"

echo "
