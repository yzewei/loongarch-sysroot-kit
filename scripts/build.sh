#!/bin/bash
set -e

# env Larch
ARCH="loong64"
DISTRO="sid"
TARGET_DIR="sysroot-loong64"
MIRROR="http://ftp.ports.debian.org/debian-ports"

echo "=== 0. Prepare Build Env ==="
sudo apt-get update
sudo apt-get install -y wget curl

echo ">>> Installing QEMU v10.0.4 (User Specified)..."
# 1. 下载你指定的 tar.gz 包
wget -q -O qemu-package.tar.gz https://github.com/loong64/binfmt/releases/download/deploy%2Fv10.0.4-10/qemu_v10.0.4_linux-amd64.tar.gz

# 2. 解压
tar -xzf qemu-package.tar.gz

# 3. 安装 (自动找到解压出的二进制文件并重命名移入 /usr/bin)
# 注意：解压出来的名字可能是 qemu-loongarch64，我们需要把它重命名为 qemu-loongarch64-static 以配合后续脚本
find . -maxdepth 1 -type f -name "qemu-loongarch64*" ! -name "*.tar.gz" -exec sudo mv {} /usr/bin/qemu-loongarch64-static \;

# 4. 赋予执行权限并清理
sudo chmod +x /usr/bin/qemu-loongarch64-static
rm qemu-package.tar.gz
echo "QEMU installed version:"
/usr/bin/qemu-loongarch64-static --version

echo ">>> Detecting and installing latest Debian Ports Keyring..."
REPO_URL="http://ftp.debian.org/debian/pool/main/d/debian-ports-archive-keyring/"
LATEST_DEB=$(curl -s $REPO_URL | grep -o 'debian-ports-archive-keyring_[0-9.]\+_all.deb' | sort -V | tail -n 1)

if [ -z "$LATEST_DEB" ]; then
    echo "Error: Failed to detect latest keyring version."
    exit 1
fi

echo "Found latest keyring: $LATEST_DEB"
wget "${REPO_URL}${LATEST_DEB}"
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
# 包列表 (已修正无误)
PACKAGES="libc6,libstdc++6,libgcc-s1,libssl3t64,zlib1g,liblzma5,libzstd1,libbz2-1.0,libcrypt1,perl-base"

sudo mkdir -p "$TARGET_DIR"

echo "Running debootstrap..."
sudo debootstrap --arch="$ARCH" --foreign --keyring=/usr/share/keyrings/debian-ports-archive-keyring.gpg --include="$PACKAGES" "$DISTRO" "$TARGET_DIR" "$MIRROR"

echo "=== 2. Config (Second Stage) ==="
# 复制我们刚才下载的新版 QEMU 进 chroot 环境
sudo cp /usr/bin/qemu-loongarch64-static "$TARGET_DIR/usr/bin/"

echo "Running second-stage configuration..."
sudo chroot "$TARGET_DIR" /debootstrap/debootstrap --second-stage

echo "=== 3. Clean & Fix ==="
sudo rm -rf "$TARGET_DIR/var/cache/apt/archives/*"
sudo rm "$TARGET_DIR/usr/bin/qemu-loongarch64-static"

echo "Fixing symlinks..."
if [ -f "scripts/fix_links.py" ]; then
    sudo python3 scripts/fix_links.py "$TARGET_DIR"
else
    echo "Warning: scripts/fix_links.py not found!"
fi

echo "=== 4. Package ==="
TAR_NAME="debian-${DISTRO}-${ARCH}-sysroot.tar.gz"
sudo tar -czf "$TAR_NAME" -C "$TARGET_DIR" .
sudo chown $USER:$USER "$TAR_NAME"

echo "Build Success! Artifact: $TAR_NAME"
