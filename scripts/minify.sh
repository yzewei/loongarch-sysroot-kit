#!/bin/bash
set -e

FULL_SYSROOT="sysroot-loong64"
MINI_DIR="sysroot-libs-only"

echo "=== Creating Minified Sysroot for Box64 ==="

# 1. 清理旧目录
rm -rf "$MINI_DIR"
mkdir -p "$MINI_DIR/usr"

# 2. 核心：只复制库文件和链接器配置
# Box64 运行只需要：/lib, /lib64, /usr/lib, /etc (用于 ld.so.conf)

echo "Copying /lib..."
cp -a "$FULL_SYSROOT/lib" "$MINI_DIR/"

echo "Copying /lib64..."
# LoongArch64 的动态链接器 ld-linux 就在这里
cp -a "$FULL_SYSROOT/lib64" "$MINI_DIR/"

echo "Copying /usr/lib..."
cp -a "$FULL_SYSROOT/usr/lib" "$MINI_DIR/usr/"

echo "Copying /etc (configs)..."
# 我们只复制 etc 里的配置，避免复制太大的文件，但为了保险通常 cp -a 整个 etc 也不大
cp -a "$FULL_SYSROOT/etc" "$MINI_DIR/"

# 3. 清理不需要的静态库 (.a) 和 pkgconfig (如果只为了运行，不需要开发文件)
# 可选：如果你只做运行时，可以删掉 .a 文件减小体积
# find "$MINI_DIR" -name "*.a" -delete
# find "$MINI_DIR" -name "*.o" -delete

# 4. 打包
TAR_NAME="loong64-libs-minimal.tar.gz"
echo "Packaging to $TAR_NAME..."
tar -czf "$TAR_NAME" -C "$MINI_DIR" .

echo "Done! Size comparison:"
du -sh "$FULL_SYSROOT"
du -sh "$MINI_DIR"
echo "Artifact: $TAR_NAME"
