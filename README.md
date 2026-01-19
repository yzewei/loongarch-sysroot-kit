# LoongArch Sysroot Builder 🐉

[![Build & Release Sysroot](https://github.com/yzewei/debian-loong64-sysroot/actions/workflows/build.yml/badge.svg)](https://github.com/yzewei/debian-loong64-sysroot/actions/workflows/build.yml)

**Automated CI builder for a minimal, clean Debian LoongArch (loong64) sysroot.**

This project uses GitHub Actions, QEMU, and `debootstrap` to build a pristine LoongArch system root filesystem. It is specifically optimized for:
* **Box64 Emulation**: Providing native libraries to x86/x64 containers running on LoongArch hosts.
* **Cross-Compilation**: Linking against loong64 libraries from x86 machines.

## 🚀 Why use this?

When running x86 containers on LoongArch via Box64, you often need to map native libraries (libc, libssl, libcrypt, etc.) into the container.
Using the host's `/lib64` folder directly is problematic because:
1.  **Symlink Hell**: Host libraries often use absolute symlinks (e.g., `libc.so.6 -> /lib64/libc-2.36.so`). When mounted into a container at a different path, these links break.
2.  **Pollution**: The host system may contain unnecessary or conflicting packages.
3.  **Reproducibility**: Different LoongArch machines have different library versions.

**This builder solves these problems by:**
1.  Building a clean **Debian Trixie (13)** base.
2.  **Auto-fixing symlinks**: Converting all absolute symlinks to relative ones (e.g., `../../lib/libc.so.6`), so the sysroot works perfectly regardless of where it is

🏗 How it Works (CI Pipeline)
This repository uses a GitHub Actions workflow to:

Setup QEMU: Registers loongarch64 binfmt support on the x86 runner.

Debootstrap: Downloads Debian Trixie packages for loong64.

Second Stage: Uses chroot + QEMU to configure the packages.

Fix Symlinks: A Python script scans the resulting tree and converts absolute symlinks to relative paths.

Release: Packages the result and uploads it to GitHub Releases (triggered by v* tags).

🔨 Manual Build
If you want to build this locally on a Linux machine (x86 or LoongArch):

# Install dependencies
sudo apt-get install -y qemu-user-static debootstrap debian-ports-archive-keyring

# Run the build script
chmod +x scripts/build.sh
./scripts/build.sh

## 📥 Downloads

Go to the [**Releases Page**](../../releases) to download the latest `debian-sid-loong64-sysroot.tar.gz`.

## 🛠 Usage with Box64 & Docker

...
# Extract the artifact
tar -xzf debian-sid-loong64-sysroot.tar.gz -C /home/user/containers/sysroot-loong64
...
