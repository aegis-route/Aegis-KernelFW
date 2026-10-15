#!/usr/bin/env bash
# ===============================================================
# Aegis-KernelFW: Toolchain & Dependency Installer for Ubuntu/Debian
# ===============================================================

set -euo pipefail

echo "=========================================================="
echo " Aegis-KernelFW: Installing eBPF & Toolchain Dependencies"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run as root (or use sudo)."
    exit 1
fi

echo "[*] Updating apt package index..."
apt-get update -y

echo "[*] Installing Clang, LLVM, LibBPF, and build tools..."
apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    pkg-config \
    zlib1g-dev \
    iproute2 \
    gcc-multilib \
    linux-libc-dev \
    linux-tools-common \
    linux-tools-generic \
    bpftool 2>/dev/null || true

# Ensure asm header symlink exists for clang bpf cross-compilation
if [ ! -d /usr/include/asm ] && [ -d /usr/include/$(uname -m)-linux-gnu/asm ]; then
    ln -snf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
fi

echo ""
echo "[✓] Dependencies installed successfully!"
echo "    - Clang version: $(clang --version | head -n1)"
echo "    - GCC version:   $(gcc --version | head -n1)"
echo "    - Make version:  $(make --version | head -n1)"
echo ""
echo "You can now run: 'make all' to compile Aegis-KernelFW."
