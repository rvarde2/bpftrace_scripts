#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (use sudo)"
  exit
fi

echo "--- Updating Package Lists ---"
apt-get update

echo "--- Installing Compiler Toolchain (Clang/LLVM) ---"
apt-get install -y clang llvm build-essential gcc-multilib

echo "--- Installing BPF Development Libraries ---"
# libbpf-dev provides the headers in /usr/include/bpf
apt-get install -y libbpf-dev libelf-dev zlib1g-dev libcap-dev

echo "--- Installing Kernel Headers and Tools ---"
# Required for vmlinux.h generation and kernel-specific defines
apt-get install -y linux-headers-$(uname -r) \
                   linux-tools-common \
                   linux-tools-$(uname -r) \
                   linux-tools-generic

echo "--- Verifying bpftool installation ---"
if ! command -v bpftool &> /dev/null; then
    echo "bpftool not found in standard paths. Attempting to link..."
    # On some Ubuntu versions, bpftool is tucked away in a versioned folder
    ln -s /usr/lib/linux-tools/$(uname -r)/bpftool /usr/local/bin/bpftool 2>/dev/null
fi

bpftool version

echo "--- Setup Complete ---"
echo "Now try to compile hello.bpf.c using the Makefile."
