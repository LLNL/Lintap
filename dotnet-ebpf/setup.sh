#!/bin/bash
set -e

echo "=========================================="
echo "eBPF OpenAt Tracer - Setup Script"
echo "=========================================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Updating package lists..."
apt-get update

echo
echo "Installing eBPF development tools..."
apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    libbpf1 \
    linux-headers-$(uname -r) \
    bpftool \
    make

echo
echo "Installing .NET SDK..."
# Install .NET 8 if not already installed
if ! command -v dotnet &> /dev/null; then
    wget https://dot.net/v1/dotnet-install.sh -O /tmp/dotnet-install.sh
    chmod +x /tmp/dotnet-install.sh
    /tmp/dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet
    ln -sf /usr/share/dotnet/dotnet /usr/bin/dotnet
    rm /tmp/dotnet-install.sh
else
    echo ".NET is already installed"
fi

echo
echo "Verifying installations..."
echo -n "clang: "
clang --version | head -n1
echo -n "bpftool: "
bpftool version
echo -n "dotnet: "
dotnet --version

echo
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo
echo "Next steps:"
echo "1. Run 'make' to compile the eBPF program"
echo "2. Run 'sudo dotnet run' to start the tracer"
