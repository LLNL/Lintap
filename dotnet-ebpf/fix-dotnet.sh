#!/bin/bash
set -e

echo "=========================================="
echo ".NET 8 Quick Fix Script"
echo "=========================================="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Cleaning up any partial .NET installations..."
apt-get remove --purge -y dotnet* aspnet* netstandard* 2>/dev/null || true
rm -rf /usr/share/dotnet 2>/dev/null || true
rm -rf /usr/lib/dotnet 2>/dev/null || true
rm -f /etc/apt/sources.list.d/microsoft-prod.list 2>/dev/null || true

echo
echo "Detecting Ubuntu version..."
UBUNTU_VERSION=$(lsb_release -rs)
echo "Ubuntu $UBUNTU_VERSION detected"

echo
echo "Adding Microsoft package repository..."
wget -q https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
rm /tmp/packages-microsoft-prod.deb

echo
echo "Updating package list..."
apt-get update

echo
echo "Installing .NET SDK 8.0..."
apt-get install -y dotnet-sdk-8.0

echo
echo "=========================================="
echo "Verifying installation..."
echo "=========================================="

if command -v dotnet &> /dev/null; then
    echo "✓ .NET installed successfully!"
    echo
    echo "Version: $(dotnet --version)"
    echo "Location: $(which dotnet)"
    echo
    echo "Installed SDKs:"
    dotnet --list-sdks
    echo
    echo "Architecture:"
    file $(which dotnet) | grep -o "ARM aarch64\|x86-64"
    echo
    echo "=========================================="
    echo "Success! .NET is ready to use."
    echo "=========================================="
    echo
    echo "Now run:"
    echo "  cd ~/ebpf-openat-poc"
    echo "  make"
    echo "  sudo dotnet run"
else
    echo "✗ Installation failed. See DOTNET_INSTALL.md for manual steps."
    exit 1
fi
