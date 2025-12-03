#!/bin/bash
set -e

# Configuration file location
CONFIG_FILE="${CONFIG_FILE:-multipass-config.env}"

# Defaults
INSTANCE_NAME="${INSTANCE_NAME:-lintap-dev}"
CPUS="${CPUS:-4}"
MEMORY="${MEMORY:-8G}"
DISK="${DISK:-40G}"
UBUNTU_VERSION="${UBUNTU_VERSION:-24.04}"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Load configuration file if it exists
if [ -f "${CONFIG_FILE}" ]; then
    log "Loading configuration from ${CONFIG_FILE}"
    source "${CONFIG_FILE}"
else
    warn "Configuration file '${CONFIG_FILE}' not found"
    warn "Creating example configuration file: ${CONFIG_FILE}.example"
    
    cat > "${CONFIG_FILE}.example" <<'CONFIGEOF'
# Multipass Instance Configuration
# Copy this file to multipass-config.env and customize for your environment

# Instance settings
INSTANCE_NAME="lintap-dev"
CPUS=4
MEMORY="8G"
DISK="40G"
UBUNTU_VERSION="24.04"

# Mount configuration
# Format: "host_path:instance_path[:options]"
# Options: ro (read-only), rw (read-write, default)
MOUNTS=(
    "${HOME}/git/Wintap:/home/ubuntu/git/Wintap"
    "${HOME}/data/lintap:/home/ubuntu/data/lintap"
)
CONFIGEOF
    
    error "Please create '${CONFIG_FILE}' based on '${CONFIG_FILE}.example'"
fi

# Validate MOUNTS array exists
if [ -z "${MOUNTS+x}" ] || [ ${#MOUNTS[@]} -eq 0 ]; then
    error "MOUNTS array not defined or empty in ${CONFIG_FILE}"
fi

# Check if multipass is installed
if ! command -v multipass &> /dev/null; then
    error "Multipass is not installed. Install from https://multipass.run/"
fi

# Check if instance already exists
if multipass list | grep -q "^${INSTANCE_NAME}"; then
    log "Instance '${INSTANCE_NAME}' already exists"
    read -p "Delete and recreate? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Stopping and deleting existing instance..."
        multipass stop "${INSTANCE_NAME}" 2>/dev/null || true
        multipass delete "${INSTANCE_NAME}"
        multipass purge
    else
        log "Using existing instance"
        exit 0
    fi
fi

# Build mount arguments
MOUNT_ARGS=()
for mount in "${MOUNTS[@]}"; do
    IFS=':' read -r host_path instance_path opts <<< "$mount"
    
    # Expand home directory
    host_path="${host_path/#\~/$HOME}"
    
    # Check if host path exists
    if [ ! -e "$host_path" ]; then
        log "Creating host path: $host_path"
        mkdir -p "$host_path"
    fi
    
    # Add mount argument
    if [ -n "$opts" ]; then
        MOUNT_ARGS+=("--mount" "${host_path}:${instance_path}:${opts}")
    else
        MOUNT_ARGS+=("--mount" "${host_path}:${instance_path}")
    fi
done

# Create instance with mounts
log "Creating Multipass instance: ${INSTANCE_NAME}"
log "  CPUs: ${CPUS}"
log "  Memory: ${MEMORY}"
log "  Disk: ${DISK}"
log "  Ubuntu: ${UBUNTU_VERSION}"
log "  Mounts: ${#MOUNTS[@]}"

multipass launch "${UBUNTU_VERSION}" \
    --name "${INSTANCE_NAME}" \
    --cpus "${CPUS}" \
    --memory "${MEMORY}" \
    --disk "${DISK}" \
    "${MOUNT_ARGS[@]}" \
    --cloud-init - <<EOF
#cloud-init
package_update: true
package_upgrade: true
packages:
  - build-essential
  - git
  - curl
  - wget
  - vim
  - htop
  - net-tools
  - unzip
  - tree
  # For eBPF
  - libbpf-dev 
  - libbpf1
  - linux-headers-generic
  - clang
  - llvm
  - libelf-dev
  - linux-tools-common
  - build-essential


runcmd:

  # Headers aren't where eBPF expects, so fix with a symlink:
  - ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm

  # Add Microsoft repository and install .NET
  - |
    set -x
    . /etc/os-release
    wget https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb -O /tmp/packages-microsoft-prod.deb
    dpkg -i /tmp/packages-microsoft-prod.deb
    rm /tmp/packages-microsoft-prod.deb
    apt-get update
    apt-get install -y dotnet-sdk-8.0 aspnetcore-runtime-8.0
  
  # Install DuckDB CLI. The default installer detects the right OS/arch, but installs only for the current user. Sigh.
  - |
    set -x
    curl https://install.duckdb.org | sh
    cp ~/.duckdb/cli/latest/duckdb /usr/local/bin/duckdb
    
final_message: "LinTap dev environment is ready! Connect with: multipass shell ${INSTANCE_NAME}"
EOF

log "Waiting for instance to be ready..."
multipass exec "${INSTANCE_NAME}" -- cloud-init status --wait

# Get instance IP for SSH
INSTANCE_IP=$(multipass info "${INSTANCE_NAME}" | grep IPv4 | awk '{print $2}')

log "Instance created successfully!"

log "Configuring ~/.ssh/config"
LINTAP_INSTANCE=${INSTANCE_NAME} ./config-ssh.sh

echo
echo -e "${BLUE}=== Connection Information ===${NC}"
echo "Instance Name: ${INSTANCE_NAME}"
echo "IP Address: ${INSTANCE_IP}"
echo
echo "Shell access:"
echo "  multipass shell ${INSTANCE_NAME}"
echo
echo "VS Code Remote SSH:"
echo "  1. Install 'Remote - SSH' extension"
echo
echo "  2. Connect to '${INSTANCE_NAME}' in VS Code"
echo
echo -e "${BLUE}=== Mounted Paths ===${NC}"
for mount in "${MOUNTS[@]}"; do
    IFS=':' read -r host_path instance_path opts <<< "$mount"
    echo "  ${host_path} -> ${instance_path} ${opts:+($opts)}"
done