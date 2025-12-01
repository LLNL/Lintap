#!/bin/bash
set -e

# Set Lintap instance name as environment variable
LINTAP_INSTANCE="${LINTAP_INSTANCE:-lintap-dev}"

# Default SSH key file
default_sshkey_file="$HOME/.ssh/id_ed25519.pub"
sshkey_file="${LINTAP_SSHKEY:-$HOME/.ssh/id_ed25519.pub}"

# Check if the SSH key file exists
if [ ! -f "$sshkey_file" ]; then
    echo "Error: SSH key file '$sshkey_file' not found."
    exit 1
fi

# Push ssh key into lintap instance. Put in both root and ubuntu users
sshkey=$(cat "$sshkey_file")
echo $LINTAP_INSTANCE
multipass exec $LINTAP_INSTANCE -- sh -c "echo '$sshkey' >> .ssh/authorized_keys"
multipass exec $LINTAP_INSTANCE -- sudo sh -c "echo '$sshkey' >> /root/.ssh/authorized_keys"

# Get lintap instance IP
export LINTAP_IP=$(multipass info $LINTAP_INSTANCE --format json | jq -r ".info.\"$LINTAP_INSTANCE\".ipv4[0]")
echo "$LINTAP_INSTANCE IP: $LINTAP_IP"

# Update ssh config
config_file=~/.ssh/config

# Create config file if it doesn't exist
if [ ! -f "$config_file" ]; then
    mkdir -p ~/.ssh
    touch "$config_file"
    chmod 600 "$config_file"
    echo "Created new SSH config file: $config_file"
fi

# Check if the host entry exists
if grep -q "^Host $LINTAP_INSTANCE\$" "$config_file"; then
    # Update existing entry
    sed -i '.bak' "/^Host $LINTAP_INSTANCE/,/^Host/s/[[:space:]]*Host[Nn]ame .*/  Hostname $LINTAP_IP/" "$config_file"
    echo "Updated existing '$LINTAP_INSTANCE' entry in SSH config with IP: $LINTAP_IP"
else
    # Add new entry
    cat >> "$config_file" << EOF

Host $LINTAP_INSTANCE
  Hostname $LINTAP_IP
  User ubuntu
  LocalForward 4213 localhost:4213
EOF
    echo "Added new '$LINTAP_INSTANCE' entry to SSH config with IP: $LINTAP_IP"
fi