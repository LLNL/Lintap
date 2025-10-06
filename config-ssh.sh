#!/bin/bash

# Push ssh key into lintap-dev
sshkey_file="$HOME/.ssh/id_ed25519.pub"
sshkey=`cat $sshkey_file`
multipass exec lintap-dev -- sh -c "echo '$sshkey' >> .ssh/authorized_keys"

# Get lintap-dev IP
export LINTAP_IP=`multipass info lintap-dev --format json | jq -r '.info."lintap-dev".ipv4[0]'`
echo $LINTAP_IP

# Update ssh config
host_alias="lintap"
config_file=~/.ssh/config

# Run the replacement command with double quotes for variable expansion
# This expects a config entry to already exist, like:
#Host lintap
#  Hostname 192.168.64.16
#  User ubuntu
#  LocalForward 4213 localhost:4213
#
sed -i '.bak' "/^Host $host_alias/,/^Host/s/[[:space:]]*Host[Nn]ame .*/  Hostname $LINTAP_IP/" "$config_file"
