# Deploying to Multipass

This guide walks you through deploying the eBPF OpenAt Tracer POC on a Multipass Ubuntu instance.

## Prerequisites

- [Multipass installed](https://multipass.run/) on your host machine
- At least 2GB RAM available for the VM

## Step 1: Create Multipass Instance

```bash
# Create an Ubuntu instance with sufficient resources
multipass launch 22.04 \
    --name ebpf-poc \
    --memory 2G \
    --disk 10G \
    --cpus 2

# Verify the instance is running
multipass list
```

## Step 2: Transfer Files to Instance

```bash
# From your host machine, transfer the project directory
multipass transfer ebpf-openat-poc ebpf-poc:/home/ubuntu/

# Or mount a shared folder (alternative approach)
multipass mount /path/to/ebpf-openat-poc ebpf-poc:/home/ubuntu/ebpf-openat-poc
```

## Step 3: Enter the Instance

```bash
multipass shell ebpf-poc
```

## Step 4: Setup Environment

```bash
# Navigate to project directory
cd ~/ebpf-openat-poc

# Run setup script
sudo ./setup.sh

# This will install:
# - clang, llvm (eBPF compiler)
# - libbpf (BPF library)
# - Linux headers (required for eBPF)
# - bpftool (BPF debugging)
# - .NET 8 SDK
```

## Step 5: Build the eBPF Program

```bash
# Compile the eBPF program
make

# Verify the object file was created
ls -lh openat_tracer.bpf.o
```

## Step 6: Run the Tracer

```bash
# Start the tracer (requires root)
sudo dotnet run
```

You should see output like:

```
eBPF OpenAt Tracer - .NET Control Plane
========================================

Loading BPF object: openat_tracer.bpf.o
Loading BPF program into kernel...
...
Successfully attached! Tracing openat() calls...
Press Ctrl+C to exit

PID        COMMAND          FILENAME
--------------------------------------------------------------------------------
```

## Step 7: Generate Test Events

In a **separate terminal** (on your host machine):

```bash
# Open another shell to the instance
multipass shell ebpf-poc

# Navigate to project directory
cd ~/ebpf-openat-poc

# Run the test script
./test.sh
```

Switch back to the first terminal to see the traced events!

## Stopping the Instance

```bash
# Exit the shell
exit

# Stop the instance (from host)
multipass stop ebpf-poc

# Start it again later
multipass start ebpf-poc

# Delete when done
multipass delete ebpf-poc
multipass purge
```

## Troubleshooting Multipass-Specific Issues

### Instance won't start

```bash
# Check instance status
multipass list

# View logs
multipass info ebpf-poc

# Restart Multipass daemon (macOS)
sudo launchctl stop com.canonical.multipassd
sudo launchctl start com.canonical.multipassd
```

### Kernel too old

```bash
# Inside the instance, check kernel version
uname -r

# Should be 5.8 or higher
# If not, try launching with a newer Ubuntu version:
multipass launch 24.04 --name ebpf-poc
```

### File transfer issues

```bash
# Alternative: Use cloud-init to download files
cat > cloud-init.yaml <<EOF
#cloud-config
runcmd:
  - git clone <your-repo-url> /home/ubuntu/ebpf-openat-poc
EOF

multipass launch --name ebpf-poc --cloud-init cloud-init.yaml
```

## Performance Notes

The VM is configured with:
- **2GB RAM**: Sufficient for eBPF and .NET runtime
- **10GB Disk**: Enough for Ubuntu + tools + .NET SDK
- **2 CPUs**: Improves compilation speed

Adjust these based on your needs:

```bash
# For more intensive tracing
multipass launch 22.04 \
    --name ebpf-poc \
    --memory 4G \
    --disk 20G \
    --cpus 4
```

## Quick Reference Commands

```bash
# Create and enter instance
multipass launch 22.04 --name ebpf-poc --memory 2G --disk 10G
multipass shell ebpf-poc

# Setup and run
cd ~/ebpf-openat-poc
sudo ./setup.sh
make
sudo dotnet run

# Manage instance
multipass list                 # List instances
multipass stop ebpf-poc        # Stop instance
multipass start ebpf-poc       # Start instance
multipass delete ebpf-poc      # Delete instance
multipass purge                # Remove deleted instances
```
