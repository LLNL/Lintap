# Quick Start Guide

Get the eBPF OpenAt Tracer running in under 5 minutes!

> **🍎 Apple Silicon Users (M1/M2/M3/M4):** This works great on ARM64! The code auto-detects your architecture. See [APPLE_SILICON.md](APPLE_SILICON.md) for details.

## Option 1: Multipass (Recommended for Testing)

```bash
# 1. Create instance
multipass launch 22.04 --name ebpf-poc --memory 2G --disk 10G

# 2. Transfer files
multipass transfer ebpf-openat-poc ebpf-poc:/home/ubuntu/

# 3. Enter instance
multipass shell ebpf-poc

# 4. Setup and run
cd ~/ebpf-openat-poc
sudo ./setup.sh
make
sudo dotnet run
```

## Option 2: Native Ubuntu

```bash
# 1. Install dependencies
sudo ./setup.sh

# 2. Build eBPF program
make

# 3. Run tracer
sudo dotnet run
```

## What You'll See

```
eBPF OpenAt Tracer - .NET Control Plane
========================================

Loading BPF object: openat_tracer.bpf.o
Loading BPF program into kernel...
Finding BPF program...
Attaching BPF program to tracepoint...
Finding ring buffer map...
Setting up ring buffer...

Successfully attached! Tracing openat() calls...
Press Ctrl+C to exit

PID        COMMAND          FILENAME
--------------------------------------------------------------------------------
2451       bash             /etc/bash.bashrc
2451       bash             /home/ubuntu/.bashrc
2501       ls               /etc/ld.so.cache
2501       ls               /lib/x86_64-linux-gnu/libselinux.so.1
2502       cat              /etc/hostname
```

## Generate Test Events

In another terminal:

```bash
# Simple test
ls /tmp
cat /etc/hostname

# Or run the test script
./test.sh
```

## Stopping

Press `Ctrl+C` in the tracer terminal.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Failed to open BPF object" | Run `make` first |
| "requires root privileges" | Use `sudo dotnet run` |
| No events showing | Run commands in another terminal |
| "Failed to load BPF object" | Check kernel version: `uname -r` (need 5.8+) |

## Next Steps

- Read [README.md](README.md) for detailed documentation
- See [ARCHITECTURE.md](ARCHITECTURE.md) for how it works
- Check [MULTIPASS.md](MULTIPASS.md) for Multipass-specific tips

## One-Liner (after setup)

```bash
make && sudo dotnet run
```