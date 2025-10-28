# Quick Start Guide

Get the eBPF System Tracer running in under 5 minutes!

> **🍎 Apple Silicon Users (M1/M2/M3/M4):** This works great on ARM64! The code auto-detects your architecture. See [APPLE_SILICON.md](APPLE_SILICON.md) for details.

## Option 1: Multipass (Recommended for Testing)

```bash
# 1. Create ARM64/x86_64 Ubuntu VM
multipass launch 22.04 \
    --name ebpf-tracer \
    --memory 2G \
    --disk 10G \
    --cpus 2

# 2. Transfer files
multipass transfer ebpf-openat-poc ebpf-tracer:/home/ubuntu/

# 3. Enter VM
multipass shell ebpf-tracer

# 4. Setup and run
cd ~/ebpf-openat-poc
sudo ./setup.sh
make all
sudo ./run-unified.sh
```

## Option 2: Native Ubuntu

```bash
# 1. Install dependencies
sudo ./setup.sh

# 2. Build everything
make all
dotnet build UnifiedTracer.csproj

# 3. Run tracer (requires root)
sudo dotnet run --project UnifiedTracer.csproj
```

## What You'll See

```
eBPF Unified System Tracer
===========================

Loading execve tracer...
  ✓ execve tracer attached successfully
Loading openat tracer...
  ✓ openat tracer attached successfully

Successfully attached 2 tracer(s)!
Press Ctrl+C to exit

[    1] [10:23:45] PID:1234 PPID:1000 User:ubuntu | /usr/bin/bash
[    2] [10:23:45] PID:1234 PPID:1000 User:ubuntu | /etc/bashrc
[    3] [10:23:46] PID:1235 PPID:1234 User:ubuntu | /usr/bin/ls -la /tmp
[    4] [10:23:46] PID:1235 PPID:1234 User:ubuntu | /tmp

Sample full WintapMessage:
{
  "EventId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "EventType": "PROCESS_CREATE",
  "EventTime": "2025-10-28T10:23:46.123Z",
  "ProcessId": 1235,
  "ProcessName": "ls",
  "ProcessCommandLine": "/usr/bin/ls -la /tmp",
  "ParentProcessId": 1234,
  "User": "ubuntu",
  "Session": 1,
  "FileName": "ls",
  "FileDirectory": "/usr/bin"
}
```

## Generate Test Events

In another terminal:

```bash
# Simple commands that generate events
ls /tmp
cat /etc/hostname
vim test.txt

# Or run the test script
./test.sh
```

## Advanced Usage

```bash
# Trace only process creation
sudo dotnet run --project UnifiedTracer.csproj --execve

# Trace only file access
sudo dotnet run --project UnifiedTracer.csproj --openat

# Write to JSON file
sudo dotnet run --project UnifiedTracer.csproj -o events.json

# Console + file output
sudo dotnet run --project UnifiedTracer.csproj -o events.json --console
```

## Stopping

Press `Ctrl+C` in the tracer terminal.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "Failed to open BPF object" | Run `make all` first |
| "requires root privileges" | Use `sudo dotnet run --project UnifiedTracer.csproj` |
| No events showing | Run commands in another terminal |
| "Failed to load BPF object" | Check kernel version: `uname -r` (need 5.8+) |
| ".NET SDK not found" | Run `sudo ./fix-dotnet.sh` |

## Next Steps

- Read [README.md](README.md) for comprehensive documentation
- See [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md) for design details
- Check [MULTIPASS.md](MULTIPASS.md) for Multipass-specific tips
- View [APPLE_SILICON.md](APPLE_SILICON.md) for M1/M2/M3/M4 Macs

## One-Liner (after setup)

```bash
make all && sudo ./run-unified.sh
```

## What's Being Traced?

### Process Creation (execve)
Every time a process starts:
- Full command line with arguments
- Parent process information  
- User context
- Timestamps

### File Access (openat)
Every time a file is opened:
- File path
- Process that opened it
- User context
- Parent process

## Example Session

```bash
# Terminal 1: Start tracer
$ sudo ./run-unified.sh

# Terminal 2: Generate events
$ ls /tmp
$ cat /etc/hostname  
$ bash -c "echo hello"

# Back to Terminal 1: See the traced events!
[    1] [10:23:45] PID:1234 PPID:1000 User:ubuntu | /usr/bin/ls /tmp
[    2] [10:23:45] PID:1234 PPID:1000 User:ubuntu | /tmp
[    3] [10:23:46] PID:1235 PPID:1000 User:ubuntu | /usr/bin/cat /etc/hostname
[    4] [10:23:46] PID:1235 PPID:1000 User:ubuntu | /etc/hostname
[    5] [10:23:47] PID:1236 PPID:1000 User:ubuntu | /usr/bin/bash -c echo hello
```

## Architecture at a Glance

```
┌──────────────┐         ┌──────────────┐
│   execve     │         │   openat     │
│  (kernel)    │         │  (kernel)    │
└──────┬───────┘         └──────┬───────┘
       │                        │
       ↓                        ↓
┌─────────────────────────────────────┐
│     UnifiedTracer (userspace)       │
│  + /proc enhancement                │
│  + WintapMessage adapter            │
│  + Console/File handlers            │
└─────────────────────────────────────┘
```

**Ready?** Start with Option 1 or 2 above! 🚀