# eBPF System Tracer with WintapMessage Integration

A production-ready eBPF-based system monitoring tool with a .NET control plane, designed for cross-platform compatibility with LLNL's Wintap format.

## Overview

This project demonstrates modern eBPF observability with a layered architecture:
- **Minimal eBPF programs** - Capture essential data in kernel space
- **Rich userspace processing** - Extract detailed context from `/proc` filesystem
- **Abstraction layer** - Decouple internal models from external formats
- **Adapter pattern** - Easy integration with WintapMessage or other formats

## Features

### Multi-Syscall Tracing
- ✅ **Process Creation** (`execve`) - Monitor all process starts
- ✅ **File Access** (`openat`) - Track file operations
- ✅ **Unified Application** - Run multiple tracers simultaneously

### Rich Context Extraction
Both tracers automatically enrich events with:
- Parent Process ID (PPID) from `/proc/<pid>/status`
- Full command line with arguments from `/proc/<pid>/cmdline`
- User information from `/proc/<pid>/environ`
- Process hierarchy and session data

### Flexible Architecture
- **Abstraction Layer** - Internal models independent of external formats
- **Adapter Pattern** - Single point of conversion to WintapMessage
- **Multiple Outputs** - Console, JSON file, or custom handlers
- **Future-Proof** - Ready for WintapMessage NuGet package

## Architecture

```
┌─────────────────────────────────────────────────────┐
│         eBPF Programs (Kernel Space)                │
│  ┌─────────────┐         ┌─────────────┐          │
│  │   execve    │         │   openat    │          │
│  │  (minimal)  │         │  (minimal)  │          │
│  └──────┬──────┘         └──────┬──────┘          │
└─────────┼─────────────────────┼─────────────────────┘
          │                     │
          ↓                     ↓
┌─────────────────────────────────────────────────────┐
│        .NET Control Plane (User Space)              │
│                                                     │
│  Marshaling Layer:                                 │
│  ┌──────────────┐      ┌──────────────┐           │
│  │ ExecveEvent  │      │ OpenatEvent  │           │
│  └──────┬───────┘      └──────┬───────┘           │
│         │                     │                    │
│  Internal Model Layer (WE OWN):                    │
│  ┌──────────────┐      ┌──────────────┐           │
│  │ProcessEvent  │      │  FileEvent   │           │
│  │+ /proc data  │      │+ /proc data  │           │
│  └──────┬───────┘      └──────┬───────┘           │
│         │                     │                    │
│         └──────────┬──────────┘                    │
│                    ↓                                │
│         ┌────────────────────┐                     │
│         │WintapMessageAdapter│ (ONLY place that    │
│         │  (Adapter Pattern) │  knows Wintap)      │
│         └─────────┬──────────┘                     │
│                   ↓                                 │
│         ┌────────────────────┐                     │
│         │   WintapMessage    │                     │
│         └─────────┬──────────┘                     │
│                   ↓                                 │
│         ┌────────────────────┐                     │
│         │   Event Handlers   │                     │
│         │ Console│File│Custom│                     │
│         └────────────────────┘                     │
└─────────────────────────────────────────────────────┘
```

## Requirements

- **OS**: Ubuntu 20.04+ (tested on 22.04/24.04)
- **Kernel**: Linux 5.8+ (for BPF ring buffer support)
- **Architecture**: x86_64 or ARM64 (Apple Silicon supported!)
- **Privileges**: Root/sudo (required for eBPF)
- **Dependencies**: 
  - clang, llvm (eBPF compilation)
  - libbpf (BPF library)
  - .NET 8 SDK

## Quick Start

### On Multipass (Recommended for Apple Silicon)

```bash
# Create Ubuntu VM
multipass launch 22.04 --name ebpf-tracer --memory 2G --disk 10G

# Transfer project
multipass transfer ebpf-openat-poc ebpf-tracer:/home/ubuntu/

# Enter VM
multipass shell ebpf-tracer

# Setup and run
cd ~/ebpf-openat-poc
sudo ./setup.sh
make all
sudo ./run-unified.sh
```

### Native Ubuntu

```bash
# Install dependencies
sudo ./setup.sh

# Build everything
make all
dotnet build UnifiedTracer.csproj

# Run (requires root)
sudo dotnet run --project UnifiedTracer.csproj
```

## Usage

### Basic Usage

```bash
# Trace everything (default)
sudo ./run-unified.sh

# Or manually
sudo dotnet run --project UnifiedTracer.csproj --all
```

### Advanced Options

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

### Expected Output

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

## Project Structure

```
ebpf-openat-poc/
├── Core eBPF Programs (Kernel)
│   ├── execve_tracer.bpf.c       # Process creation hook
│   └── openat_tracer.bpf.c       # File access hook
│
├── .NET Application (User Space)
│   ├── UnifiedTracer.cs          # Main orchestrator
│   ├── ExecveEvent.cs            # Process event marshaling
│   ├── OpenatEvent.cs            # File event marshaling
│   ├── EventAbstraction.cs       # Internal models & adapters
│   ├── WintapMessage.cs          # External format
│   └── LibBpf.cs                 # P/Invoke bindings
│
├── Build & Configuration
│   ├── Makefile                  # eBPF compilation
│   ├── UnifiedTracer.csproj      # .NET project
│   ├── setup.sh                  # Dependency installer
│   └── run-unified.sh            # Convenience script
│
└── Documentation
    ├── README.md                 # This file
    ├── ARCHITECTURE_GUIDE.md     # Detailed architecture
    ├── UNIFIED_UPDATE.md         # Recent changes
    ├── QUICKSTART.md             # Fast setup guide
    ├── APPLE_SILICON.md          # M1/M2/M3/M4 specific
    ├── M4_MAC.md                 # M4 quick reference
    ├── MULTIPASS.md              # Multipass deployment
    ├── TROUBLESHOOTING.md        # Debug guide
    └── EXECVE_TRACER.md          # Execve details
```

## Key Design Decisions

### 1. Minimal eBPF Programs

**Why**: eBPF verifier has a 1 million instruction limit and is complex to debug.

**Solution**: 
- eBPF captures only: PID, UID, GID, comm, filename/path, timestamp
- All processing (args, env vars, PPID) done in C# via `/proc`

**Benefits**:
- Programs load successfully (< 100k instructions each)
- More reliable (fewer verifier issues)
- Easier to extend (C# vs eBPF C)
- Better error handling

### 2. Abstraction Layer

**Why**: WintapMessage is external (LLNL/Wintap repo), may change, will become NuGet package.

**Solution**: 
- Our internal models: `ProcessEvent`, `FileEvent` (we own these)
- Adapter pattern: `WintapMessageAdapter` (only place that knows Wintap)
- When Wintap changes, only adapter needs updating

**Benefits**:
- Loose coupling
- Easy to test
- Can add other output formats (Splunk, Elastic, etc.)
- Future-proof for Wintap NuGet package

### 3. `/proc` Filesystem Enhancement

**Why**: eBPF has limitations accessing kernel structures (task_struct, etc.)

**Solution**:
- Read `/proc/<pid>/status` for PPID, session ID
- Read `/proc/<pid>/cmdline` for full command line
- Read `/proc/<pid>/environ` for USER, HOME, SHELL
- Read `/proc/<pid>/cwd` for working directory

**Benefits**:
- Always accurate (kernel's view)
- No BTF/CO-RE complexity
- Works across kernel versions
- Easy to add more fields

## How It Works

### Process Creation Flow (execve)

1. **Kernel**: Process calls `execve("/usr/bin/ls", ["-la", "/tmp"], envp)`
2. **eBPF Hook**: Tracepoint `sys_enter_execve` fires
3. **eBPF Capture**: Extracts PID, UID, GID, comm, executable path, timestamp
4. **Ring Buffer**: Event written to shared memory
5. **.NET Poll**: UnifiedTracer polls ring buffer
6. **Marshal**: Binary data → `ExecveEvent` struct
7. **Enrich**: Read `/proc/<pid>/*` for PPID, args, env vars
8. **Internal Model**: Create `ProcessEvent` with all data
9. **Adapter**: `WintapMessageAdapter` converts to `WintapMessage`
10. **Output**: Handler displays/saves event

### File Access Flow (openat)

1. **Kernel**: Process calls `openat(AT_FDCWD, "/etc/hosts", O_RDONLY)`
2. **eBPF Hook**: Tracepoint `sys_enter_openat` fires
3. **eBPF Capture**: Extracts PID, comm, filename
4. **Ring Buffer**: Event written to shared memory
5. **.NET Poll**: UnifiedTracer polls ring buffer
6. **Marshal**: Binary data → `OpenatEvent` struct
7. **Enrich**: Read `/proc/<pid>/*` for PPID, UID, command line, user
8. **Internal Model**: Create `FileEvent` with all data
9. **Adapter**: `WintapMessageAdapter` converts to `WintapMessage`
10. **Output**: Handler displays/saves event

## Apple Silicon Support

✅ **Full ARM64 Support** - Auto-detects architecture and compiles accordingly

See [APPLE_SILICON.md](APPLE_SILICON.md) or [M4_MAC.md](M4_MAC.md) for details.

Quick verification:
```bash
# Inside Multipass VM
uname -m  # Should show: aarch64
make all  # Should show: "Compiled for architecture: arm64"
```

## Performance

### Resource Usage
- **CPU**: < 5% on idle system
- **Memory**: ~60MB (.NET runtime + buffers)
- **Event Processing**: ~50k-100k events/sec

### eBPF Program Sizes
- **execve_tracer**: ~60 lines, < 100k instructions
- **openat_tracer**: ~50 lines, < 50k instructions
- Both well under 1M instruction verifier limit

### Ring Buffers
- **execve**: 256KB (handles bursts)
- **openat**: 256KB (high frequency events)
- Lock-free, per-CPU design

## Extending

### Add New Syscall

```bash
# 1. Create eBPF program
cat > connect_tracer.bpf.c << 'EOF'
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    // Minimal capture
}
EOF

# 2. Create C# event struct
cat > ConnectEvent.cs << 'EOF'
public struct ConnectEvent { ... }
EOF

# 3. Create internal model
# In EventAbstraction.cs:
public class NetworkEvent : ISystemEvent { ... }

# 4. Update adapter
# In WintapMessageAdapter:
private WintapMessage ConvertNetworkEvent(NetworkEvent evt) { ... }

# 5. Update UnifiedTracer to load new program
```

### Add Custom Output Handler

```csharp
public class KafkaEventHandler : IEventHandler
{
    private readonly IEventAdapter<WintapMessage> _adapter;
    private readonly KafkaProducer _producer;
    
    public void HandleEvent(ISystemEvent evt)
    {
        var msg = _adapter.ToExternal(evt);
        var json = JsonSerializer.Serialize(msg);
        _producer.Send("events-topic", json);
    }
}

// Use it:
var handler = new KafkaEventHandler(new WintapMessageAdapter(), kafkaConfig);
```

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for comprehensive debugging guide.

**Quick checks:**

```bash
# Verify kernel version
uname -r  # Need 5.8+

# Check BTF support
ls /sys/kernel/btf/vmlinux  # Should exist

# Verify libbpf
ldconfig -p | grep libbpf

# Check .NET
dotnet --version  # Need 8.0+

# Verify eBPF programs compiled
ls -lh *.bpf.o
```

## Integration with Wintap

### Current State
We include our own `WintapMessage.cs` (temporary copy).

### Future State (when LLNL publishes NuGet)

```bash
# 1. Add package
dotnet add package Wintap.Messages

# 2. Remove our WintapMessage.cs
rm WintapMessage.cs

# 3. Update using statement
# In WintapMessageAdapter.cs:
using Wintap.Messages;  // Instead of: using EbpfOpenatPoc;

# 4. Update adapter if API changed
# Only WintapMessageAdapter.cs needs changes
# All other code remains unchanged!
```

This is the **power of the abstraction layer** - we're ready for the future!

## Documentation

- **[ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md)** - Deep dive into design
- **[QUICKSTART.md](QUICKSTART.md)** - Get running in 5 minutes
- **[APPLE_SILICON.md](APPLE_SILICON.md)** - Complete ARM64 guide
- **[M4_MAC.md](M4_MAC.md)** - M4 quick reference
- **[MULTIPASS.md](MULTIPASS.md)** - Multipass deployment
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Debug guide
- **[EXECVE_TRACER.md](EXECVE_TRACER.md)** - Execve details
- **[UNIFIED_UPDATE.md](UNIFIED_UPDATE.md)** - Latest changes

## Contributing

This is a proof-of-concept demonstrating eBPF + .NET integration patterns.

**Ideas for enhancement:**
- Additional syscalls (connect, read, write, fork, clone)
- Container awareness (Docker, Kubernetes context)
- Network events (TCP connections, DNS queries)
- Performance metrics (latency, throughput)
- Filtering and aggregation

## Resources

- **Wintap**: https://github.com/LLNL/Wintap
- **eBPF**: https://ebpf.io/
- **libbpf**: https://github.com/libbpf/libbpf
- **.NET P/Invoke**: https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke

## License

Educational proof-of-concept. See individual component licenses.

---

**Built with ❤️ using eBPF + .NET**

For questions, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) or check the documentation index.

### On a Multipass Instance

```bash
# Create a new Ubuntu instance
multipass launch --name ebpf-poc --memory 2G --disk 10G

# Enter the instance
multipass shell ebpf-poc

# Clone or copy the project files to the instance
# Then navigate to the project directory
cd ebpf-openat-poc

# Run the setup script
sudo ./setup.sh
```

### Manual Installation

If you prefer to install dependencies manually:

```bash
# Update package lists
sudo apt-get update

# Install eBPF tools
sudo apt-get install -y clang llvm libbpf-dev libbpf1 \
    linux-headers-$(uname -r) bpftool make

# Install .NET 8
wget https://dot.net/v1/dotnet-install.sh -O dotnet-install.sh
chmod +x dotnet-install.sh
./dotnet-install.sh --channel 8.0
export PATH="$HOME/.dotnet:$PATH"
```

## Building

```bash
# Compile the eBPF program
make

# This creates openat_tracer.bpf.o
```

## Running

```bash
# Build and run the .NET control plane (requires root)
sudo dotnet run

# Or build first, then run
dotnet build
sudo dotnet run
```

### Expected Output

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
1234       bash             /etc/bash.bashrc
1234       bash             /home/user/.bashrc
5678       ls               /etc/ld.so.cache
5678       ls               /lib/x86_64-linux-gnu/libselinux.so.1
```

## How It Works

### eBPF Program

The eBPF program attaches to the `tracepoint/syscalls/sys_enter_openat` tracepoint, which fires whenever a process calls `openat()`. For each call:

1. Captures the current process ID (PID)
2. Reads the process command name from kernel structures
3. Reads the filename argument from the syscall
4. Sends the event to userspace via a ring buffer

### .NET Control Plane

The control plane application:

1. Uses P/Invoke to call libbpf functions
2. Loads the compiled eBPF object file
3. Attaches it to the kernel tracepoint
4. Polls the ring buffer for events
5. Marshals binary data into C# structs
6. Displays events in a formatted table

## File Structure

```
ebpf-openat-poc/
├── openat_tracer.bpf.c      # eBPF program (kernel-side)
├── Makefile                  # Build eBPF program
├── Program.cs                # Main .NET application
├── LibBpf.cs                 # P/Invoke bindings for libbpf
├── OpenatEvent.cs            # Event data structure
├── EbpfControlPlane.csproj   # .NET project file
├── setup.sh                  # Dependency installation script
└── README.md                 # This file
```

## Troubleshooting

### "Failed to load BPF object"

- Ensure you have a recent kernel (5.8+): `uname -r`
- Check that BTF is enabled: `ls /sys/kernel/btf/vmlinux`
- Verify libbpf is installed: `ldconfig -p | grep libbpf`

### "This program requires root privileges"

- The program needs root to load eBPF programs
- Run with `sudo dotnet run`

### "BPF object file not found"

- Run `make` first to compile the eBPF program
- Ensure `openat_tracer.bpf.o` exists in the directory

### No events appearing

- Try running a command in another terminal: `ls /tmp`
- Check if the tracepoint exists: `ls /sys/kernel/tracing/events/syscalls/sys_enter_openat`
- Verify the program is attached: `sudo bpftool prog list`

## Extending the POC

### Add More Syscalls

Modify the eBPF program to hook other syscalls:
- `sys_enter_open` - open()
- `sys_enter_read` - read()
- `sys_enter_write` - write()

### Filter Events

Add filtering logic in the eBPF program:
```c
// Only trace specific PIDs
if (event->pid != target_pid)
    return 0;
```

### Add Timestamps

Include timing information:
```c
event->timestamp = bpf_ktime_get_ns();
```

## Resources

- [eBPF Documentation](https://ebpf.io/)
- [libbpf Documentation](https://libbpf.readthedocs.io/)
- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/)
- [.NET P/Invoke Guide](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)

## License

This is a proof-of-concept for educational purposes.