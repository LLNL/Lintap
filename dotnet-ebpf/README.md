# eBPF System Tracer with .NET Control Plane

A POC eBPF-based system monitoring tool with a .NET control plane, designed for cross-platform compatibility with LLNL's Wintap format.

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
- **Architecture**: x86_64 or ARM64 (Apple Silicon supported via Multipass!)
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
multipass transfer dotnet-ebpf ebpf-tracer:/home/ubuntu/

# Enter VM
multipass shell ebpf-tracer

# Setup and run
cd ~/dotnet-ebpf
sudo ./scripts/setup.sh
make all
sudo ./scripts/run-unified.sh
```

### Native Ubuntu

```bash
# Install dependencies
sudo ./scripts/setup.sh

# Build everything
make all
dotnet build

# Run (requires root)
sudo dotnet run
```

## Usage

### Basic Usage

```bash
# Trace everything (default)
sudo ./scripts/run-unified.sh

# Or manually
sudo dotnet run --all
```

### Advanced Options

```bash
# Trace only process creation
sudo dotnet run --execve

# Trace only file access
sudo dotnet run --openat

# Write to JSON file
sudo dotnet run -o events.json

# Console + file output
sudo dotnet run -o events.json --console
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
dotnet-ebpf/
├── Core eBPF Programs (Kernel)
│   ├── execve_tracer.bpf.c       # Process creation hook
│   └── openat_tracer.bpf.c       # File access hook
│
├── .NET Application (User Space)
│   ├── src/
│   │   ├── UnifiedTracer.cs      # Main orchestrator
│   │   ├── EventAbstraction.cs   # Internal models & adapters
│   │   ├── ExecveEvent.cs        # Process event marshaling
│   │   ├── OpenatEvent.cs        # File event marshaling
│   │   ├── WintapMessage.cs      # External format
│   │   ├── LibBpf.cs             # P/Invoke bindings
│   │   └── ProcReader.cs         # /proc filesystem utilities
│   │
│   └── UnifiedTracer.csproj      # .NET project file
│
├── Build & Scripts
│   ├── Makefile                  # eBPF compilation
│   ├── scripts/
│   │   ├── setup.sh              # Dependency installer
│   │   ├── run-unified.sh        # Convenience script
│   │   └── test.sh               # Testing script
│   └── .gitignore                # Git ignore rules
│
└── Documentation
    ├── README.md                 # This file
    ├── docs/
    │   ├── INDEX.md              # Documentation index
    │   ├── QUICKSTART.md         # Fast setup guide
    │   ├── ARCHITECTURE.md       # Architecture overview
    │   ├── ARCHITECTURE_GUIDE.md # Detailed architecture
    │   ├── PROJECT_OVERVIEW.md   # Project details
    │   ├── TROUBLESHOOTING.md    # Debug guide
    │   ├── MULTIPASS.md          # Multipass deployment
    │   └── M4_MAC.md             # M4 quick reference
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
8. **Internal Model**: Create `ProcessEvent` (our model)
9. **Adapt**: Convert to `WintapMessage` (external format)
10. **Output**: Send to handler (console, file, etc.)

### File Access Flow (openat)

1. **Kernel**: Process calls `openat(AT_FDCWD, "/etc/passwd", ...)`
2. **eBPF Hook**: Tracepoint `sys_enter_openat` fires
3. **eBPF Capture**: Extracts PID, UID, GID, comm, filepath
4. **Ring Buffer**: Event written to shared memory
5. **.NET Poll**: UnifiedTracer polls ring buffer
6. **Marshal**: Binary data → `OpenatEvent` struct
7. **Enrich**: Read `/proc/<pid>/*` for process context
8. **Internal Model**: Create `FileEvent` (our model)
9. **Adapt**: Convert to `WintapMessage`
10. **Output**: Send to handler

## Extending the Project

### Add Custom Event Handler

```csharp
public class MyCustomHandler : IEventHandler
{
    private readonly IEventAdapter<WintapMessage> _adapter;
    
    public MyCustomHandler(IEventAdapter<WintapMessage> adapter)
    {
        _adapter = adapter;
    }
    
    public void HandleEvent(ISystemEvent evt)
    {
        var wintapMsg = _adapter.ToExternal(evt);
        
        // Your custom logic here
        // - Send to Kafka
        // - Store in database
        // - Trigger alerts
        // - Aggregate metrics
    }
}
```

### Add New Syscall Tracer

1. Create eBPF program (`my_syscall.bpf.c`)
2. Create marshaling struct (`MySyscallEvent.cs`)
3. Create internal model (`MyEvent : ISystemEvent`)
4. Add conversion in adapter
5. Register in `UnifiedTracer.cs`

### Add Output Format

```csharp
// Define your format
public class MyFormat { /* ... */ }

// Create adapter
public class MyFormatAdapter : IEventAdapter<MyFormat>
{
    public MyFormat ToExternal(ISystemEvent evt) { /* ... */ }
}

// Create handler
public class MyFormatHandler : IEventHandler
{
    private readonly IEventAdapter<MyFormat> _adapter;
    
    public void HandleEvent(ISystemEvent evt)
    {
        var myFormat = _adapter.ToExternal(evt);
        // Output your format
    }
}
```

## Troubleshooting

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for comprehensive debugging guide.

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
rm src/WintapMessage.cs

# 3. Update using statement in EventAbstraction.cs
using Wintap.Messages;  # Instead of: using EbpfTracer;

# 4. Update adapter if API changed
# Only WintapMessageAdapter needs changes
# All other code remains unchanged!
```

This is the **power of the abstraction layer** - we're ready for the future!

## Documentation

- **[docs/INDEX.md](docs/INDEX.md)** - Documentation index
- **[docs/QUICKSTART.md](docs/QUICKSTART.md)** - Get running in 5 minutes
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - Architecture overview
- **[docs/ARCHITECTURE_GUIDE.md](docs/ARCHITECTURE_GUIDE.md)** - Deep dive into design
- **[docs/PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md)** - Project details
- **[docs/MULTIPASS.md](docs/MULTIPASS.md)** - Multipass deployment
- **[docs/M4_MAC.md](docs/M4_MAC.md)** - M4 Mac quick reference
- **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** - Debug guide

## Contributing

This is a proof-of-concept demonstrating eBPF + .NET integration patterns.

**Ideas for enhancement:**
- Additional syscalls (connect, read, write, fork, clone)
- Container awareness (Docker, Kubernetes context)
- Network events (TCP connections, DNS queries)
- Performance metrics (latency, throughput)
- Filtering and aggregation
- Real-time dashboards

## Resources

- **Wintap**: https://github.com/LLNL/Wintap
- **eBPF**: https://ebpf.io/
- **libbpf**: https://github.com/libbpf/libbpf
- **.NET P/Invoke**: https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke

## License

Educational proof-of-concept. See individual component licenses.

---

**Built with ❤️ using eBPF + .NET**

For questions, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) or check the [documentation index](docs/INDEX.md).
