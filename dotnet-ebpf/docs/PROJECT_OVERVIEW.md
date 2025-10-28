# eBPF OpenAt Tracer - Project Overview

Complete proof-of-concept for eBPF-based system call tracing with a .NET control plane.

## 📁 Project Structure

```
ebpf-openat-poc/
├── Core Components
│   ├── openat_tracer.bpf.c       eBPF program (kernel-side tracing)
│   ├── Program.cs                .NET control plane (main application)
│   ├── LibBpf.cs                 P/Invoke bindings for libbpf
│   └── OpenatEvent.cs            Event data structure
│
├── Build System
│   ├── Makefile                  Compiles eBPF program
│   ├── EbpfControlPlane.csproj   .NET project configuration
│   └── .gitignore                Git ignore rules
│
├── Setup & Testing
│   ├── setup.sh                  Installs all dependencies
│   └── test.sh                   Generates test events
│
└── Documentation
    ├── README.md                 Main documentation
    ├── QUICKSTART.md             5-minute getting started guide
    ├── MULTIPASS.md              Multipass deployment guide
    └── ARCHITECTURE.md           System architecture & data flow
```

## 🎯 What This POC Demonstrates

### eBPF Data Collection
- ✅ Hooking system calls using tracepoints
- ✅ Collecting process metadata (PID, command name)
- ✅ Reading syscall arguments (filename)
- ✅ Using BPF ring buffers for efficient data transfer
- ✅ Zero-copy data passing from kernel to userspace

### .NET Control Plane
- ✅ P/Invoke interop with native libbpf library
- ✅ Loading and attaching eBPF programs
- ✅ Real-time event processing
- ✅ Binary data marshaling
- ✅ Memory-safe event handling

## 🚀 Getting Started

### Prerequisites
- Ubuntu 20.04+ (or Multipass instance)
- Kernel 5.8+ (for ring buffer support)
- Root/sudo access

### Quick Start
```bash
# 1. Install dependencies
sudo ./setup.sh

# 2. Build and run
make
sudo dotnet run
```

See [QUICKSTART.md](QUICKSTART.md) for detailed steps.

## 🏗️ Architecture Highlights

### Kernel Space
```
Process → openat() → Tracepoint → eBPF Program → Ring Buffer
```

### User Space
```
Ring Buffer → libbpf → P/Invoke → .NET → Console Output
```

### Event Flow
1. Application calls `openat()` syscall
2. Kernel tracepoint triggers eBPF program
3. eBPF program extracts: PID, command, filename
4. Event written to BPF ring buffer
5. .NET app polls ring buffer
6. Event marshaled to C# struct
7. Displayed in formatted output

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams.

## 📊 Sample Output

```
PID        COMMAND          FILENAME
--------------------------------------------------------------------------------
1234       bash             /etc/bash.bashrc
1234       bash             /home/user/.bashrc
5678       ls               /etc/ld.so.cache
5678       ls               /lib/x86_64-linux-gnu/libselinux.so.1
5679       cat              /etc/hostname
5680       vim              /home/user/document.txt
```

## 🔧 Key Technologies

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Data Collection | eBPF + Tracepoints | Kernel-space event collection |
| Data Transfer | BPF Ring Buffer | Efficient kernel-to-user data passing |
| Control Plane | .NET 8 C# | User-space event processing |
| Native Interop | P/Invoke | Calling libbpf C functions from C# |
| Build System | Make + clang/llvm | Compiling eBPF bytecode |

## 🎓 Learning Outcomes

After working with this POC, you'll understand:

1. **eBPF Fundamentals**
   - Writing eBPF C programs
   - Using tracepoints for syscall monitoring
   - Working with BPF maps (ring buffers)

2. **.NET Native Interop**
   - P/Invoke for calling C libraries
   - Marshaling binary data between managed and unmanaged code
   - Memory management across language boundaries

3. **System Programming**
   - Linux syscall internals
   - Kernel-userspace communication
   - Real-time event processing

4. **DevOps Skills**
   - Building and packaging eBPF programs
   - Deploying to VM environments (Multipass)
   - Managing dependencies and permissions

## 🔍 Extending the POC

### Add More Syscalls
```c
// Hook read() syscall
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_entry(struct trace_event_raw_sys_enter *ctx)
{
    // Implementation
}
```

### Add Filtering
```c
// Only trace specific PIDs
__u32 target_pid = 1234;
if (event->pid != target_pid)
    return 0;
```

### Add Timestamps
```c
event->timestamp = bpf_ktime_get_ns();
```

### Persist Events
```csharp
// In Program.cs HandleEvent method
File.AppendAllText("events.log", 
    $"{evt.Pid},{evt.GetComm()},{evt.GetFilename()}\n");
```

## 📝 File Descriptions

### Core Files

**openat_tracer.bpf.c** (42 lines)
- eBPF program that hooks openat syscall
- Collects PID, command name, and filename
- Uses ring buffer for event delivery

**Program.cs** (150 lines)
- Main .NET application
- Loads and attaches eBPF program
- Polls for events and displays them

**LibBpf.cs** (67 lines)
- P/Invoke declarations for libbpf
- Wraps C functions for .NET use
- Handles BPF object lifecycle

**OpenatEvent.cs** (33 lines)
- Event data structure
- Matches eBPF struct layout
- Provides helper methods for string conversion

```
┌─────────────────────────────────────────────────────────┐
│                     Program.cs                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Load eBPF    │→ │ Poll Events  │→ │ Handle Event │ │
│  │ via LibBpf   │  │ via LibBpf   │  │ via Marshal  │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
         ↓                    ↑                  ↓
    ┌────────┐          ┌──────────┐      ┌──────────┐
    │LibBpf  │          │Ring      │      │OpenatEvent│
    │.cs     │          │Buffer    │      │.cs       │
    └────────┘          └──────────┘      └──────────┘
         ↓                    ↑                  ↓
    ┌────────────────────────────────────────────────────┐
    │          libbpf.so.1 (Native C Library)           │
    └────────────────────────────────────────────────────┘
         ↓                    ↑
    ┌────────────────────────────────────────────────────┐
    │              Linux Kernel                          │
    │  ┌──────────────────────────────────────────────┐ │
    │  │     openat_tracer.bpf.c (eBPF Program)       │ │
    │  └──────────────────────────────────────────────┘ │
    └────────────────────────────────────────────────────┘
```

### Build & Config

**Makefile**
- Compiles eBPF C code to BPF bytecode
- Targets BPF architecture
- Handles cleanup

**EbpfControlPlane.csproj**
- .NET 8 project configuration
- Enables unsafe code for P/Invoke
- No external NuGet dependencies needed

### Scripts

**setup.sh**
- Installs clang, llvm, libbpf
- Installs .NET SDK
- Verifies installations

**test.sh**
- Generates sample openat() events
- Useful for testing the tracer

## 🐛 Common Issues & Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| Failed to load BPF object | Kernel too old | Upgrade to kernel 5.8+ |
| Permission denied | Not running as root | Use `sudo dotnet run` |
| BPF object not found | Not compiled | Run `make` first |
| No events appearing | No activity | Run commands in another terminal |
| libbpf not found | Missing dependency | Run `./setup.sh` |

## 🌐 Deployment Environments

### ✅ Tested On
- Ubuntu 22.04 (Multipass)
- Ubuntu 24.04 (Multipass)
- Kernel 5.15+

### ⚠️ Requirements
- x86_64 architecture
- Kernel with eBPF and BTF support
- CAP_BPF or root privileges

### 📦 Multipass Recommended Specs
```bash
multipass launch 22.04 \
    --name ebpf-poc \
    --memory 2G \
    --disk 10G \
    --cpus 2
```

## 📚 Additional Resources

- [eBPF.io](https://ebpf.io/) - eBPF documentation
- [libbpf](https://github.com/libbpf/libbpf) - libbpf library
- [BPF Ring Buffer](https://nakryiko.com/posts/bpf-ringbuf/) - Deep dive
- [.NET P/Invoke](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke) - Interop guide

## 📄 License

This is a proof-of-concept for educational and demonstration purposes.

## 🤝 Contributing Ideas

Potential enhancements:
- [ ] Add filtering by PID, command, or filename pattern
- [ ] Support for multiple syscalls (read, write, close)
- [ ] JSON or CSV output format
- [ ] Web API for remote monitoring
- [ ] Grafana integration for visualization
- [ ] Performance metrics (events/sec, latency)
- [ ] Event deduplication
- [ ] Tail -f style following

## 💡 Use Cases

This POC demonstrates patterns useful for:
- Security monitoring and audit logging
- Performance profiling and troubleshooting
- Application behavior analysis
- File access tracking
- Compliance and forensics
- DevOps observability

---

**Ready to run?** Start with [QUICKSTART.md](QUICKSTART.md)!
