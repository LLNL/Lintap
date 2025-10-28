# eBPF System Tracer - Documentation Index

Welcome! This index helps you navigate the project documentation.

## 🚀 Getting Started (Start Here!)

1. **[QUICKSTART.md](QUICKSTART.md)** ⚡
   - 5-minute setup and run guide
   - Quick commands to get started
   - Basic troubleshooting

2. **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** 📋
   - Complete project description
   - File structure and organization
   - Key technologies and concepts

3. **[README.md](README.md)** 📚
   - Comprehensive documentation
   - Architecture overview
   - Usage examples and API

## 📖 Architecture & Design

4. **[ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md)** 🏗️
   - Layered architecture details
   - Abstraction layer design
   - Adapter pattern implementation
   - Why we made these choices

5. **[UNIFIED_UPDATE.md](UNIFIED_UPDATE.md)** 🔄
   - Latest architectural changes
   - How openat and execve are unified
   - Migration guide from old approach

## 🔧 Deployment & Setup

6. **[MULTIPASS.md](MULTIPASS.md)** 🖥️
   - Multipass-specific deployment
   - VM creation and configuration
   - File transfer methods
   - Performance tuning

7. **[APPLE_SILICON.md](APPLE_SILICON.md)** 🍎
   - **Apple Silicon (M1/M2/M3/M4) specific guide**
   - ARM64 architecture considerations
   - Multipass on Mac deployment
   - Auto-detection features

8. **[M4_MAC.md](M4_MAC.md)** 💻
   - M4 Mac quick reference
   - One-liners and shortcuts
   - Performance notes

9. **[setup.sh](setup.sh)** ⚙️
   - Automated dependency installation
   - System prerequisites
   - Verification checks

## 🐛 Troubleshooting

10. **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** 🔍
    - Common errors and solutions
    - Diagnostic commands
    - Debug mode instructions
    - Validation scripts

11. **[DOTNET_INSTALL.md](DOTNET_INSTALL.md)** 🔧
    - .NET installation issues
    - Manual installation steps
    - Alternative methods

## 💻 Source Code

### eBPF Programs (Kernel-Side)
- **[execve_tracer.bpf.c](execve_tracer.bpf.c)** - Process creation hook (minimal)
- **[openat_tracer.bpf.c](openat_tracer.bpf.c)** - File access hook (minimal)
- **[Makefile](Makefile)** - Build configuration for eBPF programs

### .NET Application (User-Side)
- **[UnifiedTracer.cs](UnifiedTracer.cs)** - Main orchestrator (loads multiple eBPF programs)
- **[ExecveEvent.cs](ExecveEvent.cs)** - Process event marshaling
- **[OpenatEvent.cs](OpenatEvent.cs)** - File event marshaling
- **[EventAbstraction.cs](EventAbstraction.cs)** - Internal models, adapters, handlers
- **[WintapMessage.cs](WintapMessage.cs)** - External format (WintapMessage)
- **[LibBpf.cs](LibBpf.cs)** - P/Invoke bindings for libbpf
- **[UnifiedTracer.csproj](UnifiedTracer.csproj)** - .NET project file

### Scripts
- **[run-unified.sh](run-unified.sh)** - Build and run unified tracer
- **[fix-dotnet.sh](fix-dotnet.sh)** - Fix .NET installation issues
- **[test.sh](test.sh)** - Generate test events

## 📊 Quick Reference

### Build Commands
```bash
make all                            # Compile both eBPF programs
make execve                         # Compile only execve tracer
make openat                         # Compile only openat tracer
make clean                          # Clean build artifacts
dotnet build UnifiedTracer.csproj   # Build .NET application
```

### Run Commands
```bash
sudo ./setup.sh                                     # Install dependencies
make all                                            # Compile eBPF programs
sudo ./run-unified.sh                               # Build and run (easiest)

# Manual run with options
sudo dotnet run --project UnifiedTracer.csproj --all               # Both tracers
sudo dotnet run --project UnifiedTracer.csproj --execve            # Process only
sudo dotnet run --project UnifiedTracer.csproj --openat            # Files only
sudo dotnet run --project UnifiedTracer.csproj -o events.json      # To file
sudo dotnet run --project UnifiedTracer.csproj -o events.json --console  # Both
```

### Debug Commands
```bash
# Check system
uname -r                                    # Kernel version (need 5.8+)
uname -m                                    # Architecture (x86_64 or aarch64)
ls /sys/kernel/btf/vmlinux                 # BTF support
ldconfig -p | grep libbpf                  # libbpf installed
dotnet --version                           # .NET version (need 8.0+)

# Inspect BPF
sudo bpftool prog list                     # List loaded programs
sudo bpftool map list                      # List BPF maps
sudo cat /sys/kernel/tracing/trace_pipe    # View kernel events

# Verify compilation
file execve_tracer.bpf.o                   # Should show: eBPF
file openat_tracer.bpf.o                   # Should show: eBPF
```

## 🎯 Common Workflows

### First-Time Setup
1. Read [QUICKSTART.md](QUICKSTART.md)
2. Run [setup.sh](setup.sh)
3. Build with `make all`
4. Run with `sudo ./run-unified.sh`

### Development Workflow
1. Modify eBPF or C# code
2. Rebuild: `make all && dotnet build UnifiedTracer.csproj`
3. Test: `sudo ./run-unified.sh`
4. Debug: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

### Multipass Deployment
1. Follow [MULTIPASS.md](MULTIPASS.md) or [M4_MAC.md](M4_MAC.md)
2. Create instance
3. Transfer files
4. Run setup and build

### Understanding the System
1. Read [README.md](README.md) for overview
2. Read [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md) for deep dive
3. Review [EventAbstraction.cs](EventAbstraction.cs) for internal models
4. Review [UnifiedTracer.cs](UnifiedTracer.cs) for orchestration

## 🔗 External Resources

- [eBPF Documentation](https://ebpf.io/)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [BPF Ring Buffer Guide](https://nakryiko.com/posts/bpf-ringbuf/)
- [.NET P/Invoke Docs](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)
- [Multipass Docs](https://multipass.run/docs)
- [Wintap Project](https://github.com/LLNL/Wintap)

## 📝 File Summary

### Core Files

| File | Lines | Purpose |
|------|-------|---------|
| execve_tracer.bpf.c | ~60 | Minimal process creation hook |
| openat_tracer.bpf.c | ~50 | Minimal file access hook |
| UnifiedTracer.cs | ~290 | Main orchestrator |
| EventAbstraction.cs | ~420 | Internal models & adapters |
| WintapMessage.cs | ~70 | External format |
| LibBpf.cs | ~67 | P/Invoke bindings |
| ExecveEvent.cs | ~50 | Process event marshaling |
| OpenatEvent.cs | ~30 | File event marshaling |

### Documentation Files

| File | Purpose |
|------|---------|
| README.md | Main documentation |
| ARCHITECTURE_GUIDE.md | Design deep dive |
| UNIFIED_UPDATE.md | Recent changes |
| QUICKSTART.md | Fast setup |
| APPLE_SILICON.md | ARM64 guide |
| M4_MAC.md | M4 quick ref |
| MULTIPASS.md | VM deployment |
| TROUBLESHOOTING.md | Debug guide |
| DOTNET_INSTALL.md | .NET setup |

## 🎓 Learning Path

### Beginner
1. Start with [QUICKSTART.md](QUICKSTART.md) to get it running
2. Explore [README.md](README.md) to understand basics
3. Run commands and observe output

### Intermediate
1. Study [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md) for system design
2. Read [EventAbstraction.cs](EventAbstraction.cs) to understand internal models
3. Read [UnifiedTracer.cs](UnifiedTracer.cs) to understand orchestration
4. Read [UNIFIED_UPDATE.md](UNIFIED_UPDATE.md) to see recent improvements

### Advanced
1. Modify eBPF programs to add new syscalls
2. Create custom output handlers (Kafka, Splunk, etc.)
3. Add filtering and aggregation logic
4. Contribute container awareness or network events

## 💡 Quick Tips

- **Always run with sudo**: eBPF requires root privileges
- **Compile first**: Run `make all` before running the tracer
- **Test in another terminal**: Generate events separately
- **Check the logs**: Use `dmesg` for kernel errors
- **Use Multipass**: Easiest way to test without affecting your system
- **Apple Silicon works**: Auto-detects ARM64, no changes needed

## 📞 Need Help?

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) first
2. Review relevant documentation section
3. Verify system requirements (kernel 5.8+, .NET 8)
4. Check error messages against common issues
5. Review [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md) for design questions

## 🆕 What's New?

See [UNIFIED_UPDATE.md](UNIFIED_UPDATE.md) for the latest changes:
- ✅ Unified abstraction layer for both tracers
- ✅ Enhanced /proc filesystem reading
- ✅ Adapter pattern for WintapMessage
- ✅ Multiple output handlers (console, file, custom)
- ✅ Simplified eBPF programs (< 100k instructions)

---

**Ready to start?** → [QUICKSTART.md](QUICKSTART.md)

**Want to understand it?** → [ARCHITECTURE_GUIDE.md](ARCHITECTURE_GUIDE.md)

**Having issues?** → [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

**Using Apple Silicon?** → [APPLE_SILICON.md](APPLE_SILICON.md) or [M4_MAC.md](M4_MAC.md)