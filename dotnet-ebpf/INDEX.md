# eBPF OpenAt Tracer - Documentation Index

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

## 📖 Core Documentation

3. **[README.md](README.md)** 📚
   - Full documentation
   - Detailed installation steps
   - How the system works
   - Extension ideas

4. **[ARCHITECTURE.md](ARCHITECTURE.md)** 🏗️
   - System architecture diagrams
   - Data flow visualization
   - Event structure details
   - Component interaction

## 🔧 Deployment & Setup

5. **[MULTIPASS.md](MULTIPASS.md)** 🖥️
   - Multipass-specific deployment
   - VM creation and configuration
   - File transfer methods
   - Performance tuning

6. **[APPLE_SILICON.md](APPLE_SILICON.md)** 🍎
   - **Apple Silicon (M1/M2/M3/M4) specific guide**
   - ARM64 architecture considerations
   - Multipass on Mac deployment
   - Auto-detection features

7. **[setup.sh](setup.sh)** ⚙️
   - Automated dependency installation
   - System prerequisites
   - Verification checks

## 🐛 Troubleshooting

8. **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** 🔍
   - Common errors and solutions
   - Diagnostic commands
   - Debug mode instructions
   - Validation scripts

## 💻 Source Code

### eBPF (Kernel-Side)
- **[openat_tracer.bpf.c](openat_tracer.bpf.c)** - eBPF program that hooks openat syscall
- **[Makefile](Makefile)** - Build configuration for eBPF program

### .NET (User-Side)
- **[Program.cs](Program.cs)** - Main control plane application
- **[LibBpf.cs](LibBpf.cs)** - P/Invoke bindings for libbpf
- **[OpenatEvent.cs](OpenatEvent.cs)** - Event data structure
- **[EbpfControlPlane.csproj](EbpfControlPlane.csproj)** - .NET project file

### Testing
- **[test.sh](test.sh)** - Generate test openat events

## 📊 Quick Reference

### Build Commands
```bash
make              # Compile eBPF program
make clean        # Clean build artifacts
dotnet build      # Build .NET application
dotnet run        # Run .NET application
```

### Run Commands
```bash
sudo ./setup.sh   # Install dependencies
make              # Compile eBPF
sudo dotnet run   # Start tracer
./test.sh         # Generate test events (in another terminal)
```

### Debug Commands
```bash
# Check system
uname -r                                    # Kernel version
ls /sys/kernel/btf/vmlinux                 # BTF support
ldconfig -p | grep libbpf                  # libbpf installed

# Inspect BPF
sudo bpftool prog list                     # List programs
sudo bpftool map list                      # List maps
sudo cat /sys/kernel/tracing/trace_pipe    # View events
```

## 🎯 Common Workflows

### First-Time Setup
1. Read [QUICKSTART.md](QUICKSTART.md)
2. Run [setup.sh](setup.sh)
3. Build with `make`
4. Run with `sudo dotnet run`

### Development Workflow
1. Modify [openat_tracer.bpf.c](openat_tracer.bpf.c) or [Program.cs](Program.cs)
2. Rebuild: `make clean && make`
3. Test: `sudo dotnet run`
4. Debug: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

### Multipass Deployment
1. Follow [MULTIPASS.md](MULTIPASS.md)
2. Create instance
3. Transfer files
4. Run setup and build

### Understanding the System
1. Read [ARCHITECTURE.md](ARCHITECTURE.md) for high-level design
2. Read [README.md](README.md) for detailed explanation
3. Review [openat_tracer.bpf.c](openat_tracer.bpf.c) for eBPF implementation
4. Review [Program.cs](Program.cs) for .NET implementation

## 🔗 External Resources

- [eBPF Documentation](https://ebpf.io/)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [BPF Ring Buffer Guide](https://nakryiko.com/posts/bpf-ringbuf/)
- [.NET P/Invoke Docs](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)
- [Multipass Docs](https://multipass.run/docs)

## 📝 File Summary

| File | Lines | Purpose |
|------|-------|---------|
| openat_tracer.bpf.c | 42 | eBPF kernel program |
| Program.cs | 150 | Main .NET application |
| LibBpf.cs | 67 | P/Invoke wrapper |
| OpenatEvent.cs | 33 | Event structure |
| Makefile | 16 | Build configuration |
| setup.sh | 45 | Dependency installer |
| test.sh | 15 | Test event generator |

## 🎓 Learning Path

### Beginner
1. Start with [QUICKSTART.md](QUICKSTART.md) to get it running
2. Explore [README.md](README.md) to understand basics
3. Run [test.sh](test.sh) and observe output

### Intermediate
1. Study [ARCHITECTURE.md](ARCHITECTURE.md) for system design
2. Read [openat_tracer.bpf.c](openat_tracer.bpf.c) line by line
3. Read [Program.cs](Program.cs) to understand control flow
4. Modify and experiment with the code

### Advanced
1. Add filtering to eBPF program
2. Hook additional syscalls
3. Add timestamp tracking
4. Implement event persistence
5. Create a web dashboard

## 💡 Quick Tips

- **Always run with sudo**: BPF programs require root privileges
- **Compile first**: Run `make` before `dotnet run`
- **Test in another terminal**: Generate events separately
- **Check the logs**: Use `dmesg` for kernel errors
- **Use Multipass**: Easiest way to test without affecting your system

## 📞 Need Help?

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) first
2. Review relevant documentation section
3. Verify system requirements
4. Check error messages against common issues
5. Review eBPF/libbpf documentation

---

**Ready to start?** → [QUICKSTART.md](QUICKSTART.md)

**Want to understand it?** → [ARCHITECTURE.md](ARCHITECTURE.md)

**Having issues?** → [TROUBLESHOOTING.md](TROUBLESHOOTING.md)