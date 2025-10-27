# eBPF OpenAt Tracer - POC

A proof-of-concept demonstrating eBPF-based system call tracing with a .NET control plane.

## Architecture

### Components

1. **eBPF Data Collection** (`openat_tracer.bpf.c`)
   - Hooks the `openat` syscall using a tracepoint
   - Collects: PID, command name, and filename
   - Sends events to userspace via BPF ring buffer

2. **.NET Control Plane** (`Program.cs`, `LibBpf.cs`, `OpenatEvent.cs`)
   - Loads and attaches the eBPF program
   - Reads events from the ring buffer
   - Displays traced system calls in real-time

## Requirements

- Ubuntu 20.04 or later (tested on Ubuntu 22.04+)
- Linux kernel 5.8+ (for ring buffer support)
- Root/sudo privileges

**Apple Silicon (M1/M2/M3/M4) Users:** ✅ Fully supported! The code auto-detects ARM64 architecture. See [APPLE_SILICON.md](APPLE_SILICON.md) for specific instructions.

## Installation

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