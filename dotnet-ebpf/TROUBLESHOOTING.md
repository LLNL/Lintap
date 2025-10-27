# Troubleshooting Checklist

Use this checklist to diagnose and resolve common issues.

## Pre-Flight Checks

Before running the tracer, verify:

```bash
# ✓ Kernel version (need 5.8+)
uname -r

# ✓ BTF support
ls -l /sys/kernel/btf/vmlinux

# ✓ libbpf installed
ldconfig -p | grep libbpf

# ✓ .NET installed
dotnet --version

# ✓ BPF object compiled
ls -l openat_tracer.bpf.o

# ✓ Running as root
whoami  # or: id -u
```

## Common Errors & Solutions

### 1. "Failed to open BPF object"

**Error Message:**
```
ERROR: Failed to open BPF object
```

**Diagnosis:**
```bash
# Check if file exists
ls -l openat_tracer.bpf.o

# Check file permissions
stat openat_tracer.bpf.o
```

**Solutions:**
- Run `make` to compile the eBPF program
- Verify the .o file was created successfully
- Check for compilation errors in make output

---

### 2. "Failed to load BPF object"

**Error Message:**
```
ERROR: Failed to load BPF object: -22
```

**Diagnosis:**
```bash
# Check kernel version
uname -r

# Verify BTF availability
ls /sys/kernel/btf/vmlinux

# Check BPF syscall support
cat /boot/config-$(uname -r) | grep BPF
```

**Solutions:**
- Ensure kernel is 5.8 or higher
- Enable BTF in kernel config (CONFIG_DEBUG_INFO_BTF=y)
- Install kernel headers: `sudo apt-get install linux-headers-$(uname -r)`

**Common Error Codes:**
- `-22` (EINVAL): Invalid BPF program or kernel incompatibility
- `-13` (EACCES): Permission denied (need root)
- `-2` (ENOENT): Missing kernel symbol or helper

---

### 3. "This program requires root privileges"

**Error Message:**
```
ERROR: This program requires root privileges.
Please run with sudo.
```

**Diagnosis:**
```bash
# Check current user
whoami

# Check effective UID
id -u
```

**Solutions:**
```bash
# Run with sudo
sudo dotnet run

# Or switch to root
sudo su -
cd /path/to/project
dotnet run
```

---

### 4. "BPF object file not found"

**Error Message:**
```
ERROR: BPF object file not found: openat_tracer.bpf.o
Please run 'make' first to compile the eBPF program.
```

**Diagnosis:**
```bash
# Check if Makefile exists
ls -l Makefile

# Check for compiler
which clang
```

**Solutions:**
```bash
# Compile the eBPF program
make

# If make fails, check for errors
make clean
make 2>&1 | tee make.log
```

---

### 5. "Failed to find BPF program"

**Error Message:**
```
ERROR: Failed to find BPF program 'trace_openat_entry'
```

**Diagnosis:**
```bash
# Inspect the BPF object
llvm-objdump -S openat_tracer.bpf.o

# Check program names
bpftool prog show
```

**Solutions:**
- Verify the program name matches in .bpf.c and Program.cs
- Recompile: `make clean && make`
- Check SEC() macro in eBPF code

---

### 6. "Failed to attach BPF program"

**Error Message:**
```
ERROR: Failed to attach BPF program
```

**Diagnosis:**
```bash
# Check if tracepoint exists
ls /sys/kernel/tracing/events/syscalls/sys_enter_openat

# Check if another program is attached
sudo bpftool prog list
```

**Solutions:**
```bash
# Detach any existing programs
sudo bpftool prog detach <prog_id>

# Restart the tracer
sudo dotnet run
```

---

### 7. No Events Appearing

**Symptom:** Tracer runs but doesn't show any events

**Diagnosis:**
```bash
# Generate test events
ls /tmp
cat /etc/hostname
find /etc -name "hosts"

# Check if program is attached
sudo bpftool prog list | grep trace_openat

# Check ring buffer
sudo bpftool map list
```

**Solutions:**
- Run commands in a **different terminal**
- Use the test script: `./test.sh`
- Verify the tracepoint is firing:
  ```bash
  sudo cat /sys/kernel/tracing/trace_pipe | grep openat
  ```

---

### 8. ".NET SDK not found"

**Error Message:**
```
bash: dotnet: command not found
```

**Solutions:**
```bash
# Install .NET 8
sudo ./setup.sh

# Or manually:
wget https://dot.net/v1/dotnet-install.sh
chmod +x dotnet-install.sh
sudo ./dotnet-install.sh --channel 8.0 --install-dir /usr/share/dotnet
sudo ln -sf /usr/share/dotnet/dotnet /usr/bin/dotnet
```

---

### 9. "libbpf.so.1 not found"

**Error Message:**
```
DllNotFoundException: Unable to load shared library 'libbpf.so.1'
```

**Diagnosis:**
```bash
# Check if libbpf is installed
dpkg -l | grep libbpf

# Check library path
ldconfig -p | grep libbpf
```

**Solutions:**
```bash
# Install libbpf
sudo apt-get update
sudo apt-get install libbpf1 libbpf-dev

# Refresh library cache
sudo ldconfig
```

---

### 10. Compilation Errors

**Error Message:**
```
fatal error: 'bpf/bpf_helpers.h' file not found
```

**Solutions:**
```bash
# Install development headers
sudo apt-get install libbpf-dev clang llvm

# Verify installation
ls /usr/include/bpf/
```

---

## Performance Issues

### High CPU Usage

**Diagnosis:**
```bash
# Check event rate
# (observe events per second in tracer output)

# Check system load
top -p $(pgrep dotnet)
```

**Solutions:**
- Add filtering in eBPF program (by PID, filename pattern)
- Increase ring buffer size in .bpf.c
- Batch event processing in .NET

---

### Memory Leaks

**Diagnosis:**
```bash
# Monitor memory usage
watch -n 1 'ps aux | grep dotnet'

# Check for ring buffer buildup
sudo bpftool map dump name events
```

**Solutions:**
- Ensure proper cleanup in HandleEvent callback
- Verify ring buffer is being consumed
- Check for exceptions in event handling

---

## Debug Mode

### Enable Verbose Logging

Add debug output to Program.cs:

```csharp
// In Main method, after loading BPF object
Console.WriteLine($"BPF Object: {bpfObject}");
Console.WriteLine($"Program: {prog}");
Console.WriteLine($"Link: {bpfLink}");
Console.WriteLine($"Map FD: {mapFd}");
```

### Check BPF Program Status

```bash
# List all BPF programs
sudo bpftool prog list

# Show details of a specific program
sudo bpftool prog show id <ID>

# Dump BPF program instructions
sudo bpftool prog dump xlated id <ID>
```

### Trace Kernel Events

```bash
# Monitor all openat calls in kernel
sudo cat /sys/kernel/tracing/trace_pipe | grep openat

# Enable specific tracepoint
echo 1 | sudo tee /sys/kernel/tracing/events/syscalls/sys_enter_openat/enable

# View tracepoint format
cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
```

---

## Multipass-Specific Issues

### Instance Won't Start

```bash
# Check status
multipass list

# Restart instance
multipass stop ebpf-poc
multipass start ebpf-poc

# Check logs
multipass info ebpf-poc --all
```

### Kernel Too Old in Instance

```bash
# Inside instance
uname -r

# If < 5.8, create new instance with newer Ubuntu
multipass delete ebpf-poc
multipass purge
multipass launch 24.04 --name ebpf-poc
```

---

## Getting Help

If you're still stuck:

1. **Check dmesg for kernel errors:**
   ```bash
   sudo dmesg | tail -50
   ```

2. **Verify BPF capability:**
   ```bash
   # Check if user has BPF capabilities
   sudo getcap $(which bpftool)
   ```

3. **Test with a minimal BPF program:**
   ```bash
   # Use bpftool to test basic BPF functionality
   sudo bpftool prog help
   ```

4. **Review the logs:**
   - Compilation: `make 2>&1 | tee build.log`
   - Runtime: `sudo dotnet run 2>&1 | tee run.log`

5. **File an issue** with:
   - Kernel version: `uname -r`
   - OS version: `cat /etc/os-release`
   - Error messages and logs
   - Steps to reproduce

---

## Quick Validation Script

Save as `validate.sh` and run to check everything:

```bash
#!/bin/bash

echo "=== System Validation ==="
echo

echo -n "Kernel version: "
uname -r | grep -q "^[5-9]\.[8-9]" && echo "✓ OK" || echo "✗ Too old (need 5.8+)"

echo -n "BTF support: "
[ -f /sys/kernel/btf/vmlinux ] && echo "✓ OK" || echo "✗ Missing"

echo -n "libbpf installed: "
ldconfig -p | grep -q libbpf && echo "✓ OK" || echo "✗ Not found"

echo -n ".NET installed: "
command -v dotnet &> /dev/null && echo "✓ OK" || echo "✗ Not found"

echo -n "clang installed: "
command -v clang &> /dev/null && echo "✓ OK" || echo "✗ Not found"

echo -n "BPF object: "
[ -f openat_tracer.bpf.o ] && echo "✓ OK" || echo "✗ Run 'make' first"

echo -n "Running as root: "
[ "$EUID" -eq 0 ] && echo "✓ OK" || echo "✗ Use sudo"

echo
echo "=== Ready to Run ==="
```

---

**Still having issues?** Review [README.md](README.md) for more details.
