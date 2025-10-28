.PHONY: all clean openat execve

# Output files
OPENAT_BPF_OBJ = openat_tracer.bpf.o
EXECVE_BPF_OBJ = execve_tracer.bpf.o
VMLINUX = vmlinux.h

all: $(OPENAT_BPF_OBJ) $(EXECVE_BPF_OBJ)

openat: $(OPENAT_BPF_OBJ)

execve: $(EXECVE_BPF_OBJ)

# Auto-detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    TARGET_ARCH := arm64
else ifeq ($(ARCH),x86_64)
    TARGET_ARCH := x86_64
else
    TARGET_ARCH := $(ARCH)
endif

# Generate vmlinux.h with BTF information
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Compile openat eBPF program
$(OPENAT_BPF_OBJ): openat_tracer.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
		-I/usr/include/bpf \
		-c openat_tracer.bpf.c -o $(OPENAT_BPF_OBJ)
	@echo "Compiled openat tracer for architecture: $(TARGET_ARCH)"

# Compile execve eBPF program
$(EXECVE_BPF_OBJ): execve_tracer.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
		-I/usr/include/bpf \
		-c execve_tracer.bpf.c -o $(EXECVE_BPF_OBJ)
	@echo "Compiled execve tracer for architecture: $(TARGET_ARCH)"

clean:
	rm -f $(OPENAT_BPF_OBJ) $(EXECVE_BPF_OBJ) $(VMLINUX)