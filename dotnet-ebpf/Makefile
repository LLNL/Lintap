.PHONY: all clean

# Output files
BPF_OBJ = openat_tracer.bpf.o
VMLINUX = vmlinux.h

all: $(BPF_OBJ)

# Generate vmlinux.h with BTF information
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Compile eBPF program
# Auto-detect architecture
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    TARGET_ARCH := arm64
else ifeq ($(ARCH),x86_64)
    TARGET_ARCH := x86_64
else
    TARGET_ARCH := $(ARCH)
endif

$(BPF_OBJ): openat_tracer.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) \
		-I/usr/include/bpf \
		-c openat_tracer.bpf.c -o $(BPF_OBJ)
	@echo "Compiled for architecture: $(TARGET_ARCH)"

clean:
	rm -f $(BPF_OBJ) $(VMLINUX)