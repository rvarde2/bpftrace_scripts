CLANG := clang

# We remove -g (debug/BTF info) to see if a stripped object loads easier
# We keep -O2 as it is mandatory for the BPF verifier
CLANG   := clang
BPFTOOL := bpftool
BPF_CFLAGS := -target bpf -O2 -fno-asynchronous-unwind-tables

all: vmlinux.h ebpf_reorder.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

ebpf_reorder.o: ebpf_reorder.c
	$(CLANG) $(BPF_CFLAGS) -c ebpf_reorder.c -o ebpf_reorder.o

clean:
	rm -f  vmlinux.h ebpf_reorder.o

.PHONY: all clean