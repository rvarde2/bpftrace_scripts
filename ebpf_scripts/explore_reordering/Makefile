CLANG := clang
BPFTOOL := bpftool
BPF_CFLAGS := -target bpf -O2 -fno-asynchronous-unwind-tables

all: vmlinux.h ebpf_reorder.o ebpf_mark_echo.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

ebpf_reorder.o: ebpf_reorder.c
	$(CLANG) $(BPF_CFLAGS) -c ebpf_reorder.c -o ebpf_reorder.o

ebpf_mark_echo.o: ebpf_mark_echo.c
	$(CLANG) $(BPF_CFLAGS) -c ebpf_mark_echo.c -o ebpf_mark_echo.o

clean:
	rm -f  vmlinux.h ebpf_reorder.o ebpf_mark_echo.o

.PHONY: all clean