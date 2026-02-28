# Tools
CLANG   := clang
CC      := gcc
BPFTOOL := bpftool

# Compiler Flags
# -I. is still needed to find your local vmlinux.h
BPF_CFLAGS := -I. -target bpf -g -O2
USER_CFLAGS := -I. -g -O2
# We link against the system installed libbpf
USER_LIBS := -lbpf -lelf -lz

# --- Build Targets ---

all: vmlinux.h hello

# Step 1: Generate vmlinux.h (The "Master Header" of the kernel)
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Step 2: Compile the eBPF kernel code
hello.bpf.o: hello.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c hello.bpf.c -o hello.bpf.o

# Step 3: Generate the Skeleton header
hello.skel.h: hello.bpf.o
	$(BPFTOOL) gen skeleton hello.bpf.o > hello.skel.h

# Step 4: Compile the user-space loader
hello: hello.c hello.skel.h
	$(CC) $(USER_CFLAGS) hello.c $(USER_LIBS) -o hello

clean:
	rm -f vmlinux.h hello.bpf.o hello.skel.h hello

.PHONY: all clean
