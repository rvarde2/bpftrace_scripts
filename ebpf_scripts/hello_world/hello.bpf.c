#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Moving the string out of the function makes it a global constant
// which puts it in a predictable .rodata section.
const char msg[] = "Hello from the kernel!";

SEC("tp/syscalls/sys_enter_execve")
int handle_tp(void *ctx) {
    bpf_printk("%s\n", msg);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
