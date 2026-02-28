#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"

// Add this function above main
static int libbpf_print_custom(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct hello_bpf *skel;
    int err;

    /* Set up libbpf errors/debug logging */
    libbpf_set_print(libbpf_print_custom);

    /* Open and load the BPF application */
    skel = hello_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Attach the tracepoint handler */
    err = hello_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see output.\n");

    /* Keep the program running until Ctrl+C */
    for (;;) {
        sleep(1);
    }

cleanup:
    hello_bpf__destroy(skel);
    return -err;
}
