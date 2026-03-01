#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

SEC("classifier")
int reorder_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 seq_val = 0;
    if (ip->protocol == 6) { // TCP
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        seq_val = bpf_ntohl(tcp->seq);
    } else if (ip->protocol == 1) { // ICMP
        struct icmphdr *icmp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(icmp + 1) > data_end) return TC_ACT_OK;
        seq_val = bpf_ntohs(icmp->un.echo.sequence);
    } else {
        return TC_ACT_OK;
    }

    // Logic: Map to Priorities that correspond to your priomap
    // if bpf_printk is uncommented logs can be monitored using: sudo cat /sys/kernel/debug/tracing/trace_pipe
    if (seq_val % 5 == 0) {
        //bpf_printk("Seq: %u -> SLOW (Priority 1)\n", seq_val);
        skb->priority = 1; // Priority 1 maps to Band 2
    } else {
        //bpf_printk("Seq: %u -> FAST (Priority 0)\n", seq_val);
        skb->priority = 0; // Priority 0 maps to Band 1
    }

    return TC_ACT_OK; // Tell TC to continue to the qdisc
}

char _license[] SEC("license") = "GPL";