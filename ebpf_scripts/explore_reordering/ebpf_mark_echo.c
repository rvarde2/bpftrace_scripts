#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800

SEC("classifier")
int tc_mark_pipeline(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    // Check the 3rd bit of the TOS byte (0x4)
    if (ip->tos & 0x04) {
        // Set the Most Significant Bit (MSB) of the mark
        skb->mark |= 0x80000000;
    } else {
        // Clear the MSB if the bit is not set
        skb->mark &= ~0x80000000;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
