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

        /* 1. Capture the EXACT state of the first 2 bytes (Version/IHL + ToS) */
        __be16 *word_ptr = (__be16 *)ip;
        __be16 old_word = *word_ptr;
        
        /* 2. Apply all ToS modifications to a local variable first */
        __u8 new_tos = ip->tos | 0x08;

        if (seq_val % 50 == 0) {
            new_tos |= 0x04; // Set compression bit
            skb->priority = 1; 
        } else {
            skb->priority = 0; 
        }

        /* 3. Write the new ToS back to the packet */
        __be16 new_word = (old_word & bpf_htons(0xFF00)) | bpf_htons((__u16)new_tos);
        /* 4. Update Checksum immediately */
        if (new_word != old_word) {
            ip->tos = new_tos;
            // Offset 10 is the IP Checksum field
            bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + 10, old_word, new_word, 2);
            
            // Reload pointers immediately after any packet modification
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            struct iphdr *reloaded_ip = data + sizeof(struct ethhdr);
            if ((void *)(reloaded_ip + 1) > data_end) return TC_ACT_OK;
            ip = reloaded_ip;
        }

    } else if (ip->protocol == 1) { // ICMP
        struct icmphdr *icmp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(icmp + 1) > data_end) return TC_ACT_OK;
        seq_val = bpf_ntohs(icmp->un.echo.sequence);
        // Logic: Map to Priorities that correspond to your priomap
        // if bpf_printk is uncommented logs can be monitored using: sudo cat /sys/kernel/debug/tracing/trace_pipe
        if (seq_val % 5 == 0) {
            //bpf_printk("Seq: %u -> SLOW (Priority 1)\n", seq_val);
            skb->priority = 1; // Priority 1 maps to Band 2
        } else {
            //bpf_printk("Seq: %u -> FAST (Priority 0)\n", seq_val);
            skb->priority = 0; // Priority 0 maps to Band 1
        }
    } 
    return TC_ACT_OK; // Tell TC to continue to the qdisc
}

char _license[] SEC("license") = "GPL";