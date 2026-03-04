#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define ETH_P_IP 0x0800
#define REORDER_INTERVAL 10


struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
};
// ** AI assisted explanation of the map declaration: **
// type = BPF_MAP_TYPE_ARRAY: The simplest map type. It pre-allocates contiguous memory.
// size_key = sizeof(__u32): To look up a value in an array, we use a 32-bit integer (the index 0).
// size_value = sizeof(__u64): Our persistent counter value will be a 64-bit integer, 
//      to ensure it doesn't wrap around to 0 too quickly when handling millions of packets.
// max_elem = 1: We only need an array of length 1, because we only need one global counter.
// pinning = 0: This tells the kernel not to permanently pin this map to the system's file system. 
//      As soon as you remove the tc filter, the map and its memory vanish automatically.

struct bpf_elf_map SEC("maps") pkt_counter = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u64),
    .max_elem = 1,
    .pinning = 0,
};

// if bpf_printk and seq_val are uncommented logs can be monitored using: 
//      sudo cat /sys/kernel/debug/tracing/trace_pipe

SEC("classifier")
int reorder_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

   //__u32 seq_val = 0;
    
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_counter, &key);
    __u64 pkt_idx = 1;
    if (count) {
        pkt_idx = __sync_fetch_and_add(count, 1) + 1;
    }

    if (ip->protocol == 6) { // TCP
        struct tcphdr *tcp = (void *)ip + sizeof(struct iphdr);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        //seq_val = bpf_ntohl(tcp->seq);

        // 1. Capture the EXACT state of the first 2 bytes (Version/IHL + ToS) 
        __be16 *word_ptr = (__be16 *)ip;
        __be16 old_word = *word_ptr;
        
        // 2. Apply all ToS modifications to a local variable first 
        __u8 new_tos = ip->tos | 0x08;

        if (pkt_idx % REORDER_INTERVAL == 0) {
            new_tos |= 0x04; // Set compression bit
            //bpf_printk("Seq: %u -> (Priority 1)\n", seq_val);
            skb->priority = 1;
        } else {
            //bpf_printk("Seq: %u -> (Priority 0)\n", seq_val);
            skb->priority = 0;
        }

        // 3. Write the new ToS back to the packet 
        __be16 new_word = (old_word & bpf_htons(0xFF00)) | bpf_htons((__u16)new_tos);
        // 4. Update Checksum immediately 
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
        //seq_val = bpf_ntohs(icmp->un.echo.sequence);
        // Logic: Map to Priorities that correspond to your priomap
        if (pkt_idx % REORDER_INTERVAL == 0) {
            //bpf_printk("Seq: %u -> (Priority 1)\n", seq_val);
            skb->priority = 1; // Priority 1 maps to Band 2
        } else {
            //bpf_printk("Seq: %u -> (Priority 0)\n", seq_val);
            skb->priority = 0; // Priority 0 maps to Band 1
        }
    } 
    return TC_ACT_OK; // Tell TC to continue to the qdisc
}

char _license[] SEC("license") = "GPL";
