// SPDX-License-Identifier: GPL-2.0
/*
 * net_capture.bpf.c — XDP program for passive TCP/IP header capture
 *
 * Parses Ethernet → IPv4 → TCP and writes a compact flow record to ringbuf.
 * Always returns XDP_PASS so packets are never dropped.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Ethernet frame types */
#define ETH_P_IP  0x0800

/* IP protocol numbers */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Minimum header sizes */
#define ETH_HDR_LEN  14
#define IP_HDR_MIN   20
#define TCP_HDR_MIN  20

struct net_event {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  proto;
    u8  _pad[7];  /* alignment */
    u64 ts;       /* nanoseconds since boot */
};

/* Ringbuf map — 4 MB ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} net_events SEC(".maps");

/* Minimal inline Ethernet header */
struct ethhdr_min {
    u8  h_dest[6];
    u8  h_source[6];
    u16 h_proto;
} __attribute__((packed));

/* Minimal inline IPv4 header */
struct iphdr_min {
    u8  version_ihl;
    u8  tos;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u8  ttl;
    u8  protocol;
    u16 check;
    u32 saddr;
    u32 daddr;
} __attribute__((packed));

/* Minimal inline TCP header */
struct tcphdr_min {
    u16 source;
    u16 dest;
    u32 seq;
    u32 ack_seq;
    /* data offset is in the upper nibble of a u16 */
    u16 doff_flags;
    u16 window;
    u16 check;
    u16 urg_ptr;
} __attribute__((packed));

SEC("xdp")
int xdp_net_capture(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* --- Ethernet --- */
    struct ethhdr_min *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    /* --- IPv4 --- */
    struct iphdr_min *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u8 ihl = (ip->version_ihl & 0x0f) * 4;
    if (ihl < IP_HDR_MIN)
        return XDP_PASS;

    u8 proto = ip->protocol;

    /* We emit for TCP and UDP; skip everything else */
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return XDP_PASS;

    u16 src_port = 0, dst_port = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr_min *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        /* UDP: first four bytes are src/dst ports */
        u16 *ports = (void *)ip + ihl;
        if ((void *)(ports + 2) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(ports[0]);
        dst_port = bpf_ntohs(ports[1]);
    }

    struct net_event *ev = bpf_ringbuf_reserve(&net_events, sizeof(*ev), 0);
    if (!ev)
        return XDP_PASS;

    ev->src_ip   = bpf_ntohl(ip->saddr);
    ev->dst_ip   = bpf_ntohl(ip->daddr);
    ev->src_port = src_port;
    ev->dst_port = dst_port;
    ev->proto    = proto;
    ev->ts       = bpf_ktime_get_ns();

    bpf_ringbuf_submit(ev, 0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
