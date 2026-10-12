/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_MALFORMED_H__
#define __MITIGATION_MALFORMED_H__

#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

/*
 * Method 1: Check for Malformed, Corrupted or Truncated Packets
 * Returns 1 if packet is malformed (should DROP), 0 if valid.
 */
static __always_inline int is_malformed_packet(void *data, void *data_end, struct iphdr *iph)
{
    /* 1. Validate IPv4 Header */
    if ((void *)(iph + 1) > data_end) {
        return 1;
    }

    if (iph->version != 4 || iph->ihl < 5) {
        return 1;
    }

    __u32 ip_hdr_len = iph->ihl * 4;
    if ((void *)iph + ip_hdr_len > data_end) {
        return 1;
    }

    __u16 tot_len = bpf_ntohs(iph->tot_len);
    if (tot_len < ip_hdr_len) {
        return 1;
    }

    void *l4_hdr = (void *)iph + ip_hdr_len;

    /* 2. Validate L4 Header lengths */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) {
            return 1;
        }
        if (tcph->doff < 5) {
            return 1;
        }
        if ((void *)tcph + (tcph->doff * 4) > data_end) {
            return 1;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) {
            return 1;
        }
        __u16 udp_len = bpf_ntohs(udph->len);
        if (udp_len < sizeof(struct udphdr) || (void *)udph + udp_len > data_end) {
            return 1;
        }
    }

    return 0;
}

#endif /* __MITIGATION_MALFORMED_H__ */
