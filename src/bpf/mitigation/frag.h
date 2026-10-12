/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_FRAG_H__
#define __MITIGATION_FRAG_H__

#include <linux/ip.h>
#include <bpf/bpf_endian.h>

/*
 * Method 3: Check for Fragmented Packets
 * Modern servers rarely need IP fragmentation over WAN. Attackers use fragments
 * to bypass deep-packet inspection or perform Teardrop / Ping of Death attacks.
 * Returns 1 if packet is fragmented (should DROP), 0 if unfragmented.
 */
static __always_inline int is_fragmented_packet(struct iphdr *iph)
{
    /* 0x2000 is IP_MF (More Fragments), 0x1FFF is fragment offset mask */
    __u16 frag_field = bpf_ntohs(iph->frag_off);
    if ((frag_field & 0x2000) != 0 || (frag_field & 0x1FFF) != 0) {
        return 1;
    }
    return 0;
}

#endif /* __MITIGATION_FRAG_H__ */
