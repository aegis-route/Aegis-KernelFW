/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_UDP_JUNK_H__
#define __MITIGATION_UDP_JUNK_H__

#include <linux/bpf.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

/*
 * Method 7: UDP Junk & Random Closed Port Flood Drop
 * Drops incoming UDP packets targeted at non-listening ports directly in XDP.
 * Completely prevents kernel from emitting ICMP Port Unreachable packets.
 * Returns 1 if UDP port is closed (should DROP), 0 if port is open.
 */
static __always_inline int is_udp_junk(void *open_udp_ports_map, struct udphdr *udph)
{
    __u16 dest_port = udph->dest;

    __u32 *is_open = bpf_map_lookup_elem(open_udp_ports_map, &dest_port);
    if (!is_open || *is_open == 0) {
        return 1; /* Closed port: drop immediately */
    }

    return 0;
}

#endif /* __MITIGATION_UDP_JUNK_H__ */
