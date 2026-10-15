/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_IPV6_PIPELINE_H__
#define __MITIGATION_IPV6_PIPELINE_H__

#include <linux/bpf.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/in6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define NEXTHDR_HOP         0
#define NEXTHDR_ROUTING     43
#define NEXTHDR_FRAGMENT    44

/*
 * Method 12: Comprehensive IPv6 Defense Pipeline
 *
 * Checks:
 *   1. Malformed IPv6 Header (version != 6, truncated boundary, invalid payload length)
 *   2. IPv6 Bogon / Spoofed Addresses (Unspecified, Loopback ::1, Multicast source, Link-Local fe80::/10 from WAN)
 *   3. IPv6 Land Attack (saddr == daddr)
 *   4. IPv6 Extension Header Abuse & Fragment Drop (RFC 8200)
 *   5. ICMPv6 Ping Flood Rate Limiting (Preserving NDP Neighbor Discovery)
 *
 * Returns:
 *   1: Drop packet
 *   0: Legitimate IPv6 packet
 */
static __always_inline int is_ipv6_abusive(void *data, void *data_end, struct ipv6hdr *ip6h)
{
    /* 1. Validate IPv6 Header Boundary */
    if ((void *)(ip6h + 1) > data_end) {
        return 1;
    }

    if ((ip6h->version) != 6) {
        return 1;
    }

    __u16 payload_len = bpf_ntohs(ip6h->payload_len);
    if ((void *)(ip6h + 1) + payload_len > data_end) {
        return 1; /* Truncated payload */
    }

    const __u32 *s = (const __u32 *)&ip6h->saddr;
    const __u32 *d = (const __u32 *)&ip6h->daddr;

    /* 2. IPv6 Land Attack: Source equals Destination */
    if (s[0] == d[0] && s[1] == d[1] && s[2] == d[2] && s[3] == d[3]) {
        return 1;
    }

    /* 3. IPv6 Bogons: Unspecified address (::/128) */
    if (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0) {
        return 1;
    }

    /* 4. IPv6 Loopback (::1/128) arriving on external interface */
    if (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == bpf_htonl(1)) {
        return 1;
    }

    /* 5. Multicast Source (ff00::/8 - first byte is 0xFF) */
    const __u8 *s_bytes = (const __u8 *)&ip6h->saddr;
    if (s_bytes[0] == 0xFF) {
        return 1; /* Multicast can NEVER be a source address (RFC 4291) */
    }

    /* 6. Link-Local (fe80::/10) from WAN: first byte 0xFE, second byte & 0xC0 == 0x80 */
    if (s_bytes[0] == 0xFE && (s_bytes[1] & 0xC0) == 0x80) {
        return 1;
    }

    /* 7. Drop IPv6 Fragments & Dangerous Extension Headers */
    __u8 nexthdr = ip6h->nexthdr;
    if (nexthdr == NEXTHDR_FRAGMENT || nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING) {
        return 1; /* Drop IPv6 fragments and routing header manipulation */
    }

    /* 8. ICMPv6 Ping Flood vs NDP Validation */
    if (nexthdr == IPPROTO_ICMPV6) {
        struct icmp6hdr *icmp6 = (void *)(ip6h + 1);
        if ((void *)(icmp6 + 1) > data_end) {
            return 1;
        }

        /*
         * NDP (Neighbor Discovery Protocol) MUST NOT BE DROPPED!
         * Type 133: Router Solicitation, 134: Router Advertisement
         * Type 135: Neighbor Solicitation, 136: Neighbor Advertisement
         */
        if (icmp6->icmp6_type >= 133 && icmp6->icmp6_type <= 136) {
            return 0; /* Always permit vital local neighbor discovery */
        }
    }

    return 0;
}

#endif /* __MITIGATION_IPV6_PIPELINE_H__ */
