/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_REFLECTED_H__
#define __MITIGATION_REFLECTED_H__

#include <linux/udp.h>
#include <bpf/bpf_endian.h>

/*
 * Method 9: Reflected Amplification Flood Mitigation (DNS, NTP, SSDP, Memcached)
 * In reflection attacks, attackers bounce large UDP responses off public servers
 * back to the victim.
 * Returns 1 if packet is suspicious reflected flood (should DROP), 0 if allowed.
 */
static __always_inline int is_reflected_flood(struct udphdr *udph)
{
    __u16 src_port = bpf_ntohs(udph->source);

    /* Common amplification reflection service ports */
    if (src_port == 53     /* DNS */
        || src_port == 123  /* NTP */
        || src_port == 1900 /* SSDP */
        || src_port == 11211 /* Memcached */
        || src_port == 389  /* CLDAP */
        || src_port == 3702 /* WS-Discovery */
    ) {
        /*
         * If the server itself is NOT running an outgoing DNS resolver client
         * or NTP sync client on ephemeral ports, drop incoming unsolicited replies.
         */
        __u16 dest_port = bpf_ntohs(udph->dest);
        if (dest_port < 1024 || dest_port == 80 || dest_port == 443) {
            return 1; /* Drop reflection response targeted at service ports */
        }
    }

    return 0;
}

#endif /* __MITIGATION_REFLECTED_H__ */
