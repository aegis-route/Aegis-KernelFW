/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_BOGON_H__
#define __MITIGATION_BOGON_H__

#include <linux/ip.h>

/*
 * Method 2: Check for Bogon, Spoofed IPs, and Land Attacks
 * Returns 1 if IP is bogus/spoofed (should DROP), 0 if legitimate.
 */
static __always_inline int is_bogon_or_spoofed(struct iphdr *iph)
{
    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;

    /* 1. Land Attack: Source IP matches Destination IP */
    if (saddr == daddr) {
        return 1;
    }

    /* 2. Zero IP check (0.0.0.0/8) */
    if (saddr == 0 || (saddr & 0x000000FF) == 0) {
        return 1;
    }

    /* 3. Loopback as source: 127.0.0.0/8 (0x7F in first byte) */
    if ((saddr & 0x000000FF) == 0x7F) {
        return 1;
    }

    /* 4. Multicast (224.0.0.0/4 -> first byte >= 224 and <= 239) */
    __u8 first_byte = (__u8)(saddr & 0xFF);
    if (first_byte >= 224 && first_byte <= 239) {
        return 1;
    }

    /* 5. Class E Reserved / Broadcast (240.0.0.0/4 -> first byte >= 240) */
    if (first_byte >= 240) {
        return 1;
    }

    return 0;
}

#endif /* __MITIGATION_BOGON_H__ */
