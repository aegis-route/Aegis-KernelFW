/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_ICMP_FLOOD_H__
#define __MITIGATION_ICMP_FLOOD_H__

#include <linux/bpf.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include "aegis_types.h"

/*
 * Method 8: ICMP Ping Flood Rate Limiting per IP
 * Allows legitimate ping diagnostic requests while dropping high-rate Ping floods.
 * Returns 1 if ICMP rate exceeded limit (should DROP), 0 if allowed.
 */
static __always_inline int is_icmp_flood(void *rate_map, __u32 saddr, struct icmphdr *icmph, __u32 max_icmp_pps)
{
    /* Only rate-limit Echo Requests (Ping, type 8) */
    if (icmph->type != 8) {
        return 0;
    }

    __u64 now_ns = bpf_ktime_get_ns();
    struct rate_bucket *bucket = bpf_map_lookup_elem(rate_map, &saddr);

    if (!bucket) {
        struct rate_bucket new_bucket = {
            .last_seen_ns = now_ns,
            .tokens = 0,
            .current_pps = 1,
        };
        bpf_map_update_elem(rate_map, &saddr, &new_bucket, BPF_ANY);
        return 0;
    }

    __u64 delta_ns = now_ns - bucket->last_seen_ns;
    if (delta_ns >= 1000000000ULL) {
        bucket->last_seen_ns = now_ns;
        bucket->current_pps = 1;
        return 0;
    }

    bucket->current_pps++;
    if (bucket->current_pps > max_icmp_pps) {
        return 1; /* Drop excessive ping requests */
    }

    return 0;
}

#endif /* __MITIGATION_ICMP_FLOOD_H__ */
