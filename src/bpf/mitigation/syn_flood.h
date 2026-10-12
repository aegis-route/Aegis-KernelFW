/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_SYN_FLOOD_H__
#define __MITIGATION_SYN_FLOOD_H__

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "aegis_types.h"

/*
 * Method 5: TCP SYN Flood Rate Limiting per IP
 * Returns 1 if SYN rate exceeded threshold (should DROP), 0 if allowed.
 */
static __always_inline int is_syn_flood(void *rate_map, __u32 saddr, struct tcphdr *tcph, __u32 max_syn_pps)
{
    /* Only inspect pure SYN packets (connection initiation) */
    if (!tcph->syn || tcph->ack) {
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

    /* 1-second sliding time window */
    __u64 delta_ns = now_ns - bucket->last_seen_ns;
    if (delta_ns >= 1000000000ULL) {
        bucket->last_seen_ns = now_ns;
        bucket->current_pps = 1;
        return 0;
    }

    bucket->current_pps++;
    if (bucket->current_pps > max_syn_pps) {
        return 1; /* Drop excessive SYN */
    }

    return 0;
}

#endif /* __MITIGATION_SYN_FLOOD_H__ */
