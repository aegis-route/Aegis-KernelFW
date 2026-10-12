/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_RATE_LIMIT_H__
#define __MITIGATION_RATE_LIMIT_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "aegis_types.h"

/*
 * Method 10: High PPS / Bandwidth Token Bucket Rate Limiting & Dynamic Auto-Ban
 *
 * Return values:
 *   0: Allowed (Within rate limits)
 *   1: Dropped by Rate Limit & Auto-Banned
 *   2: Dropped by Active Dynamic Ban
 */
static __always_inline int check_rate_limit_and_ban(void *ban_map, void *rate_map,
                                                    __u32 saddr, __u32 max_pps,
                                                    __u32 ban_duration_sec)
{
    __u64 now_ns = bpf_ktime_get_ns();

    /* 1. Check if IP is currently under Dynamic Auto-Ban */
    struct dynamic_ban_val *ban_val = bpf_map_lookup_elem(ban_map, &saddr);
    if (ban_val) {
        if (now_ns < ban_val->ban_until_ns) {
            ban_val->dropped_count++;
            return 2; /* Still banned: Drop */
        } else {
            /* Ban expired: remove ban */
            bpf_map_delete_elem(ban_map, &saddr);
        }
    }

    /* 2. Check Packet Rate per IP (1-second sliding window) */
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
    if (bucket->current_pps > max_pps) {
        /* Abuse detected! Trigger Dynamic Auto-Ban */
        struct dynamic_ban_val new_ban = {
            .ban_until_ns = now_ns + ((__u64)ban_duration_sec * 1000000000ULL),
            .trigger_reason = STAT_DROPPED_RATE_LIMIT,
            .dropped_count = 1,
        };
        bpf_map_update_elem(ban_map, &saddr, &new_ban, BPF_ANY);
        return 1; /* Drop & Ban */
    }

    return 0;
}

#endif /* __MITIGATION_RATE_LIMIT_H__ */
