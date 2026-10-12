#ifndef __AEGIS_TYPES_H__
#define __AEGIS_TYPES_H__

#ifndef __KERNEL__
#include <linux/types.h>
#include <stdint.h>
#endif

/*
 * Firewall Verdict / Actions
 */
enum aegis_action {
    AEGIS_ACTION_PASS = 0,     /* Allow packet through (XDP_PASS) */
    AEGIS_ACTION_DROP = 1,     /* Drop packet immediately at NIC (XDP_DROP) */
    AEGIS_ACTION_ABORTED = 2,  /* Parsing error or invalid state (XDP_ABORTED) */
};

/*
 * Supported Protocols for L4 Filtering
 */
enum aegis_proto {
    AEGIS_PROTO_ANY = 0,
    AEGIS_PROTO_ICMP = 1,
    AEGIS_PROTO_TCP = 6,
    AEGIS_PROTO_UDP = 17,
};

/*
 * Feature Flags (Bitmask) to enable/disable each mitigation method independently
 */
#define AEGIS_FEAT_MALFORMED_CHECK    (1U << 0)  /* Method 1: Malformed & short packet check */
#define AEGIS_FEAT_BOGON_FILTER       (1U << 1)  /* Method 2: Bogon, loopback, Land attack (src==dst) */
#define AEGIS_FEAT_FRAG_FILTER        (1U << 2)  /* Method 3: Fragmented packet drop (MF / offset > 0) */
#define AEGIS_FEAT_TCP_FLAGS_FILTER   (1U << 3)  /* Method 4: Stealth scan drop (Null, Xmas, SYN-FIN) */
#define AEGIS_FEAT_SYN_FLOOD_PROTECT  (1U << 4)  /* Method 5: TCP SYN Flood rate-limiting per IP */
#define AEGIS_FEAT_OUT_OF_STATE       (1U << 5)  /* Method 6: TCP Out-of-state ACK/RST to closed ports */
#define AEGIS_FEAT_UDP_JUNK_FILTER    (1U << 6)  /* Method 7: UDP junk / Closed port flood drop */
#define AEGIS_FEAT_ICMP_LIMIT         (1U << 7)  /* Method 8: ICMP Ping flood limiter */
#define AEGIS_FEAT_REFLECTED_FILTER   (1U << 8)  /* Method 9: Reflected amplification flood (DNS/NTP) */
#define AEGIS_FEAT_RATE_LIMIT_BAN     (1U << 9)  /* Method 10: High PPS token bucket & Dynamic ban */

#define AEGIS_FEAT_ALL                (0x3FF)    /* Enable all 10 defense methods */

/*
 * Statistical Metric Indices (Per-CPU Array Map)
 * Each mitigation method has its OWN distinct counter for accurate telemetry!
 */
enum aegis_stat_idx {
    STAT_TOTAL_PACKETS = 0,        /* Total evaluated packets */
    STAT_PASSED_WHITELIST,         /* Fast-path passed by IP whitelist */
    STAT_DROPPED_BLACKLIST,        /* Static blacklist drop */
    STAT_DROPPED_DYNAMIC_BAN,      /* Method 10b: Dynamic auto-ban drop */
    STAT_DROPPED_MALFORMED,        /* Method 1: Malformed packet drop */
    STAT_DROPPED_BOGON,            /* Method 2: Bogon / Spoofed IP / Land attack drop */
    STAT_DROPPED_FRAGMENTED,       /* Method 3: Fragmented packet drop */
    STAT_DROPPED_TCP_FLAGS,        /* Method 4: Invalid TCP flags / port scan drop */
    STAT_DROPPED_SYN_FLOOD,        /* Method 5: SYN flood rate-limit drop */
    STAT_DROPPED_OUT_OF_STATE,     /* Method 6: TCP out-of-state drop */
    STAT_DROPPED_UDP_JUNK,         /* Method 7: UDP closed port / junk drop */
    STAT_DROPPED_ICMP_FLOOD,       /* Method 8: ICMP ping flood drop */
    STAT_DROPPED_REFLECTED,        /* Method 9: Reflected amplification drop */
    STAT_DROPPED_RATE_LIMIT,       /* Method 10a: High PPS rate-limit drop */
    STAT_MATCHED_L4_PASS,          /* Passed by explicit L4 rule */
    STAT_MATCHED_L4_DROP,          /* Dropped by explicit L4 rule */
    STAT_DEFAULT_PASS,             /* Passed by default policy */
    STAT_DEFAULT_DROP,             /* Dropped by default policy */
    STAT_MAX_ENTRIES               /* Sentinel */
};

/*
 * LPM Trie Key for IPv4 Prefix Matching (CIDR)
 */
struct lpm_ip4_key {
    __u32 prefixlen;               /* Prefix length in bits (0 - 32) */
    __u32 ip;                      /* IPv4 address in network byte order */
};

/*
 * Value stored in IP Whitelist / Blacklist LPM Trie
 */
struct lpm_ip_val {
    __u32 action;                  /* enum aegis_action */
    __u32 flags;                   /* Reserved */
};

/*
 * Dynamic Blacklist Entry (Auto-Ban)
 */
struct dynamic_ban_val {
    __u64 ban_until_ns;            /* Timestamp (nanoseconds) when ban expires */
    __u32 trigger_reason;          /* enum aegis_stat_idx explaining why banned */
    __u32 dropped_count;           /* Number of packets dropped while banned */
};

/*
 * Token Bucket & Rate Limiting State per Source IP
 */
struct rate_bucket {
    __u64 last_seen_ns;            /* Timestamp of last packet */
    __u32 tokens;                  /* Remaining tokens */
    __u32 current_pps;             /* Current packet rate */
};

/*
 * L4 Rule Key: Protocol + Destination Port
 */
struct l4_rule_key {
    __u8 protocol;                 /* AEGIS_PROTO_* */
    __u8 _pad[1];
    __u16 dest_port;               /* Destination port in network byte order */
};

/*
 * L4 Rule Value
 */
struct l4_rule_val {
    __u32 action;                  /* enum aegis_action */
    __u32 _pad;
    __u64 packets;
    __u64 bytes;
};

/*
 * Packet & Byte Counter Structure
 */
struct stat_counter {
    __u64 packets;
    __u64 bytes;
};

/*
 * Global Firewall Runtime Configuration
 */
struct aegis_config {
    __u32 default_policy;          /* AEGIS_ACTION_PASS or AEGIS_ACTION_DROP */
    __u32 enabled_features;        /* Bitmask of AEGIS_FEAT_* */
    __u32 max_pps_per_ip;          /* Max packets/sec per IP before rate-limiting (e.g. 5000) */
    __u32 ban_duration_sec;        /* Seconds to dynamically ban abusive IP (e.g. 60) */
    __u32 max_syn_pps_per_ip;      /* Max SYN packets/sec per IP (e.g. 50) */
    __u32 max_icmp_pps;            /* Max ICMP packets/sec per IP (e.g. 10) */
    __u32 debug_mode;              /* 1: bpf_printk, 0: quiet */
};

#endif /* __AEGIS_TYPES_H__ */
