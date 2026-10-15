/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Aegis-KernelFW: Multi-Method High-Performance XDP/eBPF Firewall
 *
 * Implements 16 distinct, individually isolated defense methods:
 *   Method 1:  Malformed & Truncated packet check
 *   Method 2:  Bogon, Spoofed IP & Land attack (src==dst)
 *   Method 3:  Fragmented packet drop (MF / offset > 0)
 *   Method 4:  Invalid TCP Flags / Stealth scan drop (Null, Xmas, SYN-FIN)
 *   Method 5:  TCP SYN Flood rate-limiting per IP
 *   Method 6:  TCP Out-of-state ACK/RST flood to closed ports
 *   Method 7:  UDP Junk & Closed Port flood drop
 *   Method 8:  ICMP Ping flood limiter
 *   Method 9:  Reflected amplification flood drop (DNS/NTP/SSDP)
 *   Method 10: High PPS token bucket rate-limiting & Dynamic Auto-Ban
 *   Method 11: DNS Water Torture (PRSD) & ANY amplification drop
 *   Method 12: Comprehensive IPv6 defense pipeline & Bogon drop
 *   Method 13: TCP Anomaly & Sockstress / Zero-Window drop
 *   Method 14: QUIC / HTTP/3 Initial tiny flood mitigation
 *   Method 15: Early L7 HTTP Scanner & Exploit probe drop
 *   Method 16: TLS Record Validation & Plaintext scanner drop
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

#include "aegis_types.h"
#include "aegis_common.h"

/* Modular Defense Methods */
#include "mitigation/malformed.h"
#include "mitigation/bogon.h"
#include "mitigation/frag.h"
#include "mitigation/tcp_flags.h"
#include "mitigation/syn_flood.h"
#include "mitigation/out_of_state.h"
#include "mitigation/udp_junk.h"
#include "mitigation/icmp_flood.h"
#include "mitigation/reflected.h"
#include "mitigation/rate_limit.h"
#include "mitigation/dns_protect.h"
#include "mitigation/ipv6_pipeline.h"
#include "mitigation/tcp_anomaly.h"
#include "mitigation/quic_flood.h"
#include "mitigation/l7_scanner.h"
#include "mitigation/tls_sni.h"

/*
 * BPF Maps Definition
 */

/* 1. Static IPv4 Blacklist (LPM Trie for CIDR subnet match) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip4_key);
    __type(value, struct lpm_ip_val);
    __uint(max_entries, MAX_LPM_IP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ip_blacklist SEC(".maps");

/* 2. Static IPv4 Whitelist (LPM Trie for fast-path accept) */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip4_key);
    __type(value, struct lpm_ip_val);
    __uint(max_entries, MAX_LPM_IP_ENTRIES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_ip_whitelist SEC(".maps");

/* 3. Dynamic Auto-Ban Table (Method 10) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct dynamic_ban_val);
    __uint(max_entries, MAX_DYNAMIC_BAN_ENTRIES);
} map_dynamic_ban SEC(".maps");

/* 4. Sliding-Window Token Bucket Rate Limit Table (Methods 5, 8, 10) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct rate_bucket);
    __uint(max_entries, MAX_RATE_LIMIT_ENTRIES);
} map_rate_limit SEC(".maps");

/* 5. Allowed Listening TCP Ports (Method 6) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u32);
    __uint(max_entries, MAX_PORT_ENTRIES);
} map_open_tcp_ports SEC(".maps");

/* 6. Allowed Listening UDP Ports (Method 7) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u32);
    __uint(max_entries, MAX_PORT_ENTRIES);
} map_open_udp_ports SEC(".maps");

/* 7. L4 Port & Protocol Rules */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct l4_rule_key);
    __type(value, struct l4_rule_val);
    __uint(max_entries, MAX_L4_RULE_ENTRIES);
} map_l4_rules SEC(".maps");

/* 8. Per-CPU Statistical Telemetry (Individual Counters for every Method) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct stat_counter);
    __uint(max_entries, STAT_MAX_ENTRIES);
} map_stats SEC(".maps");

/* 9. Global Runtime Firewall Configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct aegis_config);
    __uint(max_entries, MAX_CONFIG_ENTRIES);
} map_config SEC(".maps");

/*
 * Helper: Record Per-CPU Statistics for a specific action/reason
 */
static __always_inline void record_stat(__u32 stat_idx, __u64 bytes)
{
    struct stat_counter *val = bpf_map_lookup_elem(&map_stats, &stat_idx);
    if (val) {
        val->packets++;
        val->bytes += bytes;
    }
}

/*
 * Main XDP Firewall Execution Pipeline
 */
SEC("xdp")
int aegis_xdp_firewall(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_bytes = (__u64)(data_end - data);

    record_stat(STAT_TOTAL_PACKETS, pkt_bytes);

    /* 0. Retrieve Configuration */
    __u32 cfg_key = 0;
    struct aegis_config *cfg = bpf_map_lookup_elem(&map_config, &cfg_key);
    __u32 features = cfg ? cfg->enabled_features : AEGIS_FEAT_ALL;
    __u32 max_pps = cfg && cfg->max_pps_per_ip ? cfg->max_pps_per_ip : DEFAULT_MAX_PPS_PER_IP;
    __u32 ban_dur = cfg && cfg->ban_duration_sec ? cfg->ban_duration_sec : DEFAULT_BAN_DURATION_SEC;
    __u32 max_syn = cfg && cfg->max_syn_pps_per_ip ? cfg->max_syn_pps_per_ip : DEFAULT_MAX_SYN_PPS;
    __u32 max_icmp = cfg && cfg->max_icmp_pps ? cfg->max_icmp_pps : DEFAULT_MAX_ICMP_PPS;

    /* 1. Parse Ethernet Header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        record_stat(STAT_DROPPED_MALFORMED, pkt_bytes);
        return XDP_DROP;
    }

    __u16 h_proto = eth->h_proto;
    void *nh = (void *)(eth + 1);

    /* Handle 802.1Q VLAN Tag */
    if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
        struct {
            __u16 vlan_tci;
            __u16 vlan_encapsulated_proto;
        } *vlan_hdr = nh;

        if ((void *)(vlan_hdr + 1) > data_end) {
            record_stat(STAT_DROPPED_MALFORMED, pkt_bytes);
            return XDP_DROP;
        }
        h_proto = vlan_hdr->vlan_encapsulated_proto;
        nh = (void *)(vlan_hdr + 1);
    }

    /* METHOD 12: Comprehensive IPv6 Defense Pipeline */
    if (h_proto == bpf_htons(ETH_P_IPV6)) {
        if (features & AEGIS_FEAT_IPV6_PIPELINE) {
            struct ipv6hdr *ip6h = nh;
            if (is_ipv6_abusive(data, data_end, ip6h)) {
                record_stat(STAT_DROPPED_IPV6_BOGON, pkt_bytes);
                return XDP_DROP;
            }
        }
        return XDP_PASS;
    }

    /* Pass non-IPv4 traffic (ARP, etc.) */
    if (h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    /* 2. Parse IPv4 Header */
    struct iphdr *iph = nh;

    /* METHOD 1: Malformed & Truncated Packet Check */
    if (features & AEGIS_FEAT_MALFORMED_CHECK) {
        if (is_malformed_packet(data, data_end, iph)) {
            record_stat(STAT_DROPPED_MALFORMED, pkt_bytes);
            return XDP_DROP;
        }
    } else {
        if ((void *)(iph + 1) > data_end) {
            return XDP_PASS;
        }
    }

    __u32 saddr = iph->saddr;

    /* 3. Fast-Path: IP Whitelist Check (bypasses all further checks) */
    struct lpm_ip4_key ip_key = {
        .prefixlen = 32,
        .ip = saddr,
    };
    struct lpm_ip_val *wval = bpf_map_lookup_elem(&map_ip_whitelist, &ip_key);
    if (wval && wval->action == AEGIS_ACTION_PASS) {
        record_stat(STAT_PASSED_WHITELIST, pkt_bytes);
        return XDP_PASS;
    }

    /* METHOD 2: Bogon, Spoofed IP & Land Attack Check */
    if (features & AEGIS_FEAT_BOGON_FILTER) {
        if (is_bogon_or_spoofed(iph)) {
            record_stat(STAT_DROPPED_BOGON, pkt_bytes);
            return XDP_DROP;
        }
    }

    /* 4. Static Blacklist Check */
    struct lpm_ip_val *bval = bpf_map_lookup_elem(&map_ip_blacklist, &ip_key);
    if (bval && bval->action == AEGIS_ACTION_DROP) {
        record_stat(STAT_DROPPED_BLACKLIST, pkt_bytes);
        return XDP_DROP;
    }

    /* METHOD 10: High PPS Rate-Limiting & Dynamic Auto-Ban */
    if (features & AEGIS_FEAT_RATE_LIMIT_BAN) {
        int ban_res = check_rate_limit_and_ban(&map_dynamic_ban, &map_rate_limit,
                                               saddr, max_pps, ban_dur);
        if (ban_res == 2) {
            record_stat(STAT_DROPPED_DYNAMIC_BAN, pkt_bytes);
            return XDP_DROP;
        } else if (ban_res == 1) {
            record_stat(STAT_DROPPED_RATE_LIMIT, pkt_bytes);
            return XDP_DROP;
        }
    }

    /* METHOD 3: Fragmented Packet Check */
    if (features & AEGIS_FEAT_FRAG_FILTER) {
        if (is_fragmented_packet(iph)) {
            record_stat(STAT_DROPPED_FRAGMENTED, pkt_bytes);
            return XDP_DROP;
        }
    }

    /* 5. Layer 4 Protocol Inspection */
    __u32 ip_hdr_len = iph->ihl * 4;
    void *l4_hdr = (void *)iph + ip_hdr_len;
    __u8 l4_proto = AEGIS_PROTO_ANY;
    __u16 dest_port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4_hdr;
        if ((void *)(tcph + 1) > data_end) {
            record_stat(STAT_DROPPED_MALFORMED, pkt_bytes);
            return XDP_DROP;
        }

        /* METHOD 4: Invalid TCP Flags Check (Null, Xmas, SYN-FIN scan) */
        if (features & AEGIS_FEAT_TCP_FLAGS_FILTER) {
            if (has_invalid_tcp_flags(tcph)) {
                record_stat(STAT_DROPPED_TCP_FLAGS, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 13: TCP Anomaly & Sockstress / Zero-Window */
        if (features & AEGIS_FEAT_TCP_ANOMALY) {
            __u16 tot_ip_len = bpf_ntohs(iph->tot_len);
            __u32 ip_payload_len = tot_ip_len > ip_hdr_len ? (tot_ip_len - ip_hdr_len) : 0;
            if (is_tcp_anomaly(data_end, tcph, ip_payload_len)) {
                record_stat(STAT_DROPPED_TCP_ANOMALY, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 5: TCP SYN Flood Rate Limiting */
        if (features & AEGIS_FEAT_SYN_FLOOD_PROTECT) {
            if (is_syn_flood(&map_rate_limit, saddr, tcph, max_syn)) {
                record_stat(STAT_DROPPED_SYN_FLOOD, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 6: TCP Out-of-State ACK/RST Flood to closed ports */
        if (features & AEGIS_FEAT_OUT_OF_STATE) {
            if (is_tcp_out_of_state(&map_open_tcp_ports, tcph)) {
                record_stat(STAT_DROPPED_OUT_OF_STATE, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 15: Early L7 HTTP Scanner & Exploit Probe */
        if (features & AEGIS_FEAT_L7_SCANNER) {
            if (is_l7_scanner(data_end, tcph)) {
                record_stat(STAT_DROPPED_L7_SCANNER, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 16: TLS Record Validation & Plaintext Scanner Drop */
        if (features & AEGIS_FEAT_TLS_INSPECT) {
            if (is_tls_malformed(data_end, tcph)) {
                record_stat(STAT_DROPPED_TLS_MALFORMED, pkt_bytes);
                return XDP_DROP;
            }
        }

        l4_proto = AEGIS_PROTO_TCP;
        dest_port = tcph->dest;

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4_hdr;
        if ((void *)(udph + 1) > data_end) {
            record_stat(STAT_DROPPED_MALFORMED, pkt_bytes);
            return XDP_DROP;
        }

        /* METHOD 9: Reflected Amplification Flood (DNS/NTP/SSDP) */
        if (features & AEGIS_FEAT_REFLECTED_FILTER) {
            if (is_reflected_flood(udph)) {
                record_stat(STAT_DROPPED_REFLECTED, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 11: DNS Water Torture (PRSD) & ANY Amplification */
        if (features & AEGIS_FEAT_DNS_PROTECT) {
            if (is_dns_abuse(data_end, udph)) {
                record_stat(STAT_DROPPED_DNS_PRSD, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 14: QUIC / HTTP/3 Initial Flood Mitigation */
        if (features & AEGIS_FEAT_QUIC_FILTER) {
            if (is_quic_flood(data_end, udph)) {
                record_stat(STAT_DROPPED_QUIC_FLOOD, pkt_bytes);
                return XDP_DROP;
            }
        }

        /* METHOD 7: UDP Junk / Closed Port Flood Drop */
        if (features & AEGIS_FEAT_UDP_JUNK_FILTER) {
            if (is_udp_junk(&map_open_udp_ports, udph)) {
                record_stat(STAT_DROPPED_UDP_JUNK, pkt_bytes);
                return XDP_DROP;
            }
        }

        l4_proto = AEGIS_PROTO_UDP;
        dest_port = udph->dest;

    } else if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = l4_hdr;
        if ((void *)(icmph + 1) > data_end) {
            record_stat(STAT_DROPPED_MALFORMED, pkt_bytes);
            return XDP_DROP;
        }

        /* METHOD 8: ICMP Ping Flood Limiter */
        if (features & AEGIS_FEAT_ICMP_LIMIT) {
            if (is_icmp_flood(&map_rate_limit, saddr, icmph, max_icmp)) {
                record_stat(STAT_DROPPED_ICMP_FLOOD, pkt_bytes);
                return XDP_DROP;
            }
        }

        l4_proto = AEGIS_PROTO_ICMP;
        dest_port = 0;
    }

    /* 6. Explicit L4 Rules Match */
    if (l4_proto != AEGIS_PROTO_ANY) {
        struct l4_rule_key rkey = {
            .protocol = l4_proto,
            ._pad = {0},
            .dest_port = dest_port,
        };
        struct l4_rule_val *rval = bpf_map_lookup_elem(&map_l4_rules, &rkey);

        if (!rval && dest_port != 0) {
            struct l4_rule_key wildcard_key = {
                .protocol = l4_proto,
                ._pad = {0},
                .dest_port = 0,
            };
            rval = bpf_map_lookup_elem(&map_l4_rules, &wildcard_key);
        }

        if (rval) {
            if (rval->action == AEGIS_ACTION_DROP) {
                record_stat(STAT_MATCHED_L4_DROP, pkt_bytes);
                return XDP_DROP;
            } else if (rval->action == AEGIS_ACTION_PASS) {
                record_stat(STAT_MATCHED_L4_PASS, pkt_bytes);
                return XDP_PASS;
            }
        }
    }

    /* 7. Default Policy Fallback */
    __u32 def_policy = cfg ? cfg->default_policy : AEGIS_ACTION_PASS;
    if (def_policy == AEGIS_ACTION_DROP) {
        record_stat(STAT_DEFAULT_DROP, pkt_bytes);
        return XDP_DROP;
    }

    record_stat(STAT_DEFAULT_PASS, pkt_bytes);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
