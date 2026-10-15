#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>

#include "rule_manager.h"
#include "loader.h"
#include "../../include/aegis_common.h"

int parse_cidr(const char *cidr_str, struct lpm_ip4_key *key)
{
    char buf[64];
    strncpy(buf, cidr_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 32;

    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0 || prefix > 32) {
            fprintf(stderr, "[!] Invalid prefix length: /%d (must be 0-32)\n", prefix);
            return -EINVAL;
        }
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) {
        fprintf(stderr, "[!] Invalid IPv4 address: %s\n", buf);
        return -EINVAL;
    }

    uint32_t mask = prefix == 0 ? 0 : htonl(~((1ULL << (32 - prefix)) - 1));
    addr.s_addr &= mask;

    key->prefixlen = prefix;
    key->ip = addr.s_addr;

    return 0;
}

int rule_ip_add(const char *pin_path, const char *cidr_str, enum aegis_action action)
{
    struct lpm_ip4_key key;
    if (parse_cidr(cidr_str, &key) < 0) return -1;

    int map_fd = aegis_open_pinned_map(pin_path);
    if (map_fd < 0) return -1;

    struct lpm_ip_val val = {
        .action = action,
        .flags = 0,
    };

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to insert CIDR %s into %s: %s\n", cidr_str, pin_path, strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Successfully added CIDR %s [action: %s] to %s\n",
           cidr_str, action == AEGIS_ACTION_DROP ? "DROP" : "PASS", pin_path);
    return 0;
}

int rule_ip_del(const char *pin_path, const char *cidr_str)
{
    struct lpm_ip4_key key;
    if (parse_cidr(cidr_str, &key) < 0) return -1;

    int map_fd = aegis_open_pinned_map(pin_path);
    if (map_fd < 0) return -1;

    if (bpf_map_delete_elem(map_fd, &key) != 0) {
        fprintf(stderr, "[!] Failed to delete CIDR %s from %s: %s\n", cidr_str, pin_path, strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Successfully removed CIDR %s from %s\n", cidr_str, pin_path);
    return 0;
}

int rule_ip_list(const char *pin_path, const char *table_name)
{
    int map_fd = aegis_open_pinned_map(pin_path);
    if (map_fd < 0) return -1;

    printf("\n=== [%s] Registered CIDR Rules ===\n", table_name);
    printf("%-24s %-10s\n", "CIDR Subnet", "Action");
    printf("----------------------------------------\n");

    struct lpm_ip4_key cur_key, next_key;
    int count = 0;

    if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        do {
            cur_key = next_key;
            struct lpm_ip_val val;
            if (bpf_map_lookup_elem(map_fd, &cur_key, &val) == 0) {
                struct in_addr in;
                in.s_addr = cur_key.ip;
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in, ip_buf, sizeof(ip_buf));

                char cidr_buf[32];
                snprintf(cidr_buf, sizeof(cidr_buf), "%s/%u", ip_buf, cur_key.prefixlen);

                printf("%-24s %-10s\n", cidr_buf,
                       val.action == AEGIS_ACTION_DROP ? "DROP" : "PASS");
                count++;
            }
        } while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0);
    }

    if (count == 0) {
        printf(" (No rules active)\n");
    }
    printf("----------------------------------------\nTotal: %d rules\n\n", count);

    close(map_fd);
    return 0;
}

static uint8_t parse_proto(const char *proto_str)
{
    if (strcasecmp(proto_str, "tcp") == 0) return AEGIS_PROTO_TCP;
    if (strcasecmp(proto_str, "udp") == 0) return AEGIS_PROTO_UDP;
    if (strcasecmp(proto_str, "icmp") == 0) return AEGIS_PROTO_ICMP;
    if (strcasecmp(proto_str, "any") == 0) return AEGIS_PROTO_ANY;
    return 255;
}

static const char *proto_to_str(uint8_t proto)
{
    switch (proto) {
        case AEGIS_PROTO_TCP: return "TCP";
        case AEGIS_PROTO_UDP: return "UDP";
        case AEGIS_PROTO_ICMP: return "ICMP";
        case AEGIS_PROTO_ANY: return "ANY";
        default: return "UNKNOWN";
    }
}

int rule_l4_add(const char *proto_str, uint16_t port, enum aegis_action action)
{
    uint8_t proto = parse_proto(proto_str);
    if (proto == 255) {
        fprintf(stderr, "[!] Invalid protocol '%s'. Supported: tcp, udp, icmp, any\n", proto_str);
        return -EINVAL;
    }

    int map_fd = aegis_open_pinned_map(PIN_MAP_L4_RULES);
    if (map_fd < 0) return -1;

    struct l4_rule_key key = {
        .protocol = proto,
        ._pad = {0},
        .dest_port = htons(port),
    };

    struct l4_rule_val val = {
        .action = action,
        ._pad = 0,
        .packets = 0,
        .bytes = 0,
    };

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to update L4 rule: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Added L4 Rule: Proto=%s, Port=%u -> Action=%s\n",
           proto_to_str(proto), port, action == AEGIS_ACTION_DROP ? "DROP" : "PASS");
    return 0;
}

int rule_l4_del(const char *proto_str, uint16_t port)
{
    uint8_t proto = parse_proto(proto_str);
    if (proto == 255) return -EINVAL;

    int map_fd = aegis_open_pinned_map(PIN_MAP_L4_RULES);
    if (map_fd < 0) return -1;

    struct l4_rule_key key = {
        .protocol = proto,
        ._pad = {0},
        .dest_port = htons(port),
    };

    if (bpf_map_delete_elem(map_fd, &key) != 0) {
        fprintf(stderr, "[!] Failed to delete L4 rule: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Removed L4 Rule: Proto=%s, Port=%u\n", proto_to_str(proto), port);
    return 0;
}

int rule_l4_list(void)
{
    int map_fd = aegis_open_pinned_map(PIN_MAP_L4_RULES);
    if (map_fd < 0) return -1;

    printf("\n=== Registered L4 Port & Protocol Rules ===\n");
    printf("%-10s %-12s %-10s\n", "Protocol", "Dest Port", "Action");
    printf("----------------------------------------\n");

    struct l4_rule_key cur_key, next_key;
    int count = 0;

    if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        do {
            cur_key = next_key;
            struct l4_rule_val val;
            if (bpf_map_lookup_elem(map_fd, &cur_key, &val) == 0) {
                char port_str[16];
                if (ntohs(cur_key.dest_port) == 0) {
                    snprintf(port_str, sizeof(port_str), "ANY");
                } else {
                    snprintf(port_str, sizeof(port_str), "%u", ntohs(cur_key.dest_port));
                }

                printf("%-10s %-12s %-10s\n",
                       proto_to_str(cur_key.protocol),
                       port_str,
                       val.action == AEGIS_ACTION_DROP ? "DROP" : "PASS");
                count++;
            }
        } while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0);
    }

    if (count == 0) {
        printf(" (No L4 rules active)\n");
    }
    printf("----------------------------------------\nTotal: %d rules\n\n", count);

    close(map_fd);
    return 0;
}

/* Service Ports Management */
int port_allow(const char *proto_str, uint16_t port)
{
    const char *pin_path = strcasecmp(proto_str, "udp") == 0 ? PIN_MAP_OPEN_UDP_PORTS : PIN_MAP_OPEN_TCP_PORTS;
    int map_fd = aegis_open_pinned_map(pin_path);
    if (map_fd < 0) return -1;

    uint16_t key = htons(port);
    uint32_t val = 1;

    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to allow port %u on %s: %s\n", port, proto_str, strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Whitelisted service port %s/%u (Protected against junk/flood)\n", proto_str, port);
    return 0;
}

int port_disallow(const char *proto_str, uint16_t port)
{
    const char *pin_path = strcasecmp(proto_str, "udp") == 0 ? PIN_MAP_OPEN_UDP_PORTS : PIN_MAP_OPEN_TCP_PORTS;
    int map_fd = aegis_open_pinned_map(pin_path);
    if (map_fd < 0) return -1;

    uint16_t key = htons(port);
    if (bpf_map_delete_elem(map_fd, &key) != 0) {
        fprintf(stderr, "[!] Failed to delete port %u on %s: %s\n", port, proto_str, strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Removed service port %s/%u from whitelist\n", proto_str, port);
    return 0;
}

int port_list(const char *proto_str)
{
    const char *pin_path = strcasecmp(proto_str, "udp") == 0 ? PIN_MAP_OPEN_UDP_PORTS : PIN_MAP_OPEN_TCP_PORTS;
    int map_fd = aegis_open_pinned_map(pin_path);
    if (map_fd < 0) return -1;

    printf("\n=== Allowed Listening %s Ports ===\n", proto_str);
    printf("%-10s %-10s\n", "Port", "Status");
    printf("------------------------\n");

    uint16_t cur_key, next_key;
    int count = 0;

    if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        do {
            cur_key = next_key;
            uint32_t val;
            if (bpf_map_lookup_elem(map_fd, &cur_key, &val) == 0) {
                printf("%-10u %-10s\n", ntohs(cur_key), "OPEN/ALLOWED");
                count++;
            }
        } while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0);
    }

    if (count == 0) printf(" (No allowed ports configured)\n");
    printf("------------------------\nTotal: %d ports\n\n", count);

    close(map_fd);
    return 0;
}

/* Dynamic Ban Management */
int dynamic_ban_list(void)
{
    int map_fd = aegis_open_pinned_map(PIN_MAP_DYNAMIC_BAN);
    if (map_fd < 0) return -1;

    printf("\n=== Active Dynamic Auto-Banned IPs (Method 10) ===\n");
    printf("%-18s %-20s %-12s\n", "IP Address", "Ban Duration Left", "Dropped Pkts");
    printf("----------------------------------------------------\n");

    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    uint64_t now_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    uint32_t cur_key, next_key;
    int count = 0;

    if (bpf_map_get_next_key(map_fd, NULL, &next_key) == 0) {
        do {
            cur_key = next_key;
            struct dynamic_ban_val val;
            if (bpf_map_lookup_elem(map_fd, &cur_key, &val) == 0) {
                struct in_addr in;
                in.s_addr = cur_key;
                char ip_buf[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in, ip_buf, sizeof(ip_buf));

                long left_sec = val.ban_until_ns > now_ns ? (val.ban_until_ns - now_ns) / 1000000000ULL : 0;
                printf("%-18s %-18ld s %-12u\n", ip_buf, left_sec, val.dropped_count);
                count++;
            }
        } while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0);
    }

    if (count == 0) printf(" (No dynamically banned IPs at the moment)\n");
    printf("----------------------------------------------------\nTotal Banned: %d\n\n", count);

    close(map_fd);
    return 0;
}

int dynamic_ban_clear(const char *ip_str)
{
    struct in_addr in;
    if (inet_pton(AF_INET, ip_str, &in) != 1) {
        fprintf(stderr, "[!] Invalid IP address: %s\n", ip_str);
        return -EINVAL;
    }

    int map_fd = aegis_open_pinned_map(PIN_MAP_DYNAMIC_BAN);
    if (map_fd < 0) return -1;

    uint32_t key = in.s_addr;
    if (bpf_map_delete_elem(map_fd, &key) != 0) {
        fprintf(stderr, "[!] IP %s is not currently banned: %s\n", ip_str, strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Successfully lifted dynamic ban for IP %s\n", ip_str);
    return 0;
}

/* Feature Toggle Methods */
struct feature_entry {
    const char *name;
    uint32_t flag;
    const char *description;
};

static const struct feature_entry g_features[] = {
    { "malformed",    AEGIS_FEAT_MALFORMED_CHECK,   "Method 01: Malformed & Short Header Inspection" },
    { "bogon",        AEGIS_FEAT_BOGON_FILTER,      "Method 02: Bogon, Spoofed IP & Land Attack Drop" },
    { "frag",         AEGIS_FEAT_FRAG_FILTER,       "Method 03: Fragmented Packet Drop (MF / offset>0)" },
    { "tcp-flags",    AEGIS_FEAT_TCP_FLAGS_FILTER,  "Method 04: Invalid TCP Flags & Port Scan Drop" },
    { "syn-flood",    AEGIS_FEAT_SYN_FLOOD_PROTECT, "Method 05: TCP SYN Flood Rate-Limiter" },
    { "out-of-state", AEGIS_FEAT_OUT_OF_STATE,      "Method 06: TCP Out-of-State ACK/RST Closed Port Drop" },
    { "udp-junk",     AEGIS_FEAT_UDP_JUNK_FILTER,   "Method 07: UDP Closed Port & Junk Flood Drop" },
    { "icmp-limit",   AEGIS_FEAT_ICMP_LIMIT,        "Method 08: ICMP Ping Flood Rate Limiter" },
    { "reflected",    AEGIS_FEAT_REFLECTED_FILTER,  "Method 09: Reflected Amplification Drop (DNS/NTP)" },
    { "rate-limit",   AEGIS_FEAT_RATE_LIMIT_BAN,    "Method 10: High PPS Rate-Limiting & Dynamic Auto-Ban" },
    { "dns-protect",  AEGIS_FEAT_DNS_PROTECT,       "Method 11: DNS PRSD & ANY Amplification Drop" },
    { "ipv6",         AEGIS_FEAT_IPV6_PIPELINE,     "Method 12: Comprehensive IPv6 Defense Pipeline" },
    { "tcp-anomaly",  AEGIS_FEAT_TCP_ANOMALY,       "Method 13: TCP Zero-Window & Sockstress Mitigation" },
    { "quic",         AEGIS_FEAT_QUIC_FILTER,       "Method 14: QUIC / HTTP/3 Initial Flood Mitigation" },
    { "l7-scanner",   AEGIS_FEAT_L7_SCANNER,        "Method 15: Early L7 HTTP Scanner & Exploit Drop" },
    { "tls-inspect",  AEGIS_FEAT_TLS_INSPECT,       "Method 16: TLS Record Validation & Plaintext Drop" },
};

int feature_toggle(const char *feat_name, int enable)
{
    int map_fd = aegis_open_pinned_map(PIN_MAP_CONFIG);
    if (map_fd < 0) return -1;

    uint32_t key = 0;
    struct aegis_config cfg;
    if (bpf_map_lookup_elem(map_fd, &key, &cfg) != 0) {
        /* Default config initialization */
        memset(&cfg, 0, sizeof(cfg));
        cfg.default_policy = AEGIS_ACTION_PASS;
        cfg.enabled_features = AEGIS_FEAT_ALL;
        cfg.max_pps_per_ip = DEFAULT_MAX_PPS_PER_IP;
        cfg.ban_duration_sec = DEFAULT_BAN_DURATION_SEC;
        cfg.max_syn_pps_per_ip = DEFAULT_MAX_SYN_PPS;
        cfg.max_icmp_pps = DEFAULT_MAX_ICMP_PPS;
    }

    uint32_t target_flag = 0;
    if (strcasecmp(feat_name, "all") == 0) {
        target_flag = AEGIS_FEAT_ALL;
    } else {
        int found = 0;
        for (size_t i = 0; i < sizeof(g_features)/sizeof(g_features[0]); i++) {
            if (strcasecmp(feat_name, g_features[i].name) == 0) {
                target_flag = g_features[i].flag;
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "[!] Unknown feature: '%s'. Run 'aegis-fw feature list' to view available.\n", feat_name);
            close(map_fd);
            return -EINVAL;
        }
    }

    if (enable) {
        cfg.enabled_features |= target_flag;
    } else {
        cfg.enabled_features &= ~target_flag;
    }

    if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to update config map: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Feature '%s' is now %s (Bitmask: 0x%X)\n",
           feat_name, enable ? "ENABLED [✓]" : "DISABLED [X]", cfg.enabled_features);
    return 0;
}

int feature_list(void)
{
    int map_fd = aegis_open_pinned_map(PIN_MAP_CONFIG);
    if (map_fd < 0) return -1;

    uint32_t key = 0;
    struct aegis_config cfg;
    uint32_t active_mask = AEGIS_FEAT_ALL;

    if (bpf_map_lookup_elem(map_fd, &key, &cfg) == 0) {
        active_mask = cfg.enabled_features;
    }
    close(map_fd);

    printf("\n=================== Aegis Defense Method Modules ===================\n");
    printf("%-16s %-12s %-48s\n", "Feature Name", "Status", "Description");
    printf("--------------------------------------------------------------------\n");

    for (size_t i = 0; i < sizeof(g_features)/sizeof(g_features[0]); i++) {
        int is_on = (active_mask & g_features[i].flag) != 0;
        printf("%-16s %-12s %-48s\n",
               g_features[i].name,
               is_on ? "[ENABLED]" : "[DISABLED]",
               g_features[i].description);
    }
    printf("====================================================================\n\n");
    return 0;
}

int policy_set(enum aegis_action default_action)
{
    int map_fd = aegis_open_pinned_map(PIN_MAP_CONFIG);
    if (map_fd < 0) return -1;

    uint32_t key = 0;
    struct aegis_config cfg;
    if (bpf_map_lookup_elem(map_fd, &key, &cfg) != 0) {
        memset(&cfg, 0, sizeof(cfg));
        cfg.enabled_features = AEGIS_FEAT_ALL;
        cfg.max_pps_per_ip = DEFAULT_MAX_PPS_PER_IP;
        cfg.ban_duration_sec = DEFAULT_BAN_DURATION_SEC;
        cfg.max_syn_pps_per_ip = DEFAULT_MAX_SYN_PPS;
        cfg.max_icmp_pps = DEFAULT_MAX_ICMP_PPS;
    }

    cfg.default_policy = default_action;

    if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "[!] Failed to update default policy: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[+] Default firewall policy updated to: %s\n",
           default_action == AEGIS_ACTION_DROP ? "DROP" : "PASS");
    return 0;
}

int policy_get(void)
{
    int map_fd = aegis_open_pinned_map(PIN_MAP_CONFIG);
    if (map_fd < 0) return -1;

    uint32_t key = 0;
    struct aegis_config cfg;

    if (bpf_map_lookup_elem(map_fd, &key, &cfg) != 0) {
        fprintf(stderr, "[!] Failed to read config map: %s\n", strerror(errno));
        close(map_fd);
        return -1;
    }

    close(map_fd);
    printf("[*] Default Policy: %s | Features Mask: 0x%X\n",
           cfg.default_policy == AEGIS_ACTION_DROP ? "DROP" : "PASS",
           cfg.enabled_features);
    return 0;
}
