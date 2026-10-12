#ifndef __AEGIS_COMMON_H__
#define __AEGIS_COMMON_H__

#include "aegis_types.h"

/*
 * Default BPF File System Pinned Paths
 */
#define BPF_SYSFS_ROOT           "/sys/fs/bpf"
#define AEGIS_BPF_PIN_DIR        "/sys/fs/bpf/aegis"
#define PIN_MAP_IP_BLACKLIST     "/sys/fs/bpf/aegis/map_ip_blacklist"
#define PIN_MAP_IP_WHITELIST     "/sys/fs/bpf/aegis/map_ip_whitelist"
#define PIN_MAP_DYNAMIC_BAN      "/sys/fs/bpf/aegis/map_dynamic_ban"
#define PIN_MAP_RATE_LIMIT       "/sys/fs/bpf/aegis/map_rate_limit"
#define PIN_MAP_OPEN_TCP_PORTS   "/sys/fs/bpf/aegis/map_open_tcp_ports"
#define PIN_MAP_OPEN_UDP_PORTS   "/sys/fs/bpf/aegis/map_open_udp_ports"
#define PIN_MAP_L4_RULES         "/sys/fs/bpf/aegis/map_l4_rules"
#define PIN_MAP_STATS            "/sys/fs/bpf/aegis/map_stats"
#define PIN_MAP_CONFIG           "/sys/fs/bpf/aegis/map_config"
#define PIN_PROG_XDP             "/sys/fs/bpf/aegis/prog_xdp_fw"

/*
 * Map Capacities
 */
#define MAX_LPM_IP_ENTRIES       65536
#define MAX_DYNAMIC_BAN_ENTRIES  32768
#define MAX_RATE_LIMIT_ENTRIES   65536
#define MAX_PORT_ENTRIES         1024
#define MAX_L4_RULE_ENTRIES      4096
#define MAX_CONFIG_ENTRIES       1

/*
 * Default Tuning Limits
 */
#define DEFAULT_MAX_PPS_PER_IP   2000     /* 2000 PPS per IP before throttling */
#define DEFAULT_BAN_DURATION_SEC 60       /* Ban for 60 seconds if exceeded threshold */
#define DEFAULT_MAX_SYN_PPS      50       /* 50 SYN PPS per IP */
#define DEFAULT_MAX_ICMP_PPS     10       /* 10 ICMP Ping PPS per IP */

/*
 * Version & Metadata
 */
#define AEGIS_FW_VERSION         "1.1.0-shield"
#define AEGIS_FW_PROG_NAME       "xdp_fw"

#endif /* __AEGIS_COMMON_H__ */
