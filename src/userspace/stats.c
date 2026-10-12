#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "stats.h"
#include "loader.h"
#include "../../include/aegis_common.h"

static const char *stat_idx_name(enum aegis_stat_idx idx)
{
    switch (idx) {
        case STAT_TOTAL_PACKETS:        return "Total Ingress Packets";
        case STAT_PASSED_WHITELIST:     return "[Fast-Path] Whitelist Accepted";
        case STAT_DROPPED_BLACKLIST:    return "[Blacklist] Static CIDR Dropped";
        case STAT_DROPPED_DYNAMIC_BAN:  return "[Method 10] Dynamic Auto-Ban Dropped";
        case STAT_DROPPED_MALFORMED:    return "[Method 01] Malformed / Truncated Dropped";
        case STAT_DROPPED_BOGON:        return "[Method 02] Bogon / Land Attack Dropped";
        case STAT_DROPPED_FRAGMENTED:   return "[Method 03] Fragmented Packet Dropped";
        case STAT_DROPPED_TCP_FLAGS:    return "[Method 04] Invalid TCP Flags Dropped";
        case STAT_DROPPED_SYN_FLOOD:    return "[Method 05] TCP SYN Flood Dropped";
        case STAT_DROPPED_OUT_OF_STATE: return "[Method 06] TCP Out-of-State Dropped";
        case STAT_DROPPED_UDP_JUNK:     return "[Method 07] UDP Closed Port Dropped";
        case STAT_DROPPED_ICMP_FLOOD:   return "[Method 08] ICMP Ping Flood Dropped";
        case STAT_DROPPED_REFLECTED:    return "[Method 09] Reflected Amplification Dropped";
        case STAT_DROPPED_RATE_LIMIT:   return "[Method 10] High PPS Rate-Limit Dropped";
        case STAT_MATCHED_L4_PASS:      return "[L4 Rule] Explicit Pass";
        case STAT_MATCHED_L4_DROP:      return "[L4 Rule] Explicit Drop";
        case STAT_DEFAULT_PASS:         return "[Policy] Default Pass";
        case STAT_DEFAULT_DROP:         return "[Policy] Default Drop";
        default:                        return "Unknown";
    }
}

static int read_all_stats(struct stat_counter *out_totals, int num_entries)
{
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "[!] Failed to query possible CPUs\n");
        return -1;
    }

    int map_fd = aegis_open_pinned_map(PIN_MAP_STATS);
    if (map_fd < 0) return -1;

    struct stat_counter *per_cpu_buf = calloc(num_cpus, sizeof(struct stat_counter));
    if (!per_cpu_buf) {
        close(map_fd);
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < (uint32_t)num_entries; i++) {
        memset(per_cpu_buf, 0, num_cpus * sizeof(struct stat_counter));
        out_totals[i].packets = 0;
        out_totals[i].bytes = 0;

        if (bpf_map_lookup_elem(map_fd, &i, per_cpu_buf) == 0) {
            for (int cpu = 0; cpu < num_cpus; cpu++) {
                out_totals[i].packets += per_cpu_buf[cpu].packets;
                out_totals[i].bytes += per_cpu_buf[cpu].bytes;
            }
        }
    }

    free(per_cpu_buf);
    close(map_fd);
    return 0;
}

int stats_display(void)
{
    struct stat_counter totals[STAT_MAX_ENTRIES];
    if (read_all_stats(totals, STAT_MAX_ENTRIES) < 0) {
        return -1;
    }

    printf("\n======================= Aegis XDP Multi-Method Telemetry =======================\n");
    printf("%-46s %15s %18s\n", "Defense Method / Action", "Packets", "Bytes");
    printf("--------------------------------------------------------------------------------\n");

    for (int i = 0; i < STAT_MAX_ENTRIES; i++) {
        printf("%-46s %15llu %18llu\n",
               stat_idx_name(i),
               (unsigned long long)totals[i].packets,
               (unsigned long long)totals[i].bytes);
    }
    printf("================================================================================\n\n");
    return 0;
}

static volatile sig_atomic_t g_stop_monitor = 0;
static void sig_handler(int sig)
{
    (void)sig;
    g_stop_monitor = 1;
}

int stats_monitor(int interval_sec)
{
    if (interval_sec <= 0) interval_sec = 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct stat_counter prev[STAT_MAX_ENTRIES] = {0};
    struct stat_counter curr[STAT_MAX_ENTRIES] = {0};

    read_all_stats(prev, STAT_MAX_ENTRIES);

    printf("\033[2J\033[H");
    printf("[*] Starting real-time multi-method monitor (interval: %ds). Press Ctrl+C to exit...\n", interval_sec);

    while (!g_stop_monitor) {
        sleep(interval_sec);
        if (g_stop_monitor) break;

        if (read_all_stats(curr, STAT_MAX_ENTRIES) < 0) break;

        printf("\033[2J\033[H");
        printf("====================== Aegis Live Defense Dashboard (%ds) ======================\n", interval_sec);
        printf("%-42s %12s %10s %12s\n", "Mitigation Method", "Total Pkts", "Pkts/s", "Throughput");
        printf("--------------------------------------------------------------------------------\n");

        for (int i = 0; i < STAT_MAX_ENTRIES; i++) {
            uint64_t delta_pkts = curr[i].packets >= prev[i].packets ? (curr[i].packets - prev[i].packets) : 0;
            uint64_t delta_bytes = curr[i].bytes >= prev[i].bytes ? (curr[i].bytes - prev[i].bytes) : 0;

            double pps = (double)delta_pkts / interval_sec;
            double mbps = ((double)delta_bytes * 8.0) / (interval_sec * 1000000.0);

            char mbps_str[32];
            if (mbps >= 1000.0) {
                snprintf(mbps_str, sizeof(mbps_str), "%.2f Gbps", mbps / 1000.0);
            } else {
                snprintf(mbps_str, sizeof(mbps_str), "%.2f Mbps", mbps);
            }

            printf("%-42s %12llu %10.0f %12s\n",
                   stat_idx_name(i),
                   (unsigned long long)curr[i].packets,
                   pps,
                   mbps_str);

            prev[i] = curr[i];
        }
        printf("================================================================================\n");
        printf("[*] Refreshing every %ds... Press Ctrl+C to exit.\n", interval_sec);
        fflush(stdout);
    }

    printf("\n[*] Live monitor stopped.\n");
    return 0;
}

int stats_reset(void)
{
    int num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) return -1;

    int map_fd = aegis_open_pinned_map(PIN_MAP_STATS);
    if (map_fd < 0) return -1;

    struct stat_counter *zeros = calloc(num_cpus, sizeof(struct stat_counter));
    if (!zeros) {
        close(map_fd);
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < STAT_MAX_ENTRIES; i++) {
        bpf_map_update_elem(map_fd, &i, zeros, BPF_ANY);
    }

    free(zeros);
    close(map_fd);
    printf("[+] All statistics counters reset successfully.\n");
    return 0;
}
