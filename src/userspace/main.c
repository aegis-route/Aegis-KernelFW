#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/if_link.h>

#include "loader.h"
#include "rule_manager.h"
#include "stats.h"
#include "../../include/aegis_common.h"

static void print_usage(const char *prog_name)
{
    printf("========================================================================\n");
    printf(" Aegis-KernelFW (Multi-Method XDP/eBPF Firewall CLI) - Version %s\n", AEGIS_FW_VERSION);
    printf("========================================================================\n\n");
    printf("USAGE:\n");
    printf("  %s <command> [subcommand] [arguments...]\n\n", prog_name);

    printf("LIFECYCLE MANAGEMENT:\n");
    printf("  load <iface> [--mode skb|native|offload]    Attach XDP firewall to NIC\n");
    printf("  unload <iface> [--mode skb|native]           Detach XDP firewall from NIC\n\n");

    printf("DEFENSE METHOD TOGGLES (10 Isolated Modules):\n");
    printf("  feature list                                 Show status of all 10 defense methods\n");
    printf("  feature enable <method_name|all>             Enable a defense method\n");
    printf("  feature disable <method_name|all>            Disable a defense method\n");
    printf("    (Methods: malformed, bogon, frag, tcp-flags, syn-flood,\n");
    printf("              out-of-state, udp-junk, icmp-limit, reflected, rate-limit)\n\n");

    printf("SERVICE PORT PROTECTION (Methods 6 & 7):\n");
    printf("  port allow <tcp|udp> <port>                  Whitelist listening service port\n");
    printf("  port disallow <tcp|udp> <port>               Remove port from whitelist\n");
    printf("  port list <tcp|udp>                          Show whitelisted service ports\n\n");

    printf("DYNAMIC AUTO-BAN (Method 10):\n");
    printf("  ban list                                     List all currently auto-banned IPs\n");
    printf("  ban clear <ip>                               Lift ban early for an IP\n\n");

    printf("L3/L4 STATIC RULES:\n");
    printf("  rule add blacklist <cidr>                    Block subnet/IP (e.g. 192.168.1.0/24)\n");
    printf("  rule del blacklist <cidr>                    Unblock subnet/IP\n");
    printf("  rule list blacklist                          Show blacklisted CIDRs\n");
    printf("  rule add whitelist <cidr>                    Fast-path allow IP/subnet\n");
    printf("  rule del whitelist <cidr>                    Remove from whitelist\n");
    printf("  rule list whitelist                          Show whitelisted CIDRs\n");
    printf("  rule add l4 <proto> <port> <drop|pass>       Add explicit L4 rule\n");
    printf("  rule del l4 <proto> <port>                   Remove L4 rule\n");
    printf("  rule list l4                                 Show L4 rules\n\n");

    printf("TELEMETRY & POLICY:\n");
    printf("  policy set <drop|pass>                       Set default fallback policy\n");
    printf("  policy get                                   Get current default policy\n");
    printf("  stats                                        Multi-method packet & byte telemetry\n");
    printf("  monitor [interval_sec]                       Live real-time dashboard (PPS/Throughput)\n");
    printf("  reset-stats                                  Reset all telemetry counters to 0\n");
    printf("  help                                         Print this help message\n\n");
}

static uint32_t parse_xdp_mode(int argc, char **argv, int start_idx)
{
    uint32_t flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
    for (int i = start_idx; i < argc; i++) {
        if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
            if (strcmp(argv[i + 1], "skb") == 0) {
                flags |= XDP_FLAGS_SKB_MODE;
            } else if (strcmp(argv[i + 1], "native") == 0) {
                flags |= XDP_FLAGS_DRV_MODE;
            } else if (strcmp(argv[i + 1], "offload") == 0) {
                flags |= XDP_FLAGS_HW_MODE;
            }
            i++;
        }
    }

    if (!(flags & (XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE))) {
        flags |= XDP_FLAGS_SKB_MODE;
    }

    return flags;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* 1. Lifecycle: Load / Unload */
    if (strcmp(cmd, "load") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[!] Usage: %s load <iface> [--mode native|skb]\n", argv[0]);
            return 1;
        }
        const char *ifname = argv[2];
        uint32_t flags = parse_xdp_mode(argc, argv, 3);

        const char *bpf_path = "build/xdp_fw.bpf.o";
        if (access(bpf_path, F_OK) != 0) bpf_path = "/usr/local/lib/aegis/xdp_fw.bpf.o";
        if (access(bpf_path, F_OK) != 0) bpf_path = "xdp_fw.bpf.o";

        struct xdp_attach_opts opts = {
            .ifname = ifname,
            .bpf_obj_path = bpf_path,
            .xdp_flags = flags,
            .force = 1,
        };
        return aegis_load_and_attach(&opts);
    }

    if (strcmp(cmd, "unload") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[!] Usage: %s unload <iface>\n", argv[0]);
            return 1;
        }
        uint32_t flags = parse_xdp_mode(argc, argv, 3);
        return aegis_detach_and_unload(argv[2], flags);
    }

    /* 2. Feature Toggles */
    if (strcmp(cmd, "feature") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[!] Usage: %s feature <list|enable|disable> [name]\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "list") == 0) {
            return feature_list();
        } else if (strcmp(argv[2], "enable") == 0 && argc >= 4) {
            return feature_toggle(argv[3], 1);
        } else if (strcmp(argv[2], "disable") == 0 && argc >= 4) {
            return feature_toggle(argv[3], 0);
        }
    }

    /* 3. Service Ports Whitelist (Methods 6 & 7) */
    if (strcmp(cmd, "port") == 0) {
        if (argc < 4) {
            fprintf(stderr, "[!] Usage:\n  %s port allow <tcp|udp> <port>\n  %s port disallow <tcp|udp> <port>\n  %s port list <tcp|udp>\n", argv[0], argv[0], argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "allow") == 0 && argc >= 5) {
            return port_allow(argv[3], (uint16_t)atoi(argv[4]));
        } else if (strcmp(argv[2], "disallow") == 0 && argc >= 5) {
            return port_disallow(argv[3], (uint16_t)atoi(argv[4]));
        } else if (strcmp(argv[2], "list") == 0) {
            return port_list(argv[3]);
        }
    }

    /* 4. Dynamic Auto-Ban Management (Method 10) */
    if (strcmp(cmd, "ban") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[!] Usage: %s ban <list|clear> [ip]\n", argv[0]);
            return 1;
        }
        if (strcmp(argv[2], "list") == 0) {
            return dynamic_ban_list();
        } else if (strcmp(argv[2], "clear") == 0 && argc >= 4) {
            return dynamic_ban_clear(argv[3]);
        }
    }

    /* 5. Static L3 / L4 Rules */
    if (strcmp(cmd, "rule") == 0) {
        if (argc < 3) {
            fprintf(stderr, "[!] Error: Subcommand needed: add, del, list\n");
            return 1;
        }
        const char *subcmd = argv[2];

        if (strcmp(subcmd, "add") == 0) {
            if (argc < 5) return 1;
            const char *target = argv[3];
            if (strcmp(target, "blacklist") == 0) {
                return rule_ip_add(PIN_MAP_IP_BLACKLIST, argv[4], AEGIS_ACTION_DROP);
            } else if (strcmp(target, "whitelist") == 0) {
                return rule_ip_add(PIN_MAP_IP_WHITELIST, argv[4], AEGIS_ACTION_PASS);
            } else if (strcmp(target, "l4") == 0 && argc >= 7) {
                enum aegis_action act = (strcasecmp(argv[6], "drop") == 0) ? AEGIS_ACTION_DROP : AEGIS_ACTION_PASS;
                return rule_l4_add(argv[4], (uint16_t)atoi(argv[5]), act);
            }
        } else if (strcmp(subcmd, "del") == 0) {
            if (argc < 5) return 1;
            const char *target = argv[3];
            if (strcmp(target, "blacklist") == 0) {
                return rule_ip_del(PIN_MAP_IP_BLACKLIST, argv[4]);
            } else if (strcmp(target, "whitelist") == 0) {
                return rule_ip_del(PIN_MAP_IP_WHITELIST, argv[4]);
            } else if (strcmp(target, "l4") == 0 && argc >= 6) {
                return rule_l4_del(argv[4], (uint16_t)atoi(argv[5]));
            }
        } else if (strcmp(subcmd, "list") == 0) {
            if (argc < 4) return 1;
            const char *target = argv[3];
            if (strcmp(target, "blacklist") == 0) return rule_ip_list(PIN_MAP_IP_BLACKLIST, "Blacklist");
            if (strcmp(target, "whitelist") == 0) return rule_ip_list(PIN_MAP_IP_WHITELIST, "Whitelist");
            if (strcmp(target, "l4") == 0) return rule_l4_list();
        }
    }

    /* 6. Policy */
    if (strcmp(cmd, "policy") == 0) {
        if (argc < 3) return 1;
        if (strcmp(argv[2], "get") == 0) return policy_get();
        if (strcmp(argv[2], "set") == 0 && argc >= 4) {
            enum aegis_action act = (strcasecmp(argv[3], "drop") == 0) ? AEGIS_ACTION_DROP : AEGIS_ACTION_PASS;
            return policy_set(act);
        }
    }

    /* 7. Telemetry & Monitoring */
    if (strcmp(cmd, "stats") == 0) return stats_display();
    if (strcmp(cmd, "monitor") == 0) {
        int interval = 1;
        if (argc >= 3) interval = atoi(argv[2]);
        return stats_monitor(interval);
    }
    if (strcmp(cmd, "reset-stats") == 0) return stats_reset();

    fprintf(stderr, "[!] Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}
