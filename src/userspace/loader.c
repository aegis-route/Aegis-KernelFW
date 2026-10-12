#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "loader.h"
#include "../../include/aegis_common.h"

/* Ensure BPF virtual filesystem is mounted */
static int ensure_bpffs_mounted(void)
{
    struct stat st;
    if (stat(BPF_SYSFS_ROOT, &st) != 0) {
        if (mkdir(BPF_SYSFS_ROOT, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[!] Failed to create %s: %s\n", BPF_SYSFS_ROOT, strerror(errno));
            return -1;
        }
    }

    /* Check if already mounted */
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) return 0;

    char line[512];
    int mounted = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, " " BPF_SYSFS_ROOT " bpf ")) {
            mounted = 1;
            break;
        }
    }
    fclose(fp);

    if (!mounted) {
        if (mount("bpf", BPF_SYSFS_ROOT, "bpf", 0, "mode=0700") != 0 && errno != EBUSY) {
            fprintf(stderr, "[!] Warning: Mount bpffs to %s returned: %s\n", BPF_SYSFS_ROOT, strerror(errno));
        }
    }

    /* Ensure /sys/fs/bpf/aegis exists */
    if (stat(AEGIS_BPF_PIN_DIR, &st) != 0) {
        if (mkdir(AEGIS_BPF_PIN_DIR, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "[!] Failed to mkdir %s: %s\n", AEGIS_BPF_PIN_DIR, strerror(errno));
            return -1;
        }
    }

    return 0;
}

int aegis_load_and_attach(const struct xdp_attach_opts *opts)
{
    unsigned int ifindex = if_nametoindex(opts->ifname);
    if (!ifindex) {
        fprintf(stderr, "[!] Invalid network interface: %s\n", opts->ifname);
        return -EINVAL;
    }

    if (ensure_bpffs_mounted() < 0) {
        return -1;
    }

    printf("[*] Opening eBPF ELF object: %s\n", opts->bpf_obj_path);
    struct bpf_object *obj = bpf_object__open_file(opts->bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[!] Failed to open BPF object %s: %s\n", opts->bpf_obj_path, strerror(errno));
        return -1;
    }

    printf("[*] Loading BPF programs into kernel...\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "[!] Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "aegis_xdp_firewall");
    if (!prog) {
        fprintf(stderr, "[!] Cannot find program 'aegis_xdp_firewall' in BPF object\n");
        bpf_object__close(obj);
        return -1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[!] Invalid program FD\n");
        bpf_object__close(obj);
        return -1;
    }

    printf("[*] Attaching XDP program (FD: %d) to interface %s (index: %u)...\n", prog_fd, opts->ifname, ifindex);
    int err = bpf_xdp_attach(ifindex, prog_fd, opts->xdp_flags, NULL);
    if (err < 0) {
        fprintf(stderr, "[!] bpf_xdp_attach failed: %s (%d)\n", strerror(-err), err);
        bpf_object__close(obj);
        return err;
    }

    printf("[*] Pinning BPF maps into %s for live control...\n", AEGIS_BPF_PIN_DIR);
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *name = bpf_map__name(map);
        char pin_path[256];
        snprintf(pin_path, sizeof(pin_path), "%s/%s", AEGIS_BPF_PIN_DIR, name);

        /* Unlink old pinned map if any */
        unlink(pin_path);

        if (bpf_map__pin(map, pin_path) != 0) {
            fprintf(stderr, "[!] Warning: Failed to pin map %s to %s: %s\n", name, pin_path, strerror(errno));
        } else {
            printf("    -> Pinned: %s\n", pin_path);
        }
    }

    printf("[+] Aegis XDP Firewall successfully attached to %s!\n", opts->ifname);
    return 0;
}

int aegis_detach_and_unload(const char *ifname, uint32_t xdp_flags)
{
    unsigned int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "[!] Invalid network interface: %s\n", ifname);
        return -EINVAL;
    }

    printf("[*] Detaching XDP program from %s...\n", ifname);
    int err = bpf_xdp_detach(ifindex, xdp_flags, NULL);
    if (err < 0) {
        fprintf(stderr, "[!] Failed to detach XDP program: %s (%d)\n", strerror(-err), err);
    } else {
        printf("[+] Successfully detached XDP hook from %s\n", ifname);
    }

    printf("[*] Cleaning up pinned BPF maps in %s...\n", AEGIS_BPF_PIN_DIR);
    unlink(PIN_MAP_IP_BLACKLIST);
    unlink(PIN_MAP_IP_WHITELIST);
    unlink(PIN_MAP_DYNAMIC_BAN);
    unlink(PIN_MAP_RATE_LIMIT);
    unlink(PIN_MAP_OPEN_TCP_PORTS);
    unlink(PIN_MAP_OPEN_UDP_PORTS);
    unlink(PIN_MAP_L4_RULES);
    unlink(PIN_MAP_STATS);
    unlink(PIN_MAP_CONFIG);
    rmdir(AEGIS_BPF_PIN_DIR);

    return err;
}

int aegis_open_pinned_map(const char *pin_path)
{
    int fd = bpf_obj_get(pin_path);
    if (fd < 0) {
        fprintf(stderr, "[!] Failed to open pinned map at %s: %s\n", pin_path, strerror(errno));
        fprintf(stderr, "    (Make sure the firewall is loaded via 'aegis-fw load <iface>')\n");
    }
    return fd;
}
