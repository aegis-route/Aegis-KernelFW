#ifndef __LOADER_H__
#define __LOADER_H__

#include <stdint.h>
#include <linux/if_link.h>

/*
 * XDP attachment modes:
 * - XDP_FLAGS_SKB_MODE (Generic mode - works on any driver / VM)
 * - XDP_FLAGS_DRV_MODE (Native driver mode - high performance)
 * - XDP_FLAGS_HW_MODE  (Offloaded to SmartNIC hardware)
 */
struct xdp_attach_opts {
    const char *ifname;
    const char *bpf_obj_path;
    uint32_t xdp_flags;
    int force;
};

/* Attach XDP program to interface and pin maps to /sys/fs/bpf/aegis */
int aegis_load_and_attach(const struct xdp_attach_opts *opts);

/* Detach XDP program from interface and unpin maps */
int aegis_detach_and_unload(const char *ifname, uint32_t xdp_flags);

/* Get map file descriptor from pinned path */
int aegis_open_pinned_map(const char *pin_path);

#endif /* __LOADER_H__ */
