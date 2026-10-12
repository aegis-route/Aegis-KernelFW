/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_OUT_OF_STATE_H__
#define __MITIGATION_OUT_OF_STATE_H__

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

/*
 * Method 6: TCP Out-of-State Filtering (Junk ACK/RST Flood to closed ports)
 * Attackers flood random ACK/RST packets to closed ports to force the Linux kernel
 * to allocate CPU cycles generating RST packets (RST amplification / CPU exhaustion).
 * Returns 1 if packet is out-of-state junk (should DROP), 0 if legitimate.
 */
static __always_inline int is_tcp_out_of_state(void *open_tcp_ports_map, struct tcphdr *tcph)
{
    __u16 dest_port = tcph->dest;

    /* Check if target port is an active listening service port */
    __u32 *is_open = bpf_map_lookup_elem(open_tcp_ports_map, &dest_port);
    if (!is_open || *is_open == 0) {
        /* Port is closed: If packet is ACK or RST (and not a SYN attempt), drop immediately! */
        if (tcph->ack || tcph->rst) {
            return 1;
        }
    }

    return 0;
}

#endif /* __MITIGATION_OUT_OF_STATE_H__ */
