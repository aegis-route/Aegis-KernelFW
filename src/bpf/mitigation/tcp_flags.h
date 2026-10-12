/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_TCP_FLAGS_H__
#define __MITIGATION_TCP_FLAGS_H__

#include <linux/tcp.h>

/*
 * Method 4: Detect Invalid TCP Flags (Port Scanning & OS Fingerprinting)
 * Returns 1 if flags are abnormal (should DROP), 0 if valid.
 */
static __always_inline int has_invalid_tcp_flags(struct tcphdr *tcph)
{
    __u8 syn = tcph->syn;
    __u8 ack = tcph->ack;
    __u8 fin = tcph->fin;
    __u8 rst = tcph->rst;
    __u8 psh = tcph->psh;
    __u8 urg = tcph->urg;

    /* 1. Null Scan: No flags set */
    if (!syn && !ack && !fin && !rst && !psh && !urg) {
        return 1;
    }

    /* 2. Xmas Scan: FIN + PSH + URG active together */
    if (fin && psh && urg) {
        return 1;
    }

    /* 3. SYN + FIN: Mutually exclusive flags */
    if (syn && fin) {
        return 1;
    }

    /* 4. SYN + RST: Mutually exclusive flags */
    if (syn && rst) {
        return 1;
    }

    /* 5. FIN without ACK: Legitimate connection closes always set ACK */
    if (fin && !ack) {
        return 1;
    }

    return 0;
}

#endif /* __MITIGATION_TCP_FLAGS_H__ */
