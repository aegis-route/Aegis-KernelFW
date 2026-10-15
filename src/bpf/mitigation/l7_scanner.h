/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_L7_SCANNER_H__
#define __MITIGATION_L7_SCANNER_H__

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

/*
 * Method 15: Early L7 HTTP Scanner & Exploit Probe Mitigation
 *
 * Background:
 *   Botnets and automated vulnerability scanners constantly flood web servers
 *   with HTTP requests searching for sensitive files (.env, phpmyadmin, wp-login).
 *   Passing these to userspace web servers (Nginx/Apache) wastes memory and I/O.
 *
 * Mechanism:
 *   Inspects the first payload packet of HTTP connections (Ports 80, 8080, 8000).
 *   Drops known malicious scanner signatures directly at XDP wire-speed.
 *
 * Returns 1 if scanner exploit detected (should DROP), 0 if benign traffic.
 */
static __always_inline int is_l7_scanner(void *data_end, struct tcphdr *tcph)
{
    __u16 dest_port = bpf_ntohs(tcph->dest);
    if (dest_port != 80 && dest_port != 8080 && dest_port != 8000) {
        return 0;
    }

    __u32 tcp_hdr_len = tcph->doff * 4;
    __u8 *payload = (__u8 *)tcph + tcp_hdr_len;

    /* Ensure we have at least 16 bytes of payload to inspect */
    if ((void *)(payload + 16) > data_end) {
        return 0;
    }

    /* 1. Detect "GET /.env" */
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ' &&
        payload[4] == '/' && payload[5] == '.' && payload[6] == 'e' && payload[7] == 'n' && payload[8] == 'v') {
        return 1;
    }

    /* 2. Detect "GET /wp-" (WordPress scanner probes) */
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ' &&
        payload[4] == '/' && payload[5] == 'w' && payload[6] == 'p' && payload[7] == '-') {
        return 1;
    }

    /* 3. Detect "POST /xmlrpc" (WordPress XML-RPC Brute Force / Pingback Amplification) */
    if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T' && payload[4] == ' ' &&
        payload[5] == '/' && payload[6] == 'x' && payload[7] == 'm' && payload[8] == 'l' &&
        payload[9] == 'r' && payload[10] == 'p' && payload[11] == 'c') {
        return 1;
    }

    /* 4. Detect "GET /phpmyadmin" */
    if (payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ' &&
        payload[4] == '/' && payload[5] == 'p' && payload[6] == 'h' && payload[7] == 'p' &&
        payload[8] == 'm' && payload[9] == 'y') {
        return 1;
    }

    return 0;
}

#endif /* __MITIGATION_L7_SCANNER_H__ */
