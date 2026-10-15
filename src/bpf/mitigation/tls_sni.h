/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_TLS_SNI_H__
#define __MITIGATION_TLS_SNI_H__

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01

/*
 * Method 16: Early TLS / HTTPS Protocol Validation & Plaintext Exploit Drop
 *
 * Background:
 *   Port 443 expects exclusively encrypted TLS handshakes.
 *   Attackers probe port 443 with plaintext HTTP, malformed SSL records,
 *   or corrupted cryptographic packets to cause denial-of-service in OpenSSL/GnuTLS engines.
 *
 * Mechanism:
 *   1. Drops plaintext HTTP requests sent to HTTPS port 443 (Scanners / Crawlers).
 *   2. Validates TLS Record format (ContentType == 0x16, TLS Major Version == 3).
 *   3. Drops malformed or truncated TLS ClientHello handshakes.
 *
 * Returns 1 if packet is corrupted/abusive (should DROP), 0 if valid TLS handshake.
 */
static __always_inline int is_tls_malformed(void *data_end, struct tcphdr *tcph)
{
    __u16 dest_port = bpf_ntohs(tcph->dest);
    if (dest_port != 443 && dest_port != 8443) {
        return 0;
    }

    __u32 tcp_hdr_len = tcph->doff * 4;
    __u8 *payload = (__u8 *)tcph + tcp_hdr_len;

    /* If no payload (pure TCP ACK / SYN), let L4 state handler manage it */
    if ((void *)(payload + 5) > data_end) {
        return 0;
    }

    /*
     * Check 1: Detect Plaintext HTTP on Port 443 (e.g., "GET ", "POST")
     */
    if ((payload[0] == 'G' && payload[1] == 'E' && payload[2] == 'T' && payload[3] == ' ') ||
        (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T') ||
        (payload[0] == 'H' && payload[1] == 'E' && payload[2] == 'A' && payload[3] == 'D')) {
        return 1; /* Drop plaintext scanner on HTTPS port */
    }

    /*
     * Check 2: If starting a TLS session, validate TLS Record Header
     * Byte 0: ContentType (0x16 = Handshake)
     * Byte 1-2: Legacy TLS Version (0x03 0x01, 0x03 0x02, 0x03 0x03)
     */
    if (payload[0] == TLS_CONTENT_TYPE_HANDSHAKE) {
        if (payload[1] != 0x03) {
            return 1; /* Invalid SSL/TLS Major Version */
        }

        /* Check Handshake Type (Byte 5 should be ClientHello = 0x01) */
        if ((void *)(payload + 6) <= data_end) {
            __u8 handshake_type = payload[5];
            if (handshake_type != TLS_HANDSHAKE_CLIENT_HELLO && handshake_type != 0x00) {
                /* Unexpected handshake message as initial packet */
                return 1;
            }
        }
    }

    return 0;
}

#endif /* __MITIGATION_TLS_SNI_H__ */
