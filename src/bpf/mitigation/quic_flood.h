/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_QUIC_FLOOD_H__
#define __MITIGATION_QUIC_FLOOD_H__

#include <linux/bpf.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#define MIN_QUIC_INITIAL_LEN 1200

/*
 * Method 14: QUIC / HTTP/3 Initial Flood Mitigation
 *
 * Background:
 *   RFC 9000 (QUIC Transport Protocol) Section 14.1 mandates:
 *   "A client MUST expand the payload of all UDP datagrams carrying Initial
 *    packets to at least 1200 bytes by adding PADDING frames..."
 *
 * Attack Vector:
 *   Attackers send millions of tiny (50 - 200 bytes) spoofed QUIC Initial packets
 *   to UDP port 443 to exhaust cryptographic handshakes and memory on HTTP/3 servers.
 *
 * Returns 1 if packet is an invalid/spoofed QUIC Initial flood (should DROP), 0 if allowed.
 */
static __always_inline int is_quic_flood(void *data_end, struct udphdr *udph)
{
    __u16 dest_port = bpf_ntohs(udph->dest);
    if (dest_port != 443 && dest_port != 8443) {
        return 0;
    }

    __u16 udp_len = bpf_ntohs(udph->len);
    void *payload = (void *)(udph + 1);

    if ((void *)(payload + 1) > data_end) {
        return 1; /* Truncated UDP payload */
    }

    __u8 first_byte = *((__u8 *)payload);

    /*
     * Bit 7 = 1 indicates QUIC Long Header (Used during connection establishment).
     * Bits 4-5 = 0x00 indicates QUIC Initial Packet.
     */
    if ((first_byte & 0x80) != 0) {
        __u8 pkt_type = (first_byte & 0x30) >> 4;
        if (pkt_type == 0x00) { /* QUIC Initial Packet */
            if (udp_len < MIN_QUIC_INITIAL_LEN) {
                return 1; /* Drop non-compliant tiny QUIC Initial packet */
            }
        }
    }

    return 0;
}

#endif /* __MITIGATION_QUIC_FLOOD_H__ */
