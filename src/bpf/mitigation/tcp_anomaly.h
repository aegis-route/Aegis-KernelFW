/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_TCP_ANOMALY_H__
#define __MITIGATION_TCP_ANOMALY_H__

#include <linux/bpf.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

/*
 * Method 13: TCP Anomaly & Sockstress / Zero-Window Mitigation
 *
 * Attack Vectors:
 *   1. Sockstress / Zero-Window Attack: Flooding TCP ACK with Window Size = 0
 *      to exhaust kernel socket buffers and freeze server worker threads.
 *   2. TCP Tinygram / 1-Byte Payload Flood: Flooding tiny 1-byte payloads
 *      with PSH+ACK to cause high CPU interrupt overhead (Silly Window Syndrome DoS).
 *
 * Returns 1 if packet exhibits anomaly (should DROP), 0 if normal.
 */
static __always_inline int is_tcp_anomaly(void *data_end, struct tcphdr *tcph, __u32 ip_payload_len)
{
    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < sizeof(struct tcphdr) || (void *)tcph + tcp_hdr_len > data_end) {
        return 1; /* Corrupted TCP header offset */
    }

    __u16 window = bpf_ntohs(tcph->window);
    __u32 data_len = ip_payload_len > tcp_hdr_len ? (ip_payload_len - tcp_hdr_len) : 0;

    /*
     * 1. Detect Suspicious Zero-Window Packets
     * If Window is 0 on a non-SYN packet with zero payload data and ACK set,
     * it indicates an attempt to freeze connections or probe resources.
     */
    if (window == 0 && tcph->ack && !tcph->syn && !tcph->fin && !tcph->rst && data_len == 0) {
        return 1;
    }

    /*
     * 2. Detect 1-Byte Silly Window PUSH Flood
     * Repeated single-byte payloads with PSH+ACK used to bypass L4 filters
     * while burning maximum CPU interrupt cycles.
     */
    if (data_len == 1 && tcph->psh && tcph->ack) {
        return 1;
    }

    return 0;
}

#endif /* __MITIGATION_TCP_ANOMALY_H__ */
