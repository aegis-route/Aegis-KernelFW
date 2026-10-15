/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __MITIGATION_DNS_PROTECT_H__
#define __MITIGATION_DNS_PROTECT_H__

#include <linux/bpf.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
 * Standard DNS Header Structure (12 bytes)
 */
struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

/*
 * Method 11: DNS Water Torture (PRSD) & ANY Query Amplification Mitigation
 * Inspects incoming UDP queries on port 53:
 *   - Drops DNS ANY queries (Type 255) commonly used for massive amplification.
 *   - Drops malformed DNS packets (zero queries or excessive query count).
 *   - Drops PRSD (Pseudo-Random Subdomain) queries with excessively long labels.
 *
 * Returns 1 if DNS packet is abusive/malicious (should DROP), 0 if legitimate.
 */
static __always_inline int is_dns_abuse(void *data_end, struct udphdr *udph)
{
    __u16 dest_port = bpf_ntohs(udph->dest);
    if (dest_port != 53) {
        return 0;
    }

    void *dns_start = (void *)(udph + 1);
    struct dnshdr *dns = dns_start;

    /* Verify DNS header boundary */
    if ((void *)(dns + 1) > data_end) {
        return 1; /* Truncated DNS header: drop */
    }

    __u16 flags = bpf_ntohs(dns->flags);
    __u8 qr = (flags >> 15) & 1; /* 0: Query, 1: Response */

    /* Only inspect incoming Queries */
    if (qr == 0) {
        __u16 qdcount = bpf_ntohs(dns->qdcount);
        if (qdcount == 0 || qdcount > 8) {
            return 1; /* Suspicious empty or multi-question flood */
        }

        /* Inspect first Question label */
        __u8 *qptr = (void *)(dns + 1);
        if ((void *)(qptr + 1) > data_end) {
            return 1;
        }

        __u8 first_label_len = *qptr;
        /* RFC 1035: Label length cannot exceed 63 bytes */
        if (first_label_len > 63) {
            return 1;
        }

        /*
         * Detect PRSD / DNS Water Torture:
         * Attackers generate long random subdomains (e.g. > 45 random characters).
         */
        if (first_label_len >= 45) {
            return 1; /* Water torture random subdomain drop */
        }

        /* Check for DNS Type ANY (0x00FF) if name is short */
        if (first_label_len < 32) {
            void *type_ptr = (void *)(qptr + 1 + first_label_len + 1);
            if ((void *)((__u16 *)type_ptr + 1) <= data_end) {
                __u16 qtype = bpf_ntohs(*((__u16 *)type_ptr));
                if (qtype == 255) {
                    return 1; /* Drop DNS ANY query flood */
                }
            }
        }
    }

    return 0;
}

#endif /* __MITIGATION_DNS_PROTECT_H__ */
