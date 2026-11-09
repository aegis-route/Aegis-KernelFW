#!/usr/bin/env python3
"""
Aegis AI Engine: Network Flow Feature Extractor
Extracts 9-dimensional mathematical & statistical features from raw flow batches
suitable for Isolation Forest and Random Forest classification.
"""

from typing import List, Dict, Any
import numpy as np
from entropy import calculate_shannon_entropy


FEATURE_NAMES = [
    "flow_duration_ms",       # 1. Flow Duration (ms)
    "packet_count",           # 2. Total Packets in Window
    "byte_count",             # 3. Total Bytes in Window
    "pps",                    # 4. Packet Rate (Packets Per Second)
    "bytes_per_pkt",          # 5. Average Packet Size (Bytes/Pkt)
    "syn_ratio",              # 6. TCP SYN Flag Ratio (SYN / Total TCP)
    "ack_ratio",              # 7. TCP ACK Flag Ratio (ACK / Total TCP)
    "src_ip_entropy",         # 8. Shannon Entropy of Source IPs (bits)
    "dst_port_entropy"        # 9. Shannon Entropy of Destination Ports (bits)
]


def extract_flow_features(flow_window: Dict[str, Any]) -> np.ndarray:
    """
    Extracts a normalized 9D feature vector from a flow window dictionary:
    {
      "duration_ms": float,
      "packets": List[Dict[src_ip, dst_ip, src_port, dst_port, proto, size, flags]]
    }
    """
    packets = flow_window.get("packets", [])
    duration_ms = max(flow_window.get("duration_ms", 1000.0), 1.0)
    duration_sec = duration_ms / 1000.0

    pkt_count = len(packets)
    if pkt_count == 0:
        return np.zeros(len(FEATURE_NAMES), dtype=np.float32)

    total_bytes = sum(p.get("size", 64) for p in packets)
    pps = pkt_count / duration_sec
    bytes_per_pkt = total_bytes / pkt_count

    src_ips = [p.get("src_ip", "0.0.0.0") for p in packets]
    dst_ports = [p.get("dst_port", 80) for p in packets]

    # Flags analysis
    tcp_packets = [p for p in packets if p.get("proto", "TCP").upper() == "TCP"]
    tcp_count = len(tcp_packets)

    if tcp_count > 0:
        syn_count = sum(1 for p in tcp_packets if "S" in p.get("flags", ""))
        ack_count = sum(1 for p in tcp_packets if "A" in p.get("flags", ""))
        syn_ratio = syn_count / tcp_count
        ack_ratio = ack_count / tcp_count
    else:
        syn_ratio = 0.0
        ack_ratio = 0.0

    src_ip_entropy = calculate_shannon_entropy(src_ips)
    dst_port_entropy = calculate_shannon_entropy(dst_ports)

    features = np.array([
        duration_ms,
        float(pkt_count),
        float(total_bytes),
        float(pps),
        float(bytes_per_pkt),
        float(syn_ratio),
        float(ack_ratio),
        float(src_ip_entropy),
        float(dst_port_entropy)
    ], dtype=np.float32)

    return features
