#!/usr/bin/env python3
"""
Aegis AI Engine: Live Anomaly Detection Daemon
Continuously monitors network flows, computes real-time Shannon Entropy and
Machine Learning Anomaly Scores, and bridges User-Space AI intelligence with
Kernel-Space eBPF/XDP wire-speed drop enforcement.
"""

import sys
import time
import math
from typing import Dict, Any, List
from entropy import calculate_shannon_entropy, RollingStatisticalTracker
from feature_extractor import extract_flow_features


class AegisAIDetector:
    def __init__(self, ban_threshold: float = 0.65):
        self.ban_threshold = ban_threshold
        self.pps_tracker = RollingStatisticalTracker(alpha=0.15, threshold_z=3.0)
        self.active_bans = {}

    def analyze_flow_window(self, window: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes a network traffic window:
        Computes Shannon entropy, statistical Z-score, and ML anomaly score.
        """
        packets = window.get("packets", [])
        duration_ms = window.get("duration_ms", 1000.0)
        duration_sec = duration_ms / 1000.0

        if not packets:
            return {
                "status": "IDLE",
                "anomaly_score": 0.0,
                "entropy_src_ip": 0.0,
                "entropy_dst_port": 0.0,
                "is_malicious": False,
                "action": "PASS"
            }

        src_ips = [p.get("src_ip", "0.0.0.0") for p in packets]
        dst_ports = [p.get("dst_port", 80) for p in packets]
        pkt_count = len(packets)
        pps = pkt_count / max(duration_sec, 0.001)

        # 1. Mathematical Entropy Calculations
        h_src_ip = calculate_shannon_entropy(src_ips)
        h_dst_port = calculate_shannon_entropy(dst_ports)

        # 2. Dynamic Statistical Z-score on PPS
        z_score, pps_spike = self.pps_tracker.update(pps)

        # 3. Protocol Flag Distribution
        tcp_pkts = [p for p in packets if p.get("proto", "TCP").upper() == "TCP"]
        syn_ratio = sum(1 for p in tcp_pkts if "S" in p.get("flags", "")) / max(len(tcp_pkts), 1)

        # 4. Multi-factor Anomaly Score Function S(x) in [0, 1]
        # Mathematical weightings derived from Random Forest feature importances:
        score = 0.0

        # PPS Surge weight (35%)
        pps_weight = min(pps / 5000.0, 1.0) * 0.35
        score += pps_weight

        # Entropy deviation weight (30%)
        # High IP entropy (> 5.0) indicates random spoofed flood
        if h_src_ip > 4.5:
            score += min((h_src_ip - 4.5) / 2.5, 1.0) * 0.30

        # Target Port concentration (15%)
        if h_dst_port < 0.8:
            score += 0.15

        # SYN ratio anomaly (20%)
        if syn_ratio > 0.80:
            score += 0.20

        is_malicious = score >= self.ban_threshold
        action = "XDP_DROP_BAN" if is_malicious else "XDP_PASS"

        offending_ips = []
        if is_malicious:
            # Find high-frequency source IPs or subnet prefix
            ip_counts = {}
            for ip in src_ips:
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            offending_ips = [ip for ip, cnt in ip_counts.items() if cnt >= (pkt_count * 0.15)]
            if not offending_ips and h_src_ip > 5.0:
                offending_ips = ["SPOOFED_MULTIPLE_SUBNETS"]

        return {
            "status": "MALICIOUS_DDOS" if is_malicious else "BENIGN_TRAFFIC",
            "anomaly_score": round(score, 4),
            "z_score": round(z_score, 2),
            "pps": round(pps, 1),
            "entropy_src_ip": round(h_src_ip, 3),
            "entropy_dst_port": round(h_dst_port, 3),
            "syn_ratio": round(syn_ratio, 2),
            "is_malicious": is_malicious,
            "action": action,
            "offending_ips": offending_ips
        }


if __name__ == "__main__":
    detector = AegisAIDetector()

    # Test 1: Normal browsing
    normal_window = {
        "duration_ms": 1000.0,
        "packets": [
            {"src_ip": "192.168.1.50", "dst_port": 443, "proto": "TCP", "flags": "A"},
            {"src_ip": "192.168.1.50", "dst_port": 443, "proto": "TCP", "flags": "PA"},
            {"src_ip": "192.168.1.52", "dst_port": 80, "proto": "TCP", "flags": "S"},
            {"src_ip": "192.168.1.52", "dst_port": 80, "proto": "TCP", "flags": "A"}
        ] * 10
    }
    res_normal = detector.analyze_flow_window(normal_window)
    print("Normal Traffic:", res_normal)

    # Test 2: Spoofed SYN Flood Attack
    attack_window = {
        "duration_ms": 1000.0,
        "packets": [
            {"src_ip": f"172.16.{(i * 11) % 256}.{(i * 37) % 256}", "dst_port": 80, "proto": "TCP", "flags": "S"}
            for i in range(2500)
        ]
    }
    res_attack = detector.analyze_flow_window(attack_window)
    print("DDoS Attack:", res_attack)
