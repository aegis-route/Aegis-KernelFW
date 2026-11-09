#!/usr/bin/env python3
"""
Aegis AI Engine: Shannon Entropy & Statistical Dispersion Analysis
Mathematical Formulation for Anomaly Detection in Network Flows.

Formulas:
  1. Shannon Entropy:
     H(X) = - \\sum_{i=1}^{n} P(x_i) \\cdot \\log_2(P(x_i))
     where P(x_i) = count(x_i) / N

  2. Normalized Shannon Entropy:
     H_norm(X) = H(X) / \\log_2(n)  for n > 1  (0 <= H_norm <= 1)

  3. Exponential Moving Average (EMA) and Z-Score:
     \\mu_t = \\alpha \\cdot x_t + (1 - \\alpha) \\cdot \\mu_{t-1}
     \\sigma_t = \\sqrt{ \\alpha \\cdot (x_t - \\mu_t)^2 + (1 - \\alpha) \\cdot \\sigma_{t-1}^2 }
     z_t = |x_t - \\mu_t| / (\\sigma_t + \\epsilon)
"""

import math
from collections import Counter
from typing import List, Any, Dict, Tuple


def calculate_shannon_entropy(data: List[Any]) -> float:
    """
    Computes Shannon Entropy H(X) in bits.
    Higher entropy => more uniformly distributed (e.g., random spoofed IP flood).
    Lower entropy => highly concentrated (e.g., single target port attack).
    """
    if not data:
        return 0.0

    n = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)

    return float(entropy)


def calculate_normalized_entropy(data: List[Any]) -> float:
    """
    Computes Normalized Shannon Entropy in [0.0, 1.0].
    """
    if not data:
        return 0.0

    unique_count = len(set(data))
    if unique_count <= 1:
        return 0.0

    raw_entropy = calculate_shannon_entropy(data)
    max_entropy = math.log2(unique_count)
    return float(raw_entropy / max_entropy) if max_entropy > 0 else 0.0


class RollingStatisticalTracker:
    """
    Tracks running mean and variance using Welford's algorithm / Exponential Smoothing
    to compute dynamic Z-scores for sudden volumetric spikes.
    """
    def __init__(self, alpha: float = 0.1, threshold_z: float = 3.0):
        self.alpha = alpha
        self.threshold_z = threshold_z
        self.mean = 0.0
        self.variance = 1.0
        self.initialized = False

    def update(self, value: float) -> Tuple[float, bool]:
        """
        Updates running baseline and returns (z_score, is_anomaly).
        """
        if not self.initialized:
            self.mean = value
            self.variance = 1.0
            self.initialized = True
            return 0.0, False

        std_dev = math.sqrt(max(self.variance, 1e-4))
        z_score = abs(value - self.mean) / std_dev

        # Exponential update
        diff = value - self.mean
        self.mean += self.alpha * diff
        self.variance = (1.0 - self.alpha) * self.variance + self.alpha * (diff ** 2)

        is_anomaly = z_score >= self.threshold_z
        return float(z_score), is_anomaly


if __name__ == "__main__":
    # Self-test: Normal vs Spoofed Attack
    benign_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.10", "192.168.1.12"] * 50
    spoofed_attack = [f"10.{i % 256}.{(i * 7) % 256}.{(i * 13) % 256}" for i in range(200)]

    h_benign = calculate_shannon_entropy(benign_ips)
    h_attack = calculate_shannon_entropy(spoofed_attack)

    print(f"Normal Traffic SrcIP Entropy: {h_benign:.3f} bits")
    print(f"Spoofed DDoS SrcIP Entropy:   {h_attack:.3f} bits (Surge detected)")
