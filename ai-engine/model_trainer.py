#!/usr/bin/env python3
"""
Aegis AI Engine: Machine Learning Model Trainer & Mathematical Evaluation
Trains Isolation Forest and Random Forest on flow features and evaluates performance
using rigorous scientific metrics (Confusion Matrix, Precision, Recall, F1-Score, ROC-AUC).
"""

import json
import os
from typing import Tuple, Dict, Any
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score
)
from sklearn.model_selection import train_test_split


def generate_synthetic_flow_dataset(
    n_samples: int = 4000,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates realistic network flow dataset:
    - 65% Benign traffic: Web browsing, VoIP, DNS, Video streaming, SSH
    - 35% Malicious DoS/DDoS traffic across 8 vectors matching Aegis-Stress
    """
    np.random.seed(random_state)
    n_benign = int(n_samples * 0.65)
    n_malicious = n_samples - n_benign

    # 1. Benign Traffic Distribution
    # [duration_ms, pkt_count, byte_count, pps, bytes_per_pkt, syn_ratio, ack_ratio, src_ip_entropy, dst_port_entropy]
    benign_duration = np.random.uniform(500, 30000, n_benign)
    benign_pkts = np.random.poisson(lam=45, size=n_benign) + 5
    benign_bytes_per_pkt = np.random.normal(loc=650, scale=180, size=n_benign).clip(64, 1500)
    benign_bytes = benign_pkts * benign_bytes_per_pkt
    benign_pps = (benign_pkts / (benign_duration / 1000.0)).clip(1, 150)
    benign_syn_ratio = np.random.beta(a=1.5, b=25.0, size=n_benign)  # Low SYN ratio (~0.05)
    benign_ack_ratio = np.random.beta(a=18.0, b=3.0, size=n_benign)   # High ACK ratio (~0.85)
    benign_src_entropy = np.random.normal(loc=3.2, scale=0.4, size=n_benign).clip(1.5, 4.5)
    benign_port_entropy = np.random.normal(loc=2.8, scale=0.35, size=n_benign).clip(1.2, 4.0)

    X_benign = np.column_stack([
        benign_duration,
        benign_pkts,
        benign_bytes,
        benign_pps,
        benign_bytes_per_pkt,
        benign_syn_ratio,
        benign_ack_ratio,
        benign_src_entropy,
        benign_port_entropy
    ])
    y_benign = np.zeros(n_benign, dtype=int)  # 0 = Benign

    # 2. Malicious DoS/DDoS Distribution (Volumetric + Low-Rate + Protocol)
    mal_duration = np.random.uniform(200, 5000, n_malicious)
    mal_pps = np.random.exponential(scale=3500, size=n_malicious) + 400  # High PPS
    mal_pkts = mal_pps * (mal_duration / 1000.0)
    mal_bytes_per_pkt = np.random.choice([64, 120, 512, 1400], size=n_malicious, p=[0.55, 0.25, 0.1, 0.1])
    mal_bytes = mal_pkts * mal_bytes_per_pkt

    # Attack specific flags
    # SYN Floods have SYN ratio > 0.85; Out-of-state ACK has ACK ratio 1.0; UDP/ICMP has 0
    mal_syn_ratio = np.random.choice([0.0, 0.95], size=n_malicious, p=[0.4, 0.6])
    mal_ack_ratio = np.where(mal_syn_ratio > 0.5, 0.05, np.random.choice([0.0, 0.98], size=n_malicious, p=[0.5, 0.5]))

    # Spoofed source IPs have maximum entropy (> 5.5 bits); Target single port has port entropy ~ 0.05
    mal_src_entropy = np.random.normal(loc=6.2, scale=0.5, size=n_malicious).clip(5.0, 7.8)
    mal_port_entropy = np.random.normal(loc=0.3, scale=0.2, size=n_malicious).clip(0.0, 0.9)

    X_malicious = np.column_stack([
        mal_duration,
        mal_pkts,
        mal_bytes,
        mal_pps,
        mal_bytes_per_pkt,
        mal_syn_ratio,
        mal_ack_ratio,
        mal_src_entropy,
        mal_port_entropy
    ])
    y_malicious = np.ones(n_malicious, dtype=int)  # 1 = Malicious / DDoS

    # Realistic boundary noise & edge cases (e.g., flash crowds, bursty P2P, low-rate DoS)
    # 2.5% of samples have borderline overlapping properties
    n_noisy = int(n_samples * 0.025)
    noise_indices = np.random.choice(n_samples, size=n_noisy, replace=False)

    X = np.vstack([X_benign, X_malicious])
    y = np.concatenate([y_benign, y_malicious])

    for idx in noise_indices:
        if y[idx] == 0:  # Benign with flash-crowd burst / browser multi-tab handshake
            X[idx, 3] = np.random.uniform(450, 950)  # Elevated PPS
            X[idx, 5] = np.random.uniform(0.65, 0.85) # High initial SYN ratio (many parallel tabs)
            X[idx, 7] = np.random.uniform(5.1, 5.8)  # Elevated IP entropy
            X[idx, 8] = np.random.uniform(0.8, 1.4)  # Low port entropy (all port 443)
        else:            # Malicious stealth low-rate probe / distributed slowloris
            X[idx, 3] = np.random.uniform(80, 180)   # Low PPS stealth
            X[idx, 5] = np.random.uniform(0.15, 0.35) # Low SYN ratio (established slow connections)
            X[idx, 7] = np.random.uniform(4.0, 4.6)  # Moderate IP entropy
            X[idx, 8] = np.random.uniform(2.0, 2.9)  # Distributed target port probe

    # Introduce 0.6% realistic network measurement noise (asymmetric routing / packet loss during attack)
    ambiguous_idx = np.random.choice(n_samples, size=int(n_samples * 0.006), replace=False)
    y[ambiguous_idx] = 1 - y[ambiguous_idx]

    # Shuffle
    indices = np.arange(n_samples)
    np.random.shuffle(indices)
    return X[indices], y[indices]


def train_and_evaluate(output_dir: str = "/home/minhmcpc/Projects/Aegis-KernelFW/ai-engine"):
    os.makedirs(output_dir, exist_ok=True)
    X, y = generate_synthetic_flow_dataset(n_samples=5000, random_state=42)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"Dataset Size: {len(X)} samples (Train: {len(X_train)}, Test: {len(X_test)})")

    # 1. Train Random Forest Classifier
    rf_clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
    rf_clf.fit(X_train, y_train)
    y_pred_rf = rf_clf.predict(X_test)
    y_prob_rf = rf_clf.predict_proba(X_test)[:, 1]

    # Confusion matrix & metrics
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred_rf).ravel()
    acc = accuracy_score(y_test, y_pred_rf)
    prec = precision_score(y_test, y_pred_rf)
    rec = recall_score(y_test, y_pred_rf)
    f1 = f1_score(y_test, y_pred_rf)
    auc = roc_auc_score(y_test, y_prob_rf)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    # 2. Train Isolation Forest (Unsupervised Baseline)
    iso_forest = IsolationForest(n_estimators=100, contamination=0.35, random_state=42, n_jobs=-1)
    iso_forest.fit(X_train)
    iso_preds = iso_forest.predict(X_test)
    y_pred_iso = np.where(iso_preds == -1, 1, 0)
    acc_iso = accuracy_score(y_test, y_pred_iso)
    f1_iso = f1_score(y_test, y_pred_iso)

    report = {
        "dataset": {
            "total_samples": len(X),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "benign_count": int(np.sum(y == 0)),
            "malicious_count": int(np.sum(y == 1))
        },
        "random_forest_metrics": {
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            },
            "accuracy": round(float(acc) * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2),
            "roc_auc": round(float(auc), 4),
            "false_positive_rate_percent": round(float(fpr) * 100, 2),
            "false_negative_rate_percent": round(float(fnr) * 100, 2)
        },
        "isolation_forest_metrics": {
            "accuracy": round(float(acc_iso) * 100, 2),
            "f1_score": round(float(f1_iso) * 100, 2)
        },
        "feature_importances": {
            name: round(float(imp), 4)
            for name, imp in zip([
                "flow_duration_ms", "packet_count", "byte_count", "pps",
                "bytes_per_pkt", "syn_ratio", "ack_ratio", "src_ip_entropy", "dst_port_entropy"
            ], rf_clf.feature_importances_)
        }
    }

    report_path = os.path.join(output_dir, "metrics_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print("\n--- RESULTS OF AI ANOMALY DETECTION ENGINE ---")
    print(f"Accuracy:    {report['random_forest_metrics']['accuracy']}%")
    print(f"Precision:   {report['random_forest_metrics']['precision']}%")
    print(f"Recall:      {report['random_forest_metrics']['recall']}%")
    print(f"F1-Score:    {report['random_forest_metrics']['f1_score']}%")
    print(f"ROC-AUC:     {report['random_forest_metrics']['roc_auc']}")
    print(f"FPR:         {report['random_forest_metrics']['false_positive_rate_percent']}%")
    print(f"FNR:         {report['random_forest_metrics']['false_negative_rate_percent']}%")
    print(f"Saved report to: {report_path}")

    return report


if __name__ == "__main__":
    train_and_evaluate()
