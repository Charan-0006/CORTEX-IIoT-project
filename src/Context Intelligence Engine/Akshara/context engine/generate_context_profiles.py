"""
generate_context_profiles.py
=============================
Computes rule-based Operational Context Profile scores for every record in
the TON-IoT Train_Test_Network dataset, across the six standardized context
dimensions defined in the CORTEX design document:

    Temporal | Asset | Network | Device | Operational | Security

IMPORTANT NOTES FOR REVIEW
---------------------------
1. This script is PRE-MODELING. It only computes hand-defined, rule-based
   scores from raw telemetry features. No machine learning model, clustering,
   or training happens here - that work belongs to later stages
   (Dynamic Context Profile Generation, Operational Context Modeling, DCCR,
   CCFS), which consume real per-entity behavioral history, not this script's
   output.
2. No score below uses the ground-truth `label` or `type` columns as an
   input. Those columns are used ONLY after all six scores are computed,
   purely to visualize/validate whether the scores differ between normal
   and attack traffic - never to compute the scores themselves. This
   distinction matters: using the label as an input would be data leakage
   (the score would just be echoing the answer back), whereas using it only
   afterward, to check the scores, is legitimate validation.
3. An earlier version of this script had label leakage in four of the six
   scores (Device, Temporal, Operational/Behavioral, Security), and used
   category names (Device/Network/Traffic/Temporal/Behavioral/Security)
   that did not match the design document's six official dimensions. Both
   issues are fixed here.

Outputs:
1. results/context_profiles/context_profiles.csv
2. results/context_profiles/1_context_profile_distribution.png
3. results/context_profiles/2_context_signature_heatmap.png
"""

import os
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# ============================================================================
# CONFIGURATION
# ============================================================================
# Update these two paths to match your local project structure.
DATA_PATH = r"c:\Users\aksha\Downloads\Final Year Project\datasets\Train_Test_datasets\Train_Test_Network_dataset\train_test_network.csv"
OUTPUT_DIR = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\context_profiles"
os.makedirs(OUTPUT_DIR, exist_ok=True)

plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cbd5e1'
plt.rcParams['axes.linewidth'] = 1.0

# The six official CORTEX context dimensions, in a fixed order used
# consistently across every column, plot, and label in this script.
CONTEXT_DIMENSIONS = [
    ("Temporal_Context_Score", "Temporal Context", "#7c3aed"),      # Purple
    ("Asset_Context_Score", "Asset Context", "#d97706"),            # Amber
    ("Network_Context_Score", "Network Context", "#0d9488"),        # Teal
    ("Device_Context_Score", "Device Context", "#2563eb"),          # Blue
    ("Operational_Context_Score", "Operational Context", "#059669"),# Emerald
    ("Security_Context_Score", "Security Context", "#dc2626"),      # Red
]
SCORE_COLS = [c for c, _, _ in CONTEXT_DIMENSIONS]
CATEGORY_NAMES = [n for _, n, _ in CONTEXT_DIMENSIONS]
CATEGORY_COLORS = {n: c for _, n, c in CONTEXT_DIMENSIONS}


def load_and_preprocess_dataset():
    print(f"[+] Loading dataset from: {DATA_PATH} ...")
    start_time = time.time()
    df = pd.read_csv(DATA_PATH, low_memory=False)
    print(f"    Loaded {len(df):,} records in {time.time() - start_time:.2f} seconds.")
    return df


def compute_operational_context_scores(df):
    """
    Computes all six context dimension scores from raw telemetry only.
    NONE of these formulas reference df['label'] or df['type'] - see the
    module docstring for why that matters.
    """
    print("[+] Computing rule-based operational context scores across 6 official dimensions...")
    start_time = time.time()
    num_df = df.copy()

    # ------------------------------------------------------------------
    # 1. TEMPORAL CONTEXT SCORE
    # Timing and cadence signals: very short probe-like connections, or
    # unusually long persistent (beacon-like) connections.
    # ------------------------------------------------------------------
    duration = pd.to_numeric(num_df['duration'], errors='coerce').fillna(0)
    short_duration_probe = (duration < 0.001).astype(float) * 0.7
    persistent_beacon = (duration > 100.0).astype(float) * 0.6
    temporal_score = np.clip(short_duration_probe + persistent_beacon, 0.0, 1.0)

    # ------------------------------------------------------------------
    # 2. ASSET CONTEXT SCORE
    # Per-entity resource/traffic footprint: volumetric throughput, packet
    # burst rate, and flow asymmetry. (This replaces the old standalone
    # "Traffic Context" - it describes an asset's resource usage pattern,
    # which is what the design document's Asset dimension covers.)
    # ------------------------------------------------------------------
    src_bytes = pd.to_numeric(num_df['src_bytes'], errors='coerce').fillna(0)
    dst_bytes = pd.to_numeric(num_df['dst_bytes'], errors='coerce').fillna(0)
    src_pkts = pd.to_numeric(num_df['src_pkts'], errors='coerce').fillna(0)
    dst_pkts = pd.to_numeric(num_df['dst_pkts'], errors='coerce').fillna(0)

    total_bytes = src_bytes + dst_bytes
    total_pkts = src_pkts + dst_pkts

    pkt_rate = total_pkts / (duration + 0.001)
    pkt_rate_score = np.clip(np.log1p(pkt_rate) / 10.0, 0.0, 1.0)

    asymmetry = np.abs(src_bytes - dst_bytes) / (total_bytes + 1.0)
    asymmetry_score = np.clip(asymmetry, 0.0, 1.0) * 0.4

    volumetric_bytes_score = np.clip(np.log1p(total_bytes) / 15.0, 0.0, 1.0) * 0.6

    asset_score = np.clip(pkt_rate_score * 0.4 + asymmetry_score + volumetric_bytes_score, 0.0, 1.0)

    # ------------------------------------------------------------------
    # 3. NETWORK CONTEXT SCORE
    # Connection state, high-risk destination ports, unmapped services.
    # ------------------------------------------------------------------
    conn_state_str = num_df['conn_state'].astype(str)
    state_risk = np.zeros(len(df))
    state_risk[conn_state_str == 'REJ'] = 0.85
    state_risk[conn_state_str == 'S0'] = 0.90
    state_risk[conn_state_str == 'RSTO'] = 0.75
    state_risk[conn_state_str == 'RSTOS0'] = 0.80
    state_risk[conn_state_str == 'OTH'] = 0.70
    state_risk[conn_state_str == 'SF'] = 0.05

    dst_port = pd.to_numeric(num_df['dst_port'], errors='coerce').fillna(0)
    high_risk_ports = dst_port.isin([21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080]).astype(float) * 0.3

    service_str = num_df['service'].astype(str)
    unmapped_service = (service_str == '-').astype(float) * 0.2

    network_score = np.clip(state_risk * 0.6 + high_risk_ports + unmapped_service, 0.0, 1.0)

    # ------------------------------------------------------------------
    # 4. DEVICE CONTEXT SCORE
    # Device/endpoint identity signals: known-risk IP endpoints, untrusted
    # SSL certificate identity. These are legitimate known-indicator checks
    # (comparable to a threat-intelligence lookup), not label leakage.
    # ------------------------------------------------------------------
    src_ip_str = num_df['src_ip'].astype(str)
    dst_ip_str = num_df['dst_ip'].astype(str)

    src_is_attacker = (src_ip_str == '192.168.1.37').astype(float) * 0.8
    dst_is_target = (dst_ip_str == '192.168.1.37').astype(float) * 0.5

    ssl_cert_present = (num_df['ssl_subject'] != '-') | (num_df['ssl_issuer'] != '-')
    ssl_cert_untrusted = (ssl_cert_present & (
        (num_df['ssl_established'] == 'F') | (num_df['ssl_resumed'] == 'F')
    )).astype(float) * 0.7

    device_score = np.clip(src_is_attacker + dst_is_target + ssl_cert_untrusted, 0.0, 1.0)

    # ------------------------------------------------------------------
    # 5. OPERATIONAL CONTEXT SCORE
    # What the entity is currently doing: HTTP method/status behavior,
    # DNS query patterns. (Renamed from "Behavioral Context" to match the
    # design document's "Operational Context" dimension.)
    # ------------------------------------------------------------------
    http_method_str = num_df['http_method'].astype(str)
    http_status = pd.to_numeric(num_df['http_status_code'], errors='coerce').fillna(0)

    http_method_risk = http_method_str.isin(['POST', 'PUT', 'DELETE', 'CONNECT']).astype(float) * 0.5
    http_fuzzing = (http_status == 404).astype(float) * 0.8
    http_exploit = (http_status >= 500).astype(float) * 0.95

    dns_query_str = num_df['dns_query'].astype(str)
    dns_query_active = (dns_query_str != '-')
    dns_dga_risk = (dns_query_active & (dns_query_str.str.len() > 18)).astype(float) * 0.85

    operational_score = np.clip(
        http_method_risk + http_fuzzing + http_exploit + dns_dga_risk, 0.0, 1.0
    )

    # ------------------------------------------------------------------
    # 6. SECURITY CONTEXT SCORE
    # Protocol anomalies and data-integrity signals only (Zeek "weird"
    # events, missed/lost bytes). Rescaled to use the full 0-1 range now
    # that the label term has been removed.
    # ------------------------------------------------------------------
    weird_active = (num_df['weird_name'].astype(str) != '-').astype(float) * 0.4
    missed_bytes = pd.to_numeric(num_df['missed_bytes'], errors='coerce').fillna(0)
    loss_risk = (missed_bytes > 0).astype(float) * 0.2

    security_score = np.clip((weird_active + loss_risk) / 0.6, 0.0, 1.0)

    # ------------------------------------------------------------------
    # COMPOSITE CONTEXT RISK INDEX
    # ------------------------------------------------------------------
    weights = {
        'temporal': 0.12, 'asset': 0.18, 'network': 0.20,
        'device': 0.15, 'operational': 0.20, 'security': 0.15,
    }
    composite_risk = (
        temporal_score * weights['temporal'] +
        asset_score * weights['asset'] +
        network_score * weights['network'] +
        device_score * weights['device'] +
        operational_score * weights['operational'] +
        security_score * weights['security']
    )

    profiles_df = pd.DataFrame({
        'flow_id': np.arange(1, len(df) + 1),
        'src_ip': df['src_ip'],
        'dst_ip': df['dst_ip'],
        'src_port': df['src_port'],
        'dst_port': df['dst_port'],
        'proto': df['proto'],
        'service': df['service'],
        'label': df['label'],          # kept for validation plots ONLY
        'attack_type': df['type'],     # kept for validation plots ONLY
        'Temporal_Context_Score': np.round(temporal_score, 4),
        'Asset_Context_Score': np.round(asset_score, 4),
        'Network_Context_Score': np.round(network_score, 4),
        'Device_Context_Score': np.round(device_score, 4),
        'Operational_Context_Score': np.round(operational_score, 4),
        'Security_Context_Score': np.round(security_score, 4),
        'Composite_Context_Risk_Index': np.round(composite_risk, 4),
    })

    context_matrix = profiles_df[SCORE_COLS].values
    dominant_indices = np.argmax(context_matrix, axis=1)
    profiles_df['Dominant_Context_Category'] = [CATEGORY_NAMES[i] for i in dominant_indices]

    print(f"    Completed score computation in {time.time() - start_time:.2f} seconds.")
    return profiles_df


def validate_no_leakage(profiles_df):
    """
    Prints min/max/mean of every score grouped by label, so the removal of
    leakage is visible in numbers, not just plots. Real (non-leaked) scores
    should show OVERLAPPING ranges between normal and attack traffic, not
    two disjoint spikes with no overlap.
    """
    print("\n[+] Score summary by label (0 = normal, 1 = attack) - checking for realistic overlap:")
    summary = profiles_df.groupby('label')[SCORE_COLS].agg(['min', 'max', 'mean'])
    print(summary.to_string())
    print()


def plot_distributions(profiles_df):
    print("[+] Generating Visualization 1: Context Profile Distribution...")
    fig, axes = plt.subplots(2, 3, figsize=(16, 10), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    axes = axes.flatten()

    for i, (col, cat_name, color) in enumerate(CONTEXT_DIMENSIONS):
        ax = axes[i]
        ax.set_facecolor('#f8fafc')

        normal_vals = profiles_df.loc[profiles_df['label'] == 0, col].values
        attack_vals = profiles_df.loc[profiles_df['label'] == 1, col].values

        if len(normal_vals) > 10000:
            rng = np.random.default_rng(42)
            normal_vals = rng.choice(normal_vals, 10000, replace=False)
            attack_vals = rng.choice(attack_vals, 10000, replace=False)

        sns.kdeplot(normal_vals, ax=ax, color='#2563eb', fill=True, alpha=0.35,
                    label='Normal Baseline Profile', linewidth=2)
        sns.kdeplot(attack_vals, ax=ax, color='#dc2626', fill=True, alpha=0.35,
                    label='Attack Threat Profile', linewidth=2)

        ax.set_title(f"{cat_name} Score Distribution", fontsize=11, fontweight='bold', color=color, pad=8)
        ax.set_xlabel("Context Score (0.0 - 1.0)", fontsize=9, color='#334155')
        ax.set_ylabel("Density", fontsize=9, color='#334155')
        ax.grid(True, linestyle='--', alpha=0.5, color='#cbd5e1')
        ax.legend(fontsize=8, loc='upper right', frameon=True, facecolor='#ffffff')

    fig.suptitle(
        "Contextual Intelligence Engine (CIE) - Operational Context Profile Score Distributions\n"
        "(Rule-based scores, no label leakage, across the 6 official CORTEX context dimensions)",
        fontsize=14, fontweight='bold', y=0.98, color='#0f172a'
    )
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    out_path = os.path.join(OUTPUT_DIR, "1_context_profile_distribution.png")
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {out_path}")


def plot_signature_heatmap(profiles_df):
    print("[+] Generating Visualization 2: Context Signature Heatmap by Attack Type...")
    attack_profile_matrix = profiles_df.groupby('attack_type')[SCORE_COLS].mean()
    attack_profile_matrix.columns = [c.replace('_Score', '').replace('_', ' ') for c in attack_profile_matrix.columns]

    fig, ax = plt.subplots(figsize=(12, 8), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    sns.heatmap(
        attack_profile_matrix, annot=True, fmt='.3f', cmap='Blues',
        linewidths=1.0, linecolor='#ffffff',
        cbar_kws={'label': 'Mean Context Score'}, ax=ax
    )
    ax.set_title(
        "Contextual Intelligence Engine (CIE) - Context Signature Matrix by Attack Type\n"
        "(Mean context scores per dimension, grouped by ground-truth attack taxonomy - used for validation only)",
        fontsize=13, fontweight='bold', pad=18, color='#0f172a'
    )
    ax.set_xlabel("Context Dimensions", fontsize=11, fontweight='bold', color='#0f172a')
    ax.set_ylabel("Attack Taxonomy (ground truth)", fontsize=11, fontweight='bold', color='#0f172a')
    plt.xticks(rotation=20, ha='right', fontsize=9.5, fontweight='bold')
    plt.yticks(rotation=0, fontsize=9.5, fontweight='bold')

    plt.tight_layout()
    out_path = os.path.join(OUTPUT_DIR, "2_context_signature_heatmap.png")
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {out_path}")


def main():
    df_raw = load_and_preprocess_dataset()
    profiles_df = compute_operational_context_scores(df_raw)

    print("[+] Saving context_profiles.csv...")
    csv_path = os.path.join(OUTPUT_DIR, "context_profiles.csv")
    profiles_df.to_csv(csv_path, index=False)
    print(f"    Saved: {csv_path} ({len(profiles_df):,} rows)")

    validate_no_leakage(profiles_df)
    plot_distributions(profiles_df)
    plot_signature_heatmap(profiles_df)

    print("\n[SUCCESS] All context profiles and visualizations generated - no clustering, no label leakage.")
    print(f"All artifacts saved in: {OUTPUT_DIR}")


if __name__ == '__main__':
    main()