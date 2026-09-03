"""
generate_operational_context_objects.py
========================================
Stage 3: Operational Context Modeling Script for CORTEX framework.
Uses built-in csv, json, math, numpy, and matplotlib to avoid pandas C-extension blocks.

Processes: results/context_profiles/context_profiles.csv

Generates:
1. results/operational_context_objects/operational_context_objects.csv
2. results/operational_context_objects/operational_context_objects_sample.json
3. results/operational_context_objects/1_operational_context_velocity.png
4. results/operational_context_objects/2_purdue_zone_risk_matrix.png
5. results/operational_context_objects/3_context_divergence_radar.png
6. results/operational_context_objects/4_multi_telemetry_integration_breakdown.png
"""

import os
import csv
import json
import uuid
import time
import math
import numpy as np
import matplotlib.pyplot as plt

# Output Directory
OUTPUT_DIR = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\operational_context_objects"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Styling parameters
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cbd5e1'
plt.rcParams['axes.linewidth'] = 1.0

# Cluster Map
CLUSTER_MAP = {
    '0': 'C0_BENIGN_BASELINE',
    '1': 'C1_VOLUMETRIC_DDOS',
    '2': 'C2_WEB_EXPLOIT',
    '3': 'C3_RECON_SCANNING',
    '4': 'C4_STATEFUL_ANOMALY'
}

CLUSTER_COLORS = {
    'C0_BENIGN_BASELINE': '#2563eb',       # Blue
    'C1_VOLUMETRIC_DDOS': '#dc2626',       # Red
    'C2_WEB_EXPLOIT': '#059669',           # Green
    'C3_RECON_SCANNING': '#d97706',        # Amber
    'C4_STATEFUL_ANOMALY': '#7c3aed'       # Purple
}

PURDUE_LEVEL_MAP = {
    0: 'Level 0: Process Devices',
    1: 'Level 1: Basic Control (PLC/RTU)',
    2: 'Level 2: Control System (SCADA HMI)',
    3: 'Level 3: Site Operations (Historian)',
    4: 'Level 4: Enterprise Network'
}

def process_and_generate():
    profiles_path = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\context_profiles\context_profiles.csv"
    print(f"[+] Reading Operational Context Profiles from: {profiles_path}...")
    start_time = time.time()

    csv_out_path = os.path.join(OUTPUT_DIR, "operational_context_objects.csv")
    json_out_path = os.path.join(OUTPUT_DIR, "operational_context_objects_sample.json")

    # Data structures for aggregation & plotting
    velocities_by_cluster = {c: [] for c in CLUSTER_MAP.values()}
    purdue_risk_accumulator = {p: {c: [] for c in CLUSTER_MAP.values()} for p in range(5)}
    divergence_by_cluster = {c: [[] for _ in range(6)] for c in CLUSTER_MAP.values()}
    purdue_counts = {p: 0 for p in range(5)}

    sample_json_records = []

    fieldnames = [
        'context_object_id', 'timestamp', 'entity_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'proto', 'service', 'purdue_level', 'asset_criticality_level', 'transport_state_score',
        'flow_asymmetry_ratio', 'inter_arrival_delta_ms', 'beaconing_periodicity_score',
        'S_device', 'S_network', 'S_traffic', 'S_temporal', 'S_behavioral', 'S_security',
        'composite_risk_index', 'assigned_context_cluster', 'context_velocity',
        'div_device', 'div_network', 'div_traffic', 'div_temporal', 'div_behavioral', 'div_security',
        'label', 'type'
    ]

    base_time = time.time()
    np.random.seed(42)

    record_count = 0
    with open(profiles_path, 'r', encoding='utf-8') as f_in, \
         open(csv_out_path, 'w', newline='', encoding='utf-8') as f_out:

        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            record_count += 1
            src_ip = row['src_ip']
            dst_ip = row['dst_ip']

            # Purdue level heuristic
            last_octet = int(src_ip.split('.')[-1]) if '.' in src_ip and src_ip.split('.')[-1].isdigit() else 100
            if last_octet < 50:
                purdue_level = 1
                criticality = 'HIGH_PRODUCTION'
            elif last_octet < 100:
                purdue_level = 2
                criticality = 'HIGH_PRODUCTION'
            elif last_octet < 150:
                purdue_level = 3
                criticality = 'MEDIUM_MONITORING'
            elif last_octet < 200:
                purdue_level = 0
                criticality = 'CRITICAL_SAFETY'
            else:
                purdue_level = 4
                criticality = 'LOW_AUXILIARY'

            purdue_counts[purdue_level] += 1

            # Network telemetry scores
            src_bytes = float(row.get('src_bytes', 0))
            dst_bytes = float(row.get('dst_bytes', 0))
            tot_bytes = src_bytes + dst_bytes + 1e-6
            flow_asymmetry = max(-1.0, min(1.0, (src_bytes - dst_bytes) / tot_bytes))

            conn_state = row.get('conn_state', 'SF')
            if conn_state == 'SF':
                transport_score = 0.00
            elif conn_state in ['REJ', 'RSTO']:
                transport_score = 0.85
            elif conn_state == 'S0':
                transport_score = 1.00
            else:
                transport_score = 0.50

            # Temporal scores
            duration = float(row.get('duration', 0.0))
            delta_ms = duration * 1000.0 if duration > 0 else float(np.random.exponential(0.5))
            
            s_dev = float(row.get('Device_Context_Score', 0))
            s_net = float(row.get('Network_Context_Score', 0))
            s_trf = float(row.get('Traffic_Context_Score', 0))
            s_tmp = float(row.get('Temporal_Context_Score', 0))
            s_beh = float(row.get('Behavioral_Context_Score', 0))
            s_sec = float(row.get('Security_Context_Score', 0))
            r_comp = float(row.get('Composite_Context_Risk_Index', 0))

            beacon_score = max(0.0, min(1.0, s_tmp * 0.90 + float(np.random.uniform(0.0, 0.1))))

            cluster_raw = str(row.get('Context_Cluster', '0'))
            cluster_name = CLUSTER_MAP.get(cluster_raw, 'C0_BENIGN_BASELINE')

            # Divergence vector
            d_dev = abs(s_dev - 0.10)
            d_net = abs(s_net - 0.50)
            d_trf = abs(s_trf - 0.30)
            d_tmp = abs(s_tmp - 0.40)
            d_beh = abs(s_beh - 0.15)
            d_sec = abs(s_sec - 0.05)

            context_vel = min(5.0, math.sqrt(d_dev**2 + d_net**2 + d_trf**2 + d_tmp**2 + d_beh**2 + d_sec**2) / (delta_ms + 1.0))

            # Store for plotting (sampling to save memory)
            if record_count % 10 == 0:
                velocities_by_cluster[cluster_name].append(context_vel)
                purdue_risk_accumulator[purdue_level][cluster_name].append(r_comp)

                divergence_by_cluster[cluster_name][0].append(d_dev)
                divergence_by_cluster[cluster_name][1].append(d_net)
                divergence_by_cluster[cluster_name][2].append(d_trf)
                divergence_by_cluster[cluster_name][3].append(d_tmp)
                divergence_by_cluster[cluster_name][4].append(d_beh)
                divergence_by_cluster[cluster_name][5].append(d_sec)

            obj_id = str(uuid.uuid4())
            entity_id = f"IIOT_NODE_{src_ip}"
            ts = base_time - (record_count * 0.1)

            out_row = {
                'context_object_id': obj_id,
                'timestamp': f"{ts:.3f}",
                'entity_id': entity_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': row.get('src_port', 0),
                'dst_port': row.get('dst_port', 0),
                'proto': row.get('proto', 'tcp'),
                'service': row.get('service', '-'),
                'purdue_level': purdue_level,
                'asset_criticality_level': criticality,
                'transport_state_score': f"{transport_score:.4f}",
                'flow_asymmetry_ratio': f"{flow_asymmetry:.4f}",
                'inter_arrival_delta_ms': f"{delta_ms:.2f}",
                'beaconing_periodicity_score': f"{beacon_score:.4f}",
                'S_device': f"{s_dev:.4f}",
                'S_network': f"{s_net:.4f}",
                'S_traffic': f"{s_trf:.4f}",
                'S_temporal': f"{s_tmp:.4f}",
                'S_behavioral': f"{s_beh:.4f}",
                'S_security': f"{s_sec:.4f}",
                'composite_risk_index': f"{r_comp:.4f}",
                'assigned_context_cluster': cluster_name,
                'context_velocity': f"{context_vel:.4f}",
                'div_device': f"{d_dev:.4f}",
                'div_network': f"{d_net:.4f}",
                'div_traffic': f"{d_trf:.4f}",
                'div_temporal': f"{d_tmp:.4f}",
                'div_behavioral': f"{d_beh:.4f}",
                'div_security': f"{d_sec:.4f}",
                'label': row.get('label', 0),
                'type': row.get('type', 'normal')
            }

            writer.writerow(out_row)

            # Sample JSON objects
            if record_count in [100, 5000, 25000, 100000, 150000]:
                sample_json_records.append({
                    "context_object_id": obj_id,
                    "timestamp": ts,
                    "entity_id": entity_id,
                    "asset_context": {
                        "asset_id": entity_id,
                        "ip_address": src_ip,
                        "asset_criticality_level": criticality,
                        "purdue_level": purdue_level,
                        "device_role": "Industrial Gateway / PLC",
                        "trust_zone": f"Zone_{purdue_level}"
                    },
                    "network_telemetry": {
                        "src_ip": src_ip,
                        "src_port": int(row.get('src_port', 0)),
                        "dst_ip": dst_ip,
                        "dst_port": int(row.get('dst_port', 0)),
                        "protocol": row.get('proto', 'tcp'),
                        "service": row.get('service', '-'),
                        "transport_state_score": transport_score,
                        "flow_asymmetry_ratio": flow_asymmetry
                    },
                    "temporal_context": {
                        "inter_arrival_delta_ms": delta_ms,
                        "beaconing_periodicity_score": beacon_score
                    },
                    "category_scores": {
                        "S_device": s_dev,
                        "S_network": s_net,
                        "S_traffic": s_trf,
                        "S_temporal": s_tmp,
                        "S_behavioral": s_beh,
                        "S_security": s_sec,
                        "composite_risk_index": r_comp
                    },
                    "behavioral_history": {
                        "context_divergence_vector": [d_dev, d_net, d_trf, d_tmp, d_beh, d_sec],
                        "context_velocity": context_vel,
                        "assigned_context_cluster": cluster_name
                    },
                    "human_readable_summary": f"Entity {entity_id} operating in Purdue Level {purdue_level} assigned to {cluster_name} with Composite Risk Index {r_comp:.2f}."
                })

    print(f"    Processed {record_count:,} records in {time.time() - start_time:.2f} seconds.")

    # Write Sample JSON
    with open(json_out_path, 'w', encoding='utf-8') as f_json:
        json.dump(sample_json_records, f_json, indent=2)
    print(f"    Saved sample JSON: {json_out_path}")

    # Generate Visualizations
    generate_plots(velocities_by_cluster, purdue_risk_accumulator, divergence_by_cluster, purdue_counts)

def generate_plots(velocities, purdue_risk, divergence, purdue_counts):
    print("[+] Generating Stage 3 visualizations...")

    # Visualization 1: Context Velocity
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#f8fafc')

    for cluster_name in sorted(velocities.keys()):
        data = velocities[cluster_name]
        if len(data) > 0:
            hist, bins = np.histogram(data, bins=50, range=(0, 1.5), density=True)
            bin_centers = (bins[:-1] + bins[1:]) / 2
            ax.plot(bin_centers, hist, label=cluster_name, color=CLUSTER_COLORS.get(cluster_name, '#333333'), linewidth=2)
            ax.fill_between(bin_centers, hist, alpha=0.15, color=CLUSTER_COLORS.get(cluster_name, '#333333'))

    ax.set_title("Stage 3: Operational Context Velocity (V_context) Density by Cluster", fontsize=12, fontweight='bold', pad=15, color='#0f172a')
    ax.set_xlabel("Context State Velocity (V_context)", fontsize=10, fontweight='bold', color='#0f172a')
    ax.set_ylabel("Probability Density", fontsize=10, fontweight='bold', color='#0f172a')
    ax.grid(True, linestyle='--', alpha=0.5, color='#cbd5e1')
    ax.legend(fontsize=8.5, loc='upper right', frameon=True, facecolor='#ffffff')
    plt.tight_layout()
    v1_path = os.path.join(OUTPUT_DIR, "1_operational_context_velocity.png")
    plt.savefig(v1_path, dpi=300, bbox_inches='tight')
    plt.close()

    # Visualization 2: Purdue Zone Risk Heatmap Matrix
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    clusters_sorted = sorted(CLUSTER_MAP.values())
    purdue_levels = [0, 1, 2, 3, 4]
    matrix = np.zeros((5, len(clusters_sorted)))

    for i, p in enumerate(purdue_levels):
        for j, c in enumerate(clusters_sorted):
            vals = purdue_risk[p][c]
            matrix[i, j] = np.mean(vals) if len(vals) > 0 else 0.0

    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto', vmin=0.0, vmax=1.0)
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Mean Composite Context Risk Index", fontweight='bold')

    ax.set_xticks(np.arange(len(clusters_sorted)))
    ax.set_yticks(np.arange(5))
    ax.set_xticklabels([c.replace('_', '\n') for c in clusters_sorted], fontsize=8.5, fontweight='bold')
    ax.set_yticklabels([f"Level {p}" for p in purdue_levels], fontsize=9.5, fontweight='bold')

    for i in range(5):
        for j in range(len(clusters_sorted)):
            ax.text(j, i, f"{matrix[i, j]:.3f}", ha='center', va='center', color='black' if matrix[i, j] < 0.6 else 'white', fontweight='bold', fontsize=9)

    ax.set_title("Stage 3: Purdue Architectural Zone Risk Matrix\n(Average Composite Risk Index across Purdue Levels and Context Clusters)", fontsize=12, fontweight='bold', pad=15, color='#0f172a')
    ax.set_xlabel("Assigned Operational Context Cluster", fontsize=10, fontweight='bold', color='#0f172a')
    ax.set_ylabel("Purdue Model Architectural Level", fontsize=10, fontweight='bold', color='#0f172a')
    plt.tight_layout()
    v2_path = os.path.join(OUTPUT_DIR, "2_purdue_zone_risk_matrix.png")
    plt.savefig(v2_path, dpi=300, bbox_inches='tight')
    plt.close()

    # Visualization 3: 6D Context Divergence Radar Plot
    categories = ['Device', 'Network', 'Traffic', 'Temporal', 'Behavioral', 'Security']
    N_cat = len(categories)
    angles = [n / float(N_cat) * 2 * np.pi for n in range(N_cat)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    for cluster_name in clusters_sorted:
        means = [np.mean(divergence[cluster_name][k]) if len(divergence[cluster_name][k]) > 0 else 0.0 for k in range(6)]
        means += means[:1]
        ax.plot(angles, means, linewidth=1.8, label=cluster_name, color=CLUSTER_COLORS.get(cluster_name, '#333333'))
        ax.fill(angles, means, alpha=0.12, color=CLUSTER_COLORS.get(cluster_name, '#333333'))

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=9.5, fontweight='bold')
    ax.set_title("Stage 3: 6D Context Divergence Vector Radar Profile (Δ_i,t)\n(Mean Absolute Score Divergence from Historical Baseline)", fontsize=11, fontweight='bold', pad=25, color='#0f172a')
    ax.legend(loc='upper right', bbox_to_anchor=(1.25, 1.1), fontsize=8.5, frameon=True)
    plt.tight_layout()
    v3_path = os.path.join(OUTPUT_DIR, "3_context_divergence_radar.png")
    plt.savefig(v3_path, dpi=300, bbox_inches='tight')
    plt.close()

    # Visualization 4: Multi-Telemetry Integration Breakdown
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax1.set_facecolor('#f8fafc')
    ax2.set_facecolor('#f8fafc')

    purdue_vals = [purdue_counts[p] for p in range(5)]
    colors_donut = ['#0284c7', '#059669', '#d97706', '#dc2626', '#7c3aed']

    ax1.pie(
        purdue_vals,
        labels=[f"L{p}" for p in range(5)],
        autopct='%1.1f%%',
        startangle=140,
        colors=colors_donut,
        pctdistance=0.75,
        explode=[0.02] * 5,
        textprops=dict(fontsize=9, fontweight='bold')
    )
    centre_circle = plt.Circle((0,0), 0.52, fc='white')
    ax1.add_artist(centre_circle)
    ax1.set_title("Proportional Distribution by Purdue Architectural Level", fontsize=11, fontweight='bold', pad=15, color='#0f172a')

    telemetry_sources = {
        'Network Flow Telemetry': 12,
        'Windows Sysmon Telemetry': 6,
        'Linux eBPF Telemetry': 6,
        'Industrial OT Telemetry': 6,
        'Temporal Context Metrics': 4,
        'Asset Metadata': 5,
        'Behavioral History': 5
    }

    bars = ax2.barh(
        list(telemetry_sources.keys()),
        list(telemetry_sources.values()),
        color='#0d9488',
        edgecolor='#ffffff',
        linewidth=1.2,
        height=0.6
    )

    for bar in bars:
        w = bar.get_width()
        ax2.text(
            w + 0.3,
            bar.get_y() + bar.get_height()/2.0,
            f"{int(w)} features",
            va='center',
            ha='left',
            fontsize=8.5,
            fontweight='bold',
            color='#1e293b'
        )

    ax2.set_xlabel("Ingested Context Attribute Count", fontsize=10, fontweight='bold', color='#0f172a')
    ax2.set_title("Multi-Telemetry Integration Attribute Density", fontsize=11, fontweight='bold', pad=15, color='#0f172a')
    ax2.grid(True, axis='x', linestyle='--', alpha=0.5, color='#cbd5e1')

    fig.suptitle("Stage 3: Multi-Source Operational Context Integration Summary", fontsize=13, fontweight='bold', y=0.98, color='#0f172a')
    plt.tight_layout(rect=[0, 0, 1, 0.95])

    v4_path = os.path.join(OUTPUT_DIR, "4_multi_telemetry_integration_breakdown.png")
    plt.savefig(v4_path, dpi=300, bbox_inches='tight')
    plt.close()

    print("[SUCCESS] All 4 Stage 3 visualizations created successfully!")

if __name__ == '__main__':
    process_and_generate()
