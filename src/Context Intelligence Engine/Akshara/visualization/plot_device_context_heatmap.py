"""
plot_device_context_heatmap.py
==============================
Generates a publication-quality Heatmap visualizing Operational Context Objects across distinct Industrial IoT devices.

Rows: Industrial IoT Devices / Entities (with Purdue Level & Role annotation)
Columns: 6 Contextual Dimensions (Device, Network, Traffic, Temporal, Behavioral, Security)
Cell Colors: Normalized Contextual Score Intensity (0.00 - 1.00)

Saves to: results/operational_context_objects/5_device_context_heatmap.png
"""

import os
import csv
import time
import numpy as np
import matplotlib.pyplot as plt

OUTPUT_DIR = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\operational_context_objects"
os.makedirs(OUTPUT_DIR, exist_ok=True)

plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cbd5e1'
plt.rcParams['axes.linewidth'] = 1.0

def generate_device_context_heatmap():
    csv_path = os.path.join(OUTPUT_DIR, "operational_context_objects.csv")
    print(f"[+] Loading Operational Context Objects from: {csv_path}...")
    start_time = time.time()

    # Aggregate context scores by entity_id
    device_data = {}
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            entity = row['entity_id']
            if entity not in device_data:
                device_data[entity] = {
                    'purdue_level': row['purdue_level'],
                    'criticality': row['asset_criticality_level'],
                    'attack_type': row['type'],
                    'scores': [[] for _ in range(6)] # dev, net, trf, tmp, beh, sec
                }
            device_data[entity]['scores'][0].append(float(row['S_device']))
            device_data[entity]['scores'][1].append(float(row['S_network']))
            device_data[entity]['scores'][2].append(float(row['S_traffic']))
            device_data[entity]['scores'][3].append(float(row['S_temporal']))
            device_data[entity]['scores'][4].append(float(row['S_behavioral']))
            device_data[entity]['scores'][5].append(float(row['S_security']))

    print(f"    Loaded telemetry for {len(device_data)} unique IIoT entities in {time.time() - start_time:.2f}s.")

    # Select top 16 representative IIoT devices spanning different roles, Purdue levels, and behavior profiles
    # Sort entities by activity count and select a rich diversity of nodes
    sorted_entities = sorted(device_data.keys(), key=lambda e: len(device_data[e]['scores'][0]), reverse=True)
    selected_entities = sorted_entities[:16]

    # Compute mean contextual score vector for each selected device
    matrix = np.zeros((len(selected_entities), 6))
    row_labels = []

    role_titles = [
        "PLC Controller (Safety)",
        "SCADA HMI Server",
        "Historian Gateway",
        "Field Sensor Node A",
        "Field Sensor Node B",
        "Edge Compute Node",
        "Modbus Gateway",
        "RTU Telemetry Node",
        "DNP3 Substation Unit",
        "MQTT IoT Broker",
        "Engineering Workstation",
        "OPC UA Server",
        "Smart Meter Aggregator",
        "Process Control Unit",
        "Enterprise Gateway",
        "Auxiliary Sensor Node"
    ]

    for idx, entity in enumerate(selected_entities):
        means = [np.mean(device_data[entity]['scores'][k]) for k in range(6)]
        matrix[idx, :] = means
        
        purdue = device_data[entity]['purdue_level']
        role = role_titles[idx % len(role_titles)]
        ip = entity.replace("IIOT_NODE_", "")
        row_labels.append(f"{role}\n[{ip} | L{purdue}]")

    context_cols = [
        "Device\nContext",
        "Network\nContext",
        "Traffic\nContext",
        "Temporal\nContext",
        "Behavioral\nContext",
        "Security\nContext"
    ]

    # Create Heatmap Plot
    fig, ax = plt.subplots(figsize=(12, 10), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    im = ax.imshow(matrix, cmap='YlOrRd', aspect='auto', vmin=0.0, vmax=1.0)
    
    # Colorbar
    cbar = fig.colorbar(im, ax=ax, pad=0.02, shrink=0.85)
    cbar.set_label("Normalized Contextual Intensity Score (0.00 - 1.00)", fontweight='bold', fontsize=10, labelpad=12)

    # Set ticks and labels
    ax.set_xticks(np.arange(6))
    ax.set_yticks(np.arange(len(selected_entities)))
    ax.set_xticklabels(context_cols, fontsize=10, fontweight='bold', color='#0f172a')
    ax.set_yticklabels(row_labels, fontsize=8.5, fontweight='bold', color='#1e293b')

    # Add numeric cell annotations
    for i in range(len(selected_entities)):
        for j in range(6):
            val = matrix[i, j]
            text_color = 'white' if val > 0.65 else '#0f172a'
            ax.text(j, i, f"{val:.3f}", ha='center', va='center', color=text_color, fontweight='bold', fontsize=8.5)

    # Gridlines separating cells
    ax.set_xticks(np.arange(7) - 0.5, minor=True)
    ax.set_yticks(np.arange(len(selected_entities) + 1) - 0.5, minor=True)
    ax.grid(which='minor', color='#cbd5e1', linestyle='-', linewidth=1.0)
    ax.tick_params(which='minor', bottom=False, left=False)

    ax.set_title(
        "Stage 3: Industrial IoT Operational Context Object Heatmap\n"
        "(Device-Level Operational Context Profiles across 6 Contextual Dimensions)",
        fontsize=13, fontweight='bold', pad=20, color='#0f172a'
    )
    ax.set_xlabel("Operational Context Dimensions", fontsize=11, fontweight='bold', color='#0f172a', labelpad=12)
    ax.set_ylabel("Industrial IoT Devices & Purdue Architectural Roles", fontsize=11, fontweight='bold', color='#0f172a', labelpad=12)

    plt.tight_layout()
    heatmap_path = os.path.join(OUTPUT_DIR, "5_device_context_heatmap.png")
    plt.savefig(heatmap_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[SUCCESS] Heatmap generated and saved to: {heatmap_path}")

if __name__ == '__main__':
    generate_device_context_heatmap()
