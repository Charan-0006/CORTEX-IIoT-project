"""
analyze_device_context.py
=========================
Analyzes device-related contextual features across the TON-IoT dataset testbed.
Generates publication-quality visualizations saved in 'results/device_context/':
1. Device Types Overview (7 IoT Devices + 5 System Nodes)
2. Device Telemetry Frequency (Record counts & Attack vs Normal proportions)
3. Device Communication Patterns (IP flow matrix, protocol preferences, service target vectors)
"""

import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

def generate_device_context_visualizations():
    output_dir = os.path.join('results', 'device_context')
    os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Output directory ready: {output_dir}")

    # Set publication styling
    plt.rcParams['font.sans-serif'] = 'Arial'
    plt.rcParams['font.family'] = 'sans-serif'

    dataset_base = r'Train_Test_datasets'

    # =========================================================================
    # PART 1: Gather Device Types & Telemetry Frequencies
    # =========================================================================
    print("[+] Gathering device telemetry statistics...")
    
    # 1. IoT Devices
    iot_dir = os.path.join(dataset_base, 'Train_Test_IoT_dataset')
    iot_files = glob.glob(os.path.join(iot_dir, '*.csv'))
    
    device_data = []
    
    for f in sorted(iot_files):
        dev_name = os.path.basename(f).replace('Train_Test_IoT_', '').replace('.csv', '').replace('_', ' ')
        df = pd.read_csv(f)
        total_rows = len(df)
        normal_cnt = int((df['label'] == 0).sum())
        attack_cnt = int((df['label'] == 1).sum())
        device_data.append({
            'device_name': dev_name,
            'category': 'IoT Device',
            'total_records': total_rows,
            'normal_records': normal_cnt,
            'attack_records': attack_cnt,
            'attack_pct': (attack_cnt / total_rows) * 100
        })

    # 2. Linux Nodes
    linux_dir = os.path.join(dataset_base, 'Train_Test_Linux_dataset')
    for f in sorted(glob.glob(os.path.join(linux_dir, '*.csv'))):
        dev_name = 'Linux ' + os.path.basename(f).replace('Train_test_linux_', '').replace('Train_Test_Linux_', '').replace('.csv', '').capitalize()
        df = pd.read_csv(f, low_memory=False)
        target_col = 'label' if 'label' in df.columns else 'attack'
        total_rows = len(df)
        normal_cnt = int((df[target_col] == 0).sum())
        attack_cnt = int((df[target_col] == 1).sum())
        device_data.append({
            'device_name': dev_name,
            'category': 'Linux System Node',
            'total_records': total_rows,
            'normal_records': normal_cnt,
            'attack_records': attack_cnt,
            'attack_pct': (attack_cnt / total_rows) * 100
        })

    # 3. Windows Nodes
    win_dir = os.path.join(dataset_base, 'Train_Test_Windows_dataset')
    for f in sorted(glob.glob(os.path.join(win_dir, '*.csv'))):
        dev_name = 'Windows ' + os.path.basename(f).replace('Train_Test_Windows_', '').replace('.csv', '')
        df = pd.read_csv(f)
        total_rows = len(df)
        normal_cnt = int((df['label'] == 0).sum())
        attack_cnt = int((df['label'] == 1).sum())
        device_data.append({
            'device_name': dev_name,
            'category': 'Windows System Node',
            'total_records': total_rows,
            'normal_records': normal_cnt,
            'attack_records': attack_cnt,
            'attack_pct': (attack_cnt / total_rows) * 100
        })

    device_df = pd.DataFrame(device_data).sort_values(by='total_records', ascending=False)
    print(f"[+] Found {len(device_df)} unique device/node types across 3 categories.")

    # =========================================================================
    # FIGURE 1: Device Types Overview & Category Distribution
    # =========================================================================
    print("[+] Generating Figure 1: Device Types Overview...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    category_counts = device_df['category'].value_counts()
    colors_cat = ['#0284c7', '#7c3aed', '#059669']

    # Donut Chart for Categories
    wedges, texts, autotexts = ax1.pie(
        category_counts.values,
        labels=category_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=colors_cat,
        pctdistance=0.75,
        explode=(0.04, 0.04, 0.04),
        textprops=dict(fontsize=11, fontweight='bold')
    )
    centre_circle = plt.Circle((0,0), 0.50, fc='white')
    ax1.add_artist(centre_circle)
    ax1.set_title("Distribution of Device Categories (12 Total Nodes)", fontsize=13, fontweight='bold', pad=15)

    # Bar chart for Device Types Count per Category
    dev_names = device_df['device_name'].tolist()
    dev_cats = device_df['category'].tolist()
    bar_colors = ['#0284c7' if c=='IoT Device' else ('#7c3aed' if c=='Linux System Node' else '#059669') for c in dev_cats]

    bars = ax2.barh(dev_names[::-1], device_df['total_records'].values[::-1], color=bar_colors[::-1], edgecolor='black', alpha=0.85)
    ax2.set_title("Telemetry Volume by Device / System Node", fontsize=13, fontweight='bold', pad=15)
    ax2.set_xlabel("Number of Telemetry Records", fontsize=11, fontweight='bold')
    ax2.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars:
        w = bar.get_width()
        ax2.text(w + (max(device_df['total_records'])*0.01), bar.get_y() + bar.get_height()/2, f"{int(w):,}",
                 ha='left', va='center', fontsize=9, fontweight='bold', color='#0f172a')

    ax2.set_xlim(0, max(device_df['total_records']) * 1.18)
    ax2.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, p: f"{int(x):,}"))

    plt.tight_layout()
    fig1_path = os.path.join(output_dir, '1_device_types_overview.png')
    plt.savefig(fig1_path, dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # FIGURE 2: Device Telemetry Frequency & Attack Proportions
    # =========================================================================
    print("[+] Generating Figure 2: Device Telemetry Frequency...")
    fig, ax = plt.subplots(figsize=(12, 7), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    y_pos = np.arange(len(device_df))
    height = 0.65

    # Stacked bar: Normal vs Attack
    p1 = ax.barh(y_pos[::-1], device_df['normal_records'].values[::-1], height, label='Normal Telemetry', color='#10b981', edgecolor='black')
    p2 = ax.barh(y_pos[::-1], device_df['attack_records'].values[::-1], height, left=device_df['normal_records'].values[::-1], label='Attack Telemetry', color='#ef4444', edgecolor='black')

    ax.set_yticks(y_pos[::-1])
    ax.set_yticklabels(device_df['device_name'].values[::-1], fontsize=11, fontweight='bold')
    ax.set_xlabel("Total Records (Normal vs Attack Split)", fontsize=12, fontweight='bold', labelpad=10)
    ax.set_title("Device Telemetry Frequency & Attack Ratio Analysis", fontsize=14, fontweight='bold', pad=18)
    ax.grid(axis='x', linestyle='--', alpha=0.5)
    ax.legend(loc='lower right', frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=11)

    for i, row in enumerate(device_df.iloc[::-1].itertuples()):
        tot = row.total_records
        pct_att = row.attack_pct
        ax.text(tot + 1500, i, f"{tot:,} ({pct_att:.1f}% Attack)", ha='left', va='center', fontsize=9, fontweight='bold', color='#1e293b')

    ax.set_xlim(0, max(device_df['total_records']) * 1.22)
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, p: f"{int(x):,}"))

    plt.tight_layout()
    fig2_path = os.path.join(output_dir, '2_device_frequency.png')
    plt.savefig(fig2_path, dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # FIGURE 3: Device Communication Patterns (IP / Port Traffic Flows)
    # =========================================================================
    print("[+] Generating Figure 3: Device Communication Patterns...")
    net_df = pd.read_csv(os.path.join(dataset_base, 'Train_Test_Network_dataset', 'train_test_network.csv'), low_memory=False)

    top_src_ips = net_df['src_ip'].value_counts().head(6)
    top_dst_ips = net_df['dst_ip'].value_counts().head(6)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    # Subplot A: Top Initiators (Source IPs)
    bars1 = ax1.barh(top_src_ips.index[::-1], top_src_ips.values[::-1], color='#2563eb', edgecolor='black', alpha=0.85)
    ax1.set_title("Top Network Communication Initiators (Source IPs)", fontsize=13, fontweight='bold', pad=15)
    ax1.set_xlabel("Number of Flow Connections", fontsize=11, fontweight='bold')
    ax1.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars1:
        w = bar.get_width()
        pct = (w / len(net_df)) * 100
        ax1.text(w + 1000, bar.get_y() + bar.get_height()/2, f"{int(w):,} ({pct:.1f}%)", ha='left', va='center', fontsize=9, fontweight='bold')

    ax1.set_xlim(0, max(top_src_ips.values) * 1.20)
    ax1.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, p: f"{int(x):,}"))

    # Subplot B: Top Target Endpoints (Destination IPs)
    bars2 = ax2.barh(top_dst_ips.index[::-1], top_dst_ips.values[::-1], color='#dc2626', edgecolor='black', alpha=0.85)
    ax2.set_title("Top Target Network Endpoints (Destination IPs)", fontsize=13, fontweight='bold', pad=15)
    ax2.set_xlabel("Number of Flow Connections", fontsize=11, fontweight='bold')
    ax2.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars2:
        w = bar.get_width()
        pct = (w / len(net_df)) * 100
        ax2.text(w + 800, bar.get_y() + bar.get_height()/2, f"{int(w):,} ({pct:.1f}%)", ha='left', va='center', fontsize=9, fontweight='bold')

    ax2.set_xlim(0, max(top_dst_ips.values) * 1.20)
    ax2.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, p: f"{int(x):,}"))

    plt.suptitle("Device Network Communication Patterns & IP Flow Volume", fontsize=15, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    fig3_path = os.path.join(output_dir, '3_device_communication_patterns.png')
    plt.savefig(fig3_path, dpi=300, bbox_inches='tight')
    plt.close()

    print("[SUCCESS] Device contextual visualizations saved successfully in results/device_context/")

if __name__ == '__main__':
    generate_device_context_visualizations()
