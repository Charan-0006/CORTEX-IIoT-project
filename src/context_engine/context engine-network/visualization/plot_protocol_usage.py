"""
plot_protocol_usage.py
======================
Generates publication-quality visualizations comparing TCP, UDP, ICMP and other 
protocols in the TON-IoT dataset, including protocol breakdown across attack types 
and threat ratios.
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

def generate_protocol_visualizations():
    output_dir = os.path.join('results', 'dashboard')
    os.makedirs(output_dir, exist_ok=True)
    
    print("[+] Loading raw network dataset for protocol analysis...")
    df = pd.read_csv('Train_Test_datasets/Train_Test_Network_dataset/train_test_network.csv', low_memory=False)
    
    total_records = len(df)
    proto_counts = df['proto'].value_counts()
    
    print(f"[+] Total records analyzed: {total_records:,}")
    print(f"[+] Protocol distribution:\n{proto_counts}")

    # Set publication styling defaults
    plt.rcParams['font.sans-serif'] = 'Arial'
    plt.rcParams['font.family'] = 'sans-serif'
    
    fig = plt.figure(figsize=(16, 11), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    # Grid layout: Top 2 subplots (Overall & Threat Ratio), Bottom subplot (Protocol breakdown by Attack Class)
    gs = fig.add_gridspec(2, 2, height_ratios=[1, 1.2], hspace=0.35, wspace=0.25)
    
    ax1 = fig.add_subplot(gs[0, 0]) # Overall Protocol Share
    ax2 = fig.add_subplot(gs[0, 1]) # Threat Ratio (Normal vs Attack per Protocol)
    ax3 = fig.add_subplot(gs[1, :])  # Grouped Bar Chart by Attack Type

    # -------------------------------------------------------------------------
    # PANEL A: Overall Protocol Share (Donut / Bar)
    # -------------------------------------------------------------------------
    proto_labels = [p.upper() for p in proto_counts.index]
    proto_vals = proto_counts.values
    colors_proto = ['#2563eb', '#0284c7', '#dc2626'] # Blue (TCP), Cyan (UDP), Red (ICMP)

    bars1 = ax1.bar(proto_labels, proto_vals, color=colors_proto, width=0.55, edgecolor='#0f172a', linewidth=1)
    ax1.set_title("A. Overall Network Protocol Distribution", fontsize=13, fontweight='bold', pad=12, color='#0f172a')
    ax1.set_ylabel("Number of Connections", fontsize=11, fontweight='bold')
    ax1.set_yscale('log') # Log scale due to large disparity
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    for bar, val in zip(bars1, proto_vals):
        pct = (val / total_records) * 100
        ax1.text(bar.get_x() + bar.get_width()/2, val * 1.2, f"{val:,}\n({pct:.1f}%)", 
                 ha='center', va='bottom', fontsize=10, fontweight='bold', color='#0f172a')

    ax1.set_ylim(10, total_records * 3)
    ax1.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, p: f"{int(y):,}"))

    # -------------------------------------------------------------------------
    # PANEL B: Threat Ratio (Normal vs Attack per Protocol)
    # -------------------------------------------------------------------------
    cross_proto_label = pd.crosstab(df['proto'], df['label'], normalize='index') * 100
    protocols = cross_proto_label.index.tolist()
    normal_pcts = cross_proto_label[0].values
    attack_pcts = cross_proto_label[1].values

    x = np.arange(len(protocols))
    width = 0.35

    bars_n = ax2.bar(x - width/2, normal_pcts, width, label='Normal Traffic', color='#10b981', edgecolor='black')
    bars_a = ax2.bar(x + width/2, attack_pcts, width, label='Attack Traffic', color='#ef4444', edgecolor='black')

    ax2.set_title("B. Threat Concentration Ratio per Protocol", fontsize=13, fontweight='bold', pad=12, color='#0f172a')
    ax2.set_ylabel("Percentage (%)", fontsize=11, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels([p.upper() for p in protocols], fontsize=11, fontweight='bold')
    ax2.set_ylim(0, 115)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)
    ax2.legend(frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=10)

    for bar in bars_n:
        h = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2, h + 2, f"{h:.1f}%", ha='center', va='bottom', fontsize=9, fontweight='bold')
    for bar in bars_a:
        h = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2, h + 2, f"{h:.1f}%", ha='center', va='bottom', fontsize=9, fontweight='bold')

    # -------------------------------------------------------------------------
    # PANEL C: Protocol Breakdown across 10 Attack Classes
    # -------------------------------------------------------------------------
    cross_proto_type = pd.crosstab(df['type'], df['proto'])
    # Normalize rows to show percentage composition per attack class
    cross_proto_type_pct = cross_proto_type.div(cross_proto_type.sum(axis=1), axis=0) * 100

    attack_classes = cross_proto_type_pct.index.tolist()
    tcp_comp = cross_proto_type_pct['tcp'].values if 'tcp' in cross_proto_type_pct else np.zeros(len(attack_classes))
    udp_comp = cross_proto_type_pct['udp'].values if 'udp' in cross_proto_type_pct else np.zeros(len(attack_classes))
    icmp_comp = cross_proto_type_pct['icmp'].values if 'icmp' in cross_proto_type_pct else np.zeros(len(attack_classes))

    indices = np.arange(len(attack_classes))
    bar_width = 0.65

    # Stacked horizontal bar chart
    p1 = ax3.barh(indices, tcp_comp, bar_width, label='TCP Protocol', color='#2563eb', edgecolor='black', alpha=0.9)
    p2 = ax3.barh(indices, udp_comp, bar_width, left=tcp_comp, label='UDP Protocol', color='#0284c7', edgecolor='black', alpha=0.9)
    p3 = ax3.barh(indices, icmp_comp, bar_width, left=tcp_comp+udp_comp, label='ICMP Protocol', color='#dc2626', edgecolor='black', alpha=0.9)

    ax3.set_title("C. Protocol Composition Across Attack & Normal Traffic Classes", fontsize=13, fontweight='bold', pad=12, color='#0f172a')
    ax3.set_xlabel("Protocol Composition Percentage (%)", fontsize=11, fontweight='bold')
    ax3.set_yticks(indices)
    ax3.set_yticklabels([ac.upper() for ac in attack_classes], fontsize=10, fontweight='bold')
    ax3.set_xlim(0, 100)
    ax3.grid(axis='x', linestyle='--', alpha=0.5)
    ax3.legend(loc='lower right', frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=10)

    # Annotate significant UDP / ICMP composition percentages
    for i in range(len(attack_classes)):
        tcp_val = tcp_comp[i]
        udp_val = udp_comp[i]
        icmp_val = icmp_comp[i]
        
        if udp_val > 5:
            ax3.text(tcp_val + udp_val/2, i, f"{udp_val:.1f}%", ha='center', va='center', color='white', fontweight='bold', fontsize=9)
        if icmp_val > 0.3:
            ax3.text(tcp_val + udp_val + icmp_val/2 + 2, i, f"{icmp_val:.1f}%", ha='left', va='center', color='#dc2626', fontweight='bold', fontsize=8)

    plt.suptitle("Protocol Usage & Threat Intelligence Profile (TON-IoT Dataset)", fontsize=16, fontweight='bold', y=0.98, color='#0f172a')
    
    output_path = os.path.join(output_dir, 'protocol_usage_distribution.png')
    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()

    print(f"[SUCCESS] Protocol visualization saved to: {output_path}")

if __name__ == '__main__':
    generate_protocol_visualizations()
