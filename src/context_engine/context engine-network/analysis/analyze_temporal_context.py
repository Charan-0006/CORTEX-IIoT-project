"""
analyze_temporal_context.py
===========================
Generates publication-quality temporal context visualizations for TON-IoT dataset.

Generates 4 high-resolution figures saved in 'results/temporal/':
1. 1_hourly_activity_distribution.png: Hourly traffic event volume & attack breakdown
2. 2_daily_activity_timeline.png: Daily dataset collection timeline & volume
3. 3_attack_occurrence_over_time.png: Timeline of normal vs attack occurrences
4. 4_session_duration_distribution.png: Session duration distribution (Log-scale KDE & Histogram)
"""

import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

def generate_temporal_visualizations():
    output_dir = os.path.join('results', 'temporal')
    os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Output directory ready: {output_dir}")

    # Set publication styling
    plt.rcParams['font.sans-serif'] = 'Arial'
    plt.rcParams['font.family'] = 'sans-serif'
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    # Load IoT temporal data
    print("[+] Loading IoT telemetry datasets for timestamp processing...")
    iot_files = glob.glob('Train_Test_datasets/Train_Test_IoT_dataset/*.csv')
    dfs = []
    for f in iot_files:
        df = pd.read_csv(f)
        dfs.append(df)

    iot_full = pd.concat(dfs, ignore_index=True)
    iot_full['datetime'] = pd.to_datetime(iot_full['date'] + ' ' + iot_full['time'], format='%d-%b-%y %H:%M:%S', errors='coerce')
    
    # Filter out invalid datetimes
    iot_full = iot_full.dropna(subset=['datetime']).copy()
    iot_full['hour'] = iot_full['datetime'].dt.hour
    iot_full['date_str'] = iot_full['datetime'].dt.strftime('%Y-%m-%d')
    iot_full['date_label'] = iot_full['datetime'].dt.strftime('%b %d, %Y')

    total_records = len(iot_full)
    print(f"[+] Processed {total_records:,} valid timestamp records.")

    # =========================================================================
    # FIGURE 1: Hourly Activity Distribution (00:00 to 23:00)
    # =========================================================================
    print("[+] Generating Figure 1: Hourly Activity Distribution...")
    fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    hourly_cross = pd.crosstab(iot_full['hour'], iot_full['label'])
    # Reindex to ensure all 24 hours (0 to 23) exist
    hourly_cross = hourly_cross.reindex(range(24), fill_value=0)

    hours = hourly_cross.index.values
    normal_h = hourly_cross[0].values if 0 in hourly_cross else np.zeros(24)
    attack_h = hourly_cross[1].values if 1 in hourly_cross else np.zeros(24)

    bars_norm = ax.bar(hours - 0.2, normal_h, width=0.4, label='Normal Telemetry', color='#10b981', edgecolor='black', alpha=0.85)
    bars_att = ax.bar(hours + 0.2, attack_h, width=0.4, label='Attack Telemetry', color='#ef4444', edgecolor='black', alpha=0.85)

    ax.set_title("Hourly Activity Distribution (24-Hour Operational Cycle)", fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel("Hour of Day (00:00 - 23:00)", fontsize=12, fontweight='bold', labelpad=10)
    ax.set_ylabel("Event Record Count", fontsize=12, fontweight='bold')
    ax.set_xticks(range(24))
    ax.set_xticklabels([f"{h:02d}:00" for h in range(24)], rotation=45, fontsize=9, fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    ax.legend(frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=11)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, p: f"{int(y):,}"))

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '1_hourly_activity_distribution.png'), dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # FIGURE 2: Daily Activity Timeline
    # =========================================================================
    print("[+] Generating Figure 2: Daily Activity Timeline...")
    fig, ax = plt.subplots(figsize=(12, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    daily_counts = iot_full.groupby(['date_str', 'label']).size().unstack(fill_value=0)
    
    dates = daily_counts.index.tolist()
    norm_daily = daily_counts[0].values if 0 in daily_counts else np.zeros(len(dates))
    att_daily = daily_counts[1].values if 1 in daily_counts else np.zeros(len(dates))

    x_idx = np.arange(len(dates))
    ax.plot(x_idx, norm_daily, marker='o', linewidth=2.5, markersize=8, color='#10b981', label='Normal Activity')
    ax.plot(x_idx, att_daily, marker='s', linewidth=2.5, markersize=8, color='#ef4444', label='Attack Activity')

    ax.set_title("Daily Dataset Collection & Attack Experimentation Timeline", fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel("Testbed Execution Date", fontsize=12, fontweight='bold', labelpad=10)
    ax.set_ylabel("Total Recorded Events", fontsize=12, fontweight='bold')
    ax.set_xticks(x_idx)
    ax.set_xticklabels(dates, fontsize=10, fontweight='bold')
    ax.grid(True, linestyle='--', alpha=0.5)
    ax.legend(frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=11)
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, p: f"{int(y):,}"))

    # Annotate key peaks
    for i, (nd, ad) in enumerate(zip(norm_daily, att_daily)):
        if nd > 0:
            ax.annotate(f"Normal: {nd:,}", (i, nd), textcoords="offset points", xytext=(0,10), ha='center', fontweight='bold', color='#047857')
        if ad > 0:
            ax.annotate(f"Attack: {ad:,}", (i, ad), textcoords="offset points", xytext=(0,10), ha='center', fontweight='bold', color='#b91c1c')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '2_daily_activity_timeline.png'), dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # FIGURE 3: Attack Occurrence Over Time (Multi-Class Timeline)
    # =========================================================================
    print("[+] Generating Figure 3: Attack Occurrence Over Time...")
    fig, ax = plt.subplots(figsize=(13, 6.5), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    attack_time = pd.crosstab(iot_full['date_str'], iot_full['type'])
    attack_time.plot(kind='bar', stacked=True, ax=ax, colormap='tab10', width=0.6, edgecolor='black', alpha=0.85)

    ax.set_title("Multi-Class Attack Category Occurrence Over Time", fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel("Collection Date", fontsize=12, fontweight='bold', labelpad=10)
    ax.set_ylabel("Record Volume", fontsize=12, fontweight='bold')
    ax.set_xticklabels(attack_time.index, rotation=0, fontsize=10, fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    ax.legend(title="Traffic / Attack Type", bbox_to_anchor=(1.02, 1), loc='upper left', frameon=True, facecolor='white', edgecolor='#cbd5e1')
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, p: f"{int(y):,}"))

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '3_attack_occurrence_over_time.png'), dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # FIGURE 4: Session Duration Distribution (Log Scale KDE & Histogram)
    # =========================================================================
    print("[+] Generating Figure 4: Session Duration Distribution...")
    net_df = pd.read_csv('Train_Test_datasets/Train_Test_Network_dataset/train_test_network.csv', usecols=['duration', 'label'])
    
    # Filter valid non-negative durations
    net_df = net_df[net_df['duration'] >= 0].copy()
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    # Subplot A: Overall Session Duration Distribution (Log Scale)
    log_durations = np.log10(net_df['duration'] + 1e-6) # Add epsilon for 0 duration
    
    sns.histplot(log_durations, bins=50, kde=True, ax=ax1, color='#2563eb', edgecolor='black', alpha=0.7)
    ax1.set_title("Network Flow Session Duration Distribution (Log Scale)", fontsize=13, fontweight='bold', pad=15)
    ax1.set_xlabel("Log10(Duration in Seconds)", fontsize=11, fontweight='bold')
    ax1.set_ylabel("Flow Connection Frequency", fontsize=11, fontweight='bold')
    ax1.grid(True, linestyle='--', alpha=0.5)

    # Subplot B: Duration Comparison (Normal vs Attack Session Durations)
    norm_durations = np.log10(net_df[net_df['label'] == 0]['duration'] + 1e-6)
    att_durations = np.log10(net_df[net_df['label'] == 1]['duration'] + 1e-6)

    sns.kdeplot(norm_durations, ax=ax2, color='#10b981', label='Normal Flow Sessions', linewidth=2.5, fill=True, alpha=0.3)
    sns.kdeplot(att_durations, ax=ax2, color='#ef4444', label='Attack Flow Sessions', linewidth=2.5, fill=True, alpha=0.3)

    ax2.set_title("Session Duration Density (Normal vs Attack Flows)", fontsize=13, fontweight='bold', pad=15)
    ax2.set_xlabel("Log10(Duration in Seconds)", fontsize=11, fontweight='bold')
    ax2.set_ylabel("Probability Density", fontsize=11, fontweight='bold')
    ax2.grid(True, linestyle='--', alpha=0.5)
    ax2.legend(frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=10)

    plt.suptitle("Network Connection Session Duration Analysis", fontsize=15, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(os.path.join(output_dir, '4_session_duration_distribution.png'), dpi=300, bbox_inches='tight')
    plt.close()

    print("[SUCCESS] Temporal context visualizations saved successfully in results/temporal/")

if __name__ == '__main__':
    generate_temporal_visualizations()
