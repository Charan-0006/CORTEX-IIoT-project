"""
plot_attack_distribution.py
============================
Generates a standalone, publication-quality bar chart showing the distribution 
of all attack classes (counts and percentages) in the cleaned TON-IoT dataset.
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

def generate_attack_distribution_barchart():
    output_dir = os.path.join('results', 'dashboard')
    os.makedirs(output_dir, exist_ok=True)
    
    print("[+] Loading cleaned datasets...")
    train_df = pd.read_csv('cleaned_train.csv', usecols=['type'])
    test_df = pd.read_csv('cleaned_test.csv', usecols=['type'])
    
    # Combine train & test multi-class targets
    full_types = pd.concat([train_df['type'], test_df['type']])
    total_records = len(full_types)
    
    # Frequency table sorted by count descending
    class_counts = full_types.value_counts()
    classes = class_counts.index.tolist()
    counts = class_counts.values.tolist()
    percentages = [(c / total_records) * 100 for c in counts]

    print(f"[+] Total records analyzed: {total_records:,}")
    print(f"[+] Attack classes ({len(classes)}): {classes}")

    # Set publication styling
    plt.rcParams['font.sans-serif'] = 'Arial'
    plt.rcParams['font.family'] = 'sans-serif'
    
    fig, ax = plt.subplots(figsize=(12, 7), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#f8fafc')

    # Color palette: Highlight 'normal' in emerald, attack classes in modern blue shades, and minority class in amber/coral
    colors = []
    for cls in classes:
        if cls == 'normal':
            colors.append('#059669') # Emerald green for normal
        elif cls == 'mitm':
            colors.append('#dc2626') # Crimson red for extreme minority class (MITM)
        else:
            colors.append('#2563eb') # Professional blue for cyber attacks

    # Horizontal bars (sorted highest count at top)
    y_pos = np.arange(len(classes))
    bars = ax.barh(y_pos[::-1], counts, color=colors, height=0.65, edgecolor='#1e293b', linewidth=0.8, alpha=0.9)

    # Annotate exact count AND percentage on each bar
    max_count = max(counts)
    for idx, (bar, count, pct, cls) in enumerate(zip(bars, counts, percentages, classes)):
        width = bar.get_width()
        label_text = f"{count:,}  ({pct:.2f}%)"
        
        # Position label to the right of the bar
        ax.text(
            width + (max_count * 0.015), 
            bar.get_y() + bar.get_height() / 2, 
            label_text, 
            ha='left', 
            va='center', 
            fontsize=10, 
            fontweight='bold', 
            color='#0f172a'
        )

    # Set axes labels and titles
    ax.set_yticks(y_pos[::-1])
    ax.set_yticklabels([cls.upper() if cls != 'normal' else 'NORMAL (Baseline)' for cls in classes], fontsize=11, fontweight='bold', color='#1e293b')
    ax.set_xlabel("Number of Records", fontsize=12, fontweight='bold', labelpad=10, color='#0f172a')
    ax.set_title("Distribution of Target Attack Classes in Cleaned TON-IoT Dataset", fontsize=14, fontweight='bold', pad=18, color='#0f172a')

    # Grid & Spines formatting
    ax.grid(axis='x', linestyle='--', alpha=0.5, color='#94a3b8')
    ax.set_axisbelow(True)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_color('#64748b')
    ax.spines['bottom'].set_color('#64748b')

    # Format x-axis with comma separator and extra right padding for labels
    ax.xaxis.set_major_formatter(ticker.FuncFormatter(lambda x, p: f"{int(x):,}"))
    ax.set_xlim(0, max_count * 1.20)

    # Legend annotations
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='#059669', edgecolor='black', label='Normal Baseline Traffic (25.89%)'),
        Patch(facecolor='#2563eb', edgecolor='black', label='Cyber Attack Classes (~10.4% each)'),
        Patch(facecolor='#dc2626', edgecolor='black', label='Minority Attack (MITM - 0.23%)')
    ]
    ax.legend(handles=legend_elements, loc='lower right', frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=10)

    # Save figure
    output_path = os.path.join(output_dir, 'attack_class_bar_chart.png')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    
    print(f"[SUCCESS] Publication-quality bar chart saved to: {output_path}")

if __name__ == '__main__':
    generate_attack_distribution_barchart()
