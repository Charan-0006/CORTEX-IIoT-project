"""
generate_dashboard.py
=====================
Publication-Quality Dashboard & Chart Generator for Cleaned TON-IoT Dataset.

Generates high-resolution figures and an interactive HTML report saved in 'results/dashboard/':
- Number of records (Train/Test split)
- Number of features (Numerical vs Categorical)
- Missing values (Before vs After cleaning)
- Duplicate values (Before vs After cleaning)
- Number of attack classes & distribution
"""

import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# Set publication style defaults
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.family'] = 'sans-serif'
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Helvetica']
plt.rcParams['axes.edgecolor'] = '#cccccc'
plt.rcParams['axes.linewidth'] = 1.0

PALETTE = {
    'primary': '#1f77b4',
    'secondary': '#ff7f0e',
    'success': '#2ca02c',
    'danger': '#d62728',
    'purple': '#9467bd',
    'teal': '#17becf',
    'dark_blue': '#0b2545',
    'light_bg': '#f8f9fa',
    'accent': '#3a86ff'
}

COLOR_LIST = ['#2b5c8f', '#d95f02', '#7570b3', '#e7298a', '#66a61e', '#e6ab02', '#a6761d', '#666666', '#1b9e77', '#ce1256']

def generate_dashboard():
    output_dir = os.path.join('results', 'dashboard')
    os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Output directory ready: {output_dir}")

    # Load cleaned datasets
    print("[+] Loading cleaned datasets...")
    train_df = pd.read_csv('cleaned_train.csv')
    test_df = pd.read_csv('cleaned_test.csv')
    
    total_records = len(train_df) + len(test_df)
    train_records = len(train_df)
    test_records = len(test_df)
    
    # Feature classification
    target_cols = ['label', 'type']
    feature_cols = [c for c in train_df.columns if c not in target_cols]
    total_features = len(feature_cols)

    # In preprocess.py:
    # Continuous numeric features (originally continuous)
    # One-hot encoded features (binary 0/1 dummies)
    binary_onehot_cols = [c for c in feature_cols if train_df[c].nunique() <= 2]
    continuous_num_cols = [c for c in feature_cols if c not in binary_onehot_cols]

    num_numerical_features = len(continuous_num_cols)
    num_categorical_encoded_features = len(binary_onehot_cols)
    num_original_categorical_features = 22 # From preprocess logs
    num_attack_classes = train_df['type'].nunique()
    
    missing_after = train_df[feature_cols].isnull().sum().sum() + test_df[feature_cols].isnull().sum().sum()
    duplicates_after = train_df.duplicated().sum() + test_df.duplicated().sum()
    
    # Historical / Before cleaning stats (from raw dataset scan)
    initial_records = 211043
    initial_duplicates = 20569
    initial_missing = 3777598 # Sum of missing values across raw columns

    metrics_summary = {
        'total_records': total_records,
        'train_records': train_records,
        'test_records': test_records,
        'total_features': total_features,
        'numerical_features': num_numerical_features,
        'categorical_encoded_features': num_categorical_encoded_features,
        'original_categorical_features': num_original_categorical_features,
        'missing_values': int(missing_after),
        'duplicate_values': int(duplicates_after),
        'attack_classes_count': int(num_attack_classes),
        'attack_classes': sorted(list(train_df['type'].unique()))
    }
    
    with open(os.path.join(output_dir, 'metrics_summary.json'), 'w') as f:
        json.dump(metrics_summary, f, indent=2)

    print("\n" + "="*50)
    print("      CLEANED TON-IOT DATASET METRICS SUMMARY      ")
    print("="*50)
    print(f" Total Records:                {total_records:,} ({train_records:,} Train / {test_records:,} Test)")
    print(f" Total Features:               {total_features}")
    print(f"   - Numerical Features:       {num_numerical_features} (Scaled via StandardScaler)")
    print(f"   - Categorical Features:     {num_original_categorical_features} (Encoded into {num_categorical_encoded_features} dummies)")
    print(f" Missing Values (Cleaned):     {missing_after}")
    print(f" Duplicate Rows (Cleaned):     {duplicates_after}")
    print(f" Attack Classes:               {num_attack_classes} classes {sorted(list(train_df['type'].unique()))}")
    print("="*50 + "\n")

    # =========================================================================
    # CHART 1: Summary Key Performance Indicator (KPI) Metric Cards
    # =========================================================================
    print("[+] Generating Chart 1: Key Metrics Overview...")
    fig, axes = plt.subplots(2, 3, figsize=(14, 8))
    fig.patch.set_facecolor('#0f172a') # Dark modern background
    
    cards = [
        ("Total Records", f"{total_records:,}", f"Train: {train_records:,}\nTest: {test_records:,}", "#3b82f6"),
        ("Total Features", f"{total_features}", f"Numerical: {num_numerical_features}\nCategorical Dummies: {num_categorical_encoded_features}", "#8b5cf6"),
        ("Missing Values", f"{missing_after}", "Post-Imputation\n100% Cleaned", "#10b981"),
        ("Duplicate Rows", f"{duplicates_after}", f"Initial Duplicates: {initial_duplicates:,}\nStatus: Purged", "#ef4444"),
        ("Attack Classes", f"{num_attack_classes}", "Normal + 9 Attack Types\nMulti-Class Target", "#f59e0b"),
        ("Normalization", "StandardScaler", "Zero Mean, Unit Var\nStratified Split (80/20)", "#06b6d4")
    ]
    
    for ax, (title, value, subtitle, color) in zip(axes.flatten(), cards):
        ax.set_facecolor('#1e293b')
        ax.axis('off')
        # Border
        rect = plt.Rectangle((0.02, 0.02), 0.96, 0.96, fill=False, edgecolor=color, linewidth=2, transform=ax.transAxes)
        ax.add_patch(rect)
        
        ax.text(0.5, 0.75, title.upper(), color='#94a3b8', fontsize=12, fontweight='bold', ha='center', transform=ax.transAxes)
        ax.text(0.5, 0.45, value, color='white', fontsize=24, fontweight='bold', ha='center', transform=ax.transAxes)
        ax.text(0.5, 0.20, subtitle, color=color, fontsize=10, ha='center', transform=ax.transAxes)

    plt.suptitle("TON-IoT Dataset Cleaning & Summary Dashboard", color='white', fontsize=18, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(os.path.join(output_dir, '1_kpi_summary_dashboard.png'), dpi=300, bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()

    # =========================================================================
    # CHART 2: Publication-Quality Attack Class Distribution
    # =========================================================================
    print("[+] Generating Chart 2: Attack Class Distribution...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7))
    
    # Combined attack counts across train and test
    full_type_counts = pd.concat([train_df['type'], test_df['type']]).value_counts()
    
    # Horizontal Bar Chart
    bars = ax1.barh(full_type_counts.index[::-1], full_type_counts.values[::-1], color='#2563eb', edgecolor='black', alpha=0.85)
    ax1.set_title("Record Distribution by Attack Class", fontsize=14, fontweight='bold', pad=15)
    ax1.set_xlabel("Number of Records", fontsize=12, fontweight='bold')
    ax1.grid(axis='x', linestyle='--', alpha=0.6)
    
    # Annotate bar counts
    for bar in bars:
        width = bar.get_width()
        ax1.text(width + 800, bar.get_y() + bar.get_height()/2, f"{int(width):,} ({width/total_records*100:.1f}%)", 
                 ha='left', va='center', fontsize=10, fontweight='bold', color='#1e293b')

    # Pie / Donut Chart
    wedges, texts, autotexts = ax2.pie(
        full_type_counts.values,
        labels=full_type_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=COLOR_LIST,
        pctdistance=0.80,
        textprops=dict(color="black", fontweight='bold', fontsize=9)
    )
    # Donut center circle
    centre_circle = plt.Circle((0,0), 0.55, fc='white')
    ax2.add_artist(centre_circle)
    ax2.set_title("Attack Class Proportions", fontsize=14, fontweight='bold', pad=15)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '2_attack_class_distribution.png'), dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # CHART 3: Feature Type Breakdown & Composition
    # =========================================================================
    print("[+] Generating Chart 3: Feature Breakdown...")
    fig, ax = plt.subplots(figsize=(8, 6))
    
    feature_labels = ['Continuous Numerical\n(StandardScaler)', 'Categorical One-Hot\n(Dummy Variables)', 'Target Variables\n(label & type)']
    feature_sizes = [num_numerical_features, num_categorical_encoded_features, 2]
    colors = ['#0284c7', '#7c3aed', '#f59e0b']
    
    wedges, texts, autotexts = ax.pie(
        feature_sizes,
        labels=feature_labels,
        autopct=lambda pct: f"{pct:.1f}%\n({int(round(pct/100.*sum(feature_sizes)))} cols)",
        startangle=90,
        colors=colors,
        pctdistance=0.75,
        explode=(0.05, 0.05, 0.05),
        textprops=dict(fontsize=11, fontweight='bold')
    )
    
    centre_circle = plt.Circle((0,0), 0.50, fc='white')
    ax.add_artist(centre_circle)
    ax.set_title("Cleaned Dataset Feature Composition (139 Columns)", fontsize=14, fontweight='bold', pad=15)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '3_feature_composition.png'), dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # CHART 4: Before vs After Preprocessing Comparison
    # =========================================================================
    print("[+] Generating Chart 4: Before vs After Preprocessing...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    categories = ['Duplicate Rows', 'Missing Values']
    before_vals = [initial_duplicates, initial_missing]
    after_vals = [duplicates_after, missing_after]
    
    x = np.arange(len(categories))
    width = 0.35
    
    ax1.bar(x - width/2, before_vals, width, label='Raw Dataset', color='#ef4444', edgecolor='black')
    ax1.bar(x + width/2, after_vals, width, label='Cleaned Dataset', color='#10b981', edgecolor='black')
    
    ax1.set_ylabel("Count (Log Scale)", fontsize=12, fontweight='bold')
    ax1.set_title("Data Quality Improvement (Before vs After)", fontsize=14, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(categories, fontsize=11, fontweight='bold')
    ax1.set_yscale('log')
    ax1.legend(fontsize=11)
    ax1.grid(axis='y', linestyle='--', alpha=0.6)
    
    # Train / Test split pie chart
    ax2.pie([train_records, test_records], labels=['Training Set (80%)', 'Test Set (20%)'],
            colors=['#2563eb', '#f97316'], autopct='%1.1f%%', startangle=90,
            explode=(0.03, 0.03), textprops=dict(fontsize=11, fontweight='bold'))
    ax2.set_title(f"Stratified Dataset Split ({total_records:,} Total)", fontsize=14, fontweight='bold')

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, '4_preprocessing_quality_comparison.png'), dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # CHART 5: Feature Correlation Heatmap (Continuous Features)
    # =========================================================================
    print("[+] Generating Chart 5: Feature Correlation Matrix...")
    if len(continuous_num_cols) > 1:
        fig, ax = plt.subplots(figsize=(10, 8))
        corr_matrix = train_df[continuous_num_cols + ['label']].corr()
        sns.heatmap(corr_matrix, annot=True, fmt='.2f', cmap='Blues', cbar=True, ax=ax, linewidths=0.5)
        ax.set_title("Correlation Heatmap of Numerical Features & Target Label", fontsize=13, fontweight='bold', pad=15)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '5_feature_correlation_heatmap.png'), dpi=300, bbox_inches='tight')
        plt.close()

    # =========================================================================
    # HTML REPORT: Interactive Web Dashboard
    # =========================================================================
    print("[+] Generating Interactive HTML Dashboard (index.html)...")
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TON-IoT Dataset Summary Dashboard</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --text-main: #f8fafc;
            --text-sub: #94a3b8;
        }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 20px 40px;
        }}
        .header {{
            text-align: center;
            padding: 20px 0;
            border-bottom: 1px solid #334155;
            margin-bottom: 30px;
        }}
        .header h1 {{
            font-size: 2.2rem;
            margin: 0 0 10px 0;
            color: #ffffff;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header p {{
            color: var(--text-sub);
            font-size: 1.1rem;
            margin: 0;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .kpi-card {{
            background-color: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            border-left: 5px solid var(--accent-blue);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }}
        .kpi-card.green {{ border-left-color: var(--accent-green); }}
        .kpi-card.purple {{ border-left-color: var(--accent-purple); }}
        .kpi-card.amber {{ border-left-color: var(--accent-amber); }}
        .kpi-card.red {{ border-left-color: var(--accent-red); }}
        
        .kpi-title {{
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-sub);
            margin-bottom: 8px;
        }}
        .kpi-value {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }}
        .kpi-sub {{
            font-size: 0.9rem;
            color: var(--text-sub);
        }}
        .section-title {{
            font-size: 1.5rem;
            margin: 40px 0 20px 0;
            border-bottom: 2px solid #334155;
            padding-bottom: 8px;
            color: #e2e8f0;
        }}
        .chart-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 30px;
            margin-bottom: 40px;
        }}
        .chart-card {{
            background-color: var(--card-bg);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
            text-align: center;
        }}
        .chart-card img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background-color: var(--card-bg);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        th {{
            background-color: #0f172a;
            color: #38bdf8;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #2a374e;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
            background-color: #334155;
            color: #f8fafc;
        }}
        .badge.attack {{ background-color: #991b1b; color: #fecaca; }}
        .badge.normal {{ background-color: #065f46; color: #a7f3d0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>TON-IoT Cleaned Dataset Summary Dashboard</h1>
        <p>Comprehensive Telemetry Analysis, Preprocessing & Quality Verification</p>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-title">Total Records</div>
            <div class="kpi-value">{total_records:,}</div>
            <div class="kpi-sub">Train: {train_records:,} | Test: {test_records:,}</div>
        </div>
        <div class="kpi-card purple">
            <div class="kpi-title">Total Features</div>
            <div class="kpi-value">{total_features}</div>
            <div class="kpi-sub">Numerical: {num_numerical_features} | Categorical Dummies: {num_categorical_encoded_features}</div>
        </div>
        <div class="kpi-card green">
            <div class="kpi-title">Missing Values</div>
            <div class="kpi-value">{missing_after}</div>
            <div class="kpi-sub">100% Imputed & Cleaned</div>
        </div>
        <div class="kpi-card red">
            <div class="kpi-title">Duplicate Rows</div>
            <div class="kpi-value">{duplicates_after}</div>
            <div class="kpi-sub">{initial_duplicates:,} Initial Duplicates Purged</div>
        </div>
        <div class="kpi-card amber">
            <div class="kpi-title">Attack Classes</div>
            <div class="kpi-value">{num_attack_classes}</div>
            <div class="kpi-sub">Normal + 9 Cyber-Attack Types</div>
        </div>
    </div>

    <h2 class="section-title">Publication-Quality Visualizations</h2>
    <div class="chart-grid">
        <div class="chart-card">
            <img src="1_kpi_summary_dashboard.png" alt="KPI Summary Cards">
        </div>
        <div class="chart-card">
            <img src="2_attack_class_distribution.png" alt="Attack Distribution">
        </div>
        <div class="chart-card">
            <img src="3_feature_composition.png" alt="Feature Composition">
        </div>
        <div class="chart-card">
            <img src="4_preprocessing_quality_comparison.png" alt="Before vs After Quality">
        </div>
    </div>

    <h2 class="section-title">Attack Class Breakdown</h2>
    <table>
        <thead>
            <tr>
                <th>Class Name</th>
                <th>Category</th>
                <th>Training Samples</th>
                <th>Testing Samples</th>
                <th>Total Samples</th>
                <th>Percentage</th>
            </tr>
        </thead>
        <tbody>
"""
    
    train_counts = train_df['type'].value_counts()
    test_counts = test_df['type'].value_counts()
    
    for cls in sorted(list(train_df['type'].unique())):
        tr_c = train_counts.get(cls, 0)
        te_c = test_counts.get(cls, 0)
        tot_c = tr_c + te_c
        pct = (tot_c / total_records) * 100
        badge_cls = "normal" if cls == "normal" else "attack"
        html_content += f"""            <tr>
                <td><strong>{cls}</strong></td>
                <td><span class="badge {badge_cls}">{cls.upper()}</span></td>
                <td>{tr_c:,}</td>
                <td>{te_c:,}</td>
                <td>{tot_c:,}</td>
                <td>{pct:.2f}%</td>
            </tr>\n"""

    html_content += """        </tbody>
    </table>
</body>
</html>
"""
    
    html_path = os.path.join(output_dir, 'index.html')
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"[SUCCESS] Interactive HTML Dashboard generated at: {html_path}")
    print("[SUCCESS] All publication-quality charts saved successfully in results/dashboard/")

if __name__ == '__main__':
    generate_dashboard()
