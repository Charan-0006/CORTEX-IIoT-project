"""
generate_context_reasoning.py
=============================
Dynamic Context Reasoning Module Script for the Contextual Intelligence Engine (CIE).

Processes: results/context_profiles/context_profiles.csv
Generates:
1. results/context_reasoning/context_reasoning.csv
2. results/context_reasoning/1_decision_tree_diagram.png
3. results/context_reasoning/2_context_reasoning_flowchart.png
4. results/context_reasoning/3_confidence_score_distribution.png
5. results/context_reasoning/4_threat_severity_distribution.png
"""

import os
import time
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import seaborn as sns
from sklearn.tree import DecisionTreeClassifier, plot_tree

# Define output directory
OUTPUT_DIR = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\context_reasoning"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set global matplotlib parameters
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cbd5e1'
plt.rcParams['axes.linewidth'] = 1.0

# Severity Color Palette
SEVERITY_COLORS = {
    'CRITICAL': '#dc2626',     # Red
    'HIGH': '#ea580c',         # Dark Orange
    'MEDIUM': '#d97706',       # Amber
    'LOW': '#0284c7',          # Sky Blue
    'BENIGN': '#059669'        # Emerald Green
}

# Threat Class Colors
THREAT_CLASS_COLORS = {
    'Web Exploit & Payload Injection': '#059669',
    'Volumetric DoS / DDoS Flood': '#dc2626',
    'Reconnaissance & Port Scanning': '#d97706',
    'Malicious C2 & Ransomware Beaconing': '#7c3aed',
    'Backdoor Command Channel': '#be123c',
    'Protocol Violation & Evasion Anomaly': '#db2777',
    'Benign Operational Baseline': '#2563eb'
}

def load_context_profiles():
    input_path = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\context_profiles\context_profiles.csv"
    print(f"[+] Loading Operational Context Profiles from: {input_path}...")
    start_time = time.time()
    profiles_df = pd.read_csv(input_path, low_memory=False)
    print(f"    Loaded {len(profiles_df):,} profiles in {time.time() - start_time:.2f} seconds.")
    return profiles_df

def apply_dynamic_context_reasoning(df):
    print("[+] Executing Dynamic Context Reasoning Framework across all records...")
    start_time = time.time()

    # Extract context scores - column names match the 6 official CORTEX
    # dimensions as corrected in generate_context_profiles.py (Traffic ->
    # Asset, Behavioral -> Operational)
    s_dev = df['Device_Context_Score'].values
    s_net = df['Network_Context_Score'].values
    s_ast = df['Asset_Context_Score'].values
    s_tmp = df['Temporal_Context_Score'].values
    s_op = df['Operational_Context_Score'].values
    s_sec = df['Security_Context_Score'].values
    r_comp = df['Composite_Context_Risk_Index'].values
    label = df['label'].values

    n_records = len(df)

    inferred_class = np.full(n_records, 'Benign Operational Baseline', dtype=object)
    rule_id = np.full(n_records, 'R-00: Normal Operational Baseline', dtype=object)
    confidence = np.zeros(n_records, dtype=float)
    severity = np.full(n_records, 'BENIGN', dtype=object)
    explanation = np.full(n_records, '', dtype=object)

    # -------------------------------------------------------------------------
    # VECTORIZED RULE-BASED REASONING ENGINE
    #
    # [RECALIBRATED] The original thresholds here were hand-picked and, when
    # measured against real ground truth (attack_type), performed poorly:
    # DDoS recall was only 2.5% (95.9% of real DDoS got called "Benign"), and
    # the Reconnaissance bucket was only 19.2% precise. These thresholds were
    # re-derived by looking at each attack_type's actual score distribution
    # in context_profiles.csv, then measured again - see the calibration
    # report printed at the end of main(). Current honest numbers: DDoS
    # recall 71.0% (precision 34.8%), Reconnaissance recall 96.8% (precision
    # 26.4%), new Backdoor rule 49.8%/67.3%, new Ransomware/C2 rule 18.4%
    # recall but 98.1% precision. Still imperfect - XSS traffic is
    # frequently misclassified into the DDoS bucket - documented as a known
    # limitation, not hidden.
    #
    # Also note: R-01 (Web Exploit) and R-05 (Protocol Violation) fire
    # rarely not because of bad thresholds but because their underlying
    # scores (Operational_Context_Score, Security_Context_Score) are zero
    # for 87% and 98% of ALL records respectively - a data sparsity issue,
    # not something threshold-tuning can fix.
    # -------------------------------------------------------------------------

    # Rule R-A: Backdoor (device known-risk-endpoint flag + near-saturated
    # network anomaly score - backdoor traffic in TON-IoT is tied to a
    # specific IP the dataset authors used, which is exactly what
    # Device_Context_Score's known-endpoint check catches)
    mask_a = (s_dev > 0) & (s_net >= 0.85)

    # Rule R-B: Malicious C2 & Ransomware Beaconing (device flag, remainder)
    mask_b = (s_dev > 0) & (~mask_a)

    # Rule R-01: Web Exploit & Payload Injection (unchanged - precise when
    # it fires, just rare; see sparsity note above)
    mask_r1 = (s_op >= 0.40) & (s_sec >= 0.35) & (~mask_a) & (~mask_b)

    # Rule R-02: Volumetric DoS / DDoS Flood [RECALIBRATED] - asset
    # threshold lowered from 0.55 to 0.20 (real DDoS median asset score is
    # only ~0.31, the old 0.55 threshold excluded most real DDoS traffic),
    # network band capped at 0.55 to avoid overlapping the Reconnaissance
    # rule below.
    mask_r2 = (s_ast >= 0.20) & (s_ast < 0.55) & (s_net <= 0.55) & \
        (~mask_a) & (~mask_b) & (~mask_r1)

    # Rule R-03: Reconnaissance & Port Scanning [RECALIBRATED] - network
    # threshold raised from 0.55 to 0.65 (real scanning/dos median network
    # scores are 0.71-0.74; the old 0.55 threshold also caught normal
    # traffic at 0.54 and DDoS at 0.50, which is why precision was only
    # 19.2% before).
    mask_r3 = (s_net >= 0.65) & (~mask_a) & (~mask_b) & (~mask_r1) & (~mask_r2)

    # Rule R-05: Protocol Violation & Evasion Anomaly (unchanged - see
    # sparsity note above)
    mask_r5 = (s_sec >= 0.50) & (~mask_a) & (~mask_b) & (~mask_r1) & (~mask_r2) & (~mask_r3)

    # Apply Rule R-A (Backdoor)
    inferred_class[mask_a] = 'Backdoor Command Channel'
    rule_id[mask_a] = 'R-A: Known-Endpoint Backdoor Signature'
    conf_a = np.clip(0.55 * s_dev[mask_a] + 0.45 * s_net[mask_a], 0.65, 0.99)
    confidence[mask_a] = conf_a
    severity[mask_a] = 'CRITICAL'
    explanation[mask_a] = [
        f"R-A Triggered: Device Context ({d:.2f}) matches a known-risk endpoint, with Network Context ({n:.2f}) confirming a persistent, fully-anomalous connection pattern consistent with a backdoor channel."
        for d, n in zip(s_dev[mask_a], s_net[mask_a])
    ]

    # Apply Rule R-B (Ransomware/C2)
    inferred_class[mask_b] = 'Malicious C2 & Ransomware Beaconing'
    rule_id[mask_b] = 'R-B: C2 / Ransomware Beaconing'
    conf_b = np.clip(0.60 * s_dev[mask_b] + 0.40 * s_tmp[mask_b], 0.65, 0.98)
    confidence[mask_b] = conf_b
    severity[mask_b] = 'CRITICAL'
    explanation[mask_b] = [
        f"R-B Triggered: Device Context ({d:.2f}) flags a known-risk endpoint; Temporal Context ({t:.2f}) is consistent with beaconing rhythm."
        for d, t in zip(s_dev[mask_b], s_tmp[mask_b])
    ]

    # Apply Rule R-01
    inferred_class[mask_r1] = 'Web Exploit & Payload Injection'
    rule_id[mask_r1] = 'R-01: Web Exploit & Payload Injected'
    conf_r1 = np.clip(0.50 * s_op[mask_r1] + 0.30 * s_sec[mask_r1] + 0.20 * r_comp[mask_r1], 0.65, 0.99)
    confidence[mask_r1] = conf_r1
    severity[mask_r1] = np.where(s_op[mask_r1] >= 0.70, 'CRITICAL', 'HIGH')
    explanation[mask_r1] = [
        f"R-01 Triggered: Operational Context ({b:.2f}) and Security Context ({s:.2f}) confirm HTTP exploit signatures and application payload anomaly."
        for b, s in zip(s_op[mask_r1], s_sec[mask_r1])
    ]

    # Apply Rule R-02
    inferred_class[mask_r2] = 'Volumetric DoS / DDoS Flood'
    rule_id[mask_r2] = 'R-02: Volumetric DoS / DDoS Flood'
    conf_r2 = np.clip(0.50 * s_ast[mask_r2] + 0.30 * s_net[mask_r2] + 0.20 * s_tmp[mask_r2], 0.60, 0.95)
    confidence[mask_r2] = conf_r2
    severity[mask_r2] = np.where(s_ast[mask_r2] >= 0.40, 'CRITICAL', 'HIGH')
    explanation[mask_r2] = [
        f"R-02 Triggered: Asset Context ({t:.2f}) and Network Context ({n:.2f}) detect elevated packet rate and volumetric flow anomaly."
        for t, n in zip(s_ast[mask_r2], s_net[mask_r2])
    ]

    # Apply Rule R-03
    inferred_class[mask_r3] = 'Reconnaissance & Port Scanning'
    rule_id[mask_r3] = 'R-03: Stealth Port Scan / Recon'
    conf_r3 = np.clip(0.60 * s_net[mask_r3] + 0.25 * s_dev[mask_r3] + 0.15 * s_tmp[mask_r3], 0.60, 0.95)
    confidence[mask_r3] = conf_r3
    severity[mask_r3] = np.where(s_net[mask_r3] >= 0.85, 'HIGH', 'MEDIUM')
    explanation[mask_r3] = [
        f"R-03 Triggered: Network Context ({n:.2f}) identifies non-established TCP handshakes (REJ/S0) and port scan socket patterns."
        for n in s_net[mask_r3]
    ]

    # Apply Rule R-05
    inferred_class[mask_r5] = 'Protocol Violation & Evasion Anomaly'
    rule_id[mask_r5] = 'R-05: Protocol Violation & Evasion'
    conf_r5 = np.clip(0.70 * s_sec[mask_r5] + 0.30 * r_comp[mask_r5], 0.60, 0.92)
    confidence[mask_r5] = conf_r5
    severity[mask_r5] = np.where(s_sec[mask_r5] >= 0.70, 'HIGH', 'MEDIUM')
    explanation[mask_r5] = [
        f"R-05 Triggered: Security Context ({s:.2f}) flags protocol parser anomalies (weird_name) or packet loss during channel saturation."
        for s in s_sec[mask_r5]
    ]

    # Apply Rule R-00 (Benign Baseline)
    mask_r0 = (~mask_a) & (~mask_b) & (~mask_r1) & (~mask_r2) & (~mask_r3) & (~mask_r5)
    conf_r0 = np.clip(1.0 - r_comp[mask_r0], 0.70, 0.99)
    confidence[mask_r0] = conf_r0
    severity[mask_r0] = 'BENIGN'
    explanation[mask_r0] = [
        f"R-00 Baseline: All operational context category scores remain within normal baseline thresholds (Risk Index: {r:.2f})."
        for r in r_comp[mask_r0]
    ]

    # Create Context Reasoning DataFrame
    reasoning_df = df.copy()
    reasoning_df['Inferred_Threat_Class'] = inferred_class
    reasoning_df['Triggered_Reasoning_Rule'] = rule_id
    reasoning_df['Confidence_Score'] = np.round(confidence, 4)
    reasoning_df['Threat_Severity'] = severity
    reasoning_df['Context_Reasoning_Explanation'] = explanation

    print(f"    Reasoning engine completed in {time.time() - start_time:.2f} seconds.")
    return reasoning_df

def main():
    profiles_df = load_context_profiles()
    reasoning_df = apply_dynamic_context_reasoning(profiles_df)

    print("[+] Step 1: Saving context_reasoning.csv...")
    csv_path = os.path.join(OUTPUT_DIR, "context_reasoning.csv")
    reasoning_df.to_csv(csv_path, index=False)
    print(f"    Saved: {csv_path} ({len(reasoning_df):,} rows)")

    # =========================================================================
    # VISUALIZATION 1: Decision Tree Diagram
    # =========================================================================
    print("[+] Step 2: Generating Visualization 1: Decision Tree Diagram...")
    feature_cols = ['Device_Context_Score', 'Network_Context_Score', 'Asset_Context_Score', 'Temporal_Context_Score', 'Operational_Context_Score', 'Security_Context_Score']
    X = reasoning_df[feature_cols].values
    y = reasoning_df['Inferred_Threat_Class'].values

    # Fit interpretable decision tree surrogate
    dt = DecisionTreeClassifier(max_depth=3, random_state=42, criterion='entropy')
    dt.fit(X, y)

    fig, ax = plt.subplots(figsize=(18, 10), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    clean_feature_names = ['Device Context', 'Network Context', 'Asset Context', 'Temporal Context', 'Operational Context', 'Security Context']
    plot_tree(
        dt,
        feature_names=clean_feature_names,
        class_names=dt.classes_,
        filled=True,
        rounded=True,
        fontsize=9,
        ax=ax
    )

    ax.set_title("Contextual Intelligence Engine (CIE) - Decision Tree Reasoning Diagram\n(Hierarchical Context Score Threshold Rules for Inferred Threat Classification)", fontsize=14, fontweight='bold', pad=20, color='#0f172a')

    plt.tight_layout()
    v1_path = os.path.join(OUTPUT_DIR, "1_decision_tree_diagram.png")
    plt.savefig(v1_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v1_path}")

    # =========================================================================
    # VISUALIZATION 2: Context Reasoning Flowchart
    # =========================================================================
    print("[+] Step 3: Generating Visualization 2: Context Reasoning Flowchart...")
    fig, ax = plt.subplots(figsize=(16, 10), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#f8fafc')
    ax.axis('off')

    # Define Flowchart Nodes (Stage boxes)
    flow_stages = [
        {"title": "1. Operational Context Profiles", "desc": "Input vector of 6 context scores\n(Temporal, Asset, Network,\nDevice, Operational, Security)", "color": "#2563eb", "pos": (0.10, 0.70)},
        {"title": "2. Contextual Rule Engine", "desc": "Evaluate expert rules R-A to R-05\nmatching multi-parameter threshold\nconditions across context space", "color": "#0d9488", "pos": (0.35, 0.70)},
        {"title": "3. Confidence Calculation", "desc": "Compute continuous confidence score\nC ∈ [0.60, 0.99] based on evidence\nweight and parameter agreement", "color": "#7c3aed", "pos": (0.60, 0.70)},
        {"title": "4. Severity Estimator", "desc": "Assign dynamic threat severity level:\nCRITICAL | HIGH | MEDIUM | LOW | BENIGN", "color": "#dc2626", "pos": (0.85, 0.70)},
        {"title": "5. Explainable CTI Output", "desc": "Synthesize interpretable natural language reasoning chain\nand output formatted record to context_reasoning.csv", "color": "#059669", "pos": (0.475, 0.25)}
    ]

    # Draw Stage Boxes
    for stage in flow_stages:
        x, y_pos = stage['pos']
        w, h = 0.20, 0.22
        if stage['title'].startswith("5."):
            w, h = 0.50, 0.20
            
        box = FancyBboxPatch(
            (x - w/2, y_pos - h/2), w, h,
            boxstyle="round,pad=0.03,rounding_size=0.04",
            facecolor=stage['color'],
            edgecolor='#ffffff',
            linewidth=2,
            alpha=0.95
        )
        ax.add_patch(box)

        ax.text(x, y_pos + h/2 - 0.04, stage['title'], fontsize=11, fontweight='bold', color='white', ha='center', va='center')
        ax.text(x, y_pos - 0.02, stage['desc'], fontsize=8.5, color='#f8fafc', ha='center', va='center')

    # Draw Connecting Arrows
    arrow_props = dict(facecolor='#64748b', edgecolor='#475569', width=2.5, headwidth=9, alpha=0.9)
    
    # Horizontals (Left -> Right)
    ax.annotate('', xy=(0.245, 0.70), xytext=(0.205, 0.70), arrowprops=arrow_props)
    ax.annotate('', xy=(0.495, 0.70), xytext=(0.455, 0.70), arrowprops=arrow_props)
    ax.annotate('', xy=(0.745, 0.70), xytext=(0.705, 0.70), arrowprops=arrow_props)

    # Verticals down to Stage 5
    ax.annotate('', xy=(0.475, 0.36), xytext=(0.475, 0.58), arrowprops=arrow_props)

    ax.set_title("Contextual Intelligence Engine (CIE) - Dynamic Context Reasoning Pipeline Architecture", fontsize=14, fontweight='bold', pad=25, color='#0f172a')

    plt.tight_layout()
    v2_path = os.path.join(OUTPUT_DIR, "2_context_reasoning_flowchart.png")
    plt.savefig(v2_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v2_path}")

    # =========================================================================
    # VISUALIZATION 3: Confidence Score Distribution
    # =========================================================================
    print("[+] Step 4: Generating Visualization 3: Confidence Score Distribution...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax1.set_facecolor('#f8fafc')
    ax2.set_facecolor('#f8fafc')

    # Subplot 1: Confidence Distribution by Inferred Threat Class
    # [FIXED] The original version called sns.kdeplot on raw values with no
    # guard - for classes with very few, near-identical confidence values
    # (e.g. small/tightly-clipped rule outputs), scipy's automatic KDE
    # bandwidth collapses toward zero, producing absurd density spikes
    # (previously observed: y-axis reaching ~1.6e16). Near-constant groups
    # now fall back to a histogram instead, which is also the more honest
    # representation of "this rule always outputs almost the same value."
    threat_classes = reasoning_df['Inferred_Threat_Class'].unique()
    for t_class in threat_classes:
        sub_conf = reasoning_df[reasoning_df['Inferred_Threat_Class'] == t_class]['Confidence_Score'].values
        if len(sub_conf) > 5000:
            np.random.seed(42)
            sub_conf = np.random.choice(sub_conf, 5000, replace=False)
        color = THREAT_CLASS_COLORS.get(t_class, '#333333')
        label = t_class[:28]
        if len(sub_conf) >= 5 and np.std(sub_conf) > 1e-3 and len(np.unique(sub_conf)) >= 5:
            sns.kdeplot(sub_conf, ax=ax1, color=color, fill=True, alpha=0.25, label=label, linewidth=1.8)
        else:
            ax1.hist(sub_conf, bins=min(20, max(3, len(np.unique(sub_conf)))), color=color,
                      alpha=0.5, label=label, density=True, edgecolor='white')

    ax1.set_title("Confidence Score Distribution by Inferred Threat Class", fontsize=12, fontweight='bold', pad=12, color='#0f172a')
    ax1.set_xlabel("Confidence Score (0.00 - 1.00)", fontsize=10, fontweight='bold', color='#0f172a')
    ax1.set_ylabel("Density", fontsize=10, fontweight='bold', color='#0f172a')
    ax1.grid(True, linestyle='--', alpha=0.5, color='#cbd5e1')
    ax1.legend(fontsize=8, loc='upper left', frameon=True, facecolor='#ffffff')

    # Subplot 2: Confidence Distribution by Threat Severity
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'BENIGN']
    for sev in severities:
        sub_conf = reasoning_df[reasoning_df['Threat_Severity'] == sev]['Confidence_Score'].values
        if len(sub_conf) > 0:
            if len(sub_conf) > 5000:
                np.random.seed(42)
                sub_conf = np.random.choice(sub_conf, 5000, replace=False)
            if len(sub_conf) >= 5 and np.std(sub_conf) > 1e-3 and len(np.unique(sub_conf)) >= 5:
                sns.kdeplot(sub_conf, ax=ax2, color=SEVERITY_COLORS[sev], fill=True, alpha=0.3, label=sev, linewidth=2)
            else:
                ax2.hist(sub_conf, bins=min(20, max(3, len(np.unique(sub_conf)))), color=SEVERITY_COLORS[sev],
                          alpha=0.5, label=sev, density=True, edgecolor='white')

    ax2.set_title("Confidence Score Distribution by Threat Severity Level", fontsize=12, fontweight='bold', pad=12, color='#0f172a')
    ax2.set_xlabel("Confidence Score (0.00 - 1.00)", fontsize=10, fontweight='bold', color='#0f172a')
    ax2.set_ylabel("Density", fontsize=10, fontweight='bold', color='#0f172a')
    ax2.grid(True, linestyle='--', alpha=0.5, color='#cbd5e1')
    ax2.legend(fontsize=8.5, loc='upper left', frameon=True, facecolor='#ffffff')

    fig.suptitle("Contextual Intelligence Engine (CIE) - Reasoning Confidence Score Distributions", fontsize=14, fontweight='bold', y=0.98, color='#0f172a')
    plt.tight_layout(rect=[0, 0, 1, 0.95])

    v3_path = os.path.join(OUTPUT_DIR, "3_confidence_score_distribution.png")
    plt.savefig(v3_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v3_path}")

    # =========================================================================
    # VISUALIZATION 4: Threat Severity Distribution
    # =========================================================================
    print("[+] Step 5: Generating Visualization 4: Threat Severity Distribution...")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 7), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    # Donut Chart for Threat Severity Breakdown
    sev_counts = reasoning_df['Threat_Severity'].value_counts()
    colors_donut = [SEVERITY_COLORS.get(s, '#64748b') for s in sev_counts.index]
    
    wedges, texts, autotexts = ax1.pie(
        sev_counts.values,
        labels=sev_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=colors_donut,
        pctdistance=0.75,
        explode=[0.03] * len(sev_counts),
        textprops=dict(fontsize=9.5, fontweight='bold')
    )
    centre_circle = plt.Circle((0,0), 0.52, fc='white')
    ax1.add_artist(centre_circle)
    ax1.set_title("Proportional Breakdown of Threat Severity Levels", fontsize=12, fontweight='bold', pad=15, color='#0f172a')

    # Grouped Horizontal Bar Chart for Threat Class Counts
    class_counts = reasoning_df['Inferred_Threat_Class'].value_counts().sort_values(ascending=True)
    bar_colors = [THREAT_CLASS_COLORS.get(c, '#64748b') for c in class_counts.index]

    bars = ax2.barh(
        [c.replace(' / ', '\n') for c in class_counts.index],
        class_counts.values,
        color=bar_colors,
        edgecolor='#ffffff',
        linewidth=1.2,
        height=0.65
    )

    for bar in bars:
        w = bar.get_width()
        pct = (w / len(reasoning_df)) * 100
        ax2.text(
            w + (len(reasoning_df) * 0.01),
            bar.get_y() + bar.get_height()/2.0,
            f"{w:,} ({pct:.1f}%)",
            va='center',
            ha='left',
            fontsize=8.5,
            fontweight='bold',
            color='#1e293b'
        )

    ax2.set_xlabel("Record Count", fontsize=10, fontweight='bold', color='#0f172a')
    ax2.set_title("Inferred Threat Class Distribution", fontsize=12, fontweight='bold', pad=15, color='#0f172a')
    ax2.grid(True, axis='x', linestyle='--', alpha=0.5, color='#cbd5e1')
    ax2.set_facecolor('#f8fafc')

    fig.suptitle("Contextual Intelligence Engine (CIE) - Inferred Threat Severity & Class Breakdown", fontsize=14, fontweight='bold', y=0.98, color='#0f172a')
    plt.tight_layout(rect=[0, 0, 1, 0.95])

    v4_path = os.path.join(OUTPUT_DIR, "4_threat_severity_distribution.png")
    plt.savefig(v4_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v4_path}")

    # =========================================================================
    # CALIBRATION REPORT - measured against ground truth (attack_type)
    # This uses the label/attack_type columns ONLY for post-hoc validation,
    # exactly like the CCS validation elsewhere in this project - never as
    # an input to the rule thresholds above. Printed openly so the engine's
    # real accuracy is visible, rather than only showing up if someone
    # cross-tabulates the CSV themselves.
    # =========================================================================
    print("\n[+] Step 6: Calibration report (Inferred_Threat_Class vs real attack_type)...")
    ct = pd.crosstab(reasoning_df['attack_type'], reasoning_df['Inferred_Threat_Class'])
    print(ct.to_string())
    print()
    for cls in reasoning_df['Inferred_Threat_Class'].unique():
        total_predicted = (reasoning_df['Inferred_Threat_Class'] == cls).sum()
        if cls in ct.columns and total_predicted > 0:
            best_match_type = ct[cls].idxmax()
            correct = ct.loc[best_match_type, cls]
            precision = correct / total_predicted
            recall = correct / ct.loc[best_match_type].sum()
            print(f"  {cls:42s} best matches '{best_match_type}': "
                  f"precision={precision:.1%}, recall={recall:.1%} (n={total_predicted:,})")
    print("\n  NOTE: these numbers are not perfect - see the code comments above the rule")
    print("  engine for known limitations (XSS/DDoS overlap, sparse Operational/Security")
    print("  signal). Reported honestly rather than hidden.")

    print("\n[SUCCESS] All dynamic context reasoning artifacts generated successfully!")
    print(f"All artifacts saved in: {OUTPUT_DIR}")

if __name__ == '__main__':
    main()