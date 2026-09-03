"""
generate_context_parameters.py
================================
Dynamic Contextual Parameter Definition and Visualization Script
for the Contextual Intelligence Engine (CIE).

Generates:
1. results/context_parameters/context_parameters.csv
2. results/context_parameters/1_parameter_importance_bar_chart.png
3. results/context_parameters/2_parameter_dependency_network.png
4. results/context_parameters/4_context_parameter_matrix.png
   (numbered "4" - visualization "3" was removed; it plotted fabricated
   synthetic data with no real basis in the dataset)
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import networkx as nx

# Define output path
OUTPUT_DIR = r"c:\Users\aksha\Downloads\Final Year Project\datasets\results\context_parameters"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set global matplotlib parameters for publication quality aesthetics
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#cbd5e1'
plt.rcParams['axes.linewidth'] = 1.0

# Context category color palette
CATEGORY_COLORS = {
    'Device Context': '#2563eb',       # Vibrant Blue
    'Network Context': '#0d9488',      # Teal
    'Asset Context': '#d97706',        # Amber
    'Temporal Context': '#7c3aed',     # Purple
    'Security Context': '#dc2626',     # Red
    'Operational Context': '#059669',  # Emerald Green
}

# 18 Dynamic Contextual Parameters Definition
PARAMETERS_DATA = [
    {
        'Parameter Name': 'Host Endpoint Reputation Score',
        'Related Dataset Features': 'src_ip, dst_ip',
        'Description': 'Quantifies historical host threat activity level, endpoint centrality, and involvement in malicious traffic flows.',
        'Context Category': 'Device Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.88,
        'Influence on Threat Detection': 'Directly elevates risk priority when known compromised endpoints or command-and-control (C2) hosts are active.',
        'Influence on Contextual Intelligence': 'Provides persistent device identity state to adjust baseline anomaly thresholds per endpoint.'
    },
    {
        'Parameter Name': 'SSL Certificate Trust Index',
        'Related Dataset Features': 'ssl_subject, ssl_issuer',
        'Description': 'Evaluates X.509 certificate authenticity, Certificate Authority (CA) reputation, self-signed status, and subject mismatch.',
        'Context Category': 'Device Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.78,
        'Influence on Threat Detection': 'Flags spoofed SSL certificates, self-signed C2 channels, and rogue internal servers.',
        'Influence on Contextual Intelligence': 'Establishes cryptographic identity verification score for encrypted sessions.'
    },
    {
        'Parameter Name': 'Socket Randomization & Port Entropy',
        'Related Dataset Features': 'src_port, dst_port',
        'Description': 'Measures ephemeral port usage randomness, port scanning frequency, and non-standard socket allocations.',
        'Context Category': 'Network Context',
        'Expected Value Range': '0.00 - 5.00',
        'Importance Weight': 0.75,
        'Influence on Threat Detection': 'Detects high-velocity port sweeps, automated vulnerability scanning, and custom C2 listening ports.',
        'Influence on Contextual Intelligence': 'Characterizes transport layer connection patterns and ephemeral socket dynamics.'
    },
    {
        'Parameter Name': 'Service Target Vulnerability Index',
        'Related Dataset Features': 'dst_port, service, proto',
        'Description': 'Maps targeted transport/application services to known CVE exploit sensitivity and critical service exposure.',
        'Context Category': 'Network Context',
        'Expected Value Range': '0.00 - 10.00',
        'Importance Weight': 0.85,
        'Influence on Threat Detection': 'Prioritizes exploits targeted at high-value exposed services (e.g. SSH, HTTP, RDP, DNS).',
        'Influence on Contextual Intelligence': 'Contextualizes target asset criticality and potential exploit impact.'
    },
    {
        'Parameter Name': 'TCP Handshake Anomaly Rate',
        'Related Dataset Features': 'conn_state, proto',
        'Description': 'Tracks non-established, rejected, or aborted TCP handshake flags (S0, REJ, RSTO, RSTOS0) relative to normal state (SF).',
        'Context Category': 'Network Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.90,
        'Influence on Threat Detection': 'Primary indicator for SYN flooding DDoS, half-open port probes, and firewall connection drops.',
        'Influence on Contextual Intelligence': 'Supplies stateful transport health metrics to distinguish network congestion from active attacks.'
    },
    {
        'Parameter Name': 'Flow Duration Anomaly Ratio',
        'Related Dataset Features': 'duration',
        'Description': 'Evaluates connection duration deviations against standard protocol and service baseline distributions.',
        'Context Category': 'Asset Context',
        'Expected Value Range': '0.00 - 100.00',
        'Importance Weight': 0.80,
        'Influence on Threat Detection': 'Identifies ultra-short reconnaissance probes and persistent long-lived C2 interactive beaconing sessions.',
        'Influence on Contextual Intelligence': 'Adds temporal lifespan context to correlate transient spikes vs persistent threats.'
    },
    {
        'Parameter Name': 'Traffic Asymmetry & Volumetric Ratio',
        'Related Dataset Features': 'src_bytes, dst_bytes, src_ip_bytes, dst_ip_bytes',
        'Description': 'Quantifies directional upload vs download byte imbalances (src_bytes / (src_bytes + dst_bytes)).',
        'Context Category': 'Asset Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.88,
        'Influence on Threat Detection': 'High ratio indicates data exfiltration or outbound DDoS flooding; low ratio indicates large payload downloads.',
        'Influence on Contextual Intelligence': 'Profiles flow asymmetry to distinguish interactive web browsing from automated exfiltration.'
    },
    {
        'Parameter Name': 'Packet Burst Intensity Score',
        'Related Dataset Features': 'src_pkts, dst_pkts, duration',
        'Description': 'Calculates instantaneous packet transfer rates (packets per second) across source and destination endpoints.',
        'Context Category': 'Asset Context',
        'Expected Value Range': '0.00 - 10000.00',
        'Importance Weight': 0.86,
        'Influence on Threat Detection': 'Detects high-density volumetric packet floods, DDoS attacks, and aggressive brute-force attempts.',
        'Influence on Contextual Intelligence': 'Measures volumetric pressure on network interfaces and edge processing capacity.'
    },
    {
        'Parameter Name': 'HTTP Payload Exfiltration Density',
        'Related Dataset Features': 'http_request_body_len, http_response_body_len, src_bytes, dst_bytes',
        'Description': 'Measures ratio of HTTP body payload bytes relative to total application layer bytes transferred.',
        'Context Category': 'Asset Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.82,
        'Influence on Threat Detection': 'Flags hidden web webshell uploads, SQL injection payload injections, and file exfiltration over HTTP POST.',
        'Influence on Contextual Intelligence': 'Separates HTTP header overhead from actual application content payload size.'
    },
    {
        'Parameter Name': 'Event Inter-Arrival Velocity',
        'Related Dataset Features': 'ts',
        'Description': 'Computes delta time between consecutive event initiation timestamps for a specific source IP or subnet.',
        'Context Category': 'Temporal Context',
        'Expected Value Range': '0.0001 - 3600.00',
        'Importance Weight': 0.84,
        'Influence on Threat Detection': 'Extremely low inter-arrival times indicate automated botnet attacks; fixed periodic intervals indicate automated C2 beaconing.',
        'Influence on Contextual Intelligence': 'Provides high-precision temporal rhythm and cadence profiling across host event streams.'
    },
    {
        'Parameter Name': 'Zeek Protocol Violation Score',
        'Related Dataset Features': 'weird_name, weird_notice, weird_addl',
        'Description': 'Aggregates Zeek protocol parser anomalies, malformed headers, and security notice flags into a severity score.',
        'Context Category': 'Security Context',
        'Expected Value Range': '0.00 - 10.00',
        'Importance Weight': 0.92,
        'Influence on Threat Detection': 'Directly alerts on protocol abuse, illegal header structures, and zero-day protocol evasion techniques.',
        'Influence on Contextual Intelligence': 'Highlights underlying network protocol stack non-compliance and monitor parsing errors.'
    },
    {
        'Parameter Name': 'Packet Loss & Channel Saturation Rate',
        'Related Dataset Features': 'missed_bytes, src_bytes, dst_bytes',
        'Description': 'Calculates the percentage of dropped or uncaptured bytes relative to total flow bytes.',
        'Context Category': 'Security Context',
        'Expected Value Range': '0.00 - 100.00',
        'Importance Weight': 0.72,
        'Influence on Threat Detection': 'Detects network sensor overload, TAP buffer overruns during DDoS, and intentional TCP evasion drops.',
        'Influence on Contextual Intelligence': 'Assesses sensor data fidelity and measurement confidence during high-traffic events.'
    },
    {
        'Parameter Name': 'Cryptographic Security Weakness Index',
        'Related Dataset Features': 'ssl_version, ssl_cipher, ssl_established, ssl_resumed',
        'Description': 'Evaluates TLS/SSL cipher suite security, handshake completion status, and protocol version vulnerability.',
        'Context Category': 'Security Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.87,
        'Influence on Threat Detection': 'Identifies SSL/TLS handshake failures, downgrade attacks, and weak cipher usage.',
        'Influence on Contextual Intelligence': 'Tracks enterprise encryption compliance and identifies unencrypted or weakly encrypted channels.'
    },
    {
        'Parameter Name': 'Domain Generation Algorithm (DGA) Score',
        'Related Dataset Features': 'dns_query, dns_rcode',
        'Description': 'Analyzes character randomness, n-gram entropy, length, and NXDOMAIN response rates of queried domain names.',
        'Context Category': 'Operational Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.91,
        'Influence on Threat Detection': 'Detects dynamically generated C2 domain lookups used by malware and ransomware families.',
        'Influence on Contextual Intelligence': 'Profiles DNS resolution intent and identifies algorithmically generated domain patterns.'
    },
    {
        'Parameter Name': 'DNS Tunneling & Payload Intensity',
        'Related Dataset Features': 'dns_qtype, dns_qclass, dns_AA, dns_RD, dns_RA',
        'Description': 'Tracks unusual DNS query record types (TXT, NULL, CNAME) and payload size within DNS request/response records.',
        'Context Category': 'Operational Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.83,
        'Influence on Threat Detection': 'Uncovers covert data exfiltration and C2 command channels hidden inside DNS queries.',
        'Influence on Contextual Intelligence': 'Contextualizes non-standard DNS usage beyond typical A/AAAA web resolution.'
    },
    {
        'Parameter Name': 'Web Exploit Payload Threat Index',
        'Related Dataset Features': 'http_method, http_uri, http_orig_mime_types, http_resp_mime_types',
        'Description': 'Scans HTTP URI parameters, methods, and MIME types for web exploit signatures (SQLi, XSS, Path Traversal).',
        'Context Category': 'Operational Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.95,
        'Influence on Threat Detection': 'Immediate detection of web application attacks, web shell injections, and unauthorized command execution.',
        'Influence on Contextual Intelligence': 'Decodes application-level user intent and malicious input parameter strings.'
    },
    {
        'Parameter Name': 'HTTP Application Anomaly Status Score',
        'Related Dataset Features': 'http_status_code, http_trans_depth, http_version',
        'Description': 'Evaluates distribution of HTTP response status codes and pipelining depth.',
        'Context Category': 'Operational Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.79,
        'Influence on Threat Detection': 'High 404 rates indicate automated web directory fuzzing; high 500 errors signal successful application exploitation.',
        'Influence on Contextual Intelligence': 'Reflects server-side execution outcomes and application stability under attack.'
    },
    {
        'Parameter Name': 'Scanner User-Agent Threat Index',
        'Related Dataset Features': 'http_user_agent',
        'Description': 'Matches client User-Agent strings against signatures of vulnerability scanners, automated bots, and web scraping scripts.',
        'Context Category': 'Operational Context',
        'Expected Value Range': '0.00 - 1.00',
        'Importance Weight': 0.86,
        'Influence on Threat Detection': 'Detects automated recon tools (Nikto, Sqlmap, Nmap, Zgrab, Masscan, Metasploit).',
        'Influence on Contextual Intelligence': 'Establishes environmental context of client software stack and execution context.'
    }
]

def main():
    print("[+] Step 1: Creating context_parameters.csv...")
    df = pd.DataFrame(PARAMETERS_DATA)
    csv_path = os.path.join(OUTPUT_DIR, "context_parameters.csv")
    df.to_csv(csv_path, index=False)
    print(f"    Saved: {csv_path}")

    # =========================================================================
    # VISUALIZATION 1: Parameter Importance Bar Chart
    # =========================================================================
    print("[+] Step 2: Generating Visualization 1: Parameter Importance Bar Chart...")
    df_sorted = df.sort_values(by='Importance Weight', ascending=True)

    fig, ax = plt.subplots(figsize=(13, 9), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#f8fafc')

    bars = ax.barh(
        df_sorted['Parameter Name'],
        df_sorted['Importance Weight'],
        color=[CATEGORY_COLORS[cat] for cat in df_sorted['Context Category']],
        edgecolor='#ffffff',
        linewidth=1.2,
        height=0.7
    )

    # Add numeric labels to bars
    for bar in bars:
        w = bar.get_width()
        ax.text(
            w + 0.008,
            bar.get_y() + bar.get_height()/2.0,
            f"{w:.2f}",
            va='center',
            ha='left',
            fontsize=9.5,
            fontweight='bold',
            color='#1e293b'
        )

    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Importance Weight (0.0 - 1.0)", fontsize=11, fontweight='bold', labelpad=10, color='#0f172a')
    ax.set_title("Contextual Intelligence Engine (CIE) - Dynamic Parameter Importance Weights", fontsize=14, fontweight='bold', pad=18, color='#0f172a')
    ax.grid(True, axis='x', linestyle='--', alpha=0.5, color='#cbd5e1')
    ax.set_axisbelow(True)

    # Add Category Legend
    legend_patches = [mpatches.Patch(color=color, label=cat) for cat, color in CATEGORY_COLORS.items()]
    ax.legend(handles=legend_patches, title="Context Category", loc='lower right', frameon=True, facecolor='#ffffff', edgecolor='#cbd5e1', fontsize=9, title_fontsize=10)

    plt.tight_layout()
    v1_path = os.path.join(OUTPUT_DIR, "1_parameter_importance_bar_chart.png")
    plt.savefig(v1_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v1_path}")

    # =========================================================================
    # VISUALIZATION 2: Parameter Dependency Network
    # =========================================================================
    print("[+] Step 3: Generating Visualization 2: Parameter Dependency Network...")
    G = nx.DiGraph()

    # Build multi-layer dependency graph: Category -> Parameter -> Dataset Feature
    categories = list(set(df['Context Category']))
    for cat in categories:
        G.add_node(cat, node_type='category', label=cat)

    for idx, row in df.iterrows():
        param_name = row['Parameter Name']
        cat = row['Context Category']
        features = [f.strip() for f in row['Related Dataset Features'].split(',')]
        
        G.add_node(param_name, node_type='parameter', category=cat, label=param_name)
        G.add_edge(cat, param_name, edge_type='cat_to_param')

        for feat in features:
            if feat not in G:
                G.add_node(feat, node_type='feature', label=feat)
            G.add_edge(param_name, feat, edge_type='param_to_feat')

    # Position layout (Multipartite column-wise positioning)
    pos = {}
    
    # Layer 1: Context Categories (x = 0)
    cat_list = sorted(categories)
    for i, cat in enumerate(cat_list):
        pos[cat] = np.array([0.0, (len(cat_list) - 1 - i) * 2.5])

    # Layer 2: Dynamic Parameters (x = 2.5)
    param_list = list(df['Parameter Name'])
    for i, p in enumerate(param_list):
        pos[p] = np.array([2.5, (len(param_list) - 1 - i) * 1.0])

    # Layer 3: Features (x = 5.0)
    feature_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'feature']
    feature_list = sorted(feature_nodes)
    for i, f in enumerate(feature_list):
        pos[f] = np.array([5.0, (len(feature_list) - 1 - i) * 0.65])

    fig, ax = plt.subplots(figsize=(18, 14), dpi=300)
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#f8fafc')

    # Draw edges
    cat_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('edge_type') == 'cat_to_param']
    feat_edges = [(u, v) for u, v, d in G.edges(data=True) if d.get('edge_type') == 'param_to_feat']

    nx.draw_networkx_edges(G, pos, edgelist=cat_edges, edge_color='#64748b', alpha=0.6, width=1.5, arrows=True, arrowsize=10, ax=ax)
    nx.draw_networkx_edges(G, pos, edgelist=feat_edges, edge_color='#94a3b8', alpha=0.4, width=1.0, arrows=True, arrowsize=8, ax=ax)

    # Draw Category Nodes
    cat_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'category']
    nx.draw_networkx_nodes(G, pos, nodelist=cat_nodes, node_size=2800, node_color=[CATEGORY_COLORS[c] for c in cat_nodes], edgecolors='#1e293b', linewidths=2, ax=ax)
    cat_labels = {n: n.replace(' ', '\n') for n in cat_nodes}
    nx.draw_networkx_labels(G, pos, labels=cat_labels, font_size=9, font_weight='bold', font_color='white', ax=ax)

    # Draw Parameter Nodes
    param_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'parameter']
    param_colors = [CATEGORY_COLORS[G.nodes[n]['category']] for n in param_nodes]
    nx.draw_networkx_nodes(G, pos, nodelist=param_nodes, node_size=1200, node_color=param_colors, edgecolors='#ffffff', linewidths=1.5, alpha=0.9, ax=ax)
    param_labels = {n: n for n in param_nodes}
    # Offset parameter labels slightly for readability
    pos_param_labels = {k: (v[0] + 0.12, v[1]) for k, v in pos.items() if k in param_nodes}
    nx.draw_networkx_labels(G, pos_param_labels, labels=param_labels, font_size=8, font_weight='bold', font_color='#0f172a', horizontalalignment='left', ax=ax)

    # Draw Feature Nodes
    feat_nodes = [n for n, d in G.nodes(data=True) if d.get('node_type') == 'feature']
    nx.draw_networkx_nodes(G, pos, nodelist=feat_nodes, node_size=500, node_color='#cbd5e1', edgecolors='#475569', linewidths=1, ax=ax)
    pos_feat_labels = {k: (v[0] + 0.1, v[1]) for k, v in pos.items() if k in feat_nodes}
    feat_labels = {n: n for n in feat_nodes}
    nx.draw_networkx_labels(G, pos_feat_labels, labels=feat_labels, font_size=7.5, font_color='#334155', horizontalalignment='left', ax=ax)

    ax.set_xlim(-0.6, 6.5)
    ax.set_title("Contextual Intelligence Engine (CIE) - Parameter Dependency Network\n(Category Hubs → Dynamic Context Parameters → Dataset Features)", fontsize=15, fontweight='bold', pad=20, color='#0f172a')
    ax.axis('off')

    plt.tight_layout()
    v2_path = os.path.join(OUTPUT_DIR, "2_parameter_dependency_network.png")
    plt.savefig(v2_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v2_path}")

    # =========================================================================
    # VISUALIZATION 3: REMOVED
    # =========================================================================
    # The previous version of this visualization generated entirely
    # synthetic data via np.random (beta/exponential/normal distributions)
    # and labeled it "Normal Operational Baseline vs Malicious Threat
    # Distribution" with no indication it was fabricated. It has been
    # removed rather than kept, since this parameter-definition script has
    # no real per-record data to plot a genuine distribution from - that
    # data lives in context_profiles.csv / context_reasoning.csv instead.
    # If a distribution view of real parameter behavior is needed, build it
    # from those files' actual columns, not from invented data here.

    # =========================================================================
    # VISUALIZATION 4: Context Parameter Matrix
    # =========================================================================
    print("[+] Step 5: Generating Visualization 4: Context Parameter Matrix...")
    # Build a cross-impact and category contribution matrix for all 18 parameters
    matrix_data = []
    cat_keys = list(CATEGORY_COLORS.keys())

    for idx, row in df.iterrows():
        p_cat = row['Context Category']
        imp_weight = row['Importance Weight']
        
        # Calculate feature count
        feat_count = len([f.strip() for f in row['Related Dataset Features'].split(',')])

        # Assign category affinity score
        cat_scores = []
        for ck in cat_keys:
            if ck == p_cat:
                cat_scores.append(round(imp_weight, 2))
            else:
                cat_scores.append(0.0)

        # Additional analytical scores
        threat_inf = round(imp_weight * 0.95, 2)
        context_inf = round(imp_weight * 0.90, 2)

        matrix_data.append([row['Parameter Name']] + cat_scores + [threat_inf, context_inf, feat_count])

    matrix_cols = ['Parameter Name'] + [c.replace(' Context', '') for c in cat_keys] + ['Threat Detection Inf', 'Context Intelligence Inf', 'Feature Count']
    matrix_df = pd.DataFrame(matrix_data, columns=matrix_cols)
    matrix_df.set_index('Parameter Name', inplace=True)

    fig, ax = plt.subplots(figsize=(14, 10), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    # Draw Heatmap
    sns.heatmap(
        matrix_df.iloc[:, :-1],
        annot=True,
        fmt='.2f',
        cmap='YlGnBu',
        linewidths=0.8,
        linecolor='#ffffff',
        cbar_kws={'label': 'Context Contribution & Influence Score'},
        ax=ax
    )

    ax.set_title("Contextual Intelligence Engine (CIE) - Context Parameter Impact & Category Matrix", fontsize=14, fontweight='bold', pad=18, color='#0f172a')
    ax.set_ylabel("Dynamic Context Parameters", fontsize=11, fontweight='bold', color='#0f172a')
    ax.set_xlabel("Context Categories & Intelligence Influence Dimensions", fontsize=11, fontweight='bold', color='#0f172a')
    plt.xticks(rotation=30, ha='right', fontsize=9.5, fontweight='bold')
    plt.yticks(fontsize=9)

    plt.tight_layout()
    v4_path = os.path.join(OUTPUT_DIR, "4_context_parameter_matrix.png")
    plt.savefig(v4_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"    Saved: {v4_path}")

    print("\n[SUCCESS] All dynamic contextual parameters and visualizations generated successfully!")
    print(f"All artifacts saved in: {OUTPUT_DIR}")

if __name__ == '__main__':
    main()