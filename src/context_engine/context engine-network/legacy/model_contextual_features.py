"""
model_contextual_features.py
=============================
Contextual Intelligence Engine (CIE) Feature Modeling Script.

Analyzes the recommended Processed Network Dataset (Network_dataset_*.csv / train_test_network.csv),
maps all 45 features into 7 Context Categories:
- Device Context
- Network Context
- Traffic Context
- Temporal Context
- Security Context
- Behavioral Context
- Environmental Context

Generates:
1. results/context_modeling/contextual_feature_mapping.csv
2. results/context_modeling/contextual_feature_report.pdf
3. 4 publication-quality visualizations saved in results/context_modeling/
"""

import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages

# Define the complete 45 feature contextual mapping dictionary
FEATURE_CONTEXT_MAP = [
    # Device Context
    {
        'Feature_Name': 'src_ip',
        'Context_Category': 'Device Context',
        'Description': 'Source IP address of the initiating network endpoint.',
        'Category_Justification': 'Identifies the initiating host device in the network topology.',
        'Nature': 'Static (per flow)',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: Essential for origin host tracking and identifying compromised IoT devices.'
    },
    {
        'Feature_Name': 'dst_ip',
        'Context_Category': 'Device Context',
        'Description': 'Destination IP address of the targeted network endpoint.',
        'Category_Justification': 'Identifies the targeted server or destination IoT node.',
        'Nature': 'Static (per flow)',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: Critical for identifying targeted assets and infrastructure impact.'
    },
    {
        'Feature_Name': 'ssl_subject',
        'Context_Category': 'Device Context',
        'Description': 'X.509 SSL certificate subject identity name.',
        'Category_Justification': 'Establishes the identity of the domain or host presenting the certificate.',
        'Nature': 'Static (per cert)',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Indirect: Helps verify server identity and detect fraudulent SSL certificates.'
    },
    {
        'Feature_Name': 'ssl_issuer',
        'Context_Category': 'Device Context',
        'Description': 'X.509 SSL certificate issuer Certificate Authority (CA) name.',
        'Category_Justification': 'Identifies the issuing authority validating the host identity.',
        'Nature': 'Static (per cert)',
        'Importance_Score': 7.5,
        'CTI_Contribution': 'Indirect: Useful for detecting self-signed or untrusted certificate authorities.'
    },

    # Network Context
    {
        'Feature_Name': 'src_port',
        'Context_Category': 'Network Context',
        'Description': 'Source transport-layer port number.',
        'Category_Justification': 'Defines the ephemeral source socket port for the transport connection.',
        'Nature': 'Dynamic',
        'Importance_Score': 7.5,
        'CTI_Contribution': 'Indirect: Helps track socket reuse and source port randomization patterns.'
    },
    {
        'Feature_Name': 'dst_port',
        'Context_Category': 'Network Context',
        'Description': 'Destination transport-layer port number.',
        'Category_Justification': 'Defines the targeted service port (e.g. 80=HTTP, 53=DNS, 22=SSH).',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Essential for pinpointing targeted network services and port scans.'
    },
    {
        'Feature_Name': 'proto',
        'Context_Category': 'Network Context',
        'Description': 'Transport-layer network protocol (e.g. TCP, UDP, ICMP).',
        'Category_Justification': 'Determines the fundamental transport protocol mechanism.',
        'Nature': 'Static (per flow)',
        'Importance_Score': 9.5,
        'CTI_Contribution': 'Direct: Governs stateful vs. stateless analysis and attack classification.'
    },
    {
        'Feature_Name': 'service',
        'Context_Category': 'Network Context',
        'Description': 'Application-layer service protocol (e.g. http, dns, ssl, ftp).',
        'Category_Justification': 'Identifies the application protocol handling payload traffic.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: Crucial for applying application-specific threat detection rules.'
    },
    {
        'Feature_Name': 'conn_state',
        'Context_Category': 'Network Context',
        'Description': 'Zeek TCP connection state flag (e.g. SF, S0, REJ, RSTO).',
        'Category_Justification': 'Reflects the transport handshake state and completion status.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.5,
        'CTI_Contribution': 'Direct: High indicator for TCP SYN floods (S0) and port scans (REJ).'
    },

    # Traffic Context
    {
        'Feature_Name': 'duration',
        'Context_Category': 'Traffic Context',
        'Description': 'Connection flow duration in seconds.',
        'Category_Justification': 'Measures the temporal lifespan of the network connection.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Distinguishes persistent backdoor C2 sessions from short scan probes.'
    },
    {
        'Feature_Name': 'src_bytes',
        'Context_Category': 'Traffic Context',
        'Description': 'Payload bytes transmitted from source to destination.',
        'Category_Justification': 'Quantifies payload volume sent by the flow initiator.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: Key metric for detecting data exfiltration and injection payload size.'
    },
    {
        'Feature_Name': 'dst_bytes',
        'Context_Category': 'Traffic Context',
        'Description': 'Payload bytes transmitted from destination to source.',
        'Category_Justification': 'Quantifies payload volume returned by the server.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: Critical for identifying large file downloads and exfiltration responses.'
    },
    {
        'Feature_Name': 'src_pkts',
        'Context_Category': 'Traffic Context',
        'Description': 'Number of network packets sent from source to destination.',
        'Category_Justification': 'Measures packet-level activity volume from the initiator.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Essential metric for identifying high-rate packet flooding attacks.'
    },
    {
        'Feature_Name': 'dst_pkts',
        'Context_Category': 'Traffic Context',
        'Description': 'Number of network packets sent from destination to source.',
        'Category_Justification': 'Measures packet-level response volume from the server.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Differentiates interactive sessions from non-responsive probes.'
    },
    {
        'Feature_Name': 'src_ip_bytes',
        'Context_Category': 'Traffic Context',
        'Description': 'IP layer bytes sent from source (includes IP header bytes).',
        'Category_Justification': 'Measures total raw IP layer bandwidth consumed by source.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Indirect: Provides exact network layer bandwidth utilization.'
    },
    {
        'Feature_Name': 'dst_ip_bytes',
        'Context_Category': 'Traffic Context',
        'Description': 'IP layer bytes sent from destination (includes IP headers).',
        'Category_Justification': 'Measures total raw IP layer bandwidth consumed by destination.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Indirect: Evaluates total network bandwidth response volume.'
    },
    {
        'Feature_Name': 'http_request_body_len',
        'Context_Category': 'Traffic Context',
        'Description': 'Actual length of HTTP POST/PUT request body in bytes.',
        'Category_Justification': 'Measures HTTP application payload upload size.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Direct: Detects large HTTP payload uploads and SQL injection vectors.'
    },
    {
        'Feature_Name': 'http_response_body_len',
        'Context_Category': 'Traffic Context',
        'Description': 'Actual length of HTTP response body in bytes.',
        'Category_Justification': 'Measures HTTP application payload download size.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Direct: Identifies web page leakage and data exfiltration payloads.'
    },

    # Temporal Context
    {
        'Feature_Name': 'ts',
        'Context_Category': 'Temporal Context',
        'Description': 'Unix epoch timestamp of flow initiation.',
        'Category_Justification': 'Establishes absolute chronological time for event sequencing.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Crucial for event correlation, inter-arrival gaps, and burst rates.'
    },

    # Security Context
    {
        'Feature_Name': 'weird_name',
        'Context_Category': 'Security Context',
        'Description': 'Zeek network protocol anomaly or violation identifier name.',
        'Category_Justification': 'Explicit security anomaly flag logged by network monitor.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.5,
        'CTI_Contribution': 'Direct: Immediate indicator of malformed headers or protocol abuse.'
    },
    {
        'Feature_Name': 'weird_notice',
        'Context_Category': 'Security Context',
        'Description': 'Zeek security notice level flag for protocol anomalies.',
        'Category_Justification': 'Categorizes protocol anomaly severity.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: High-fidelity security alert context for SOC analysts.'
    },
    {
        'Feature_Name': 'weird_addl',
        'Context_Category': 'Security Context',
        'Description': 'Additional details string associated with Zeek protocol anomaly.',
        'Category_Justification': 'Provides contextual details for protocol violations.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Indirect: Supplies additional diagnostic context for anomaly rules.'
    },
    {
        'Feature_Name': 'missed_bytes',
        'Context_Category': 'Security Context',
        'Description': 'Number of bytes missed due to packet drop or loss during capture.',
        'Category_Justification': 'Measures traffic capture integrity and potential overload.',
        'Nature': 'Dynamic',
        'Importance_Score': 7.0,
        'CTI_Contribution': 'Indirect: Highlights network interface saturation during DDoS.'
    },
    {
        'Feature_Name': 'dns_rejected',
        'Context_Category': 'Security Context',
        'Description': 'Boolean flag indicating whether DNS query was rejected by server.',
        'Category_Justification': 'Explicit security rejection response status.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Direct: Indicates DNS firewall block or unauthorized domain query.'
    },
    {
        'Feature_Name': 'ssl_established',
        'Context_Category': 'Security Context',
        'Description': 'Flag indicating if SSL/TLS handshake successfully completed.',
        'Category_Justification': 'Validates encrypted session establishment security state.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Failed SSL handshakes indicate scanning or handshake attacks.'
    },
    {
        'Feature_Name': 'ssl_version',
        'Context_Category': 'Security Context',
        'Description': 'SSL/TLS protocol version used in session (e.g. TLSv1.2, TLSv1.3).',
        'Category_Justification': 'Evaluates encryption protocol strength and version security.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Identifies outdated, vulnerable SSL/TLS protocol versions.'
    },
    {
        'Feature_Name': 'ssl_cipher',
        'Context_Category': 'Security Context',
        'Description': 'SSL/TLS encryption cipher suite negotiated during handshake.',
        'Category_Justification': 'Evaluates cryptographic cipher strength.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Detects weak or deprecated cryptographic ciphers.'
    },
    {
        'Feature_Name': 'ssl_resumed',
        'Context_Category': 'Security Context',
        'Description': 'Boolean flag indicating if SSL session was resumed from ticket/cache.',
        'Category_Justification': 'Tracks session cache security dynamics.',
        'Nature': 'Dynamic',
        'Importance_Score': 6.5,
        'CTI_Contribution': 'Indirect: Contextualizes session ticket reuse vs new handshakes.'
    },
    {
        'Feature_Name': 'label',
        'Context_Category': 'Security Context',
        'Description': 'Ground truth binary classification target (0=Normal, 1=Attack).',
        'Category_Justification': 'Primary security ground truth annotation.',
        'Nature': 'Static (Target)',
        'Importance_Score': 10.0,
        'CTI_Contribution': 'Direct: Core supervised target for ML threat classification.'
    },
    {
        'Feature_Name': 'type',
        'Context_Category': 'Security Context',
        'Description': 'Ground truth multi-class attack category (e.g. ddos, backdoor, xss).',
        'Category_Justification': 'Primary attack category ground truth annotation.',
        'Nature': 'Static (Target)',
        'Importance_Score': 10.0,
        'CTI_Contribution': 'Direct: Core target for multi-class threat taxonomy modeling.'
    },

    # Behavioral Context
    {
        'Feature_Name': 'dns_query',
        'Context_Category': 'Behavioral Context',
        'Description': 'Requested DNS domain name string.',
        'Category_Justification': 'Reflects domain lookup behavior and host resolution intent.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Detects DGA domains, C2 servers, and phishing destinations.'
    },
    {
        'Feature_Name': 'dns_qclass',
        'Context_Category': 'Behavioral Context',
        'Description': 'DNS query class (e.g. 1=IN Internet).',
        'Category_Justification': 'Specifies DNS protocol query class semantics.',
        'Nature': 'Dynamic',
        'Importance_Score': 6.0,
        'CTI_Contribution': 'Indirect: Verifies standard DNS query class conventions.'
    },
    {
        'Feature_Name': 'dns_qtype',
        'Context_Category': 'Behavioral Context',
        'Description': 'DNS query type (e.g. 1=A, 28=AAAA, 15=MX, 16=TXT).',
        'Category_Justification': 'Determines record type requested during DNS resolution.',
        'Nature': 'Dynamic',
        'Importance_Score': 7.0,
        'CTI_Contribution': 'Direct: Detects DNS tunneling via unusual TXT/NULL record queries.'
    },
    {
        'Feature_Name': 'dns_rcode',
        'Context_Category': 'Behavioral Context',
        'Description': 'DNS response code (e.g. 0=NOERROR, 3=NXDOMAIN).',
        'Category_Justification': 'Reflects server resolution outcome and domain validity.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.0,
        'CTI_Contribution': 'Direct: High NXDOMAIN rates indicate active DGA malware activity.'
    },
    {
        'Feature_Name': 'dns_AA',
        'Context_Category': 'Behavioral Context',
        'Description': 'DNS Authoritative Answer boolean flag.',
        'Category_Justification': 'Indicates if response originated from authoritative server.',
        'Nature': 'Dynamic',
        'Importance_Score': 6.5,
        'CTI_Contribution': 'Indirect: Helps detect DNS spoofing and cache poisoning.'
    },
    {
        'Feature_Name': 'dns_RD',
        'Context_Category': 'Behavioral Context',
        'Description': 'DNS Recursion Desired boolean flag.',
        'Category_Justification': 'Reflects client query recursion preference.',
        'Nature': 'Dynamic',
        'Importance_Score': 6.5,
        'CTI_Contribution': 'Indirect: Contextualizes recursive DNS resolver behavior.'
    },
    {
        'Feature_Name': 'dns_RA',
        'Context_Category': 'Behavioral Context',
        'Description': 'DNS Recursion Available boolean flag.',
        'Category_Justification': 'Reflects server recursion capability.',
        'Nature': 'Dynamic',
        'Importance_Score': 6.5,
        'CTI_Contribution': 'Indirect: Evaluates recursive DNS amplification exposure.'
    },
    {
        'Feature_Name': 'http_trans_depth',
        'Context_Category': 'Behavioral Context',
        'Description': 'Pipelined HTTP transaction depth counter.',
        'Category_Justification': 'Tracks HTTP pipelined request interaction depth.',
        'Nature': 'Dynamic',
        'Importance_Score': 7.0,
        'CTI_Contribution': 'Indirect: Detects HTTP session pipelining & abuse patterns.'
    },
    {
        'Feature_Name': 'http_method',
        'Context_Category': 'Behavioral Context',
        'Description': 'HTTP request method verb (e.g. GET, POST, HEAD, PUT).',
        'Category_Justification': 'Defines client request action intent.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.0,
        'CTI_Contribution': 'Direct: Critical for identifying web attack methods (POST vs GET).'
    },
    {
        'Feature_Name': 'http_uri',
        'Context_Category': 'Behavioral Context',
        'Description': 'HTTP request URI path and query parameters.',
        'Category_Justification': 'Contains full web request path and parameter payload.',
        'Nature': 'Dynamic',
        'Importance_Score': 9.5,
        'CTI_Contribution': 'Direct: Primary feature for detecting SQL Injection, XSS, and path traversal.'
    },
    {
        'Feature_Name': 'http_version',
        'Context_Category': 'Behavioral Context',
        'Description': 'HTTP protocol version (e.g. 1.1, 1.0).',
        'Category_Justification': 'Specifies HTTP protocol version semantics.',
        'Nature': 'Dynamic',
        'Importance_Score': 6.5,
        'CTI_Contribution': 'Indirect: Detects anomalous or ancient HTTP protocol stacks.'
    },
    {
        'Feature_Name': 'http_status_code',
        'Context_Category': 'Behavioral Context',
        'Description': 'HTTP response status code (e.g. 200, 404, 500, 403).',
        'Category_Justification': 'Reflects web application execution outcome.',
        'Nature': 'Dynamic',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: High 404 rates signal directory scanning; 500 signals exploit success.'
    },
    {
        'Feature_Name': 'http_orig_mime_types',
        'Context_Category': 'Behavioral Context',
        'Description': 'Client request MIME content type string.',
        'Category_Justification': 'Specifies uploaded payload MIME type.',
        'Nature': 'Dynamic',
        'Importance_Score': 7.5,
        'CTI_Contribution': 'Direct: Identifies malicious file uploads (e.g., shell scripts).'
    },
    {
        'Feature_Name': 'http_resp_mime_types',
        'Context_Category': 'Behavioral Context',
        'Description': 'Server response MIME content type string.',
        'Category_Justification': 'Specifies downloaded response MIME type.',
        'Nature': 'Dynamic',
        'Importance_Score': 7.5,
        'CTI_Contribution': 'Direct: Identifies returned payload types (executable vs HTML).'
    },

    # Environmental Context
    {
        'Feature_Name': 'http_user_agent',
        'Context_Category': 'Environmental Context',
        'Description': 'HTTP User-Agent string identifying client application/environment.',
        'Category_Justification': 'Identifies client operating system, browser, or automated script agent.',
        'Nature': 'Static (per client)',
        'Importance_Score': 8.5,
        'CTI_Contribution': 'Direct: Key feature for identifying automated vulnerability scanners (Nikto, Nmap, Sqlmap).'
    }
]

def model_and_generate_artifacts():
    output_dir = os.path.join('results', 'context_modeling')
    os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Output directory ready: {output_dir}")

    # 1. Create DataFrame
    mapping_df = pd.DataFrame(FEATURE_CONTEXT_MAP)
    print(f"[+] Successfully mapped {len(mapping_df)} features across context categories.")

    # Save CSV
    csv_path = os.path.join(output_dir, 'contextual_feature_mapping.csv')
    mapping_df.to_csv(csv_path, index=False)
    print(f"[SUCCESS] Saved CSV mapping to: {csv_path}")

    # Set publication plot styling
    plt.rcParams['font.sans-serif'] = 'Arial'
    plt.rcParams['font.family'] = 'sans-serif'
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

    # Palette
    cat_colors = {
        'Behavioral Context': '#7c3aed',
        'Traffic Context': '#0284c7',
        'Security Context': '#ef4444',
        'Network Context': '#2563eb',
        'Device Context': '#10b981',
        'Environmental Context': '#f59e0b',
        'Temporal Context': '#ec4899'
    }

    # =========================================================================
    # VISUALIZATION 1: Context Category Distribution Bar Chart
    # =========================================================================
    print("[+] Generating Visualization 1: Context Category Distribution Bar Chart...")
    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    cat_counts = mapping_df['Context_Category'].value_counts()
    bars = ax.bar(cat_counts.index, cat_counts.values, color=[cat_colors.get(c, '#333333') for c in cat_counts.index], edgecolor='black', width=0.6, alpha=0.85)

    ax.set_title("Context Category Distribution (45 Features in Network Dataset)", fontsize=13, fontweight='bold', pad=15)
    ax.set_ylabel("Number of Features", fontsize=11, fontweight='bold')
    ax.set_xticks(range(len(cat_counts)))
    ax.set_xticklabels(cat_counts.index, rotation=30, ha='right', fontsize=10, fontweight='bold')
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    for bar in bars:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.3, f"{int(h)} ({h/len(mapping_df)*100:.1f}%)", ha='center', va='bottom', fontsize=9, fontweight='bold')

    ax.set_ylim(0, max(cat_counts.values) + 2)
    plt.tight_layout()
    v1_path = os.path.join(output_dir, '1_context_category_distribution.png')
    plt.savefig(v1_path, dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # VISUALIZATION 2: Context Feature Importance Chart
    # =========================================================================
    print("[+] Generating Visualization 2: Context Feature Importance Chart...")
    fig, ax = plt.subplots(figsize=(12, 10), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    sorted_df = mapping_df.sort_values(by='Importance_Score', ascending=True)
    bar_colors = [cat_colors.get(c, '#333333') for c in sorted_df['Context_Category']]

    bars = ax.barh(sorted_df['Feature_Name'], sorted_df['Importance_Score'], color=bar_colors, edgecolor='black', height=0.65, alpha=0.85)
    ax.set_title("Contextual Feature CTI Importance Scores (0 to 10 Scale)", fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel("Importance Score for Contextual Reasoning", fontsize=12, fontweight='bold')
    ax.set_xlim(0, 11)
    ax.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.15, bar.get_y() + bar.get_height()/2, f"{w:.1f}", ha='left', va='center', fontsize=8, fontweight='bold', color='#1e293b')

    # Legend for categories
    from matplotlib.patches import Patch
    legend_patches = [Patch(facecolor=color, edgecolor='black', label=cat) for cat, color in cat_colors.items() if cat in sorted_df['Context_Category'].values]
    ax.legend(handles=legend_patches, loc='lower right', frameon=True, facecolor='white', edgecolor='#cbd5e1', fontsize=9)

    plt.tight_layout()
    v2_path = os.path.join(output_dir, '2_context_feature_importance.png')
    plt.savefig(v2_path, dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # VISUALIZATION 3: Context Category Pie Chart
    # =========================================================================
    print("[+] Generating Visualization 3: Context Category Pie Chart...")
    fig, ax = plt.subplots(figsize=(8, 7), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    wedges, texts, autotexts = ax.pie(
        cat_counts.values,
        labels=cat_counts.index,
        autopct='%1.1f%%',
        startangle=140,
        colors=[cat_colors.get(c, '#333333') for c in cat_counts.index],
        pctdistance=0.75,
        explode=[0.03]*len(cat_counts),
        textprops=dict(fontsize=10, fontweight='bold')
    )
    centre_circle = plt.Circle((0,0), 0.50, fc='white')
    ax.add_artist(centre_circle)
    ax.set_title("Proportional Percentage of Features by Context Category", fontsize=13, fontweight='bold', pad=15)

    plt.tight_layout()
    v3_path = os.path.join(output_dir, '3_context_category_pie_chart.png')
    plt.savefig(v3_path, dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # VISUALIZATION 4: Contextual Feature Correlation Heatmap
    # =========================================================================
    print("[+] Generating Visualization 4: Contextual Feature Correlation Heatmap...")
    net_df = pd.read_csv('Train_Test_datasets/Train_Test_Network_dataset/train_test_network.csv', usecols=['duration', 'src_bytes', 'dst_bytes', 'src_pkts', 'dst_pkts', 'src_ip_bytes', 'dst_ip_bytes', 'http_request_body_len', 'http_response_body_len', 'label'])
    
    fig, ax = plt.subplots(figsize=(10, 8), dpi=300)
    fig.patch.set_facecolor('#ffffff')

    corr = net_df.corr()
    sns.heatmap(corr, annot=True, fmt='.2f', cmap='Blues', cbar=True, ax=ax, linewidths=0.5)
    ax.set_title("Correlation Heatmap of Numerical Context Features & Target Label", fontsize=13, fontweight='bold', pad=15)

    plt.tight_layout()
    v4_path = os.path.join(output_dir, '4_contextual_feature_correlation_heatmap.png')
    plt.savefig(v4_path, dpi=300, bbox_inches='tight')
    plt.close()

    # =========================================================================
    # GENERATE PDF REPORT: contextual_feature_report.pdf
    # =========================================================================
    pdf_path = os.path.join(output_dir, 'contextual_feature_report.pdf')
    print(f"[+] Generating PDF Report at: {pdf_path}...")

    with PdfPages(pdf_path) as pdf:
        # Page 1: Title & Overview
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.94, "Contextual Intelligence Engine (CIE)", fontsize=18, fontweight='bold', ha='center', color='#0f172a')
        plt.text(0.5, 0.915, "Operational Context Modeling & Feature Taxonomy Report", fontsize=12, ha='center', color='#475569')
        plt.axhline(0.90, color='#2563eb', linewidth=2)

        p1_text = (
            "OVERVIEW & SCOPE\n"
            "----------------\n"
            "This report models operational context for the Cyber Threat Intelligence (CTI) Platform using\n"
            "the official TON-IoT Processed Network Dataset (Network_dataset_*.csv).\n\n"
            "Every feature in the 45-feature network schema is categorized into exactly one of 7 context groups:\n"
            "1. Device Context (4 features): Source/Destination IP addresses and X.509 SSL certificate identity.\n"
            "2. Network Context (5 features): Transport/Service protocols, socket ports, and TCP handshake states.\n"
            "3. Traffic Context (9 features): Flow durations, byte throughput, packet counts, and payload lengths.\n"
            "4. Temporal Context (1 feature): Unix epoch timestamp for chronological event ordering.\n"
            "5. Security Context (11 features): Zeek anomaly flags, SSL protocol strength, and ground-truth targets.\n"
            "6. Behavioral Context (14 features): Application payload interactions across HTTP and DNS protocols.\n"
            "7. Environmental Context (1 feature): Client browser/OS User-Agent software environment.\n\n"
            "SUMMARY DISTRIBUTION TABLE\n"
            "--------------------------\n"
            "Context Category      | Feature Count | Share (%) | Key CTI Contribution\n"
            "----------------------|---------------|-----------|-----------------------------------------\n"
            "Behavioral Context    | 14 features   | 31.1%     | HTTP & DNS payload interaction behavior\n"
            "Security Context      | 11 features   | 24.4%     | Protocol anomalies & ground-truth labels\n"
            "Traffic Context       | 9 features    | 20.0%     | Flow duration & packet/byte throughput\n"
            "Network Context       | 5 features    | 11.1%     | Transport protocols & connection states\n"
            "Device Context        | 4 features    | 8.9%      | IP endpoint & certificate identities\n"
            "Temporal Context      | 1 feature     | 2.2%      | Event timestamp & inter-arrival time\n"
            "Environmental Context | 1 feature     | 2.2%      | Client User-Agent & OS environment\n"
            "----------------------|---------------|-----------|-----------------------------------------\n"
            "TOTAL                 | 45 features   | 100.0%    | Unified Multi-Layer Operational Context"
        )

        plt.text(0.06, 0.85, p1_text, fontsize=8.5, verticalalignment='top', fontfamily='monospace', bbox=dict(boxstyle='round,pad=0.8', facecolor='#f8fafc', edgecolor='#cbd5e1'))
        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

        # Page 2: Detailed Feature Mapping Table Part 1
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.95, "Context Feature Mapping Table (Part 1: Device, Network, Traffic)", fontsize=13, fontweight='bold', ha='center', color='#0f172a')
        plt.axhline(0.93, color='#2563eb', linewidth=1.5)

        table1_rows = []
        for f_info in FEATURE_CONTEXT_MAP[:20]:
            table1_rows.append([f_info['Feature_Name'], f_info['Context_Category'], f_info['Nature'], str(f_info['Importance_Score']), f_info['CTI_Contribution'][:35]+'...'])

        table1 = plt.table(cellText=table1_rows, colLabels=["Feature", "Context Category", "Nature", "Score", "CTI Contribution"], loc='center', cellLoc='left')
        table1.auto_set_font_size(False)
        table1.set_fontsize(7.5)
        table1.scale(1.1, 1.4)

        for (row, col), cell in table1.get_celld().items():
            if row == 0:
                cell.set_facecolor('#1e293b')
                cell.get_text().set_color('white')
                cell.get_text().set_weight('bold')

        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

        # Page 3: Detailed Feature Mapping Table Part 2
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.95, "Context Feature Mapping Table (Part 2: Security, Behavioral, Environmental)", fontsize=13, fontweight='bold', ha='center', color='#0f172a')
        plt.axhline(0.93, color='#2563eb', linewidth=1.5)

        table2_rows = []
        for f_info in FEATURE_CONTEXT_MAP[20:]:
            table2_rows.append([f_info['Feature_Name'], f_info['Context_Category'], f_info['Nature'], str(f_info['Importance_Score']), f_info['CTI_Contribution'][:35]+'...'])

        table2 = plt.table(cellText=table2_rows, colLabels=["Feature", "Context Category", "Nature", "Score", "CTI Contribution"], loc='center', cellLoc='left')
        table2.auto_set_font_size(False)
        table2.set_fontsize(7.5)
        table2.scale(1.1, 1.4)

        for (row, col), cell in table2.get_celld().items():
            if row == 0:
                cell.set_facecolor('#1e293b')
                cell.get_text().set_color('white')
                cell.get_text().set_weight('bold')

        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

    print(f"[SUCCESS] PDF Report generated at: {pdf_path}")
    print("[SUCCESS] All contextual modeling artifacts generated successfully!")

if __name__ == '__main__':
    model_and_generate_artifacts()
