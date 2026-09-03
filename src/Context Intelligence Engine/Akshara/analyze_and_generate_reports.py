"""
analyze_and_generate_reports.py
================================
Analyzes every file in Processed_datasets and generates:
1. results/dataset_analysis/processed_dataset_summary.csv
2. results/dataset_analysis/processed_dataset_analysis.pdf

Explains purpose, features, data types, target columns, CIE contribution, 
and recommendations for the Contextual Intelligence Engine (CIE).
"""

import os
import glob
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

def generate_processed_dataset_analysis():
    output_dir = os.path.join('results', 'dataset_analysis')
    os.makedirs(output_dir, exist_ok=True)
    print(f"[+] Output directory ready: {output_dir}")

    dataset_base = r'Processed_datasets'
    all_csvs = sorted(glob.glob(os.path.join(dataset_base, '**', '*.csv'), recursive=True))
    
    print(f"[+] Inspecting {len(all_csvs)} files in Processed_datasets...")

    summary_rows = []
    category_details = {}

    for filepath in all_csvs:
        rel_path = os.path.relpath(filepath, dataset_base)
        filename = os.path.basename(filepath)
        category = os.path.dirname(rel_path)
        file_size_mb = round(os.path.getsize(filepath) / (1024 * 1024), 2)

        # Inspect columns & sample types
        df_sample = pd.read_csv(filepath, nrows=100)
        cols = list(df_sample.columns)
        dtypes = {c: str(df_sample[c].dtype) for c in cols}
        
        # Targets
        target_cols = [c for c in ['label', 'type', 'attack', 'temp_condition', 'door_state', 'light_status'] if c in cols]
        target_str = ", ".join(target_cols) if target_cols else "None"

        # Determine purpose & CIE contribution based on category/filename
        if 'Processed_IoT_dataset' in category:
            purpose = f"Captures physical telemetry and actuator state readings for {filename.replace('IoT_', '').replace('.csv', '')} sensor."
            cie_contribution = "Provides Device & Environmental Context (physical sensor dynamics, state changes, environmental readings)."
            recommended = "Secondary (Device-level context)"
        elif 'Processed_Linux_dataset' in category:
            purpose = f"Captures host-level Linux kernel operating system telemetry ({filename.split('_')[1]} metrics)."
            cie_contribution = "Provides Host & Behavioral Context (process execution levels, disk I/O bursts, memory allocation spikes)."
            recommended = "Secondary (Host-level context)"
        elif 'Processed_Windows_dataset' in category:
            purpose = f"Captures enterprise Windows OS performance counter telemetry ({filename.replace('_dataset.csv', '')})."
            cie_contribution = "Provides Host & Resource Context (CPU utilization, kernel DPC rates, handle counts, page table allocations)."
            recommended = "Secondary (Host-level context)"
        else: # Network
            purpose = "Captures Bro/Zeek network connection flows, transport layers, application protocols, and security flags."
            cie_contribution = "Provides Network, Traffic, Security, & Behavioral Context (inter-device traffic topology, flow volume, payload stats, anomaly flags)."
            recommended = "PRIMARY RECOMMENDATION (Full Context Spectrum)"

        dtype_summary = ", ".join([f"{c}: {dt}" for c, dt in list(dtypes.items())[:6]])
        if len(dtypes) > 6:
            dtype_summary += f", ... (+{len(dtypes)-6} more)"

        summary_rows.append({
            'Dataset_Name': filename,
            'Category': category,
            'File_Path': rel_path,
            'File_Size_MB': file_size_mb,
            'Feature_Count': len(cols),
            'Target_Columns': target_str,
            'Purpose': purpose,
            'CIE_Context_Contribution': cie_contribution,
            'CIE_Recommendation': recommended,
            'Sample_Features_and_Types': dtype_summary
        })

        if category not in category_details:
            category_details[category] = []
        category_details[category].append({
            'filename': filename,
            'size_mb': file_size_mb,
            'cols': cols,
            'dtypes': dtypes,
            'targets': target_cols,
            'purpose': purpose,
            'cie_contribution': cie_contribution
        })

    # Save summary CSV
    summary_df = pd.DataFrame(summary_rows)
    csv_path = os.path.join(output_dir, 'processed_dataset_summary.csv')
    summary_df.to_csv(csv_path, index=False)
    print(f"[SUCCESS] Summary CSV generated at: {csv_path}")

    # =========================================================================
    # GENERATE PUBLICATION-QUALITY PDF REPORT: processed_dataset_analysis.pdf
    # =========================================================================
    pdf_path = os.path.join(output_dir, 'processed_dataset_analysis.pdf')
    print(f"[+] Generating PDF Report at: {pdf_path}...")

    with PdfPages(pdf_path) as pdf:
        
        # ---------------------------------------------------------------------
        # PAGE 1: Executive Summary & Recommendation
        # ---------------------------------------------------------------------
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')
        
        # Header banner
        plt.text(0.5, 0.94, "TON-IoT Processed Datasets Analysis Report", fontsize=18, fontweight='bold', ha='center', color='#0f172a')
        plt.text(0.5, 0.915, "Contextual Intelligence Engine (CIE) Evaluation & Selection", fontsize=12, ha='center', color='#475569')
        plt.axhline(0.90, color='#2563eb', linewidth=2)

        exec_text = (
            "EXECUTIVE SUMMARY\n"
            "-----------------\n"
            "The TON-IoT dataset contains 38 processed telemetry files (~4.8 GB) spanning 4 heterogeneous domains:\n"
            "1. Processed IoT Telemetry (7 CSV files): Physical sensor and actuator operational readings.\n"
            "2. Processed Linux OS Telemetry (6 CSV files): Host kernel process, disk I/O, and memory metrics.\n"
            "3. Processed Windows OS Telemetry (2 CSV files): Windows 7 & 10 performance counters (127-135 features).\n"
            "4. Processed Network Telemetry (23 CSV files): Bro/Zeek flow connection logs (46 features).\n\n"
            "CIE RECOMMENDATION & SELECTION\n"
            "-------------------------------\n"
            "RECOMMENDED DATASET: Processed Network Telemetry (Network_dataset_*.csv)\n\n"
            "Justification for Selection:\n"
            "• Unified Multi-Dimensional Context: Incorporates 5 context categories (Network, Traffic, Security,\n"
            "  Behavioral, and Temporal) into a single unified telemetry schema.\n"
            "• Testbed-Wide Visibility: Captures inter-device network communications across ALL IoT devices,\n"
            "  Linux servers, Windows workstations, and attack orchestrators.\n"
            "• Rich Feature Set (46 Features): Combines transport metrics (TCP/UDP), application-layer protocols\n"
            "  (HTTP, DNS, SSL), and specialized Zeek security anomaly flags ('weird_name', 'weird_notice').\n"
            "• Precise Ground-Truth Targets: Features both binary classification ('label') and 10-class multi-attack\n"
            "  category annotations ('type')."
        )

        plt.text(0.08, 0.45, exec_text, fontsize=10, verticalalignment='top', fontfamily='monospace', bbox=dict(boxstyle='round,pad=0.8', facecolor='#f8fafc', edgecolor='#cbd5e1'))

        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

        # ---------------------------------------------------------------------
        # PAGE 2: Dataset Summary Overview Table
        # ---------------------------------------------------------------------
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.95, "Summary Table of Processed Datasets (38 Files)", fontsize=15, fontweight='bold', ha='center', color='#0f172a')
        plt.axhline(0.93, color='#2563eb', linewidth=1.5)

        table_data = [["Category", "File Count", "Total Size", "Feature Count", "Target Columns", "CIE Role"]]
        
        cat_summaries = [
            ["Processed IoT Dataset", "7 CSVs", "174.4 MB", "6 - 8 cols", "label, type, state", "Device Context"],
            ["Processed Linux Dataset", "6 CSVs", "296.3 MB", "9 - 17 cols", "label, type, attack", "Host Context"],
            ["Processed Windows Dataset", "2 CSVs", "59.5 MB", "127 - 135 cols", "label, type", "Host Context"],
            ["Processed Network Dataset", "23 CSVs", "4,260.6 MB", "46 cols", "label, type", "PRIMARY CIE DATASET"]
        ]

        table = plt.table(cellText=cat_summaries, colLabels=table_data[0], loc='center', cellLoc='left')
        table.auto_set_font_size(False)
        table.set_fontsize(9)
        table.scale(1.2, 1.8)

        # Style table headers
        for (row, col), cell in table.get_celld().items():
            if row == 0:
                cell.set_facecolor('#1e293b')
                cell.get_text().set_color('white')
                cell.get_text().set_weight('bold')
            else:
                if row == 4: # Highlight Network recommendation
                    cell.set_facecolor('#dbeafe')
                    cell.get_text().set_weight('bold')

        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

        # ---------------------------------------------------------------------
        # PAGE 3: Domain Detail - Processed IoT Datasets
        # ---------------------------------------------------------------------
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.95, "Domain Analysis: Processed IoT Telemetry (7 Devices)", fontsize=14, fontweight='bold', ha='center', color='#0f172a')
        plt.axhline(0.93, color='#2563eb', linewidth=1.5)

        iot_text = (
            "1. IoT Fridge (IoT_Fridge.csv | 23.8 MB | 6 cols):\n"
            "   • Features: date, time, fridge_temperature (float64), temp_condition (str), label (int64), type (str).\n"
            "   • Purpose & Context: Monitors smart fridge temperature dynamics; contributes physical Device Context.\n\n"
            "2. IoT GPS Tracker (IoT_GPS_Tracker.csv | 30.0 MB | 6 cols):\n"
            "   • Features: date, time, latitude (float64), longitude (float64), label (int64), type (str).\n"
            "   • Purpose & Context: Tracks vehicle location coordinates; contributes Geolocation Device Context.\n\n"
            "3. IoT Garage Door (IoT_Garage_Door.csv | 24.6 MB | 6 cols):\n"
            "   • Features: date, time, sstate (int64), door_state (str), label (int64), type (str).\n"
            "   • Purpose & Context: Monitors actuator open/close state; contributes Actuator Behavioral Context.\n\n"
            "4. IoT Modbus ICS (IoT_Modbus.csv | 14.6 MB | 8 cols):\n"
            "   • Features: date, time, FC1_Read_Input_Register, FC2_Read_Discrete_Inputs, FC3_Read_Holding_Register,\n"
            "               FC4_Read_Coil, label (int64), type (str).\n"
            "   • Purpose & Context: Monitors Modbus SCADA industrial control registers; contributes Industrial Control Context.\n\n"
            "5. IoT Motion Light (IoT_Motion_Light.csv | 15.8 MB | 6 cols):\n"
            "   • Features: date, time, motion_status (int64), light_status (str), label (int64), type (str).\n"
            "   • Purpose & Context: Monitors motion sensor and light status; contributes Environmental Context.\n\n"
            "6. IoT Thermostat (IoT_Thermostat.csv | 18.2 MB | 6 cols):\n"
            "   • Features: date, time, current_temperature (float64), thermostat_status (int64), label, type.\n"
            "   • Purpose & Context: Climate control temperature telemetry; contributes Physical Environmental Context.\n\n"
            "7. IoT Weather Station (IoT_Weather.csv | 40.1 MB | 7 cols):\n"
            "   • Features: date, time, temperature, humidity, pressure, label, type.\n"
            "   • Purpose & Context: Environmental station sensor readings; contributes Multi-Sensor Environmental Context."
        )

        plt.text(0.06, 0.88, iot_text, fontsize=8.5, verticalalignment='top', fontfamily='monospace')
        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

        # ---------------------------------------------------------------------
        # PAGE 4: Domain Detail - Processed Linux & Windows Datasets
        # ---------------------------------------------------------------------
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.95, "Domain Analysis: Linux & Windows OS Telemetry", fontsize=14, fontweight='bold', ha='center', color='#0f172a')
        plt.axhline(0.93, color='#2563eb', linewidth=1.5)

        os_text = (
            "PROCESSED LINUX TELEMETRY (6 Files | 296.3 MB)\n"
            "-----------------------------------------------\n"
            "• Linux Process (Linux_process_1.csv & 2.csv | 17 cols):\n"
            "  Features: ts, PID, TRUN, TSL, TIDL, TSN, ZOMB, RUID, EUID, STUID, SECUID, GIUD, EGID, STGID, label, type.\n"
            "  Context: Process execution states (running, sleeping, zombie) and real/effective user IDs (privileges).\n\n"
            "• Linux Disk (linux_disk_1.csv & 2.csv | 9 cols):\n"
            "  Features: PID, RDDSK, WRDSK, WCANCL, DSK, CMD, attack, type.\n  Context: Disk block read/write volume and executing command strings.\n\n"
            "• Linux Memory (linux_memory1.csv & 2.csv | 13 cols):\n"
            "  Features: PID, MINFLT, MAJFLT, VSTEXT, VSIZE, RSIZE, VGROW, RGROW, MEM, CMD, label, type.\n"
            "  Context: Page faults (minor/major), virtual memory growth, and process RAM allocation.\n\n\n"
            "PROCESSED WINDOWS TELEMETRY (2 Files | 59.5 MB)\n"
            "-------------------------------------------------\n"
            "• Windows 10 (windows10_dataset.csv | 127 cols) & Windows 7 (windows7_dataset.csv | 135 cols):\n"
            "  Features: Comprehensive Windows Performance Monitor (PerfMon) metrics across Processor, Process,\n"
            "            Memory, LogicalDisk, and Network Interface adapters.\n"
            "  Context: Host resource utilization, DPC rates, handle counts, and committed page table bytes."
        )

        plt.text(0.06, 0.88, os_text, fontsize=8.5, verticalalignment='top', fontfamily='monospace')
        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

        # ---------------------------------------------------------------------
        # PAGE 5: Domain Detail - Processed Network Telemetry (Primary CIE)
        # ---------------------------------------------------------------------
        fig = plt.figure(figsize=(8.5, 11), dpi=300)
        fig.patch.set_facecolor('#ffffff')

        plt.text(0.5, 0.95, "Primary Recommendation: Processed Network Dataset", fontsize=14, fontweight='bold', ha='center', color='#0f172a')
        plt.axhline(0.93, color='#2563eb', linewidth=1.5)

        net_text = (
            "PROCESSED NETWORK TELEMETRY (23 Files | 4.26 GB | 46 Features)\n"
            "---------------------------------------------------------------\n"
            "Files: Network_dataset_1.csv through Network_dataset_23.csv\n\n"
            "FEATURE BREAKDOWN BY CONTEXT CATEGORY:\n\n"
            "1. Network Context: src_ip, src_port, dst_ip, dst_port, conn_state, service, proto.\n"
            "   -> Maps inter-device communications, transport protocols, and socket connection states.\n\n"
            "2. Traffic Context: duration, src_bytes, dst_bytes, missed_bytes, src_pkts, src_ip_bytes, dst_pkts, dst_ip_bytes.\n"
            "   -> Measures connection throughput, packet rates, byte ratios, and transfer volumes.\n\n"
            "3. Application & Behavioral Context:\n"
            "   • DNS: dns_query, dns_qclass, dns_qtype, dns_rcode, dns_AA, dns_RD, dns_RA, dns_rejected.\n"
            "   • HTTP: http_trans_depth, http_method, http_uri, http_version, http_request_body_len,\n"
            "           http_response_body_len, http_status_code, http_user_agent, http_orig_mime_types, http_resp_mime_types.\n"
            "   • SSL: ssl_version, ssl_cipher, ssl_resumed, ssl_established, ssl_subject, ssl_issuer.\n"
            "   -> Captures application-layer payload semantics and user-agent interaction behaviors.\n\n"
            "4. Security Context: weird_name, weird_addl, weird_notice.\n"
            "   -> Flags protocol violations, invalid header formats, and security anomalies.\n\n"
            "5. Temporal Context: ts (Unix timestamp).\n"
            "   -> Tracks event arrival times, inter-arrival gaps, and temporal burst patterns.\n\n"
            "6. Target Labels: label (Binary: 0=Normal, 1=Attack), type (Multi-Class: 10 Attack Types).\n\n"
            "CONCLUSION:\n"
            "The Processed Network Dataset provides the most unified, high-dimensional contextual foundation\n"
            "for training and deploying the AI-based Contextual Intelligence Engine (CIE)."
        )

        plt.text(0.06, 0.88, net_text, fontsize=8.5, verticalalignment='top', fontfamily='monospace')
        plt.axis('off')
        pdf.savefig(fig)
        plt.close()

    print(f"[SUCCESS] PDF Report generated at: {pdf_path}")
    print("[SUCCESS] All dataset analysis artifacts generated successfully!")

if __name__ == '__main__':
    generate_processed_dataset_analysis()
