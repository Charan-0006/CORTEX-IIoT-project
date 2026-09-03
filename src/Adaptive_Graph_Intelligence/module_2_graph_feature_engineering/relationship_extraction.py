"""
Relationship Extraction Module for Graph Feature Engineering.

This module infers candidate graph relationships supported by dataset attributes.
It evaluates attribute co-occurrences in telemetry schemas without building graph databases
and records Evidence Column(s) for research traceability.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def infer_relationships_for_file(df_cols: List[str], dataset_name: str, file_name: str, total_rows: int) -> List[Dict[str, Any]]:
    """
    Infers valid directed relationships present in a single dataset file based on column combinations.

    Args:
        df_cols: List of column names in dataset file.
        dataset_name: Name of dataset category.
        file_name: Name of CSV file.
        total_rows: Number of rows in dataset file.

    Returns:
        List of relationship records containing Evidence Column(s).
    """
    rels = []
    cols_set = {c.lower().strip() for c in df_cols}

    # 1. Source IP -> communicates_with -> Destination IP
    has_src = any(c in cols_set for c in ['src_ip', 'source_ip', 'ip_src', 'orig_h'])
    has_dst = any(c in cols_set for c in ['dst_ip', 'dest_ip', 'ip_dst', 'resp_h'])
    if has_src and has_dst:
        src_col = [c for c in df_cols if c.lower().strip() in ['src_ip', 'source_ip', 'ip_src', 'orig_h']][0]
        dst_col = [c for c in df_cols if c.lower().strip() in ['dst_ip', 'dest_ip', 'ip_dst', 'resp_h']][0]
        evidence = f"{src_col} -> {dst_col}"
        rels.append({
            'Source Entity': 'Source IP',
            'Relationship Type': 'communicates_with',
            'Target Entity': 'Destination IP',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 2. Connection -> uses -> Protocol
    has_proto = any('proto' in c or 'protocol' in c for c in cols_set)
    if (has_src or has_dst) and has_proto:
        proto_col = [c for c in df_cols if 'proto' in c.lower()][0]
        evidence = f"connection -> {proto_col}"
        rels.append({
            'Source Entity': 'Connection',
            'Relationship Type': 'uses',
            'Target Entity': 'Protocol',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 3. User -> executes -> Process
    has_user = any('user' in c or 'account' in c for c in cols_set)
    has_proc = any('pid' in c or 'process' in c or 'cmd' in c for c in cols_set)
    if has_user and has_proc:
        u_col = [c for c in df_cols if 'user' in c.lower()][0]
        p_col = [c for c in df_cols if 'pid' in c.lower() or 'process' in c.lower()][0]
        evidence = f"{u_col} -> {p_col}"
        rels.append({
            'Source Entity': 'User',
            'Relationship Type': 'executes',
            'Target Entity': 'Process',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 4. Host -> runs -> Process
    has_host = any('host' in c or 'machine' in c or 'asset' in c for c in cols_set)
    if has_host and has_proc:
        h_col = [c for c in df_cols if 'host' in c.lower() or 'asset' in c.lower()][0]
        p_col = [c for c in df_cols if 'pid' in c.lower() or 'process' in c.lower()][0]
        evidence = f"{h_col} -> {p_col}"
        rels.append({
            'Source Entity': 'Host',
            'Relationship Type': 'runs',
            'Target Entity': 'Process',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 5. Process -> creates -> Process
    has_parent_proc = any('creating' in c and 'process' in c for c in cols_set)
    has_child_proc = any('id_process' in c or ('id' in c and 'process' in c) for c in cols_set)
    if has_parent_proc and has_child_proc:
        pp_col = [c for c in df_cols if 'creating' in c.lower() and 'process' in c.lower()][0]
        cp_col = [c for c in df_cols if 'id' in c.lower() and 'process' in c.lower() and 'creating' not in c.lower()][0]
        evidence = f"{pp_col} -> {cp_col}"
        rels.append({
            'Source Entity': 'Process',
            'Relationship Type': 'creates',
            'Target Entity': 'Process',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 6. Service -> runs_on -> Host
    has_svc = any('service' in c for c in cols_set)
    if has_svc and (has_host or 'network' in dataset_name.lower()):
        svc_col = [c for c in df_cols if 'service' in c.lower()][0]
        evidence = f"{svc_col} -> Host"
        rels.append({
            'Source Entity': 'Service',
            'Relationship Type': 'runs_on',
            'Target Entity': 'Host',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 7. Source IP / Destination IP -> belongs_to -> Host
    if (has_src or has_dst) and has_host:
        ip_col = [c for c in df_cols if 'ip' in c.lower()][0]
        h_col = [c for c in df_cols if 'host' in c.lower() or 'asset' in c.lower()][0]
        evidence = f"{ip_col} -> {h_col}"
        rels.append({
            'Source Entity': 'Source IP',
            'Relationship Type': 'belongs_to',
            'Target Entity': 'Host',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 8. Device -> generates -> Event
    has_dev = any(c in cols_set for c in ['device', 'fridge', 'thermostat', 'door', 'light', 'gps', 'weather', 'modbus']) or ('iot' in dataset_name.lower())
    has_evt = any(c in cols_set for c in ['label', 'type', 'event', 'action', 'status', 'state'])
    if has_dev and has_evt:
        evt_col = [c for c in df_cols if c.lower() in ['label', 'type', 'event', 'action', 'status']][0]
        evidence = f"device_sensor -> {evt_col}"
        rels.append({
            'Source Entity': 'Device',
            'Relationship Type': 'generates',
            'Target Entity': 'Event',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    # 9. Process -> accesses -> Asset
    has_sys_metric = any('logicaldisk' in c or 'memory' in c or 'processor' in c for c in cols_set)
    if has_proc and has_sys_metric:
        p_col = [c for c in df_cols if 'process' in c.lower() or 'pid' in c.lower()][0]
        evidence = f"{p_col} -> system_resource"
        rels.append({
            'Source Entity': 'Process',
            'Relationship Type': 'accesses',
            'Target Entity': 'Asset',
            'Source Dataset': dataset_name,
            'Supporting Columns': evidence,
            'Evidence Column(s)': evidence,
            'Occurrence Count': total_rows
        })

    return rels


def extract_relationships_from_datasets(processed_dir: Path) -> pd.DataFrame:
    """
    Traverses processed datasets and extracts candidate graph relationships.

    Args:
        processed_dir: Path to data/Processed_datasets/

    Returns:
        DataFrame containing candidate graph relationships with Evidence Column(s).
    """
    all_rels = []

    if not processed_dir.exists():
        return pd.DataFrame()

    dataset_folders = [d for d in sorted(processed_dir.iterdir()) if d.is_dir()]

    for d_folder in dataset_folders:
        dataset_name = d_folder.name
        csv_files = sorted(list(d_folder.glob('*.csv')))

        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file, nrows=10)
                columns = list(df.columns)
                total_rows = sum(1 for _ in open(csv_file, encoding='utf-8', errors='ignore')) - 1

                file_rels = infer_relationships_for_file(columns, dataset_name, csv_file.name, max(total_rows, 1))
                all_rels.extend(file_rels)
            except Exception:
                continue

    df_rels = pd.DataFrame(all_rels)
    if not df_rels.empty:
        df_rels = df_rels.groupby(
            ['Source Entity', 'Relationship Type', 'Target Entity', 'Source Dataset', 'Supporting Columns', 'Evidence Column(s)'],
            as_index=False
        ).agg({'Occurrence Count': 'sum'})

    return df_rels
