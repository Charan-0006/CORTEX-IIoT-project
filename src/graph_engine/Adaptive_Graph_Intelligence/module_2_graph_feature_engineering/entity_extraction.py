"""
Entity Extraction Module for Graph Feature Engineering.

This module automatically discovers and extracts candidate graph entity nodes
from raw Industrial IoT datasets using rule-based attribute analysis.
It deduplicates equivalent schema entities and returns structured entity metadata.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def detect_entity_category_for_column(col_name: str) -> str:
    """
    Determines entity category for a dataset column based on naming rules.

    Args:
        col_name: Name of dataset column.

    Returns:
        Entity category string or None if not an entity.
    """
    col_lower = col_name.lower().strip()
    tokens = set(col_lower.replace('_', ' ').replace('-', ' ').split())

    # Exclude physical measurement metrics and counters unless explicit identifier/entity
    exclude = {'temperature', 'temp', 'humidity', 'pressure', 'latitude', 'longitude', 'bytes', 'pct', 'rate', 'speed', 'idle', 'working_set', 'pool', 'faults', 'elapsed', 'trans_depth', 'body_len'}
    if any(ex in col_lower for ex in exclude):
        if not ('process' in col_lower or 'user' in col_lower or 'device' in col_lower or 'host' in col_lower or 'ip' in col_lower or 'pid' in col_lower):
            return None

    if any(kw in col_lower for kw in ['src_ip', 'ip_src', 'source_ip', 'orig_h']):
        return 'Source IP'
    if any(kw in col_lower for kw in ['dst_ip', 'ip_dst', 'dest_ip', 'resp_h']):
        return 'Destination IP'
    if 'ip' in tokens and not ('bytes' in tokens or 'pkts' in tokens or 'addr' in tokens):
        return 'IP Address'
    if any(kw in col_lower for kw in ['pid', 'cmd', 'command', 'exec', 'id_process', 'creating_process_id']):
        return 'Process'
    if any(kw in col_lower for kw in ['user', 'username', 'usr', 'account']):
        return 'User'
    if any(kw in col_lower for kw in ['device', 'fridge', 'thermostat', 'door', 'light', 'gps', 'weather', 'modbus', 'iot', 'hardware']):
        return 'Device'
    if any(kw in col_lower for kw in ['host', 'hostname', 'machine', 'system', 'asset']):
        return 'Host'
    if any(kw in col_lower for kw in ['proto', 'protocol']):
        return 'Protocol'
    if any(kw in col_lower for kw in ['service', 'service_name']):
        return 'Service'
    if any(kw in col_lower for kw in ['uid', 'session', 'session_id', 'handle']):
        return 'Session'
    if col_lower in ['label', 'type', 'attack', 'anomaly', 'conn_state', 'weird_name']:
        return 'Event'

    return None


def extract_entities_from_datasets(processed_dir: Path) -> pd.DataFrame:
    """
    Traverses processed datasets and extracts deduplicated candidate graph entity attributes.

    Args:
        processed_dir: Path to data/Processed_datasets/

    Returns:
        DataFrame containing extracted entities details.
    """
    records = []

    if not processed_dir.exists():
        return pd.DataFrame()

    dataset_folders = [d for d in sorted(processed_dir.iterdir()) if d.is_dir()]

    # Track seen (dataset, col_name, category) to avoid duplicate Event extractions
    seen_entities = set()

    for d_folder in dataset_folders:
        dataset_name = d_folder.name
        csv_files = sorted(list(d_folder.glob('*.csv')))

        for csv_file in csv_files:
            try:
                df_head = pd.read_csv(csv_file, nrows=100)
                columns = list(df_head.columns)
                df_sample = pd.read_csv(csv_file, low_memory=False)

                for col in columns:
                    category = detect_entity_category_for_column(col)
                    if category:
                        entity_key = (dataset_name, col.strip(), category)
                        if entity_key in seen_entities:
                            continue
                        seen_entities.add(entity_key)

                        dtype_str = str(df_sample[col].dtype)
                        unique_cnt = int(df_sample[col].nunique(dropna=True))

                        records.append({
                            'Entity Name': col,
                            'Entity Type': category,
                            'Source Dataset': dataset_name,
                            'Source File': csv_file.name,
                            'Original Column': col,
                            'Data Type': dtype_str,
                            'Unique Count': unique_cnt
                        })
            except Exception:
                continue

    return pd.DataFrame(records)
