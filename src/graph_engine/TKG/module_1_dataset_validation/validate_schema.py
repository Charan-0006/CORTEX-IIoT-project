"""
Schema Validation Module for Industrial IoT Datasets.

This module provides schema analysis and feature auto-detection capabilities
for evaluating the readiness of raw telemetry/log datasets for graph construction.
It is strictly read-only and does not modify, scale, or clean any dataset.
"""

from pathlib import Path
from typing import Dict, List, Any
import pandas as pd


def detect_timestamp_columns(columns: List[str]) -> List[str]:
    """
    Auto-detect columns containing true timestamp or date/time information.
    Excludes metric counters, performance stats, and duration timers.

    Args:
        columns: List of dataset column names.

    Returns:
        List of matching column names.
    """
    exact_keywords = {'ts', 'timestamp', 'date', 'time', 'datetime', 'event_time', 'date_time', 'created_at', 'time_stamp'}
    false_positives = {'pkts', 'pct', 'faults', 'bytes', 'rate', 'sec', 'transitions', 'queues', 'counts', 'idle_time', 'user_time', 'privileged_time', 'disk_time', 'elapsed_time', 'c1_time', 'c2_time', 'c3_time'}

    detected = []
    for col in columns:
        col_lower = col.lower().strip()

        # Skip performance metric counters containing time-like words (e.g., Processor_pct_ Idle_Time, Memory Page Faults sec)
        if any(fp in col_lower for fp in false_positives):
            # Exception for exact 'time' or 'date' column names
            if col_lower not in {'time', 'date', 'datetime', 'timestamp', 'ts'}:
                continue

        # Check exact or token match
        tokens = set(col_lower.replace('_', ' ').replace('-', ' ').split())
        if col_lower in exact_keywords or bool(tokens & exact_keywords):
            detected.append(col)

    return detected


def detect_identifier_columns(columns: List[str]) -> List[str]:
    """
    Auto-detect columns that serve as true explicit identifiers
    (PID, UID, Device ID, Session ID, User ID, Host ID, UUID, IP Address, MAC Address, Connection UID, etc.).
    Excludes sensor values, physical measurements, and performance counters.

    Args:
        columns: List of dataset column names.

    Returns:
        List of matching explicit identifier column names.
    """
    id_tokens = {'pid', 'uid', 'uuid', 'guid', 'device_id', 'session_id', 'user_id', 'host_id', 'mac', 'src_ip', 'dst_ip', 'orig_h', 'resp_h', 'source_ip', 'destination_ip', 'ip_src', 'ip_dst', 'id_process', 'creating_process_id'}

    # Exclude physical/sensor measurements and metric values
    exclude_keywords = {
        'temperature', 'temp', 'humidity', 'pressure', 'latitude', 'longitude',
        'cpu', 'memory', 'bytes', 'rate', 'speed', 'pct', 'disk', 'idle',
        'working_set', 'pool', 'faults', 'handles', 'condition', 'status', 'state', 'value'
    }

    detected = []
    for col in columns:
        col_lower = col.lower().strip()

        # Skip sensor metrics
        if any(ex in col_lower for ex in exclude_keywords):
            # Unless it's an explicit ID column like 'process_id_process'
            if not ('id' in col_lower and ('process' in col_lower or 'user' in col_lower or 'device' in col_lower or 'host' in col_lower or 'session' in col_lower)):
                continue

        tokens = set(col_lower.replace('_', ' ').replace('-', ' ').split())

        # Exact or targeted token check
        if col_lower in id_tokens or bool(tokens & id_tokens) or col_lower.endswith('_id') or col_lower.endswith(' ip'):
            detected.append(col)
        elif 'ip' in tokens and ('src' in tokens or 'dst' in tokens or 'source' in tokens or 'dest' in tokens):
            detected.append(col)
        elif 'id' in tokens and any(t in tokens for t in ['device', 'host', 'session', 'user', 'process', 'client', 'server']):
            detected.append(col)

    return detected


def detect_entity_columns(columns: List[str]) -> Dict[str, List[str]]:
    """
    Auto-detect potential graph entity node columns (Source IP, Destination IP, Device, User, Process, Asset).

    Args:
        columns: List of dataset column names.

    Returns:
        Dictionary mapping entity categories to detected column names.
    """
    entities = {
        'Source IP': ['src_ip', 'source_ip', 'ip_src', 'orig_h', 'source_address'],
        'Destination IP': ['dst_ip', 'dest_ip', 'destination_ip', 'ip_dst', 'resp_h', 'destination_address'],
        'Device': ['device', 'fridge', 'thermostat', 'door', 'light', 'gps', 'weather', 'modbus', 'iot', 'hardware'],
        'User': ['user', 'username', 'usr', 'account'],
        'Process': ['process', 'pid', 'cmd', 'command', 'exec'],
        'Asset': ['asset', 'host', 'hostname', 'machine', 'system']
    }

    detected_entities = {category: [] for category in entities}

    for col in columns:
        col_lower = col.lower().strip()
        for category, keywords in entities.items():
            if any(kw in col_lower for kw in keywords):
                if col not in detected_entities[category]:
                    detected_entities[category].append(col)

    return detected_entities


def detect_relationship_columns(columns: List[str]) -> Dict[str, List[str]]:
    """
    Auto-detect potential graph relationship/edge attribute columns.

    Args:
        columns: List of dataset column names.

    Returns:
        Dictionary mapping relationship categories to detected column names.
    """
    rel_keywords = {
        'Protocol': ['proto', 'protocol', 'service'],
        'Connection State': ['conn_state', 'state', 'status', 'action', 'event'],
        'Ports': ['port', 'src_port', 'dst_port']
    }

    detected_rels = {cat: [] for cat in rel_keywords}

    for col in columns:
        col_lower = col.lower().strip()
        for cat, keywords in rel_keywords.items():
            if any(kw in col_lower for kw in keywords):
                if col not in detected_rels[cat]:
                    detected_rels[cat].append(col)

    return detected_rels


def detect_label_columns(columns: List[str]) -> List[str]:
    """
    Auto-detect target/attack label columns.

    Args:
        columns: List of dataset column names.

    Returns:
        List of matching label column names.
    """
    keywords = ['label', 'type', 'attack', 'class', 'anomaly', 'category', 'target']
    detected = []
    for col in columns:
        col_lower = col.lower().strip()
        if any(kw in col_lower for kw in keywords):
            detected.append(col)
    return detected


def validate_file_schema(filepath: Path) -> Dict[str, Any]:
    """
    Loads and validates the schema of a single CSV file.

    Args:
        filepath: Path to the target CSV dataset file.

    Returns:
        Dictionary containing schema analysis metrics, column types,
        detected attributes, missing values, duplicates, and file-level graph readiness metrics.
    """
    try:
        df = pd.read_csv(filepath, low_memory=False)
        rows, cols = df.shape
        columns = list(df.columns)
        dtypes = {str(col): str(dtype) for col, dtype in df.dtypes.items()}
        missing_total = int(df.isna().sum().sum())
        missing_by_col = {str(col): int(val) for col, val in df.isna().sum().items()}
        duplicate_total = int(df.duplicated().sum())

        timestamps = detect_timestamp_columns(columns)
        identifiers = detect_identifier_columns(columns)
        entities = detect_entity_columns(columns)
        relationships = detect_relationship_columns(columns)
        labels = detect_label_columns(columns)

        has_timestamp = len(timestamps) > 0
        has_explicit_id = len(identifiers) > 0
        has_composite_id = not has_explicit_id and any(len(v) > 0 for v in entities.values())

        graph_ready = bool(has_timestamp and (has_explicit_id or has_composite_id) and rows > 0 and cols > 0)

        return {
            'success': True,
            'filepath': str(filepath),
            'filename': filepath.name,
            'rows': rows,
            'cols': cols,
            'columns': columns,
            'dtypes': dtypes,
            'missing_total': missing_total,
            'missing_by_col': missing_by_col,
            'duplicate_total': duplicate_total,
            'timestamps': timestamps,
            'identifiers': identifiers,
            'entities': entities,
            'relationships': relationships,
            'labels': labels,
            'has_explicit_identifier': has_explicit_id,
            'has_composite_identifier': has_composite_id,
            'graph_ready': graph_ready,
            'error_message': None
        }

    except Exception as e:
        return {
            'success': False,
            'filepath': str(filepath),
            'filename': filepath.name,
            'rows': 0,
            'cols': 0,
            'columns': [],
            'dtypes': {},
            'missing_total': 0,
            'missing_by_col': {},
            'duplicate_total': 0,
            'timestamps': [],
            'identifiers': [],
            'entities': {},
            'relationships': {},
            'labels': [],
            'has_explicit_identifier': False,
            'has_composite_identifier': False,
            'graph_ready': False,
            'error_message': str(e)
        }
