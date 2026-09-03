"""
Node Schema Builder Module for Graph Schema Construction.

This module automatically derives data-driven graph node schemas, properties,
primary keys, and attribute constraints from Module 2 feature engineering outputs.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def derive_primary_key_for_node(node_type: str, df_entities: pd.DataFrame) -> str:
    """
    Derives the primary key attribute name for a given node type.

    Args:
        node_type: Node type label.
        df_entities: Module 2 entities DataFrame.

    Returns:
        Primary identifier attribute name.
    """
    matches = df_entities[df_entities['Entity Type'] == node_type]
    if not matches.empty:
        # Prefer explicit ID columns if available
        id_cols = [c for c in matches['Entity Name'] if any(k in c.lower() for k in ['id', 'ip', 'pid', 'uid', 'host', 'user', 'device'])]
        if id_cols:
            return id_cols[0]
        return matches['Entity Name'].iloc[0]

    defaults = {
        'Source IP': 'src_ip',
        'Destination IP': 'dst_ip',
        'IP Address': 'ip',
        'Process': 'PID',
        'User': 'user',
        'Host': 'host',
        'Device': 'device_id',
        'Protocol': 'proto',
        'Service': 'service',
        'Session': 'uid',
        'Event': 'event_id',
        'Asset': 'asset_id'
    }
    return defaults.get(node_type, 'node_id')


def derive_node_schemas(m2_outputs_dir: Path) -> pd.DataFrame:
    """
    Derives complete node schema definitions from Module 2 output files.

    Args:
        m2_outputs_dir: Path to module_2_graph_feature_engineering/outputs/

    Returns:
        DataFrame containing graph node schema blueprint.
    """
    entities_file = m2_outputs_dir / 'entities.csv'
    mapping_file = m2_outputs_dir / 'feature_mapping.csv'
    features_file = m2_outputs_dir / 'entity_features.csv'

    if not entities_file.exists() or not mapping_file.exists():
        return pd.DataFrame()

    df_entities = pd.read_csv(entities_file)
    df_mapping = pd.read_csv(mapping_file)
    df_features = pd.read_csv(features_file) if features_file.exists() else pd.DataFrame()

    node_records = []
    unique_node_types = sorted(df_entities['Entity Type'].unique())

    for n_type in unique_node_types:
        primary_key = derive_primary_key_for_node(n_type, df_entities)

        # Get all entities of this type
        type_entities = df_entities[df_entities['Entity Type'] == n_type]

        # 1. Add Primary Key Property
        pk_dataset = type_entities['Source Dataset'].iloc[0] if not type_entities.empty else 'System'
        pk_dtype = type_entities['Data Type'].iloc[0] if not type_entities.empty else 'str'

        node_records.append({
            'Node Type': n_type,
            'Property Name': primary_key,
            'Data Type': pk_dtype,
            'Is Primary Key': 'True',
            'Requirement': 'Mandatory (NOT NULL)',
            'Description': f'Primary unique identifier for {n_type} node',
            'Source Dataset': pk_dataset
        })

        # 2. Add associated properties from feature mapping
        mapped_attrs = df_mapping[
            (df_mapping['Mapped Entity / Relationship'] == n_type) |
            (df_mapping['Mapped Classification'] == 'Graph Attribute')
        ]

        # Add node-specific attributes
        seen_props = {primary_key}
        for _, row in type_entities.iterrows():
            col_name = row['Original Column']
            if col_name not in seen_props:
                seen_props.add(col_name)
                node_records.append({
                    'Node Type': n_type,
                    'Property Name': col_name,
                    'Data Type': row['Data Type'],
                    'Is Primary Key': 'False',
                    'Requirement': 'Mandatory (NOT NULL)',
                    'Description': f'Entity attribute representing {col_name}',
                    'Source Dataset': row['Source Dataset']
                })

        # Add metric attributes mapped to Graph Attribute
        graph_attrs = df_mapping[df_mapping['Mapped Classification'] == 'Graph Attribute']
        for _, row in graph_attrs.iterrows():
            col_name = row['Original Column']

            # Match dataset relevance
            if row['Source Dataset'] in type_entities['Source Dataset'].values and col_name not in seen_props:
                seen_props.add(col_name)
                node_records.append({
                    'Node Type': n_type,
                    'Property Name': col_name,
                    'Data Type': row['Data Type'],
                    'Is Primary Key': 'False',
                    'Requirement': 'Optional (NULLABLE)',
                    'Description': f'Numerical telemetry metric: {row["Description"]}',
                    'Source Dataset': row['Source Dataset']
                })

    return pd.DataFrame(node_records)
