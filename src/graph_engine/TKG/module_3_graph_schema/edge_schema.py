"""
Edge Schema Builder Module for Graph Schema Construction.

This module automatically derives data-driven graph edge relationship schemas,
edge properties, cardinalities, constraints, and evidence column mappings from Module 2 outputs.
It performs canonical node type alias normalization to enforce 100% referential integrity.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Alias normalization map to align edge endpoints with defined node types
NODE_TYPE_ALIASES = {
    'Connection': 'Session',
    'Asset': 'Host'
}


def derive_edge_cardinality(rel_type: str, src_node: str, tgt_node: str) -> str:
    """
    Determines cardinality rule for a relationship type.

    Args:
        rel_type: Relationship type label.
        src_node: Source node type label.
        tgt_node: Target node type label.

    Returns:
        Cardinality string (e.g. 1:N, N:M).
    """
    if rel_type in ['communicates_with', 'accesses']:
        return 'N:M'
    elif rel_type in ['generates', 'executes', 'creates', 'runs', 'runs_on']:
        return '1:N'
    elif rel_type in ['uses', 'belongs_to']:
        return 'N:1'
    return 'N:M'


def derive_edge_schemas(m2_outputs_dir: Path) -> pd.DataFrame:
    """
    Derives complete edge relationship schema definitions from Module 2 outputs.

    Args:
        m2_outputs_dir: Path to module_2_graph_feature_engineering/outputs/

    Returns:
        DataFrame containing graph edge schema blueprint.
    """
    rels_file = m2_outputs_dir / 'relationships.csv'
    mapping_file = m2_outputs_dir / 'feature_mapping.csv'

    if not rels_file.exists():
        return pd.DataFrame()

    df_rels = pd.read_csv(rels_file)
    df_mapping = pd.read_csv(mapping_file) if mapping_file.exists() else pd.DataFrame()

    edge_records = []

    for _, row in df_rels.iterrows():
        raw_src = row['Source Entity']
        raw_tgt = row['Target Entity']

        # Normalize node type aliases for 100% referential integrity
        src_node = NODE_TYPE_ALIASES.get(raw_src, raw_src)
        tgt_node = NODE_TYPE_ALIASES.get(raw_tgt, raw_tgt)

        rel_type = row['Relationship Type']
        dataset_source = row['Source Dataset']
        evidence = row.get('Evidence Column(s)', row.get('Supporting Columns', 'Unspecified'))

        cardinality = derive_edge_cardinality(rel_type, src_node, tgt_node)

        # 1. Primary Edge Link
        edge_records.append({
            'Edge Type': rel_type,
            'Source Node Type': src_node,
            'Target Node Type': tgt_node,
            'Edge Property': 'timestamp',
            'Data Type': 'timestamp',
            'Cardinality': cardinality,
            'Constraint': 'FOREIGN_KEY_SOURCE_AND_TARGET',
            'Evidence Column(s)': evidence,
            'Source Dataset': dataset_source
        })

        # 2. Add Relationship Attributes from feature mapping
        if not df_mapping.empty:
            rel_attrs = df_mapping[
                (df_mapping['Mapped Classification'] == 'Relationship Attribute') &
                (df_mapping['Source Dataset'] == dataset_source)
            ]
            for _, attr_row in rel_attrs.iterrows():
                edge_records.append({
                    'Edge Type': rel_type,
                    'Source Node Type': src_node,
                    'Target Node Type': tgt_node,
                    'Edge Property': attr_row['Original Column'],
                    'Data Type': attr_row['Data Type'],
                    'Cardinality': cardinality,
                    'Constraint': 'OPTIONAL_EDGE_PROPERTY',
                    'Evidence Column(s)': attr_row['Original Column'],
                    'Source Dataset': dataset_source
                })

    return pd.DataFrame(edge_records)
