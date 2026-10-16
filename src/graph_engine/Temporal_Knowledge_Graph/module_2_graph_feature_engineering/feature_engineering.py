"""
Graph Feature Engineering Module.

This module computes graph-oriented feature vectors for extracted entities.

MATHEMATICAL FORMULATION DOCUMENTATION:

1. Entity Set Definition:
   E = {e₁, e₂, ..., eₙ}
   Represents the set of all unique graph entity nodes extracted from raw datasets.

2. Relationship Set Definition:
   R = {(eᵢ, eⱼ) | eᵢ, eⱼ ∈ E}
   Represents candidate directed relationships between entities eᵢ and eⱼ.

3. Entity Feature Vector:
   F(e) = {f₁, f₂, ..., fₖ}
   Where each f_m represents an engineered graph-oriented attribute:
   f₁: Entity ID (Semantic Identifier e.g., SRCIP_001, PROC_001, DEVICE_001)
   f₂: Entity Type Category
   f₃: Dataset Source Context
   f₄: Occurrence Frequency Freq(e)
   f₅: Temporal Availability Flag
   f₆: Attack Label Availability Flag
   f₇: Relationship Degree Degree(e)
   f₈: Attribute Count
   f₉: Composite Key Availability
   f₁₀: Graph Readiness Tag (Ready, Conditional, Metadata Only)

4. Mathematical Metrics:
   - Entity Frequency: Freq(e) = Total occurrences of entity e across dataset logs.
   - Relationship Degree: Degree(e) = |{(e, e') ∈ R} ∪ {(e', e) ∈ R}|
"""

import sys
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Prefix mapping for semantic Entity IDs
ENTITY_PREFIX_MAP = {
    'Source IP': 'SRCIP',
    'Destination IP': 'DSTIP',
    'IP Address': 'IP',
    'Process': 'PROC',
    'User': 'USER',
    'Host': 'HOST',
    'Device': 'DEVICE',
    'Protocol': 'PROTO',
    'Service': 'SVC',
    'Session': 'SESS',
    'Event': 'EVT',
    'Asset': 'ASSET'
}


def build_entity_feature_vectors(df_entities: pd.DataFrame, df_rels: pd.DataFrame, validation_stats: Dict[str, Any]) -> pd.DataFrame:
    """
    Constructs graph feature vectors F(e) with semantic Entity IDs and 3-level readiness tags.

    Args:
        df_entities: DataFrame produced by entity_extraction.py.
        df_rels: DataFrame produced by relationship_extraction.py.
        validation_stats: Statistics loaded from Module 1 (dataset_statistics.json).

    Returns:
        DataFrame containing engineered entity feature vectors.
    """
    feature_records = []

    if df_entities.empty:
        return pd.DataFrame()

    # Track sequence counters per entity type prefix
    prefix_counters = {p: 0 for p in ENTITY_PREFIX_MAP.values()}

    for idx, row in df_entities.iterrows():
        entity_name = row['Entity Name']
        entity_type = row['Entity Type']
        dataset_source = row['Source Dataset']
        unique_cnt = row['Unique Count']

        # Generate semantic Entity ID (e.g., SRCIP_001, PROC_001, USER_001)
        prefix = ENTITY_PREFIX_MAP.get(entity_type, 'ENT')
        prefix_counters[prefix] = prefix_counters.get(prefix, 0) + 1
        seq_num = prefix_counters[prefix]
        semantic_entity_id = f"{prefix}_{seq_num:03d}"

        # Temporal availability check from Module 1 stats
        ds_stats = validation_stats.get(dataset_source, {})
        has_timestamp = bool(ds_stats.get('timestamps_detected', []))

        # Attack label availability check
        has_attack_label = bool(ds_stats.get('feature_availability', {}).get('Attack Label', False))

        # Relationship degree calculation
        rel_degree = 0
        if not df_rels.empty:
            rel_matches = df_rels[
                ((df_rels['Source Entity'] == entity_type) | (df_rels['Target Entity'] == entity_type)) &
                (df_rels['Source Dataset'] == dataset_source)
            ]
            rel_degree = len(rel_matches)

        attr_count = ds_stats.get('unique_columns_count', 1)
        composite_key = bool(has_timestamp and (rel_degree > 0 or entity_type in ['Device', 'Process', 'Source IP', 'Host']))

        # Graph Readiness Tag (3 Levels: Ready, Conditional, Metadata Only)
        if has_timestamp and rel_degree > 0:
            readiness_tag = 'Ready'
        elif has_timestamp or rel_degree > 0 or composite_key:
            readiness_tag = 'Conditional'
        else:
            readiness_tag = 'Metadata Only'

        feature_records.append({
            'Entity ID': semantic_entity_id,
            'Entity Type': entity_type,
            'Dataset Source': dataset_source,
            'Occurrence Frequency': unique_cnt,
            'Temporal Availability': 'Yes' if has_timestamp else 'No',
            'Attack Label Availability': 'Yes' if has_attack_label else 'No',
            'Relationship Participation': rel_degree,
            'Attribute Count': attr_count,
            'Composite Key Availability': 'Yes' if composite_key else 'No',
            'Graph Readiness Tag': readiness_tag
        })

    return pd.DataFrame(feature_records)
