"""
Dataset Statistics Module for Industrial IoT Datasets.

This module scans dataset directories dynamically, aggregates statistics
across multiple CSV files for each dataset category, and computes the Graph
Readiness Score (GRS), missing percentage, duplicate ratios, and readiness levels.
"""

import sys
from pathlib import Path
from typing import Dict, List, Any

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from module_1_dataset_validation.validate_schema import validate_file_schema


def discover_processed_datasets(processed_data_dir: Path) -> List[Path]:
    """
    Dynamically discover all dataset directories inside Processed_datasets.

    Args:
        processed_data_dir: Path to data/Processed_datasets/

    Returns:
        List of dataset folder paths.
    """
    if not processed_data_dir.exists():
        return []
    return [d for d in sorted(processed_data_dir.iterdir()) if d.is_dir()]


def calculate_graph_readiness_score(
    schema_loaded: bool,
    has_timestamp: bool,
    has_explicit_id: bool,
    has_composite_id: bool,
    missing_ratio: float,
    duplicate_ratio: float
) -> Dict[str, Any]:
    """
    Computes the Graph Readiness Score (GRS) and classifies readiness level.

    Formula:
      GRS = 0.30 * Schema + 0.20 * Timestamp + 0.20 * Identifier + 0.15 * (1 - Missing Ratio) + 0.15 * (1 - Duplicate Ratio)

    Where:
      - Schema = 1.0 if successfully loaded, else 0.0
      - Timestamp = 1.0 if timestamp exists, else 0.0
      - Identifier = 1.0 if explicit identifier exists, 0.7 if composite identifier exists, else 0.0
      - Missing Ratio = Missing Values / Total Cells
      - Duplicate Ratio = Duplicate Rows / Total Rows
    """
    schema_val = 1.0 if schema_loaded else 0.0
    ts_val = 1.0 if has_timestamp else 0.0

    if has_explicit_id:
        id_val = 1.0
    elif has_composite_id:
        id_val = 0.7
    else:
        id_val = 0.0

    m_ratio_clean = min(max(missing_ratio, 0.0), 1.0)
    d_ratio_clean = min(max(duplicate_ratio, 0.0), 1.0)

    grs = (
        0.30 * schema_val +
        0.20 * ts_val +
        0.20 * id_val +
        0.15 * (1.0 - m_ratio_clean) +
        0.15 * (1.0 - d_ratio_clean)
    )

    # Clamp to [0.0, 1.0]
    grs_clamped = min(max(grs, 0.0), 1.0)
    grs_percentage = round(grs_clamped * 100.0, 2)

    if grs_percentage >= 90.0:
        level = "Excellent"
    elif grs_percentage >= 75.0:
        level = "Good"
    elif grs_percentage >= 60.0:
        level = "Fair"
    else:
        level = "Needs Improvement"

    return {
        'grs_score': round(grs_clamped, 4),
        'grs_percentage': grs_percentage,
        'readiness_level': level,
        'breakdown': {
            'schema': schema_val,
            'timestamp': ts_val,
            'identifier': id_val,
            'missing_ratio': round(m_ratio_clean, 6),
            'duplicate_ratio': round(d_ratio_clean, 6)
        }
    }


def analyze_single_dataset_folder(dataset_dir: Path) -> Dict[str, Any]:
    """
    Analyzes all CSV files contained within a single dataset folder.

    Args:
        dataset_dir: Directory path of the dataset category.

    Returns:
        Aggregated statistics dictionary for the dataset.
    """
    dataset_name = dataset_dir.name
    csv_files = sorted(list(dataset_dir.glob('*.csv')))

    total_rows = 0
    unique_columns = set()
    total_missing = 0
    total_duplicates = 0
    file_results = []

    timestamps_detected = set()
    identifiers_detected = set()

    feature_checks = {
        'Timestamp': False,
        'Identifier': False,
        'Source IP': False,
        'Destination IP': False,
        'Protocol': False,
        'Attack Label': False,
        'Device': False,
        'User': False,
        'Process': False,
        'Asset': False
    }

    schema_all_loaded = True
    load_failures = []

    if not csv_files:
        schema_all_loaded = False

    has_explicit_id_any = False
    has_composite_id_any = False

    for csv_file in csv_files:
        file_res = validate_file_schema(csv_file)
        file_results.append(file_res)

        if not file_res['success']:
            load_failures.append(f"{csv_file.name}: {file_res['error_message']}")
            schema_all_loaded = False
            continue

        total_rows += file_res['rows']
        unique_columns.update(file_res['columns'])
        total_missing += file_res['missing_total']
        total_duplicates += file_res['duplicate_total']

        timestamps_detected.update(file_res['timestamps'])
        identifiers_detected.update(file_res['identifiers'])

        if file_res['has_explicit_identifier']:
            has_explicit_id_any = True
        if file_res['has_composite_identifier']:
            has_composite_id_any = True

        if file_res['timestamps']:
            feature_checks['Timestamp'] = True
        if file_res['identifiers']:
            feature_checks['Identifier'] = True

        entities = file_res['entities']
        if entities.get('Source IP'):
            feature_checks['Source IP'] = True
        if entities.get('Destination IP'):
            feature_checks['Destination IP'] = True
        if entities.get('Device'):
            feature_checks['Device'] = True
        if entities.get('User'):
            feature_checks['User'] = True
        if entities.get('Process'):
            feature_checks['Process'] = True
        if entities.get('Asset'):
            feature_checks['Asset'] = True

        rels = file_res['relationships']
        if rels.get('Protocol'):
            feature_checks['Protocol'] = True

        if file_res['labels']:
            feature_checks['Attack Label'] = True

    total_cols_count = len(unique_columns)
    total_cells = total_rows * total_cols_count if total_rows > 0 and total_cols_count > 0 else 1

    missing_ratio = total_missing / float(total_cells)
    missing_pct = round(missing_ratio * 100.0, 4)

    duplicate_ratio = (total_duplicates / float(total_rows)) if total_rows > 0 else 0.0

    has_ts = feature_checks['Timestamp']
    has_id = has_explicit_id_any or feature_checks['Identifier']

    grs_result = calculate_graph_readiness_score(
        schema_loaded=schema_all_loaded,
        has_timestamp=has_ts,
        has_explicit_id=has_id,
        has_composite_id=has_composite_id_any,
        missing_ratio=missing_ratio,
        duplicate_ratio=duplicate_ratio
    )

    return {
        'dataset_name': dataset_name,
        'dataset_path': str(dataset_dir),
        'file_count': len(csv_files),
        'total_rows': total_rows,
        'unique_columns_count': total_cols_count,
        'columns_list': sorted(list(unique_columns)),
        'total_cells': total_cells,
        'total_missing_values': total_missing,
        'missing_percentage': missing_pct,
        'total_duplicate_records': total_duplicates,
        'duplicate_ratio': round(duplicate_ratio, 6),
        'timestamps_detected': sorted(list(timestamps_detected)),
        'identifiers_detected': sorted(list(identifiers_detected)),
        'feature_availability': feature_checks,
        'graph_readiness_score': grs_result['grs_score'],
        'graph_readiness_percentage': grs_result['grs_percentage'],
        'readiness_level': grs_result['readiness_level'],
        'score_breakdown': grs_result['breakdown'],
        'graph_ready': bool(grs_result['grs_percentage'] >= 75.0),
        'load_failures': load_failures,
        'file_details': file_results
    }


def compile_all_dataset_statistics(processed_data_dir: Path) -> Dict[str, Any]:
    """
    Compiles complete statistics for all processed datasets.

    Args:
        processed_data_dir: Path to base Processed_datasets directory.

    Returns:
        Structured dictionary containing all dataset statistics.
    """
    dataset_dirs = discover_processed_datasets(processed_data_dir)
    results = {}

    for d in dataset_dirs:
        stats = analyze_single_dataset_folder(d)
        results[d.name] = stats

    return results
