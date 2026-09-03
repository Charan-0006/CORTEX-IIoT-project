"""
Dataset Validation Main Module.

This is the primary execution script for Module 1 (Graph Dataset Validation).
It coordinates dataset schema inspection, aggregates statistical metrics, generates
validation reports, outputs summary tables, saves machine-readable JSON data,
and renders visualization charts.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any
import pandas as pd
import matplotlib.pyplot as plt

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from module_1_dataset_validation.dataset_statistics import compile_all_dataset_statistics


def generate_validation_report(stats: Dict[str, Any], output_file: Path) -> None:
    """
    Generates a detailed, concise human-readable text validation report.

    Args:
        stats: Aggregated dataset statistics.
        output_file: Target filepath for validation_report.txt.
    """
    lines = []
    lines.append("================================================================================")
    lines.append("                    MODULE 1: GRAPH DATASET VALIDATION REPORT                   ")
    lines.append("================================================================================")
    lines.append("")

    for dataset_name, d_stats in stats.items():
        lines.append(f"DATASET NAME: {dataset_name}")
        lines.append("-" * 80)
        lines.append(f"  • Files Analyzed              : {d_stats['file_count']}")
        lines.append(f"  • Total Rows (Records)        : {d_stats['total_rows']:,}")
        lines.append(f"  • Total Columns               : {d_stats['unique_columns_count']}")

        # Truncate column list for datasets with many columns (> 15)
        cols_list = d_stats['columns_list']
        if len(cols_list) > 15:
            first_15 = ", ".join(cols_list[:15])
            lines.append(f"  • First 15 Columns            : {first_15}")
            lines.append(f"  • Column Details              : ...Remaining columns available in dataset_statistics.json")
        else:
            lines.append(f"  • Columns List                : {', '.join(cols_list)}")

        lines.append(f"  • Total Missing Values        : {d_stats['total_missing_values']:,} ({d_stats['missing_percentage']}%)")
        lines.append(f"  • Total Duplicate Records     : {d_stats['total_duplicate_records']:,} ({round(d_stats['duplicate_ratio'] * 100, 2)}%)")

        ts_str = ", ".join(d_stats['timestamps_detected']) if d_stats['timestamps_detected'] else "No Timestamp Column Detected"
        lines.append(f"  • Detected Timestamp Column(s): {ts_str}")

        id_str = ", ".join(d_stats['identifiers_detected']) if d_stats['identifiers_detected'] else "No Explicit Identifier Detected"
        lines.append(f"  • Detected Identifier Col(s) : {id_str}")

        avail = d_stats['feature_availability']
        detected_feats = [k for k, v in avail.items() if v]
        lines.append(f"  • Detected Graph Features     : {', '.join(detected_feats) if detected_feats else 'None'}")

        if d_stats['load_failures']:
            lines.append("  • Loading Errors/Failures     :")
            for err in d_stats['load_failures']:
                lines.append(f"      - {err}")
        else:
            lines.append("  • Loading Errors/Failures     : None")

        lines.append(f"  • Graph Readiness Score (0-1) : {d_stats['graph_readiness_score']}")
        lines.append(f"  • Graph Readiness Percentage  : {d_stats['graph_readiness_percentage']}%")
        lines.append(f"  • Readiness Level             : {d_stats['readiness_level']}")

        readiness_str = f"PASSED ({d_stats['readiness_level']}) - Ready for Graph Construction" if d_stats['graph_ready'] else f"FAIR/NEEDS IMPROVEMENT ({d_stats['readiness_level']}) - Conditional Graph Readiness"
        lines.append(f"  • GRAPH READINESS CONCLUSION  : {readiness_str}")
        lines.append("")
        lines.append("=" * 80)
        lines.append("")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))


def generate_dataset_summary_csv(stats: Dict[str, Any], output_file: Path) -> None:
    """
    Generates dataset_summary.csv containing key metrics and GRS per dataset category.

    Args:
        stats: Aggregated dataset statistics.
        output_file: Target filepath for dataset_summary.csv.
    """
    rows = []
    for dataset_name, d_stats in stats.items():
        avail = d_stats['feature_availability']
        has_id = len(d_stats['identifiers_detected']) > 0 or (avail['Source IP'] or avail['Device'] or avail['Asset'])
        rows.append({
            'Dataset': dataset_name,
            'Rows': d_stats['total_rows'],
            'Columns': d_stats['unique_columns_count'],
            'Missing Values': d_stats['total_missing_values'],
            'Missing %': d_stats['missing_percentage'],
            'Duplicate Records': d_stats['total_duplicate_records'],
            'Timestamp Available': 'Yes' if avail['Timestamp'] else 'No',
            'Identifier Available': 'Yes' if has_id else 'No',
            'Graph Readiness Score': d_stats['graph_readiness_score'],
            'Readiness Level': d_stats['readiness_level']
        })

    df = pd.DataFrame(rows)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_file, index=False)


def generate_dataset_statistics_json(stats: Dict[str, Any], output_file: Path) -> None:
    """
    Saves complete machine-readable statistics to dataset_statistics.json.

    Args:
        stats: Aggregated dataset statistics.
        output_file: Target filepath for dataset_statistics.json.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=4)


def plot_dataset_distribution(stats: Dict[str, Any], output_file: Path) -> None:
    """
    Renders dataset_distribution.png bar chart showing record counts per dataset.

    Args:
        stats: Aggregated dataset statistics.
        output_file: Target filepath for image.
    """
    dataset_names = list(stats.keys())
    row_counts = [stats[d]['total_rows'] for d in dataset_names]

    plt.figure(figsize=(10, 6))
    colors = ['#1f77b4', '#2ca02c', '#ff7f0e', '#d62728']
    bars = plt.bar(dataset_names, row_counts, color=colors[:len(dataset_names)], edgecolor='black', alpha=0.85)

    plt.title('Dataset Record Distribution (Number of Rows)', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Processed Dataset Category', fontsize=12, labelpad=10)
    plt.ylabel('Total Records (Rows)', fontsize=12, labelpad=10)
    plt.grid(axis='y', linestyle='--', alpha=0.5)

    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2.0,
            height + (max(row_counts) * 0.01),
            f'{height:,}',
            ha='center', va='bottom', fontsize=10, fontweight='bold'
        )

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_missing_values(stats: Dict[str, Any], output_file: Path) -> None:
    """
    Renders missing_values.png bar chart showing Missing Values Percentage (%) per dataset.
    Displays 0.00% explicitly if missing values percentage is zero.

    Args:
        stats: Aggregated dataset statistics.
        output_file: Target filepath for image.
    """
    dataset_names = list(stats.keys())
    missing_pcts = [stats[d]['missing_percentage'] for d in dataset_names]

    plt.figure(figsize=(10, 6))
    colors = ['#4c72b0', '#55a868', '#c44e52', '#8172b0']
    bars = plt.bar(dataset_names, missing_pcts, color=colors[:len(dataset_names)], edgecolor='black', alpha=0.85)

    plt.title('Missing Values Percentage (%) per Processed Dataset', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Processed Dataset Category', fontsize=12, labelpad=10)
    plt.ylabel('Missing Values Percentage (%)', fontsize=12, labelpad=10)
    plt.grid(axis='y', linestyle='--', alpha=0.5)

    max_val = max(missing_pcts) if max(missing_pcts) > 0 else 1.0
    plt.ylim(0, max_val * 1.25)

    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2.0,
            height + (max_val * 0.02),
            f'{height:.2f}%',
            ha='center', va='bottom', fontsize=10, fontweight='bold'
        )

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_feature_availability(stats: Dict[str, Any], output_file: Path) -> None:
    """
    Renders feature_availability.png horizontal bar chart displaying
    availability of target features across datasets.

    Args:
        stats: Aggregated dataset statistics.
        output_file: Target filepath for image.
    """
    features = [
        'Timestamp', 'Identifier', 'Source IP', 'Destination IP',
        'Protocol', 'Attack Label', 'Device', 'User', 'Process', 'Asset'
    ]

    dataset_names = list(stats.keys())
    counts = []
    for feat in features:
        cnt = sum(1 for d in dataset_names if stats[d]['feature_availability'].get(feat, False))
        counts.append(cnt)

    plt.figure(figsize=(10, 7))
    colors = ['#2b5c8f' if c > 0 else '#d9534f' for c in counts]
    bars = plt.barh(features[::-1], counts[::-1], color=colors[::-1], edgecolor='black', alpha=0.85)

    plt.title('Graph Feature Availability Across Processed Datasets', fontsize=14, fontweight='bold', pad=15)
    plt.xlabel('Number of Datasets Supporting Feature (Out of 4)', fontsize=12, labelpad=10)
    plt.ylabel('Detected Graph Feature Category', fontsize=12, labelpad=10)
    plt.xlim(0, len(dataset_names) + 0.5)
    plt.xticks(range(0, len(dataset_names) + 1))
    plt.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars:
        width = bar.get_width()
        plt.text(
            width + 0.08,
            bar.get_y() + bar.get_height() / 2.0,
            f'{int(width)} / {len(dataset_names)}',
            ha='left', va='center', fontsize=10, fontweight='bold'
        )

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def run_module_1_validation() -> None:
    """
    Main entry point to run Module 1 Graph Dataset Validation.
    """
    base_dir = Path(__file__).resolve().parent.parent
    processed_dir = base_dir / 'data' / 'Processed_datasets'

    outputs_dir = base_dir / 'module_1_dataset_validation' / 'outputs'
    visualizations_dir = base_dir / 'module_1_dataset_validation' / 'visualizations'

    print("Starting Refined Module 1: Graph Dataset Validation...")
    print(f"Scanning processed datasets in: {processed_dir}")

    stats = compile_all_dataset_statistics(processed_dir)

    report_file = outputs_dir / 'validation_report.txt'
    summary_csv_file = outputs_dir / 'dataset_summary.csv'
    stats_json_file = outputs_dir / 'dataset_statistics.json'

    print("Generating refined validation report...")
    generate_validation_report(stats, report_file)

    print("Generating refined dataset summary CSV...")
    generate_dataset_summary_csv(stats, summary_csv_file)

    print("Generating refined dataset statistics JSON...")
    generate_dataset_statistics_json(stats, stats_json_file)

    dist_plot = visualizations_dir / 'dataset_distribution.png'
    missing_plot = visualizations_dir / 'missing_values.png'
    feature_plot = visualizations_dir / 'feature_availability.png'

    print("Rendering dataset distribution plot...")
    plot_dataset_distribution(stats, dist_plot)

    print("Rendering refined missing values plot (Percentage %)...")
    plot_missing_values(stats, missing_plot)

    print("Rendering feature availability plot...")
    plot_feature_availability(stats, feature_plot)

    print("\nRefined Module 1 Dataset Validation Completed Successfully!")
    print(f"Outputs updated in: {outputs_dir}")
    print(f"Visualizations updated in: {visualizations_dir}")


if __name__ == '__main__':
    run_module_1_validation()
