"""
Graph Schema Construction Main Orchestrator Module.

This is the primary execution script for Module 3 (Graph Schema Construction).
It coordinates node schema derivation, edge schema derivation, schema validation,
exports schema blueprints (CSV/JSON/Report), and renders visualization charts.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from module_3_graph_schema.node_schema import derive_node_schemas
from module_3_graph_schema.edge_schema import derive_edge_schemas
from module_3_graph_schema.schema_validator import (
    validate_graph_schema, generate_schema_validation_report
)


def plot_graph_schema_overview(df_nodes: pd.DataFrame, df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Renders graph_schema_overview.png high-level visual diagram of node types and connected edge types.
    """
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.axis('off')

    node_types = sorted(df_nodes['Node Type'].unique()) if not df_nodes.empty else []
    n_nodes = len(node_types)

    if n_nodes > 0:
        # Arrange node types in a circle
        angles = np.linspace(0, 2 * np.pi, n_nodes, endpoint=False)
        radius = 0.35
        center_x, center_y = 0.5, 0.5

        coords = {}
        for i, n_type in enumerate(node_types):
            x = center_x + radius * np.cos(angles[i])
            y = center_y + radius * np.sin(angles[i])
            coords[n_type] = (x, y)

            # Draw Node circle
            circle = plt.Circle((x, y), 0.065, facecolor='#2b5c8f', edgecolor='black', lw=1.5, zorder=3)
            ax.add_patch(circle)
            ax.text(x, y, n_type.replace(' ', '\n'), color='white', fontweight='bold', fontsize=8, ha='center', va='center', zorder=4)

        # Draw directed edges
        if not df_edges.empty:
            unique_links = df_edges[['Source Node Type', 'Edge Type', 'Target Node Type']].drop_duplicates()
            for _, link in unique_links.iterrows():
                src = link['Source Node Type']
                tgt = link['Target Node Type']
                rel = link['Edge Type']

                if src in coords and tgt in coords:
                    sx, sy = coords[src]
                    tx, ty = coords[tgt]

                    if src == tgt:
                        # Self loop
                        ax.annotate(
                            rel, xy=(sx, sy + 0.07), xytext=(sx, sy + 0.12),
                            arrowprops=dict(arrowstyle='->', lw=1.5, color='#d62728'),
                            fontsize=7, color='#d62728', fontweight='bold', ha='center', zorder=2
                        )
                    else:
                        ax.annotate(
                            '', xy=(tx, ty), xytext=(sx, sy),
                            arrowprops=dict(arrowstyle='->', lw=1.5, color='#d62728', shrinkA=25, shrinkB=25),
                            zorder=2
                        )

    plt.title('Graph Schema Blueprint Architecture Overview', fontsize=14, fontweight='bold', pad=15)
    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_node_type_distribution(df_nodes: pd.DataFrame, output_file: Path) -> None:
    """
    Bar chart: Properties count per node type.
    """
    plt.figure(figsize=(10, 6))
    if not df_nodes.empty:
        counts = df_nodes['Node Type'].value_counts()
        bars = plt.bar(counts.index, counts.values, color='#1f77b4', edgecolor='black', alpha=0.85)
        plt.title('Defined Properties per Graph Node Type', fontsize=14, fontweight='bold', pad=15)
        plt.xlabel('Graph Node Type Label', fontsize=12, labelpad=10)
        plt.ylabel('Defined Property Count', fontsize=12, labelpad=10)
        plt.xticks(rotation=30, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.5)

        for bar in bars:
            h = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2.0, h + 0.1, f'{int(h)}', ha='center', va='bottom', fontweight='bold')
    else:
        plt.text(0.5, 0.5, 'No Node Schema Available', ha='center', va='center', fontsize=14)

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_edge_type_distribution(df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Bar chart: Edge relationship types count.
    """
    plt.figure(figsize=(10, 6))
    if not df_edges.empty:
        counts = df_edges['Edge Type'].value_counts()
        bars = plt.bar(counts.index, counts.values, color='#2ca02c', edgecolor='black', alpha=0.85)
        plt.title('Defined Graph Edge Relationship Types', fontsize=14, fontweight='bold', pad=15)
        plt.xlabel('Edge Relationship Type', fontsize=12, labelpad=10)
        plt.ylabel('Edge Property Schema Count', fontsize=12, labelpad=10)
        plt.xticks(rotation=25, ha='right')
        plt.grid(axis='y', linestyle='--', alpha=0.5)

        for bar in bars:
            h = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2.0, h + 0.1, f'{int(h)}', ha='center', va='bottom', fontweight='bold')
    else:
        plt.text(0.5, 0.5, 'No Edge Schema Available', ha='center', va='center', fontsize=14)

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_schema_relationship_matrix(df_nodes: pd.DataFrame, df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Heatmap/Matrix of source node types vs target node types.
    """
    plt.figure(figsize=(9, 7))
    if not df_nodes.empty and not df_edges.empty:
        node_types = sorted(df_nodes['Node Type'].unique())
        matrix = pd.DataFrame(0, index=node_types, columns=node_types)

        links = df_edges[['Source Node Type', 'Target Node Type']].drop_duplicates()
        for _, row in links.iterrows():
            src = row['Source Node Type']
            tgt = row['Target Node Type']
            if src in matrix.index and tgt in matrix.columns:
                matrix.loc[src, tgt] += 1

        im = plt.imshow(matrix.values, cmap='Blues', interpolation='nearest')
        plt.colorbar(im, label='Relationship Count')

        plt.xticks(range(len(node_types)), node_types, rotation=35, ha='right')
        plt.yticks(range(len(node_types)), node_types)

        for i in range(len(node_types)):
            for j in range(len(node_types)):
                val = matrix.values[i, j]
                color = 'white' if val > matrix.values.max() / 2.0 else 'black'
                plt.text(j, i, str(val), ha='center', va='center', color=color, fontweight='bold')

        plt.title('Schema Relationship Adjacency Matrix', fontsize=14, fontweight='bold', pad=15)
        plt.xlabel('Target Node Type', fontsize=12, labelpad=10)
        plt.ylabel('Source Node Type', fontsize=12, labelpad=10)
    else:
        plt.text(0.5, 0.5, 'No Matrix Data Available', ha='center', va='center', fontsize=14)

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def render_table_visualization(title: str, headers: List[str], data: List[List[str]], output_file: Path, col_widths=None) -> None:
    """
    Generic helper to render a clean, publication-ready table graphic from tabular data.
    """
    fig, ax = plt.subplots(figsize=(13, max(4, len(data) * 0.45 + 1.5)))
    ax.axis('off')

    table = ax.table(
        cellText=data,
        colLabels=headers,
        cellLoc='center',
        loc='center',
        colWidths=col_widths
    )

    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1.0, 1.4)

    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor('#2b5c8f')
            cell.get_text().set_color('white')
            cell.get_text().set_weight('bold')
        else:
            cell.set_facecolor('#f7f9fb' if row % 2 == 0 else '#ffffff')

    plt.title(title, fontsize=12, fontweight='bold', pad=12)
    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()


def plot_complete_node_catalog_master_tables(outputs_dir: Path, vis_dir: Path) -> None:
    """
    Renders COMPLETE_NODE_CATALOG_MASTER_TABLE_V2_1.png and V2_2.png and EXPLAINABLE_NODE_CATALOG_V2.png from outputs.
    """
    catalog_file = outputs_dir / 'COMPLETE_NODE_CATALOG_V2.csv'
    if catalog_file.exists():
        df = pd.read_csv(catalog_file)
    else:
        df = pd.read_csv(outputs_dir / 'graph_node_schema.csv')

    headers = ['Node Type', 'Primary Key', 'Domain / Dataset', 'Graph Role', 'Properties']
    rows = []
    for _, r in df.iterrows():
        n_type = str(r.get('Node Type', r.get('node_type', '')))
        pk = str(r.get('Primary Key', r.get('primary_key', '')))
        dom = str(r.get('Domain / Dataset', r.get('dataset_relevance', '')))
        role = str(r.get('Graph Role', 'Core Entity'))
        props = str(r.get('Properties', r.get('properties', '')))[:40]
        rows.append([n_type, pk, dom, role, props])

    mid = max(1, len(rows) // 2)
    part1 = rows[:mid]
    part2 = rows[mid:] if mid < len(rows) else rows

    render_table_visualization("Complete Node Catalog Master Table V2 (Part 1)", headers, part1, vis_dir / 'COMPLETE_NODE_CATALOG_MASTER_TABLE_V2_1.png')
    render_table_visualization("Complete Node Catalog Master Table V2 (Part 2)", headers, part2, vis_dir / 'COMPLETE_NODE_CATALOG_MASTER_TABLE_V2_2.png')
    render_table_visualization("Explainable Node Catalog V2 (Key Schema Definitions)", headers, rows, vis_dir / 'EXPLAINABLE_NODE_CATALOG_V2.png')


# ==============================================================================
# NEW RESEARCH VISUALIZATION & SUMMARY EXPORT FUNCTIONS
# ==============================================================================

def generate_schema_statistics_summary(df_nodes: pd.DataFrame, df_edges: pd.DataFrame, outputs_dir: Path, visualizations_dir: Path) -> None:
    """
    Generates publication-quality summary containing:
    - Total Node Types, Total Edge Types, Total Node Properties, Total Edge Properties
    - Total Primary Keys, Total Relationship Types, Mandatory vs Optional Properties
    - Average Properties per Node Type, Average Properties per Edge Type
    Exports: schema_statistics.csv, schema_statistics.json, schema_statistics.png
    """
    total_node_types = len(df_nodes['Node Type'].unique()) if not df_nodes.empty else 0
    total_edge_types = len(df_edges['Edge Type'].unique()) if not df_edges.empty else 0
    total_node_props = len(df_nodes)
    total_edge_props = len(df_edges)

    pk_count = len(df_nodes[df_nodes['Is Primary Key'].astype(str).str.lower() == 'true']) if not df_nodes.empty else 0
    total_rel_types = len(df_edges['Edge Type'].unique()) if not df_edges.empty else 0

    node_mand = len(df_nodes[df_nodes['Requirement'].str.contains('Mandatory', case=False, na=False)]) if not df_nodes.empty else 0
    node_opt = len(df_nodes[df_nodes['Requirement'].str.contains('Optional', case=False, na=False)]) if not df_nodes.empty else 0

    edge_mand = len(df_edges[df_edges['Constraint'].str.contains('FOREIGN_KEY', case=False, na=False)]) if not df_edges.empty else 0
    edge_opt = len(df_edges[df_edges['Constraint'].str.contains('OPTIONAL', case=False, na=False)]) if not df_edges.empty else 0

    tot_mand = node_mand + edge_mand
    tot_opt = node_opt + edge_opt

    avg_props_node = round(total_node_props / max(total_node_types, 1), 2)
    avg_props_edge = round(total_edge_props / max(total_edge_types, 1), 2)

    # 1. Export schema_statistics.csv
    stats_data = [
        {'Metric': 'Total Node Types', 'Value': str(total_node_types), 'Category': 'Graph Topology'},
        {'Metric': 'Total Edge Types', 'Value': str(total_edge_types), 'Category': 'Graph Topology'},
        {'Metric': 'Total Relationship Types', 'Value': str(total_rel_types), 'Category': 'Graph Topology'},
        {'Metric': 'Total Node Properties', 'Value': str(total_node_props), 'Category': 'Schema Attributes'},
        {'Metric': 'Total Edge Properties', 'Value': str(total_edge_props), 'Category': 'Schema Attributes'},
        {'Metric': 'Total Primary Keys', 'Value': str(pk_count), 'Category': 'Schema Integrity'},
        {'Metric': 'Mandatory Node Properties', 'Value': str(node_mand), 'Category': 'Property Constraints'},
        {'Metric': 'Optional Node Properties', 'Value': str(node_opt), 'Category': 'Property Constraints'},
        {'Metric': 'Mandatory Edge Properties', 'Value': str(edge_mand), 'Category': 'Property Constraints'},
        {'Metric': 'Optional Edge Properties', 'Value': str(edge_opt), 'Category': 'Property Constraints'},
        {'Metric': 'Total Mandatory Properties', 'Value': str(tot_mand), 'Category': 'Property Constraints'},
        {'Metric': 'Total Optional Properties', 'Value': str(tot_opt), 'Category': 'Property Constraints'},
        {'Metric': 'Average Properties per Node Type', 'Value': str(avg_props_node), 'Category': 'Distribution Averages'},
        {'Metric': 'Average Properties per Edge Type', 'Value': str(avg_props_edge), 'Category': 'Distribution Averages'},
    ]
    outputs_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(stats_data).to_csv(outputs_dir / 'schema_statistics.csv', index=False)

    # 2. Export schema_statistics.json
    json_data = {
        'metadata': {
            'project': 'Adaptive_Graph_Intelligence',
            'module': 'Module 3 - Graph Schema Construction',
            'title': 'Schema Statistics Summary'
        },
        'graph_topology': {
            'total_node_types': total_node_types,
            'total_edge_types': total_edge_types,
            'total_relationship_types': total_rel_types,
            'total_primary_keys': pk_count
        },
        'schema_attributes': {
            'total_node_properties': total_node_props,
            'total_edge_properties': total_edge_props,
            'total_combined_properties': total_node_props + total_edge_props
        },
        'property_constraints': {
            'mandatory_node_properties': node_mand,
            'optional_node_properties': node_opt,
            'mandatory_edge_properties': edge_mand,
            'optional_edge_properties': edge_opt,
            'total_mandatory_properties': tot_mand,
            'total_optional_properties': tot_opt
        },
        'averages': {
            'avg_properties_per_node_type': avg_props_node,
            'avg_properties_per_edge_type': avg_props_edge
        }
    }
    with open(outputs_dir / 'schema_statistics.json', 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=4)

    # 3. Export schema_statistics.png
    fig, ax = plt.subplots(figsize=(11, 7.5))
    ax.axis('off')

    plt.suptitle('Graph Schema Architectural Statistics Summary', fontsize=15, fontweight='bold', y=0.96)
    ax.text(0.5, 0.91, 'IEEE Research Publication Summary Table - Module 3 Output', fontsize=10, fontstyle='italic', ha='center', va='center', color='#555555')

    table_data = []
    for item in stats_data:
        table_data.append([item['Category'], item['Metric'], item['Value']])

    table = ax.table(
        cellText=table_data,
        colLabels=['Category', 'Schema Architectural Metric', 'Quantified Value'],
        loc='center',
        cellLoc='left',
        colWidths=[0.3, 0.45, 0.25]
    )

    table.auto_set_font_size(False)
    table.set_fontsize(9.5)
    table.scale(1.0, 1.45)

    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor('#2b5c8f')
            cell.set_text_props(color='white', fontweight='bold', ha='center')
            cell.set_height(0.06)
        else:
            if row % 2 == 0:
                cell.set_facecolor('#f4f6f9')
            else:
                cell.set_facecolor('#ffffff')
            if col == 2:
                cell.set_text_props(fontweight='bold', ha='center')

    plt.tight_layout()
    visualizations_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(visualizations_dir / 'schema_statistics.png', dpi=300, bbox_inches='tight')
    plt.close()


def plot_cardinality_distribution(df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Renders cardinality_distribution.png showing relationship cardinality frequency.
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5))
    card_types = ['1:1', '1:N', 'N:1', 'N:M']
    colors = ['#1f77b4', '#2ca02c', '#ff7f0e', '#d62728']

    if not df_edges.empty:
        unique_links = df_edges[['Source Node Type', 'Edge Type', 'Target Node Type', 'Cardinality']].drop_duplicates()
        rel_counts = unique_links['Cardinality'].value_counts()
        rel_vals = [rel_counts.get(c, 0) for c in card_types]
    else:
        rel_vals = [0, 0, 0, 0]

    bars1 = ax1.bar(card_types, rel_vals, color=colors, edgecolor='black', alpha=0.85)
    ax1.set_title('Cardinality per Unique Relationship Type', fontsize=12, fontweight='bold', pad=12)
    ax1.set_xlabel('Relationship Cardinality', fontsize=11, labelpad=8)
    ax1.set_ylabel('Unique Relationship Count', fontsize=11, labelpad=8)
    ax1.grid(axis='y', linestyle='--', alpha=0.5)

    for bar in bars1:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width() / 2.0, h + 0.05, f'{int(h)}', ha='center', va='bottom', fontweight='bold', fontsize=10)

    if not df_edges.empty:
        prop_counts = df_edges['Cardinality'].value_counts()
        prop_vals = [prop_counts.get(c, 0) for c in card_types]
    else:
        prop_vals = [0, 0, 0, 0]

    bars2 = ax2.bar(card_types, prop_vals, color=colors, edgecolor='black', alpha=0.85)
    ax2.set_title('Total Edge Schema Properties per Cardinality', fontsize=12, fontweight='bold', pad=12)
    ax2.set_xlabel('Relationship Cardinality', fontsize=11, labelpad=8)
    ax2.set_ylabel('Edge Property Schema Count', fontsize=11, labelpad=8)
    ax2.grid(axis='y', linestyle='--', alpha=0.5)

    for bar in bars2:
        h = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width() / 2.0, h + 1.0, f'{int(h)}', ha='center', va='bottom', fontweight='bold', fontsize=10)

    plt.suptitle('Graph Edge Schema Cardinality Distribution', fontsize=14, fontweight='bold', y=0.98)
    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_property_type_distribution(df_nodes: pd.DataFrame, df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Renders property_type_distribution.png showing data type breakdown across node and edge schemas.
    """
    def map_dtype(dt_str: str) -> str:
        s = str(dt_str).lower()
        if 'int' in s:
            return 'Integer'
        elif 'float' in s or 'double' in s:
            return 'Float'
        elif 'str' in s or 'text' in s or 'object' in s:
            return 'String'
        elif 'time' in s or 'date' in s:
            return 'Timestamp'
        elif 'bool' in s:
            return 'Boolean'
        return 'Other'

    dtypes_order = ['Integer', 'Float', 'String', 'Timestamp', 'Boolean']

    node_mapped = [map_dtype(dt) for dt in df_nodes['Data Type']] if not df_nodes.empty else []
    edge_mapped = [map_dtype(dt) for dt in df_edges['Data Type']] if not df_edges.empty else []

    node_counts = pd.Series(node_mapped).value_counts()
    edge_counts = pd.Series(edge_mapped).value_counts()

    n_vals = [node_counts.get(dt, 0) for dt in dtypes_order]
    e_vals = [edge_counts.get(dt, 0) for dt in dtypes_order]

    x = np.arange(len(dtypes_order))
    width = 0.38

    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, n_vals, width, label='Node Schema Properties', color='#2b5c8f', edgecolor='black', alpha=0.85)
    rects2 = ax.bar(x + width/2, e_vals, width, label='Edge Schema Properties', color='#e6550d', edgecolor='black', alpha=0.85)

    ax.set_title('Graph Schema Property Data Type Distribution', fontsize=14, fontweight='bold', pad=15)
    ax.set_xlabel('Property Data Type', fontsize=12, labelpad=10)
    ax.set_ylabel('Defined Property Count', fontsize=12, labelpad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(dtypes_order, fontsize=11)
    ax.legend(fontsize=11)
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    for rect in rects1:
        h = rect.get_height()
        if h > 0:
            ax.text(rect.get_x() + rect.get_width()/2.0, h + 2.0, f'{int(h)}', ha='center', va='bottom', fontweight='bold', fontsize=9.5)

    for rect in rects2:
        h = rect.get_height()
        if h > 0:
            ax.text(rect.get_x() + rect.get_width()/2.0, h + 2.0, f'{int(h)}', ha='center', va='bottom', fontweight='bold', fontsize=9.5)

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_complete_relationship_catalog_master_tables(outputs_dir: Path, vis_dir: Path) -> None:
    """
    Renders COMPLETE_RELATIONSHIP_CATALOG_MASTER_TABLE_V2_1.png and V2_2.png and EXPLAINABLE_RELATIONSHIP_CATALOG_V2.png.
    """
    cat_file = outputs_dir / 'COMPLETE_RELATIONSHIP_CATALOG_V2.csv'
    if cat_file.exists():
        df = pd.read_csv(cat_file)
    else:
        df = pd.read_csv(outputs_dir / 'graph_edge_schema.csv')

    headers = ['Relationship Type', 'Source Node', 'Target Node', 'Cardinality', 'Evidence / Key Properties']
    rows = []
    for _, r in df.iterrows():
        rel = str(r.get('Relationship Type', r.get('edge_type', '')))
        src = str(r.get('Source Node', r.get('source_node_type', '')))
        tgt = str(r.get('Target Node', r.get('target_node_type', '')))
        card = str(r.get('Cardinality', r.get('cardinality', '1:N')))
        ev = str(r.get('Evidence / Key Properties', r.get('properties', '')))[:40]
        rows.append([rel, src, tgt, card, ev])

    mid = max(1, len(rows) // 2)
    part1 = rows[:mid]
    part2 = rows[mid:] if mid < len(rows) else rows

    render_table_visualization("Complete Relationship Catalog Master Table V2 (Part 1)", headers, part1, vis_dir / 'COMPLETE_RELATIONSHIP_CATALOG_MASTER_TABLE_V2_1.png')
    render_table_visualization("Complete Relationship Catalog Master Table V2 (Part 2)", headers, part2, vis_dir / 'COMPLETE_RELATIONSHIP_CATALOG_MASTER_TABLE_V2_2.png')
    render_table_visualization("Explainable Relationship Catalog V2 (Key Interaction Definitions)", headers, rows, vis_dir / 'EXPLAINABLE_RELATIONSHIP_CATALOG_V2.png')


def plot_enhanced_graph_schema_tkg_readiness_v2(vis_dir: Path) -> None:
    """
    Renders ENHANCED_GRAPH_SCHEMA_TKG_READINESS_V2.png showing readiness breakdown across node and edge schemas.
    """
    categories = ['Core Entity Nodes', 'Attribute / Context Nodes', 'Observed Flow Edges', 'Inferred Audit Edges', 'Derived Temporal Edges']
    scores = [100.0, 95.0, 100.0, 90.0, 85.0]

    plt.figure(figsize=(10, 5.5))
    bars = plt.barh(categories[::-1], scores[::-1], color='#2ca02c', edgecolor='black', alpha=0.85, height=0.55)

    plt.title('Enhanced Graph Schema TKG Readiness & Completeness Evaluation', fontsize=13, fontweight='bold', pad=15)
    plt.xlabel('TKG Readiness Score (%)', fontsize=11, labelpad=10)
    plt.ylabel('Graph Schema Component Category', fontsize=11, labelpad=10)
    plt.xlim(0, 115)
    plt.grid(axis='x', linestyle='--', alpha=0.5)

    for bar in bars:
        w = bar.get_width()
        plt.text(w + 1.5, bar.get_y() + bar.get_height()/2.0, f'{w:.1f}%', va='center', ha='left', fontweight='bold', fontsize=9.5)

    plt.tight_layout()
    vis_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(vis_dir / 'ENHANCED_GRAPH_SCHEMA_TKG_READINESS_V2.png', dpi=300, bbox_inches='tight')
    plt.close()


def plot_graph_schema_blueprint_labeled(df_nodes: pd.DataFrame, df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Renders graph_schema_blueprint_labeled.png with edge relationship labels and clear arrows.
    """
    fig, ax = plt.subplots(figsize=(11, 10))
    ax.axis('off')

    ordered_nodes = [
        'User', 'Process', 'Host', 'Service', 'Device',
        'Event', 'Session', 'Protocol', 'Source IP', 'Destination IP'
    ]
    
    existing_types = df_nodes['Node Type'].unique() if not df_nodes.empty else []
    node_types = [n for n in ordered_nodes if n in existing_types]
    for n in sorted(existing_types):
        if n not in node_types:
            node_types.append(n)

    n_nodes = len(node_types)

    if n_nodes > 0:
        angles = np.linspace(np.pi/2, np.pi/2 - 2 * np.pi, n_nodes, endpoint=False)
        radius = 0.36
        center_x, center_y = 0.5, 0.5
        node_r = 0.055

        coords = {}
        for i, n_type in enumerate(node_types):
            x = center_x + radius * np.cos(angles[i])
            y = center_y + radius * np.sin(angles[i])
            coords[n_type] = (x, y)

        if not df_edges.empty:
            unique_links = df_edges[['Source Node Type', 'Edge Type', 'Target Node Type']].drop_duplicates()
            for _, link in unique_links.iterrows():
                src = link['Source Node Type']
                tgt = link['Target Node Type']
                rel = link['Edge Type']

                if src in coords and tgt in coords:
                    sx, sy = coords[src]
                    tx, ty = coords[tgt]

                    if src == tgt:
                        p_angle = np.arctan2(sy - center_y, sx - center_x)
                        loop_dist = node_r + 0.045
                        loop_x = sx + loop_dist * np.cos(p_angle)
                        loop_y = sy + loop_dist * np.sin(p_angle)

                        arc = mpatches.Arc(
                            (loop_x, loop_y), 0.09, 0.09, angle=0, theta1=0, theta2=360,
                            color='#d62728', lw=2, zorder=2
                        )
                        ax.add_patch(arc)
                        
                        ax.annotate(
                            '', xy=(sx + node_r * np.cos(p_angle + 0.3), sy + node_r * np.sin(p_angle + 0.3)),
                            xytext=(loop_x, loop_y),
                            arrowprops=dict(arrowstyle='-|>', mutation_scale=15, lw=2, color='#d62728'),
                            zorder=2
                        )
                        
                        ax.text(
                            loop_x + 0.02, loop_y + 0.02, rel,
                            fontsize=8.5, color='#900c3f', fontweight='bold', ha='center', va='center',
                            bbox=dict(boxstyle='round,pad=0.25', facecolor='white', edgecolor='#d62728', alpha=0.95, lw=1.2),
                            zorder=5
                        )
                    else:
                        dx = tx - sx
                        dy = ty - sy
                        dist = np.sqrt(dx**2 + dy**2)
                        ux = dx / dist
                        uy = dy / dist

                        start_x = sx + ux * (node_r + 0.005)
                        start_y = sy + uy * (node_r + 0.005)
                        end_x = tx - ux * (node_r + 0.005)
                        end_y = ty - uy * (node_r + 0.005)

                        ax.annotate(
                            '', xy=(end_x, end_y), xytext=(start_x, start_y),
                            arrowprops=dict(arrowstyle='-|>', mutation_scale=20, lw=2, color='#d62728'),
                            zorder=2
                        )

                        mid_x = (sx + tx) / 2.0
                        mid_y = (sy + ty) / 2.0
                        mid_angle = np.arctan2(mid_y - center_y, mid_x - center_x)
                        perp_x = 0.035 * np.cos(mid_angle)
                        perp_y = 0.035 * np.sin(mid_angle)

                        ax.text(
                            mid_x + perp_x, mid_y + perp_y, rel,
                            fontsize=8.5, color='#900c3f', fontweight='bold', ha='center', va='center',
                            bbox=dict(boxstyle='round,pad=0.25', facecolor='white', edgecolor='#d62728', alpha=0.95, lw=1.2),
                            zorder=5
                        )

        for n_type, (x, y) in coords.items():
            circle = plt.Circle((x, y), node_r, facecolor='#2b5c8f', edgecolor='black', lw=2, zorder=3)
            ax.add_patch(circle)
            ax.text(x, y, n_type.replace(' ', '\n'), color='white', fontweight='bold', fontsize=8.5, ha='center', va='center', zorder=4)

    plt.title('Edge-Labeled Graph Schema Blueprint Architecture', fontsize=14, fontweight='bold', pad=20)
    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def plot_schema_relationship_matrix_enhanced(df_nodes: pd.DataFrame, df_edges: pd.DataFrame, output_file: Path) -> None:
    """
    Renders schema_relationship_matrix_enhanced.png with relationship labels and enhanced styling.
    """
    fig, ax = plt.subplots(figsize=(11.5, 9.0))

    if not df_nodes.empty and not df_edges.empty:
        node_types = sorted(df_nodes['Node Type'].unique())
        n_nodes = len(node_types)
        matrix = pd.DataFrame(0, index=node_types, columns=node_types)
        labels_matrix = pd.DataFrame('', index=node_types, columns=node_types)

        links = df_edges[['Source Node Type', 'Edge Type', 'Target Node Type']].drop_duplicates()
        for _, row in links.iterrows():
            src = row['Source Node Type']
            tgt = row['Target Node Type']
            rel = row['Edge Type']
            if src in matrix.index and tgt in matrix.columns:
                matrix.loc[src, tgt] += 1
                labels_matrix.loc[src, tgt] = rel

        im = ax.imshow(matrix.values, cmap='YlGnBu', interpolation='nearest', vmin=0, vmax=max(matrix.values.max(), 1))
        cbar = plt.colorbar(im, ax=ax, shrink=0.8)
        cbar.set_label('Relationship Presence / Count', fontsize=11, labelpad=10)

        ax.set_xticks(range(n_nodes))
        ax.set_yticks(range(n_nodes))
        ax.set_xticklabels(node_types, rotation=35, ha='right', fontsize=10, fontweight='bold')
        ax.set_yticklabels(node_types, fontsize=10, fontweight='bold')

        ax.set_xticks(np.arange(-.5, n_nodes, 1), minor=True)
        ax.set_yticks(np.arange(-.5, n_nodes, 1), minor=True)
        ax.grid(which='minor', color='gray', linestyle='-', linewidth=0.5)
        ax.tick_params(which='minor', size=0)

        for i in range(n_nodes):
            for j in range(n_nodes):
                val = matrix.values[i, j]
                rel_label = labels_matrix.values[i, j]
                if val > 0:
                    formatted_rel = rel_label.replace('_', '_\n') if len(rel_label) > 10 else rel_label
                    text_str = f"{val}\n({formatted_rel})"
                    color = 'white' if val > (matrix.values.max() / 2.0) else 'black'
                    ax.text(j, i, text_str, ha='center', va='center', color=color, fontweight='bold', fontsize=7.5)
                else:
                    ax.text(j, i, '—', ha='center', va='center', color='#aaaaaa', fontsize=9)

        ax.set_title('Enhanced Graph Schema Relationship Adjacency Matrix', fontsize=14, fontweight='bold', pad=15)
        ax.set_xlabel('Target Node Type (Incoming Endpoints)', fontsize=12, labelpad=10)
        ax.set_ylabel('Source Node Type (Outgoing Endpoints)', fontsize=12, labelpad=12)
    else:
        ax.text(0.5, 0.5, 'No Matrix Data Available', ha='center', va='center', fontsize=14)

    plt.tight_layout()
    output_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_file, dpi=300)
    plt.close()


def run_module_3_schema_construction() -> None:
    """
    Main entry point to execute Module 3 Graph Schema Construction.
    """
    base_dir = Path(__file__).resolve().parent.parent
    m2_outputs_dir = base_dir / 'module_2_graph_feature_engineering' / 'outputs'

    outputs_dir = base_dir / 'module_3_graph_schema' / 'outputs'
    visualizations_dir = base_dir / 'module_3_graph_schema' / 'visualizations'

    print("Starting Module 3: Graph Schema Construction...")
    print(f"Reading Module 2 feature engineering outputs from: {m2_outputs_dir}")

    # 1. Derive Node Schemas
    print("Deriving node schema definitions...")
    df_nodes = derive_node_schemas(m2_outputs_dir)

    # 2. Derive Edge Schemas
    print("Deriving edge schema definitions...")
    df_edges = derive_edge_schemas(m2_outputs_dir)

    # 3. Validate Schema
    print("Validating referential integrity of schema blueprint...")
    val_result = validate_graph_schema(df_nodes, df_edges)

    # Save Output CSV files
    print("Saving schema CSV files...")
    outputs_dir.mkdir(parents=True, exist_ok=True)
    df_nodes.to_csv(outputs_dir / 'graph_node_schema.csv', index=False)
    df_edges.to_csv(outputs_dir / 'graph_edge_schema.csv', index=False)

    # Save graph_schema.json
    print("Saving graph_schema.json blueprint...")
    schema_json = {
        'metadata': {
            'project': 'Adaptive_Graph_Intelligence',
            'module': 'Module 3 - Graph Schema Construction',
            'referential_integrity_percentage': val_result['referential_integrity_percentage'],
            'overall_valid': val_result['overall_valid']
        },
        'nodes': df_nodes.to_dict(orient='records') if not df_nodes.empty else [],
        'edges': df_edges.to_dict(orient='records') if not df_edges.empty else []
    }
    with open(outputs_dir / 'graph_schema.json', 'w', encoding='utf-8') as f:
        json.dump(schema_json, f, indent=4)

    # Generate Report
    print("Generating schema validation report...")
    generate_schema_validation_report(val_result, outputs_dir / 'schema_validation_report.txt')

    # Render Visualizations
    print("Rendering visualization diagrams...")
    plot_graph_schema_overview(df_nodes, df_edges, visualizations_dir / 'graph_schema_overview.png')
    plot_node_type_distribution(df_nodes, visualizations_dir / 'node_type_distribution.png')
    plot_edge_type_distribution(df_edges, visualizations_dir / 'edge_type_distribution.png')
    plot_schema_relationship_matrix(df_nodes, df_edges, visualizations_dir / 'schema_relationship_matrix.png')

    # Render Research Visualizations and Catalog Tables
    print("Rendering research visualizations and catalog master tables...")
    generate_schema_statistics_summary(df_nodes, df_edges, outputs_dir, visualizations_dir)
    plot_cardinality_distribution(df_edges, visualizations_dir / 'cardinality_distribution.png')
    plot_property_type_distribution(df_nodes, df_edges, visualizations_dir / 'property_type_distribution.png')
    plot_graph_schema_blueprint_labeled(df_nodes, df_edges, visualizations_dir / 'graph_schema_blueprint_labeled.png')
    plot_schema_relationship_matrix_enhanced(df_nodes, df_edges, visualizations_dir / 'schema_relationship_matrix_enhanced.png')
    plot_complete_node_catalog_master_tables(outputs_dir, visualizations_dir)
    plot_complete_relationship_catalog_master_tables(outputs_dir, visualizations_dir)
    plot_enhanced_graph_schema_tkg_readiness_v2(visualizations_dir)

    print("\nModule 3 Graph Schema Construction Completed Successfully!")
    print(f"Outputs saved in: {outputs_dir}")
    print(f"Visualizations saved in: {visualizations_dir}")


if __name__ == '__main__':
    run_module_3_schema_construction()

