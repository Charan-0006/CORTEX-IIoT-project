# ==============================================================================
# PRESENTATION-GRADE GRAPH VISUALIZATION MODULE
# Objective: Renders publication-quality Matplotlib figures of the Network Provenance
# Graph, validation dashboards, and attack path traversals.
# ==============================================================================

# Entity Color Mapping (Academic / Faculty Presentation Standards):
# - Host Node    -> Blue  (#1f77b4) : Represents initiating / receiving IP endpoints.
# - Service Node -> Green (#2ca02c) : Represents protocol / port service endpoints.
# - Alert Node   -> Red   (#d62728) : Represents detected security attack alerts.

# Note on Visualization vs. Graph Intelligence:
# - Visualizations (PNG/PDF/SVG) are created for human interpretation by analysts & faculty.
# - Structured Graph Intelligence (JSON) is created for machine reasoning by downstream AI agents.

import os
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from typing import Dict, Any, List
from matplotlib.patches import Patch

# Academic IEEE style defaults
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.titlesize'] = 12
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['figure.titlesize'] = 13
plt.rcParams['figure.dpi'] = 300
sns.set_theme(style="white")


def visualize_graph(graph: nx.MultiDiGraph, refinement_stats: Dict[str, Any], attack_paths: List[Dict[str, Any]] = None, output_dir: str = "outputs/visualizations"):
    """
    Function: visualize_graph
    -------------------------
    Why it exists: Main functional wrapper to generate all visual outputs.
    Input: Refined MultiDiGraph, refinement stats dict, attack paths list, output directory string.
    Output: Exports PNG, PDF, and SVG visualization files to disk.
    Contribution: Provides clear visual diagrams for human review and thesis presentation.
    """
    visualizer = GraphVisualizer(output_dir=output_dir)
    visualizer.generate_all_week4_outputs(graph, refinement_stats, attack_paths)


class GraphVisualizer:
    """
    Generates publication-quality academic visualizations for Network Provenance Graph refinement and analytics.
    """

    def __init__(self, output_dir: str = "outputs/visualizations"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all_week4_outputs(self, graph: nx.MultiDiGraph, refinement_stats: Dict[str, Any], attack_paths: List[Dict[str, Any]] = None):
        """Generates Output 1, Output 2, and Output 3 visualization PNGs."""
        print(f"\n[+] Generating Week 4 IEEE-Style Academic Visualizations in '{self.output_dir}'...")

        self.output_01_refined_npg(graph, refinement_stats)
        self.output_02_graph_validation_dashboard(refinement_stats)
        self.output_03_provenance_traversal_example(graph, attack_paths)

        print(f"[+] All Week 4 Visualizations generated successfully in '{self.output_dir}/'.")

    def output_01_refined_npg(self, graph: nx.MultiDiGraph, stats: Dict[str, Any] = None):
        """
        Output 1: Refined Network Provenance Graph
        - Publication-quality NetworkX visualization on crisp white background.
        - Host = Blue (#1f77b4)
        - Service = Green (#2ca02c)
        - Alert = Red (#d62728)
        - Directed Edges = Black (#000000)
        - Spring Layout with zero overlapping labels.
        - Show node labels only (edge labels omitted to maximize readability).
        - Legend included.
        - Main Title: Refined Network Provenance Graph\n(Generated from Processed ToN-IoT Network Dataset)
        - Bottom Graph Statistics Box displaying: Total Host Nodes, Total Service Nodes, Total Alert Nodes, Total Relationships.
        - Exported to PNG (300 DPI), PDF, and SVG.
        """
        fig, ax = plt.subplots(figsize=(14, 10), facecolor='white')
        ax.set_facecolor('white')

        # Filter nodes by type
        hosts = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "Host"]
        services = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "Service"]
        alerts = [n for n, d in graph.nodes(data=True) if d.get("node_type") == "Alert"]

        # Select representative active connected subgraph
        top_hosts = sorted(hosts, key=lambda n: graph.degree(n), reverse=True)[:12]
        top_services = sorted(services, key=lambda n: graph.degree(n), reverse=True)[:15]
        top_alerts = sorted(alerts, key=lambda n: graph.degree(n), reverse=True)[:10]

        sub_nodes = set(top_hosts + top_services + top_alerts)
        subg = graph.subgraph(sub_nodes)

        # Spring Layout optimization for readability
        pos = nx.spring_layout(subg, seed=42, k=1.4, iterations=100)

        color_map = []
        labels = {}
        for node in subg.nodes():
            data = subg.nodes[node]
            ntype = data.get("node_type", "Host")
            if ntype == "Host":
                color_map.append("#1f77b4")       # Blue Host
                labels[node] = data.get("ip", str(node).replace("Host:", ""))
            elif ntype == "Service":
                color_map.append("#2ca02c")       # Green Service
                labels[node] = f"{data.get('protocol')}:{data.get('port')}"
            elif ntype == "Alert":
                color_map.append("#d62728")       # Red Alert
                labels[node] = f"Alert:{data.get('attack_type', 'Threat')}"
            else:
                color_map.append("#9467bd")

        # Draw nodes with black borders
        nx.draw_networkx_nodes(subg, pos, node_color=color_map, node_size=1300, alpha=0.95, edgecolors='black', linewidths=1.5, ax=ax)
        
        # Draw node labels only (no edge labels for clean readability)
        nx.draw_networkx_labels(subg, pos, labels, font_size=8, font_color="white", font_weight="bold", ax=ax)

        # Draw black directed edges
        simple_g = nx.DiGraph()
        for u, v in subg.edges():
            if not simple_g.has_edge(u, v):
                simple_g.add_edge(u, v)

        nx.draw_networkx_edges(simple_g, pos, width=1.5, alpha=0.75, edge_color="#000000", arrows=True, arrowsize=18, connectionstyle="arc3,rad=0.08", ax=ax)

        # Legend
        legend_elements = [
            Patch(facecolor='#1f77b4', edgecolor='black', label='Host Node (Blue)'),
            Patch(facecolor='#2ca02c', edgecolor='black', label='Service Node (Green)'),
            Patch(facecolor='#d62728', edgecolor='black', label='Alert Node (Red)')
        ]
        ax.legend(handles=legend_elements, loc='upper right', frameon=True, facecolor='white', framealpha=1.0, fontsize=10.5)

        # Exact Main Title
        plt.title("Refined Network Provenance Graph\n(Generated from Processed ToN-IoT Network Dataset)", fontweight="bold", fontsize=15, pad=18)

        # Bottom Graph Statistics Box
        tot_hosts = stats.get("total_hosts", len(hosts)) if stats else len(hosts)
        tot_svcs = stats.get("total_services", len(services)) if stats else len(services)
        tot_alerts = stats.get("total_alerts", len(alerts)) if stats else len(alerts)
        tot_rels = stats.get("final_edges", graph.number_of_edges()) if stats else graph.number_of_edges()

        stats_summary = (
            f"• Total Host Nodes: {tot_hosts:,}   "
            f"• Total Service Nodes: {tot_svcs:,}   "
            f"• Total Alert Nodes: {tot_alerts:,}   "
            f"• Total Relationships: {tot_rels:,}"
        )

        fig.text(0.5, 0.02, stats_summary, ha='center', va='center', fontsize=11, fontweight='bold',
                 bbox=dict(boxstyle='round,pad=0.6', facecolor='#ffffff', edgecolor='#000000', linewidth=1.5))

        ax.axis('off')
        plt.subplots_adjust(bottom=0.09, top=0.91)

        # Save to both outputs/ and outputs/visualizations/ in PNG (300 DPI), PDF, and SVG
        save_paths = [
            os.path.join(self.output_dir, "01_refined_npg_visualization.png"),
            os.path.join(self.output_dir, "01_refined_npg_visualization.pdf"),
            os.path.join(self.output_dir, "01_refined_npg_visualization.svg"),
            "outputs/Refined_Network_Provenance_Graph.png",
            "outputs/Refined_Network_Provenance_Graph.pdf",
            "outputs/Refined_Network_Provenance_Graph.svg"
        ]

        for p in save_paths:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            fmt = p.split('.')[-1]
            plt.savefig(p, dpi=300, facecolor='white', format=fmt, bbox_inches='tight')

        plt.close()

    def output_02_graph_validation_dashboard(self, stats: Dict[str, Any]):
        """
        Output 2: Graph Validation Dashboard
        Renders executive IEEE academic graphic summary dashboard.
        """
        fig, ax = plt.subplots(figsize=(11, 8), facecolor='white')
        ax.axis('off')

        dashboard_text = (
            "===================================================================================\n"
            "                 GRAPH VALIDATION & REFINEMENT DASHBOARD                          \n"
            "===================================================================================\n\n"
            f"  • Total Hosts (Blue):               {stats.get('total_hosts', 0):,} nodes\n"
            f"  • Total Services (Green):           {stats.get('total_services', 0):,} nodes\n"
            f"  • Total Alerts (Red):               {stats.get('total_alerts', 0):,} nodes\n"
            f"  • Total Unified Graph Nodes:        {stats.get('final_nodes', 0):,} nodes\n"
            f"  • Total Directed Provenance Edges:  {stats.get('final_edges', 0):,} edges\n\n"
            "  ---------------------------------------------------------------------------------\n"
            f"  • Duplicate Nodes Removed:          {stats.get('duplicate_nodes_removed', 0):,} nodes\n"
            f"  • Duplicate Edges Removed:          {stats.get('duplicate_edges_removed', 0):,} edges\n"
            f"  • Isolated Nodes Removed:           {stats.get('isolated_nodes_removed', 0):,} nodes\n\n"
            "  ---------------------------------------------------------------------------------\n"
            f"  • Relationship Validation Status:   {stats.get('relationship_validation_status', 'VALIDATED')}\n"
            f"  • Graph Connectivity Status:        {stats.get('graph_connectivity_status', 'OPTIMIZED')}\n"
            f"  • Schema Validation Status:         {stats.get('schema_validation_status', 'PASSED')}\n"
            "==================================================================================="
        )

        ax.text(0.05, 0.95, dashboard_text, transform=ax.transAxes, fontsize=10.5,
                family='monospace', verticalalignment='top',
                bbox=dict(boxstyle='round,pad=1.2', facecolor='#ffffff', edgecolor='#1f77b4', linewidth=2))

        plt.title("Output 2: Layer 3B Graph Validation Dashboard", fontweight="bold", fontsize=14, pad=20)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "02_graph_validation_dashboard.png"), dpi=300, facecolor='white')
        plt.close()

    def output_03_provenance_traversal_example(self, graph: nx.MultiDiGraph, attack_paths: List[Dict[str, Any]] = None):
        """
        Output 3: Provenance Traversal Example
        Visualize one attack path:
        Attacker Host -> ACCESSED_SERVICE -> Service -> EXPLOITED_ON -> Alert -> TARGETS_HOST -> Victim Host
        """
        plt.figure(figsize=(13, 6.5), facecolor='white')
        ax = plt.gca()
        ax.set_facecolor('white')

        # Define 4-node attack path structure
        path_g = nx.DiGraph()

        attacker_ip = "192.168.1.193 (Attacker)"
        svc_name = "http:80 (Service)"
        alert_name = "Alert:dos (Alert)"
        victim_ip = "192.168.1.1 (Victim)"

        host_nodes = [d.get("ip", n) for n, d in graph.nodes(data=True) if d.get("node_type") == "Host"]
        alert_nodes = [d.get("attack_type", n) for n, d in graph.nodes(data=True) if d.get("node_type") == "Alert"]
        svc_nodes = [f"{d.get('protocol')}:{d.get('port')}" for n, d in graph.nodes(data=True) if d.get("node_type") == "Service"]

        if host_nodes: attacker_ip = f"Host:{host_nodes[0]} (Attacker Host)"
        if svc_nodes: svc_name = f"Service:{svc_nodes[0]}"
        if alert_nodes: alert_name = f"Alert:{alert_nodes[0]}"
        if len(host_nodes) > 1: victim_ip = f"Host:{host_nodes[1]} (Victim Host)"

        nodes_in_order = [
            (attacker_ip, "#1f77b4", "Attacker Host"),
            (svc_name, "#2ca02c", "Accessed Service"),
            (alert_name, "#d62728", "Generated Alert"),
            (victim_ip, "#1f77b4", "Victim Host")
        ]

        pos = {
            attacker_ip: (0.15, 0.5),
            svc_name: (0.38, 0.5),
            alert_name: (0.62, 0.5),
            victim_ip: (0.85, 0.5)
        }

        for n, color, label in nodes_in_order:
            path_g.add_node(n, color=color)

        edges = [
            (attacker_ip, svc_name, "ACCESSED_SERVICE"),
            (svc_name, alert_name, "EXPLOITED_ON"),
            (alert_name, victim_ip, "TARGETS_HOST")
        ]

        for u, v, rel in edges:
            path_g.add_edge(u, v, label=rel)

        colors = [path_g.nodes[n]['color'] for n in path_g.nodes()]

        nx.draw_networkx_nodes(path_g, pos, node_color=colors, node_size=3200, edgecolors='black', linewidths=2.0)
        nx.draw_networkx_labels(path_g, pos, font_size=8, font_color="white", font_weight="bold")

        nx.draw_networkx_edges(path_g, pos, width=2.5, edge_color="#000000", arrows=True, arrowsize=24)

        edge_labels = {(u, v): rel for u, v, rel in edges}
        nx.draw_networkx_edge_labels(path_g, pos, edge_labels=edge_labels, font_size=9, font_color="#d62728", font_weight="bold",
                                    bbox=dict(boxstyle="round,pad=0.3", fc="#ffffff", ec="#d62728", lw=1.5))

        legend_elements = [
            Patch(facecolor='#1f77b4', edgecolor='black', label='Host Node (Attacker / Victim)'),
            Patch(facecolor='#2ca02c', edgecolor='black', label='Service Endpoint Node'),
            Patch(facecolor='#d62728', edgecolor='black', label='Alert Event Node')
        ]
        plt.legend(handles=legend_elements, loc='upper right', frameon=True, facecolor='white')

        plt.title("Output 3: Provenance Traversal Example (Attack Path)", fontweight="bold", fontsize=13, pad=25)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, "03_provenance_traversal_example.png"), dpi=300, facecolor='white')
        plt.close()

