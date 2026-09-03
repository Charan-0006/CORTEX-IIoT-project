# ==============================================================================
# MASTER ADAPTIVE GRAPH WORKFLOW ORCHESTRATOR MODULE
# Objective: Orchestrates the end-to-end execution flow:
# Data Ingestion -> NPG Construction -> Graph Refinement -> Validation -> Attack Path Reconstruction -> Graph Analytics -> Graph Intelligence Generation.
# ==============================================================================

import pandas as pd
from typing import Dict, Any, Optional
from src.graph_builder.npg_builder import NetworkProvenanceGraphBuilder, build_provenance_graph
from src.graph_builder.npg_refinement import GraphRefinementEngine, refine_graph
from src.analytics.attack_path import CausalTemporalPathFinder, reconstruct_attack_path
from src.analytics.event_correlation import GraphEventCorrelator
from src.analytics.graph_validation import GraphValidatorAndOptimizer, validate_graph
from src.analytics.graph_analytics import perform_graph_analytics
from src.analytics.graph_intelligence import generate_graph_intelligence, export_graph_intelligence_json


class AdaptiveGraphIntelligenceWorkflow:
    """
    Master pipeline orchestrator for Layer 3B.
    Executes Data Ingestion -> Graph Construction -> Graph Refinement -> Validation -> Analytics -> Intelligence Output.
    """

    def __init__(self):
        self.builder = NetworkProvenanceGraphBuilder()

    def execute_network_refinement_pipeline(
        self,
        network_df: pd.DataFrame,
        source_ip: str = "192.168.1.193",
        target_ip: str = "192.168.1.1"
    ) -> Dict[str, Any]:
        """
        Executes complete ingestion, refinement, validation, analytics, and intelligence export pipeline.
        """
        # Step 1: Initial Graph Construction
        raw_graph = build_provenance_graph(network_df)

        # Step 2: Refinement Phase (Deduplication, Consistency, Connectivity)
        refined_graph, refinement_stats = refine_graph(raw_graph)

        # Step 3: Validation & Output Table Formatting
        schema_validation_report = validate_graph(refined_graph)
        validator = GraphValidatorAndOptimizer(refined_graph)
        rel_table_str = validator.format_relationship_validation_table(refinement_stats)
        connectivity_summary_str = validator.format_connectivity_summary(refinement_stats)
        node_consistency_summary_str = validator.format_node_consistency_summary(refinement_stats)

        # Step 4: Reconstruct Causal Attack Paths
        attack_paths = reconstruct_attack_path(
            refined_graph, 
            source_ip=source_ip, 
            target_ip=target_ip
        )

        # Step 5: Perform Topological Graph Analytics (Degree & Betweenness Centrality)
        analytics_results = perform_graph_analytics(refined_graph)

        # Step 6: Perform Cross-Graph Event Correlation
        correlator = GraphEventCorrelator(refined_graph)
        correlated_clusters = correlator.correlate_alerts_by_window()

        # Step 7: Generate Structured Graph Intelligence Output for Multi-Agent AI layer
        graph_intelligence = generate_graph_intelligence(
            attack_paths=attack_paths,
            analytics_results=analytics_results,
            refinement_stats=refinement_stats,
            source_ip=source_ip,
            target_ip=target_ip
        )
        export_graph_intelligence_json(graph_intelligence, "outputs/graph_intelligence.json")

        return {
            "layer": "Layer 3B: Adaptive Graph Intelligence Engine",
            "refined_graph": refined_graph,
            "refinement_stats": refinement_stats,
            "schema_validation_report": schema_validation_report,
            "relationship_validation_table": rel_table_str,
            "connectivity_summary": connectivity_summary_str,
            "node_consistency_summary": node_consistency_summary_str,
            "reconstructed_attack_paths": attack_paths,
            "graph_analytics": analytics_results,
            "correlated_alert_clusters": correlated_clusters,
            "graph_intelligence": graph_intelligence
        }

    def execute_pipeline(self, df: pd.DataFrame, source_ip: str, target_ip: str) -> Dict[str, Any]:
        """Backward-compatible wrapper for test suite invocation."""
        results = self.execute_network_refinement_pipeline(df, source_ip=source_ip, target_ip=target_ip)
        return {
            "status": "SUCCESS",
            "schema_summary": {"total_nodes": results["refinement_stats"]["final_nodes"]},
            "validation_report": results["schema_validation_report"],
            "reconstructed_attack_paths": results["reconstructed_attack_paths"],
            "correlated_alert_clusters": results["correlated_alert_clusters"],
            "graph_analytics": results["graph_analytics"],
            "graph_intelligence": results["graph_intelligence"]
        }

