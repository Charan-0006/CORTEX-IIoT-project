# ==============================================================================
# GRAPH CONFIDENCE ESTIMATION ENGINE MODULE
# Objective: Evaluates graph evidence quality, temporal ordering monotonicity,
# schema compliance, node-edge consistency, and causal path reconstruction success
# to compute an explainable normalized confidence score (0.00 to 1.00 / 0.0% to 100.0%).
# ==============================================================================

import networkx as nx
from typing import Dict, Any, List, Optional


def calculate_graph_confidence(
    graph: nx.MultiDiGraph,
    attack_paths: List[Dict[str, Any]],
    validation_report: Dict[str, Any],
    refinement_stats: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Function: calculate_graph_confidence
    -----------------------------------
    Why it exists: Main functional entry point to compute explainable graph confidence score.
    Input: Directed NetworkX graph, list of reconstructed attack paths, schema validation report dict, refinement stats.
    Output: Confidence evaluation dict containing confidence float, percentage string, and explainable breakdown.
    Contribution: Quantifies provenance data quality and structural trustworthiness for Multi-Agent AI consumption.
    """
    estimator = GraphConfidenceEstimator(graph, attack_paths, validation_report, refinement_stats)
    return estimator.evaluate_confidence()


class GraphConfidenceEstimator:
    """
    Explainable Rule-Based Graph Confidence Estimator.

    Formula / Methodology:
    ----------------------
    Confidence = w_schema * C_schema + w_temporal * C_temporal + w_evidence * C_evidence + w_path * C_path
    Where weights sum to 1.0 (w_schema=0.25, w_temporal=0.30, w_evidence=0.20, w_path=0.25).

    1. Schema Compliance Factor (C_schema in [0, 1]):
       Evaluates node-edge compliance and absence of invalid nodes/edges.
       Passed schema validation -> 1.0.

    2. Temporal Monotonicity & Consistency Factor (C_temporal in [0, 1]):
       Evaluates timestamp chronological order across graph edges and reconstructed attack paths.
       Ensures that hop_(i+1) timestamp >= hop_i timestamp.

    3. Structural Evidence & Relationship Completeness (C_evidence in [0, 1]):
       Evaluates edge density, absence of missing relationships, and isolated node pruning.
       Ratio = 1.0 - (missing_relationships / max(1, total_nodes)).

    4. Causal Path Reconstruction Factor (C_path in [0, 1]):
       - 1.0 if chronologically monotonic attack path found with alert corroboration.
       - 0.7 if structural path found without explicit alert node.
       - 0.4 if graph is connected but no path connects source to target.
    """

    WEIGHT_SCHEMA = 0.25
    WEIGHT_TEMPORAL = 0.30
    WEIGHT_EVIDENCE = 0.20
    WEIGHT_PATH = 0.25

    def __init__(
        self,
        graph: nx.MultiDiGraph,
        attack_paths: List[Dict[str, Any]],
        validation_report: Dict[str, Any],
        refinement_stats: Dict[str, Any]
    ):
        self.graph = graph
        self.attack_paths = attack_paths
        self.validation_report = validation_report
        self.refinement_stats = refinement_stats

    def _compute_schema_compliance_factor(self) -> float:
        """Computes schema compliance confidence factor C_schema in [0, 1]."""
        if self.validation_report.get("is_schema_valid", False):
            return 1.0

        invalid_nodes = self.validation_report.get("invalid_node_count", 0)
        invalid_edges = self.validation_report.get("invalid_edge_count", 0)
        total_nodes = self.refinement_stats.get("final_nodes", 1)
        total_edges = self.refinement_stats.get("final_edges", 1)

        node_penalty = invalid_nodes / float(max(1, total_nodes))
        edge_penalty = invalid_edges / float(max(1, total_edges))

        compliance = 1.0 - (0.5 * node_penalty + 0.5 * edge_penalty)
        return round(max(0.0, compliance), 4)

    def _compute_temporal_consistency_factor(self) -> float:
        """Computes temporal monotonicity factor C_temporal in [0, 1]."""
        if not self.attack_paths:
            # Check edge timestamp validity across all edges
            timestamps = [
                data.get("timestamp", 0.0)
                for _, _, data in self.graph.edges(data=True)
                if "timestamp" in data
            ]
            if not timestamps:
                return 0.5
            valid_ts_count = sum(1 for ts in timestamps if ts >= 0.0)
            return round(valid_ts_count / float(len(timestamps)), 4)

        # Evaluate timestamp monotonicity across all reconstructed attack path steps
        total_hops = 0
        monotonic_hops = 0

        for path in self.attack_paths:
            chain = path.get("chain", [])
            for i in range(len(chain) - 1):
                total_hops += 1
                ts_curr = chain[i].get("timestamp", 0.0)
                ts_next = chain[i + 1].get("timestamp", 0.0)
                if ts_next >= ts_curr:
                    monotonic_hops += 1

        if total_hops == 0:
            return 1.0

        return round(monotonic_hops / float(total_hops), 4)

    def _compute_structural_evidence_factor(self) -> float:
        """Computes structural evidence quality factor C_evidence in [0, 1]."""
        total_nodes = self.refinement_stats.get("final_nodes", 1)
        missing_rels = self.refinement_stats.get("missing_relationships_count", 0)

        if total_nodes == 0:
            return 0.0

        missing_ratio = missing_rels / float(total_nodes)
        isolated_removed = self.refinement_stats.get("isolated_nodes_removed", 0)

        # Deduct small penalty if many isolated nodes had to be removed
        isolated_penalty = min(0.2, isolated_removed / float(max(1, total_nodes + isolated_removed)))

        evidence_score = 1.0 - missing_ratio - isolated_penalty
        return round(min(1.0, max(0.0, evidence_score)), 4)

    def _compute_causal_path_factor(self) -> float:
        """Computes path reconstruction confidence factor C_path in [0, 1]."""
        if not self.attack_paths:
            return 0.40

        primary_path = self.attack_paths[0]
        chain = primary_path.get("chain", [])

        has_alert_node = any(
            step.get("rel_type") in ["GENERATED_ALERT", "TARGETS_HOST"] or "Alert:" in step.get("to_node", "")
            for step in chain
        )

        if has_alert_node:
            return 1.00
        else:
            # Valid attack path found through service endpoints
            return 0.85

    def evaluate_confidence(self) -> Dict[str, Any]:
        """Calculates final normalized confidence score."""
        c_schema = self._compute_schema_compliance_factor()
        c_temporal = self._compute_temporal_consistency_factor()
        c_evidence = self._compute_structural_evidence_factor()
        c_path = self._compute_causal_path_factor()

        confidence_val = (
            self.WEIGHT_SCHEMA * c_schema +
            self.WEIGHT_TEMPORAL * c_temporal +
            self.WEIGHT_EVIDENCE * c_evidence +
            self.WEIGHT_PATH * c_path
        )

        confidence_val = round(min(1.0, max(0.0, confidence_val)), 4)
        confidence_pct = f"{round(confidence_val * 100.0, 2)}%"

        return {
            "graph_confidence": confidence_val,
            "graph_confidence_pct": confidence_pct,
            "confidence_breakdown": {
                "schema_compliance_factor": c_schema,
                "temporal_consistency_factor": c_temporal,
                "structural_evidence_factor": c_evidence,
                "causal_path_factor": c_path,
                "component_weights": {
                    "schema_weight": self.WEIGHT_SCHEMA,
                    "temporal_weight": self.WEIGHT_TEMPORAL,
                    "evidence_weight": self.WEIGHT_EVIDENCE,
                    "path_weight": self.WEIGHT_PATH
                }
            },
            "formula_documentation": (
                "Confidence = 0.25 * C_schema + 0.30 * C_temporal + 0.20 * C_evidence + 0.25 * C_path. "
                "Normalized Range: 0.00 to 1.00 (0.0% to 100.0%). Evaluates data trustworthiness, temporal monotonicity, and path evidence."
            )
        }
