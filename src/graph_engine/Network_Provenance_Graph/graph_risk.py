# ==============================================================================
# GRAPH-BASED RISK SCORING ENGINE MODULE
# Objective: Evaluates graph threat evidence (attack severity, causal attack path length,
# hop maliciousness ratio, topological node centrality, and alert density) to compute an
# explainable, normalized risk score (0.0 to 100.0) and categorical risk level.
# ==============================================================================

import networkx as nx
from typing import Dict, Any, List, Optional


def calculate_graph_risk(
    graph: nx.MultiDiGraph,
    attack_paths: List[Dict[str, Any]],
    analytics_results: Dict[str, Any],
    refinement_stats: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Function: calculate_graph_risk
    -----------------------------
    Why it exists: Main functional entry point to compute explainable graph-based risk score.
    Input: Directed NetworkX graph, list of reconstructed attack paths, topological analytics dict, refinement stats.
    Output: Risk evaluation dict containing risk_score, risk_level, and explainable risk breakdown.
    Contribution: Provides Layer 3B quantitative threat scoring for Layer 4 Multi-Agent AI reasoning.
    """
    scorer = GraphRiskScorer(graph, attack_paths, analytics_results, refinement_stats)
    return scorer.evaluate_risk()


class GraphRiskScorer:
    """
    Explainable Rule-Based Graph Risk Scoring Engine.
    
    Formula / Methodology:
    ----------------------
    Risk Score (R_raw) = w1 * S_attack + w2 * P_path + w3 * C_topo + w4 * A_density
    Where weights sum to 1.0 (w1=0.35, w2=0.35, w3=0.15, w4=0.15).

    1. Malicious Severity Factor (S_attack in [0, 1]):
       Evaluates the threat classification of alerts and attack steps.
       - Critical: injection, modbus_injection, dos, ddos, mitm -> 1.0
       - High: password_bruteforce, scanning, backdoor, ransomware -> 0.8
       - Medium: xss, reconnaissance -> 0.6
       - Low/Normal: normal, unknown -> 0.1

    2. Causal Path & Malicious Hop Ratio (P_path in [0, 1]):
       - If no causal path exists: P_path = 0.0
       - If path exists: P_path = 0.5 * (malicious_hop_ratio) + 0.5 * (path_existence_weight)
       Shorter, highly malicious attack paths yield higher risk scores.

    3. Node Centrality & Criticality (C_topo in [0, 1]):
       Evaluates target host degree centrality and bridge entity betweenness centrality.
       High centrality of target/bridge hosts implies widespread potential blast radius.

    4. Alert Density & Event Correlation (A_density in [0, 1]):
       Evaluates alert node proportion in the NPG and correlated alert cluster frequency.
    """

    ATTACK_SEVERITY_MAP = {
        "injection": 1.0,
        "modbus_injection": 1.0,
        "dos": 0.95,
        "ddos": 0.95,
        "mitm": 0.90,
        "password_bruteforce": 0.80,
        "backdoor": 0.85,
        "ransomware": 0.90,
        "scanning": 0.65,
        "reconnaissance": 0.60,
        "xss": 0.60,
        "normal": 0.0,
        "unknown": 0.2
    }

    WEIGHT_ATTACK_SEVERITY = 0.35
    WEIGHT_PATH_EVIDENCE = 0.35
    WEIGHT_TOPOLOGY_CENTRALITY = 0.15
    WEIGHT_ALERT_DENSITY = 0.15

    def __init__(
        self,
        graph: nx.MultiDiGraph,
        attack_paths: List[Dict[str, Any]],
        analytics_results: Dict[str, Any],
        refinement_stats: Dict[str, Any]
    ):
        self.graph = graph
        self.attack_paths = attack_paths
        self.analytics_results = analytics_results
        self.refinement_stats = refinement_stats

    def _compute_attack_severity_factor(self) -> float:
        """Computes normalized attack severity score S_attack in [0, 1]."""
        if not self.attack_paths:
            # Check if any alert nodes exist in the graph
            alert_types = [
                data.get("attack_type", "normal").lower()
                for _, data in self.graph.nodes(data=True)
                if data.get("node_type") == "Alert"
            ]
            if not alert_types:
                return 0.0
            max_sev = max([self.ATTACK_SEVERITY_MAP.get(at, 0.5) for at in alert_types])
            return max_sev

        # Extract attack types from primary path and overall reconstructed paths
        path_severities = []
        for path in self.attack_paths:
            for step in path.get("chain", []):
                atk = step.get("attack_type", "normal").lower()
                path_severities.append(self.ATTACK_SEVERITY_MAP.get(atk, 0.3))

        if not path_severities:
            return 0.0

        max_severity = max(path_severities)
        avg_severity = sum(path_severities) / len(path_severities)
        return round(0.7 * max_severity + 0.3 * avg_severity, 4)

    def _compute_path_evidence_factor(self) -> float:
        """Computes causal attack path evidence score P_path in [0, 1]."""
        if not self.attack_paths:
            return 0.0

        primary_path = self.attack_paths[0]
        malicious_ratio = primary_path.get("malicious_step_ratio", 0.0)
        hop_count = primary_path.get("hop_count", 4)
        
        # Path proximity multiplier: shorter hops = higher risk impact (cutoff=5)
        path_proximity = max(0.2, (6 - hop_count) / 5.0)

        # Combine malicious hop ratio, path proximity, and path count factor
        path_count_factor = min(1.0, len(self.attack_paths) / 5.0)

        path_factor = (0.5 * malicious_ratio) + (0.3 * path_proximity) + (0.2 * path_count_factor)
        return round(min(1.0, max(0.0, path_factor)), 4)

    def _compute_topology_centrality_factor(self) -> float:
        """Computes topological importance score C_topo in [0, 1]."""
        top_degree = self.analytics_results.get("degree_centrality_top5", [])
        top_betweenness = self.analytics_results.get("betweenness_centrality_top5", [])

        max_degree_score = top_degree[0]["degree_score"] if top_degree else 0.0
        max_betweenness_score = top_betweenness[0]["betweenness_score"] if top_betweenness else 0.0

        topo_factor = (0.6 * max_degree_score) + (0.4 * max_betweenness_score)
        return round(min(1.0, max(0.0, topo_factor)), 4)

    def _compute_alert_density_factor(self) -> float:
        """Computes alert density and correlation score A_density in [0, 1]."""
        total_nodes = self.refinement_stats.get("final_nodes", 1)
        total_alerts = self.refinement_stats.get("total_alerts", 0)

        if total_nodes == 0 or total_alerts == 0:
            return 0.0

        alert_ratio = total_alerts / float(total_nodes)
        # Scale alert ratio (e.g. 5% alerts is very high density in network graphs)
        density_factor = min(1.0, alert_ratio * 20.0)
        return round(density_factor, 4)

    def evaluate_risk(self) -> Dict[str, Any]:
        """Calculates final normalized risk score and maps to categorical risk level."""
        s_attack = self._compute_attack_severity_factor()
        p_path = self._compute_path_evidence_factor()
        c_topo = self._compute_topology_centrality_factor()
        a_density = self._compute_alert_density_factor()

        raw_score = (
            self.WEIGHT_ATTACK_SEVERITY * s_attack +
            self.WEIGHT_PATH_EVIDENCE * p_path +
            self.WEIGHT_TOPOLOGY_CENTRALITY * c_topo +
            self.WEIGHT_ALERT_DENSITY * a_density
        )

        risk_score = round(min(1.0, max(0.0, raw_score)) * 100.0, 2)

        # Categorical Risk Level Thresholds
        if risk_score >= 80.0:
            risk_level = "CRITICAL"
        elif risk_score >= 60.0:
            risk_level = "HIGH"
        elif risk_score >= 40.0:
            risk_level = "MEDIUM"
        elif risk_score > 0.0:
            risk_level = "LOW"
        else:
            risk_level = "NONE (Normal Traffic)"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_normalized": round(risk_score / 100.0, 4),
            "risk_breakdown": {
                "attack_severity_factor": s_attack,
                "attack_path_factor": p_path,
                "topology_centrality_factor": c_topo,
                "alert_density_factor": a_density,
                "component_weights": {
                    "attack_severity_weight": self.WEIGHT_ATTACK_SEVERITY,
                    "attack_path_weight": self.WEIGHT_PATH_EVIDENCE,
                    "topology_centrality_weight": self.WEIGHT_TOPOLOGY_CENTRALITY,
                    "alert_density_weight": self.WEIGHT_ALERT_DENSITY
                }
            },
            "formula_documentation": (
                "RiskScore = (0.35 * S_attack + 0.35 * P_path + 0.15 * C_topo + 0.15 * A_density) * 100. "
                "Scale: 0.0 to 100.0. Categorical mapping: CRITICAL (>=80), HIGH (60-79.9), MEDIUM (40-59.9), LOW (<40)."
            )
        }
