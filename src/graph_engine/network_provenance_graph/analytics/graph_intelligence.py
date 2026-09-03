# ==============================================================================
# STRUCTURED GRAPH INTELLIGENCE GENERATOR MODULE
# Objective: Formats Network Provenance Graph analysis, reconstructed attack paths,
# and centrality metrics into a structured Python dictionary / JSON format for consumption
# by the downstream Multi-Agent AI Layer.
# ==============================================================================

import json
from typing import Dict, Any, List


def generate_graph_intelligence(
    attack_paths: List[Dict[str, Any]],
    analytics_results: Dict[str, Any],
    refinement_stats: Dict[str, Any],
    source_ip: str,
    target_ip: str
) -> Dict[str, Any]:
    """
    Function: generate_graph_intelligence
    ------------------------------------
    Why it exists: Converts graph analytics into a machine-readable JSON structure for Multi-Agent AI consumption.
    Input: Reconstructed attack path list, graph analytics dict, refinement stats dict, source & target IP strings.
    Output: Structured Python dictionary conforming to the Layer 3B graph intelligence output schema.
    Contribution: Serves as the data export bridge between Graph Layer 3B and downstream AI Agents.
    """
    if attack_paths:
        primary_path = attack_paths[0]
        chain = primary_path.get("chain", [])
        attack_type = chain[0].get("attack_type", "Unknown") if chain else "Security_Incident"
        
        # Extract service from first hop
        service = chain[0].get("to_node", "Unknown_Service") if chain else "Unknown"
        path_nodes = []
        for step in chain:
            path_nodes.append(step["from_node"])
            path_nodes.append(step["to_node"])
        unique_path_nodes = list(dict.fromkeys(path_nodes))
    else:
        attack_type = "Normal_Traffic"
        service = "None"
        unique_path_nodes = [f"Host:{source_ip}", f"Host:{target_ip}"]

    important_nodes = analytics_results.get("important_nodes", [])

    # Assemble Structured Graph Intelligence Payload
    graph_intelligence_payload = {
        "incident_id": f"INC-{source_ip.replace('.', '')}-{target_ip.replace('.', '')}",
        "attack_type": attack_type,
        "source_host": source_ip,
        "target_host": target_ip,
        "service": service,
        "attack_path": unique_path_nodes,
        "reconstructed_path_details": attack_paths,
        "important_nodes": important_nodes,
        "connectivity": {
            "total_nodes": refinement_stats.get("final_nodes", 0),
            "total_edges": refinement_stats.get("final_edges", 0),
            "average_degree": refinement_stats.get("average_node_degree", 0.0),
            "graph_density": refinement_stats.get("graph_density", 0.0),
            "connected_components": refinement_stats.get("connected_components", 0)
        },
        # ----------------------------------------------------------------------
        # PENDING / NOT YET IMPLEMENTED FIELDS:
        # Mark clearly so faculty can see what is completed vs pending.
        # ----------------------------------------------------------------------
        "risk_level": "PENDING (Rule-based risk scoring heuristic TODO)",
        "graph_confidence": "PENDING (Multi-Agent consensus verification TODO)",
        "downstream_consumer": "Multi-Agent AI Reasoning Layer (CORTEX Layer 4)"
    }

    return graph_intelligence_payload


def export_graph_intelligence_json(payload: Dict[str, Any], filepath: str = "outputs/graph_intelligence.json"):
    """Saves structured graph intelligence payload to a JSON file."""
    import os
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=4)
    print(f"[+] Structured Graph Intelligence Output exported to '{filepath}'.")
