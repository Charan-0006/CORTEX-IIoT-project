# ==============================================================================
# GRAPH ANALYTICS MODULE
# Objective: Computes topological graph analytics (Degree Centrality, Betweenness Centrality)
# to identify critical, highly-connected candidate entities for security investigation.
# ==============================================================================

import networkx as nx
from typing import Dict, Any, List


def perform_graph_analytics(graph: nx.MultiDiGraph) -> Dict[str, Any]:
    """
    Function: perform_graph_analytics
    ---------------------------------
    Why it exists: Computes graph centrality metrics to prioritize important nodes.
    Input: Refined NetworkX MultiDiGraph.
    Output: Dictionary containing degree centrality, betweenness centrality, and top candidate nodes.
    Contribution: Provides topological intelligence to help analysts prioritize high-impact entities.
    """
    if graph.number_of_nodes() == 0:
        return {
            "top_degree_centrality": [],
            "top_betweenness_centrality": [],
            "important_nodes": []
        }

    # Convert MultiDiGraph to simple DiGraph for standard NetworkX centrality calculations
    simple_g = nx.DiGraph(graph)

    # 1. Degree Centrality:
    # Degree centrality measures how strongly a node is connected to other nodes in the NPG.
    # Highly connected entities (e.g., central gateway hosts or heavily accessed services)
    # can be prioritized as candidates for security investigation (not automatically malicious).
    degree_centrality = nx.degree_centrality(simple_g)

    # 2. Betweenness Centrality:
    # Betweenness centrality measures the fraction of shortest paths passing through a node.
    # Nodes with high betweenness act as critical structural bridges between subgraphs.
    try:
        betweenness_centrality = nx.betweenness_centrality(simple_g, k=min(100, simple_g.number_of_nodes()))
    except Exception:
        betweenness_centrality = {n: 0.0 for n in simple_g.nodes()}

    # Format top 5 degree centrality nodes
    sorted_degree = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:5]
    top_degree_list = [
        {
            "node_id": n,
            "node_type": simple_g.nodes[n].get("node_type", "Unknown"),
            "degree_score": round(score, 4)
        }
        for n, score in sorted_degree
    ]

    # Format top 5 betweenness centrality nodes
    sorted_betweenness = sorted(betweenness_centrality.items(), key=lambda x: x[1], reverse=True)[:5]
    top_betweenness_list = [
        {
            "node_id": n,
            "node_type": simple_g.nodes[n].get("node_type", "Unknown"),
            "betweenness_score": round(score, 4)
        }
        for n, score in sorted_betweenness
    ]

    # Combine top candidate nodes for investigation
    important_nodes = list(set([item["node_id"] for item in top_degree_list + top_betweenness_list]))

    return {
        "degree_centrality_top5": top_degree_list,
        "betweenness_centrality_top5": top_betweenness_list,
        "important_nodes": important_nodes,
        "analytics_explanation": (
            "Degree centrality identifies highly connected entities. "
            "Betweenness centrality identifies bridge entities connecting network subgraphs. "
            "These entities are candidate focus points for security analysts."
        )
    }
