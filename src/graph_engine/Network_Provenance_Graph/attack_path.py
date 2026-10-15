# ==============================================================================
# ATTACK PATH RECONSTRUCTION ENGINE MODULE
# Objective: Traverses connected provenance relationships (Attacker Host -> Service ->
# Alert -> Victim Host) under temporal causality constraints to reconstruct attack paths.
# ==============================================================================

import networkx as nx
import itertools
from typing import List, Dict, Any, Optional


def reconstruct_attack_path(
    graph: nx.MultiDiGraph,
    source_ip: str,
    target_ip: str,
    max_time_window_seconds: float = 86400.0,
    max_path_length: int = 5
) -> List[Dict[str, Any]]:
    """
    Function: reconstruct_attack_path
    ---------------------------------
    Why it exists: Main functional wrapper to trace attack vectors between source and victim hosts.
    Input: Refined MultiDiGraph, source IP string, victim target IP string.
    Output: List of chronologically validated attack path dictionaries.
    Contribution: Enables explainable threat reconstruction by discovering multi-hop causal chains.
    """
    finder = CausalTemporalPathFinder(graph)
    return finder.reconstruct_attack_paths(
        source_ip=source_ip,
        target_ip=target_ip,
        max_time_window_seconds=max_time_window_seconds,
        max_path_length=max_path_length
    )


class CausalTemporalPathFinder:
    """
    Reconstructs time-ordered attack paths across a Network Provenance Graph (NPG).
    Enforces strict temporal causality: timestamp(hop_i+1) >= timestamp(hop_i).
    """

    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph

    def reconstruct_attack_paths(
        self,
        source_ip: str,
        target_ip: str,
        max_time_window_seconds: float = 86400.0,
        max_path_length: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Finds chronologically ordered causal paths between source_ip and target_ip.
        
        Graph Traversal Method:
        - We use Depth-First / Simple Path Search (`nx.all_simple_paths`) over a directed view.
        - Why Simple Path Traversal is used: In provenance graphs, attack chains trace sequential
          causal relationships without visiting the same host twice.
        - Why Temporal Causality Filtering is used: An event at step (t2) cannot cause an event
          that occurred earlier at (t1 < t2). Hence we enforce timestamp(hop_i+1) >= timestamp(hop_i).
        """
        start_node = f"Host:{source_ip}"
        end_node = f"Host:{target_ip}"

        if not self.graph.has_node(start_node) or not self.graph.has_node(end_node):
            return []

        reconstructed_paths = []
        
        # Traverse structural paths using a simple DiGraph view to prevent path explosion
        simple_graph = nx.DiGraph(self.graph)
        try:
            simple_paths = list(itertools.islice(
                nx.all_simple_paths(
                    simple_graph,
                    source=start_node,
                    target=end_node,
                    cutoff=max_path_length
                ),
                50
            ))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

        for path in simple_paths:
            path_chain = []
            is_causal = True
            previous_ts = -1.0

            for i in range(len(path) - 1):
                u, v = path[i], path[i+1]
                edge_dict = self.graph.get_edge_data(u, v)

                # Select earliest edge occurring after previous_ts to maintain chronological ordering
                candidate_edge = None
                min_edge_ts = float('inf')

                for edge_key, data in edge_dict.items():
                    ts = data.get('timestamp', 0.0)
                    if ts >= previous_ts:
                        if previous_ts == -1.0 or (ts - previous_ts) <= max_time_window_seconds:
                            if ts < min_edge_ts:
                                min_edge_ts = ts
                                candidate_edge = data

                if candidate_edge is None:
                    is_causal = False
                    break

                previous_ts = min_edge_ts
                path_chain.append({
                    "hop": i + 1,
                    "from_node": u,
                    "to_node": v,
                    "rel_type": candidate_edge.get("rel_type", "ACCESSED_SERVICE"),
                    "timestamp": min_edge_ts,
                    "attack_type": candidate_edge.get("attack_type", "Normal"),
                    "label": candidate_edge.get("label", 0)
                })

            if is_causal and path_chain:
                duration = path_chain[-1]["timestamp"] - path_chain[0]["timestamp"]
                malicious_steps = sum(1 for step in path_chain if step["label"] == 1)
                
                reconstructed_paths.append({
                    "path_id": f"path_{len(reconstructed_paths)+1}",
                    "source_host": source_ip,
                    "target_host": target_ip,
                    "hop_count": len(path_chain),
                    "start_time": path_chain[0]["timestamp"],
                    "end_time": path_chain[-1]["timestamp"],
                    "duration_seconds": duration,
                    "malicious_step_ratio": malicious_steps / len(path_chain),
                    "chain": path_chain
                })

        # Sort reconstructed paths chronologically
        reconstructed_paths.sort(key=lambda p: p["start_time"])
        return reconstructed_paths

