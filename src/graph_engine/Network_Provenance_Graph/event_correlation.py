"""
CORTEX: Context & Graph-Aware Multi-Agent Framework for Explainable IIoT Threat Intelligence
Layer 3B: Adaptive Graph Intelligence Engine
Module: Graph Event Correlation Engine
"""

import networkx as nx
from typing import List, Dict, Any


class GraphEventCorrelator:
    """
    Correlates related security events across graph topological clusters and temporal windows.
    """

    def __init__(self, graph: nx.MultiDiGraph):
        self.graph = graph

    def correlate_alerts_by_window(
        self,
        time_window_seconds: float = 300.0
    ) -> List[Dict[str, Any]]:
        """
        Groups isolated security alert nodes into correlated attack clusters
        based on temporal proximity and shared host targets.
        """
        alert_nodes = [
            (n, d) for n, d in self.graph.nodes(data=True)
            if d.get("node_type") == "Alert"
        ]

        if not alert_nodes:
            return []

        # Sort alerts by timestamp
        alert_nodes.sort(key=lambda x: x[1].get("timestamp", 0.0))

        clusters = []
        current_cluster = []
        cluster_start_ts = -1.0

        for node_id, data in alert_nodes:
            ts = data.get("timestamp", 0.0)

            if cluster_start_ts == -1.0 or (ts - cluster_start_ts) <= time_window_seconds:
                current_cluster.append((node_id, data))
                if cluster_start_ts == -1.0:
                    cluster_start_ts = ts
            else:
                clusters.append(current_cluster)
                current_cluster = [(node_id, data)]
                cluster_start_ts = ts

        if current_cluster:
            clusters.append(current_cluster)

        # Format correlated cluster summaries
        correlated_events = []
        for idx, cluster in enumerate(clusters):
            attack_types = list(set(d.get("attack_type") for _, d in cluster))
            affected_hosts = set()

            for alert_id, _ in cluster:
                # Find hosts targeted by this alert
                for _, target, edge_data in self.graph.out_edges(alert_id, data=True):
                    if edge_data.get("rel_type") == "TARGETS_HOST":
                        affected_hosts.add(target)

            correlated_events.append({
                "cluster_id": f"cluster_{idx+1}",
                "event_count": len(cluster),
                "unique_attack_types": attack_types,
                "target_hosts": list(affected_hosts),
                "start_time": cluster[0][1].get("timestamp"),
                "end_time": cluster[-1][1].get("timestamp"),
                "span_seconds": cluster[-1][1].get("timestamp") - cluster[0][1].get("timestamp")
            })

        return correlated_events
