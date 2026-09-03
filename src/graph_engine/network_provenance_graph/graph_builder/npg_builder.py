# ==============================================================================
# NETWORK PROVENANCE GRAPH (NPG) BUILDER MODULE
# Objective: Converts processed ToN-IoT network DataFrame records into a structured
# directed Network Provenance Graph (NPG) using NetworkX.
# ==============================================================================

import networkx as nx
import pandas as pd
from typing import Dict, Any, Tuple
from src.schema.schema_definition import HostNode, ServiceNode, AlertNode


def extract_host(ip: str) -> HostNode:
    """
    Function: extract_host
    ----------------------
    Why it exists: Converts an IP string into a standardized HostNode entity.
    Input: IP address string (from 'src_ip' or 'dst_ip').
    Output: HostNode dataclass instance.
    Contribution: Creates Host nodes in the Network Provenance Graph.
    """
    # Source IP / Destination IP represents the network host initiating or receiving communication.
    return HostNode(ip=str(ip).strip())


def extract_service(port: int, protocol: str, service_name: str = "-") -> ServiceNode:
    """
    Function: extract_service
    -------------------------
    Why it exists: Converts network port and protocol attributes into a ServiceNode entity.
    Input: Destination port integer, protocol string (from 'dst_port' and 'proto').
    Output: ServiceNode dataclass instance.
    Contribution: Creates Service endpoint nodes in the Network Provenance Graph.
    """
    proto_clean = str(protocol).lower().strip()
    svc_clean = str(service_name).strip()
    if svc_clean in ['-', 'unknown', '']:
        svc_clean = f"port_{port}"
    return ServiceNode(port=int(port), protocol=proto_clean, service_name=svc_clean)


def extract_alert(attack_type: str, timestamp: float) -> AlertNode:
    """
    Function: extract_alert
    -----------------------
    Why it exists: Converts a malicious flow classification into an AlertNode entity.
    Input: Attack type string (from 'type' dataset field) and timestamp float.
    Output: AlertNode dataclass instance.
    Contribution: Creates Alert nodes when malicious network events (label == 1) occur.
    """
    atk_clean = str(attack_type).strip().lower()
    severity = "CRITICAL" if atk_clean in ['dos', 'ddos', 'injection'] else "HIGH"
    return AlertNode(
        alert_id=atk_clean,
        attack_type=atk_clean,
        severity=severity,
        confidence=0.95,
        timestamp=timestamp,
        domain="Network"
    )


def build_provenance_graph(df: pd.DataFrame) -> nx.MultiDiGraph:
    """
    Function: build_provenance_graph
    --------------------------------
    Why it exists: Main functional wrapper to construct NPG from DataFrame.
    Input: Cleaned ToN-IoT pandas DataFrame.
    Output: Directed NetworkX MultiDiGraph.
    Contribution: Assembles Host, Service, Alert nodes and directed provenance relationships.
    """
    builder = NetworkProvenanceGraphBuilder()
    return builder.build_from_dataframe(df)


class NetworkProvenanceGraphBuilder:
    """
    Transforms merged ToN-IoT Network DataFrame records into a directed Network Provenance Graph (NPG).
    """

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def build_from_dataframe(self, df: pd.DataFrame) -> nx.MultiDiGraph:
        """
        Parses merged ToN-IoT Network DataFrame records into Host, Service, and Alert nodes and directed edges.
        """
        self.graph.clear()

        for idx, row in df.iterrows():
            src_ip = str(row['src_ip']).strip()
            dst_ip = str(row['dst_ip']).strip()
            
            try:
                dst_port = int(row['dst_port'])
            except (ValueError, TypeError):
                dst_port = 80

            proto = str(row.get('proto', 'tcp')).lower().strip()
            service_name = str(row.get('service', '-')).strip()
            label = int(row.get('label', 0))
            attack_type = str(row.get('type', 'normal')).strip().lower()
            ts = float(row.get('ts', idx * 1.0))

            # 1. Extract Entities using Helper Functions
            src_host = extract_host(src_ip)
            dst_host = extract_host(dst_ip)
            service = extract_service(dst_port, proto, service_name)

            # Add Host Nodes to Graph
            if not self.graph.has_node(src_host.get_id()):
                self.graph.add_node(src_host.get_id(), **src_host.to_dict())

            if not self.graph.has_node(dst_host.get_id()):
                self.graph.add_node(dst_host.get_id(), **dst_host.to_dict())

            # Add Service Node to Graph
            if not self.graph.has_node(service.get_id()):
                self.graph.add_node(service.get_id(), **service.to_dict())

            # ------------------------------------------------------------------
            # PROVENANCE RELATIONSHIP CONSTRUCTION
            # ------------------------------------------------------------------

            # Relationship 1: ACCESSED_SERVICE (Host -> Service)
            # Meaning: Originating Source Host initiated communication accessing the identified network service endpoint.
            self.graph.add_edge(
                src_host.get_id(),
                service.get_id(),
                key=f"flow_{idx}_src_svc",
                rel_type="ACCESSED_SERVICE",
                timestamp=ts,
                label=label,
                attack_type=attack_type
            )

            # Relationship 2: EXPLOITED_ON (Service -> Host)
            # Meaning: Identified network service endpoint operates on or targets the Destination Victim Host.
            self.graph.add_edge(
                service.get_id(),
                dst_host.get_id(),
                key=f"flow_{idx}_svc_dst",
                rel_type="EXPLOITED_ON",
                timestamp=ts,
                label=label,
                attack_type=attack_type
            )

            # Relationship 3 & 4: GENERATED_ALERT and TARGETS_HOST (Only created when label == 1)
            # Meaning: If network flow is malicious, instantiate Alert Node and link source host to alert, and alert to victim host.
            if label == 1 and attack_type != 'normal':
                alert_node = extract_alert(attack_type, ts)

                if not self.graph.has_node(alert_node.get_id()):
                    self.graph.add_node(alert_node.get_id(), **alert_node.to_dict())

                # Relationship 3: GENERATED_ALERT (Host -> Alert)
                # Meaning: Malicious activity originating from Source Host generated a security alert.
                self.graph.add_edge(
                    src_host.get_id(),
                    alert_node.get_id(),
                    key=f"alert_trig_{idx}",
                    rel_type="GENERATED_ALERT",
                    timestamp=ts,
                    attack_type=attack_type
                )

                # Relationship 4: TARGETS_HOST (Alert -> Victim Host)
                # Meaning: Generated security alert specifically targets the victim destination host.
                self.graph.add_edge(
                    alert_node.get_id(),
                    dst_host.get_id(),
                    key=f"alert_target_{idx}",
                    rel_type="TARGETS_HOST",
                    timestamp=ts,
                    attack_type=attack_type
                )

        return self.graph

    def summarize_schema(self) -> Dict[str, Any]:
        """Provides a statistical breakdown of node types and relationship edge types."""
        node_types = {}
        for _, data in self.graph.nodes(data=True):
            ntype = data.get("node_type", "Unknown")
            node_types[ntype] = node_types.get(ntype, 0) + 1

        rel_types = {}
        for _, _, data in self.graph.edges(data=True):
            rtype = data.get("rel_type", "COMMUNICATED_WITH")
            rel_types[rtype] = rel_types.get(rtype, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_distribution": node_types,
            "relationship_distribution": rel_types
        }

