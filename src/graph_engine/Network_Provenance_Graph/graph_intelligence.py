# ==============================================================================
# STRUCTURED GRAPH INTELLIGENCE GENERATOR MODULE
# Objective: Formats Network Provenance Graph analysis, reconstructed attack paths,
# centrality metrics, risk scores, and graph confidence into a structured Python dictionary /
# JSON format for consumption by the downstream Multi-Agent AI Layer.
# ==============================================================================

import json
import networkx as nx
from typing import Dict, Any, List, Optional
from src.analytics.graph_risk import calculate_graph_risk
from src.analytics.graph_confidence import calculate_graph_confidence


def generate_graph_intelligence(
    attack_paths: List[Dict[str, Any]],
    analytics_results: Dict[str, Any],
    refinement_stats: Dict[str, Any],
    source_ip: str,
    target_ip: str,
    graph: Optional[nx.MultiDiGraph] = None,
    validation_report: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Function: generate_graph_intelligence
    ------------------------------------
    Why it exists: Converts graph analytics into a machine-readable JSON structure for Multi-Agent AI consumption.
    Conforms to CORTEX Layer 3B NPG Schema v1.0, delimiting attack window context to TKG.
    """
    # Canonical Host IDs
    source_host_id = f"Host:{source_ip}" if not str(source_ip).startswith("Host:") else str(source_ip)
    target_host_id = f"Host:{target_ip}" if not str(target_ip).startswith("Host:") else str(target_ip)
    incident_id = f"INC-{source_ip.replace('.', '')}-{target_ip.replace('.', '')}"

    # Extract Primary Attack Type and Primary Service Endpoint
    if attack_paths:
        primary_path = attack_paths[0]
        chain = primary_path.get("chain", [])

        malicious_types = [
            step.get("attack_type") for step in chain 
            if step.get("attack_type") and str(step.get("attack_type")).lower() != "normal"
        ]
        primary_attack_type = malicious_types[0] if malicious_types else (chain[0].get("attack_type", "Security_Incident") if chain else "Security_Incident")

        service_nodes = [step.get("to_node") for step in chain if str(step.get("to_node", "")).startswith("Service:")]
        primary_service = service_nodes[0] if service_nodes else (chain[0].get("to_node", "Unknown_Service") if chain else "Unknown")
    else:
        primary_attack_type = "Normal_Traffic"
        primary_service = "None"

    # Evaluate Risk and Confidence using exact existing algorithms
    dummy_graph = graph if graph is not None else nx.MultiDiGraph()
    dummy_val_report = validation_report if validation_report is not None else {"is_schema_valid": True}

    risk_eval = calculate_graph_risk(
        graph=dummy_graph,
        attack_paths=attack_paths,
        analytics_results=analytics_results,
        refinement_stats=refinement_stats
    )

    confidence_eval = calculate_graph_confidence(
        graph=dummy_graph,
        attack_paths=attack_paths,
        validation_report=dummy_val_report,
        refinement_stats=refinement_stats
    )

    # 1. Extract ENTITIES (Hosts, Services, Alerts)
    hosts_list = []
    services_list = []
    alerts_list = []
    seen_entity_ids = set()

    if graph is not None and graph.number_of_nodes() > 0:
        for node_id, data in graph.nodes(data=True):
            if node_id in seen_entity_ids:
                continue
            seen_entity_ids.add(node_id)
            ntype = data.get("node_type", "Host")

            if ntype == "Host" or str(node_id).startswith("Host:"):
                hosts_list.append({
                    "node_id": str(node_id),
                    "node_type": "HOST",
                    "attributes": {
                        "ip": data.get("ip", str(node_id).replace("Host:", "")),
                        "role": data.get("role", "IIoT_Node"),
                        "subnet": data.get("subnet", "192.168.1.0/24")
                    }
                })
            elif ntype == "Service" or str(node_id).startswith("Service:"):
                services_list.append({
                    "node_id": str(node_id),
                    "node_type": "SERVICE",
                    "attributes": {
                        "protocol": data.get("protocol", "tcp"),
                        "port": int(data.get("port", 80)),
                        "service_name": data.get("service_name", f"port_{data.get('port', 80)}")
                    }
                })
            elif ntype == "Alert" or str(node_id).startswith("Alert:"):
                alerts_list.append({
                    "node_id": str(node_id),
                    "node_type": "ALERT",
                    "attributes": {
                        "attack_type": data.get("attack_type", "unknown"),
                        "severity": data.get("severity", "HIGH"),
                        "confidence": float(data.get("confidence", 0.95)),
                        "timestamp": float(data.get("timestamp", 0.0))
                    }
                })
    else:
        # Fallback entity generation if graph object is not passed
        hosts_list = [
            {"node_id": source_host_id, "node_type": "HOST", "attributes": {"ip": source_ip, "role": "IIoT_Node", "subnet": "192.168.1.0/24"}},
            {"node_id": target_host_id, "node_type": "HOST", "attributes": {"ip": target_ip, "role": "IIoT_Node", "subnet": "192.168.1.0/24"}}
        ]

    # 2. Extract RELATIONSHIPS
    relationships_list = []
    attack_types_observed_set = set()

    if graph is not None and graph.number_of_edges() > 0:
        for idx, (u, v, key, data) in enumerate(graph.edges(keys=True, data=True)):
            rel_type = data.get("rel_type", "ACCESSED_SERVICE")
            atk_type = str(data.get("attack_type", "normal"))
            if atk_type.lower() != "normal":
                attack_types_observed_set.add(atk_type)

            relationships_list.append({
                "edge_id": f"E{idx+1:03d}",
                "source": u,
                "relationship": rel_type,
                "target": v,
                "evidence": {
                    "timestamp": float(data.get("timestamp", 0.0)),
                    "label": int(data.get("label", 0)),
                    "attack_type": atk_type
                }
            })

    # Extract observed attack types from reconstructed attack paths if any
    for path in attack_paths:
        for step in path.get("chain", []):
            atk = str(step.get("attack_type", "normal"))
            if atk.lower() != "normal":
                attack_types_observed_set.add(atk)

    if primary_attack_type.lower() != "normal_traffic":
        attack_types_observed_set.add(primary_attack_type)

    attack_types_observed = sorted(list(attack_types_observed_set))

    # 3. Format ATTACK RECONSTRUCTION Candidate Paths
    candidate_paths = []
    for idx, path in enumerate(attack_paths):
        chain_steps = []
        for step_dict in path.get("chain", []):
            chain_steps.append({
                "step": step_dict.get("hop", 1),
                "source": step_dict.get("from_node"),
                "relationship": step_dict.get("rel_type"),
                "target": step_dict.get("to_node"),
                "timestamp": float(step_dict.get("timestamp", 0.0)),
                "label": int(step_dict.get("label", 0)),
                "attack_type": str(step_dict.get("attack_type", "normal"))
            })

        candidate_paths.append({
            "path_id": path.get("path_id", f"path_{idx+1}"),
            "source": f"Host:{path['source_host']}" if not str(path.get('source_host', '')).startswith("Host:") else path['source_host'],
            "target": f"Host:{path['target_host']}" if not str(path.get('target_host', '')).startswith("Host:") else path['target_host'],
            "hop_count": path.get("hop_count", len(chain_steps)),
            "path_duration_seconds": float(path.get("duration_seconds", 0.0)),
            "steps": chain_steps,
            "malicious_step_ratio": float(path.get("malicious_step_ratio", 0.0))
        })

    services_involved = sorted(list(set([svc["node_id"] for svc in services_list])))

    candidate_path_summaries = [
        {
            "path_id": cp["path_id"],
            "hop_count": cp["hop_count"],
            "malicious_step_ratio": cp["malicious_step_ratio"],
            "path_chain": [s["source"] for s in cp["steps"]] + ([cp["steps"][-1]["target"]] if cp["steps"] else [])
        }
        for cp in candidate_paths
    ]

    important_nodes = analytics_results.get("important_nodes", [])

    # Assemble Structured Payload matching required JSON schema
    graph_intelligence_payload = {
        "schema_version": "1.0",

        "incident_context": {
            "incident_id": incident_id,
            "primary_attack_type": primary_attack_type,
            "source_host": source_host_id,
            "target_host": target_host_id,
            "primary_service": primary_service
        },

        "entities": {
            "hosts": hosts_list,
            "services": services_list,
            "alerts": alerts_list
        },

        "relationships": relationships_list,

        "temporal_context": {
            "provided_by": "TKG",
            "start_time": None,
            "end_time": None,
            "duration_seconds": None
        },

        "attack_reconstruction": {
            "candidate_paths": candidate_paths
        },

        "graph_evidence": {
            "important_nodes": important_nodes,
            "attack_types_observed": attack_types_observed,
            "metrics": {
                "total_nodes": refinement_stats.get("final_nodes", 0),
                "total_edges": refinement_stats.get("final_edges", 0),
                "total_hosts": refinement_stats.get("total_hosts", 0),
                "total_services": refinement_stats.get("total_services", 0),
                "total_alerts": refinement_stats.get("total_alerts", 0),
                "average_degree": refinement_stats.get("average_node_degree", 0.0),
                "density": refinement_stats.get("graph_density", 0.0),
                "connected_components": refinement_stats.get("connected_components", 0)
            }
        },

        "risk_assessment": {
            "risk_score": risk_eval["risk_score"],
            "risk_level": risk_eval["risk_level"],
            "factors": {
                "attack_severity": risk_eval["risk_breakdown"]["attack_severity_factor"],
                "attack_path": risk_eval["risk_breakdown"]["attack_path_factor"],
                "topology_centrality": risk_eval["risk_breakdown"]["topology_centrality_factor"],
                "alert_density": risk_eval["risk_breakdown"]["alert_density_factor"]
            },
            "weights": {
                "attack_severity": risk_eval["risk_breakdown"]["component_weights"]["attack_severity_weight"],
                "attack_path": risk_eval["risk_breakdown"]["component_weights"]["attack_path_weight"],
                "topology_centrality": risk_eval["risk_breakdown"]["component_weights"]["topology_centrality_weight"],
                "alert_density": risk_eval["risk_breakdown"]["component_weights"]["alert_density_weight"]
            }
        },

        "graph_confidence": {
            "score": confidence_eval["graph_confidence"],
            "percentage": round(float(confidence_eval["graph_confidence"]) * 100.0, 2),
            "factors": {
                "schema_compliance": confidence_eval["confidence_breakdown"]["schema_compliance_factor"],
                "temporal_consistency": confidence_eval["confidence_breakdown"]["temporal_consistency_factor"],
                "structural_evidence": confidence_eval["confidence_breakdown"]["structural_evidence_factor"],
                "causal_path": confidence_eval["confidence_breakdown"]["causal_path_factor"]
            },
            "weights": {
                "schema_compliance": confidence_eval["confidence_breakdown"]["component_weights"]["schema_weight"],
                "temporal_consistency": confidence_eval["confidence_breakdown"]["component_weights"]["temporal_weight"],
                "structural_evidence": confidence_eval["confidence_breakdown"]["component_weights"]["evidence_weight"],
                "causal_path": confidence_eval["confidence_breakdown"]["component_weights"]["path_weight"]
            }
        },

        "ai_context": {
            "input_type": "network_provenance_graph_intelligence",
            "primary_attack": primary_attack_type,
            "source_host": source_host_id,
            "target_host": target_host_id,
            "services_involved": services_involved,
            "attack_types_observed": attack_types_observed,
            "candidate_paths": candidate_path_summaries,
            "key_graph_evidence": important_nodes,
            "risk_score": risk_eval["risk_score"],
            "risk_level": risk_eval["risk_level"],
            "graph_confidence": confidence_eval["graph_confidence"],
            "temporal_context_source": "TKG",
            "downstream_consumer": "Multi-Agent AI Reasoning Layer (CORTEX Layer 4)"
        }
    }

    return graph_intelligence_payload


def export_graph_intelligence_json(payload: Dict[str, Any], filepath: str = "outputs/graph_intelligence.json"):
    """Saves structured graph intelligence payload to a JSON file."""
    import os
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=4)
    print(f"[+] Structured Graph Intelligence Output exported to '{filepath}'.")

