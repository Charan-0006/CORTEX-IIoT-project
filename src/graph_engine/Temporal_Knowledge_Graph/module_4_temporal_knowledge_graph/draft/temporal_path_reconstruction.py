"""Temporal candidate-path discovery, evidence preservation, and graph analytics."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd


def make_event_graph(events: pd.DataFrame, edges: pd.DataFrame,
                     relationship_types: set[str] | None = None) -> nx.MultiDiGraph:
    """Construct an event MultiDiGraph preserving multiple distinct relationships."""
    graph = nx.MultiDiGraph()
    if events.empty:
        return graph

    for row in events.to_dict(orient="records"):
        graph.add_node(
            str(row["event_id"]),
            source_file=str(row.get("source_file", "")),
            source_dataset=str(row.get("source_dataset", "")),
            source_row_number=row.get("source_row_number"),
            timestamp_epoch=row.get("timestamp_epoch"),
            timestamp_utc=row.get("timestamp_utc"),
            label=row.get("label"),
            src_ip=row.get("src_ip"),
            dst_ip=row.get("dst_ip"),
        )

    if not edges.empty:
        for row in edges.to_dict(orient="records"):
            rel = str(row.get("relationship_type", ""))
            if relationship_types and rel not in relationship_types:
                continue
            a, b = str(row["source_event_id"]), str(row["target_event_id"])
            if a in graph and b in graph:
                # Use edge_id as the distinct multi-edge key to preserve all evidence
                edge_key = str(row.get("edge_id") or f"{a}->{b}:{rel}")
                graph.add_edge(a, b, key=edge_key, **row)

    return graph


def is_attack_label(value: Any) -> bool:
    """Determine whether a label string represents a malicious or attack event."""
    if value is None or pd.isna(value):
        return False
    label = str(value).strip().lower()
    if label in {"", "0", "false", "normal", "benign", "none", "nan", "no_attack", "clean"}:
        return False
    if label in {"1", "true", "attack", "malicious", "anomaly"}:
        return True
    return any(term in label for term in (
        "attack", "malicious", "ransom", "ddos", "dos", "injection",
        "backdoor", "password", "scanning", "xss", "mitm", "theft", "exploit"
    ))


def discover_candidate_paths(events: pd.DataFrame, edges: pd.DataFrame,
                             max_paths: int = 100, max_hops: int = 6,
                             relationship_types: set[str] | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Find bounded source-to-attack paths over actual evidence edges.

    Paths are candidate explanations, not confirmed attack causality.
    Only chronologically valid edges (temporal_order_valid == True) are traversed.
    """
    path_cols = ["path_id", "start_event_id", "end_event_id", "hop_count",
                 "start_timestamp_utc", "end_timestamp_utc", "duration_seconds",
                 "attack_label", "relationship_types", "evidence_edge_count",
                 "source_files", "interpretation"]
    event_cols = ["path_id", "position", "event_id", "timestamp_utc", "label",
                  "src_ip", "dst_ip", "source_file", "source_row_number", "incoming_edge_id",
                  "incoming_relationship_type", "incoming_evidence_type", "incoming_matched_field",
                  "incoming_matched_value", "incoming_delta_seconds"]

    if events.empty or edges.empty:
        return pd.DataFrame(columns=path_cols), pd.DataFrame(columns=event_cols)

    # Filter out invalid temporal order edges to prevent reverse-chronological paths
    valid_edges = edges[edges["temporal_order_valid"] == True] if "temporal_order_valid" in edges.columns else edges
    if valid_edges.empty:
        return pd.DataFrame(columns=path_cols), pd.DataFrame(columns=event_cols)

    graph = make_event_graph(events, valid_edges, relationship_types)
    attack_events = events[events["label"].apply(is_attack_label)]
    if attack_events.empty:
        return pd.DataFrame(columns=path_cols), pd.DataFrame(columns=event_cols)

    event_lookup = events.set_index("event_id", drop=False).to_dict(orient="index")
    path_rows, detail_rows = [], []
    seen_paths = set()

    # Simple directed graph for efficient reachability without multi-edge overhead
    simple_dir = nx.DiGraph()
    simple_dir.add_nodes_from(graph.nodes())
    for u, v in graph.edges():
        simple_dir.add_edge(u, v)

    simple_rev = simple_dir.reverse(copy=True)

    # Search backwards from attack endpoints
    for target in attack_events["event_id"].astype(str).tolist():
        if target not in simple_rev or simple_rev.out_degree(target) == 0:
            continue
        if len(path_rows) >= max_paths:
            break

        try:
            lengths = nx.single_source_shortest_path_length(simple_rev, target, cutoff=max_hops)
        except nx.NetworkXError:
            continue

        # Select candidate start nodes
        candidates = []
        for node, dist in lengths.items():
            if node == target or dist < 1:
                continue
            if graph.in_degree(node) == 0:
                candidates.append((dist, node))
        if not candidates:
            candidates = [(dist, node) for node, dist in lengths.items() if node != target and dist >= 1]

        # Bound candidates per target to avoid combinatorial explosion
        candidates.sort(key=lambda x: (x[0], x[1]))
        candidates = candidates[:15]

        for _, start in candidates:
            if len(path_rows) >= max_paths:
                break
            try:
                paths_iter = nx.all_simple_paths(simple_dir, start, target, cutoff=max_hops)
                paths_found_for_pair = 0
                for path in paths_iter:
                    if len(path) < 2:
                        continue
                    signature = tuple(path)
                    if signature in seen_paths:
                        continue
                    seen_paths.add(signature)

                    start_rec, end_rec = event_lookup.get(path[0], {}), event_lookup.get(path[-1], {})
                    t0, t1 = start_rec.get("timestamp_epoch"), end_rec.get("timestamp_epoch")
                    duration = float(t1 - t0) if (t0 is not None and t1 is not None and pd.notna(t0) and pd.notna(t1)) else None

                    pid = f"path_{len(path_rows)+1:05d}"
                    rel_types, edge_ids, source_files = [], [], set()
                    for event_id in path:
                        rec = event_lookup.get(event_id, {})
                        source_files.add(str(rec.get("source_file", "")))

                    edge_provenance_list = []
                    for a, b in zip(path, path[1:]):
                        edata_dict = graph.get_edge_data(a, b) or {}
                        # Pick first edge data dictionary in MultiDiGraph
                        first_edata = next(iter(edata_dict.values())) if edata_dict else {}
                        rel_types.append(str(first_edata.get("relationship_type", "")))
                        edge_ids.append(str(first_edata.get("edge_id", "")))
                        edge_provenance_list.append(first_edata)

                    path_rows.append({
                        "path_id": pid,
                        "start_event_id": path[0],
                        "end_event_id": path[-1],
                        "hop_count": len(path) - 1,
                        "start_timestamp_utc": start_rec.get("timestamp_utc"),
                        "end_timestamp_utc": end_rec.get("timestamp_utc"),
                        "duration_seconds": duration,
                        "attack_label": end_rec.get("label"),
                        "relationship_types": " | ".join(rel_types),
                        "evidence_edge_count": len([e for e in edge_ids if e and e != "nan"]),
                        "source_files": " | ".join(sorted(x for x in source_files if x)),
                        "interpretation": "Candidate temporal path; not proof of causal attack execution.",
                    })

                    for position, event_id in enumerate(path):
                        rec = event_lookup.get(event_id, {})
                        incoming = edge_provenance_list[position - 1] if position > 0 else {}
                        detail_rows.append({
                            "path_id": pid,
                            "position": position,
                            "event_id": event_id,
                            "timestamp_utc": rec.get("timestamp_utc"),
                            "label": rec.get("label"),
                            "src_ip": rec.get("src_ip"),
                            "dst_ip": rec.get("dst_ip"),
                            "source_file": rec.get("source_file"),
                            "source_row_number": rec.get("source_row_number"),
                            "incoming_edge_id": (incoming or {}).get("edge_id"),
                            "incoming_relationship_type": (incoming or {}).get("relationship_type"),
                            "incoming_evidence_type": (incoming or {}).get("evidence_type"),
                            "incoming_matched_field": (incoming or {}).get("matched_field"),
                            "incoming_matched_value": (incoming or {}).get("matched_value"),
                            "incoming_delta_seconds": (incoming or {}).get("delta_seconds"),
                        })

                    paths_found_for_pair += 1
                    if paths_found_for_pair >= 5 or len(path_rows) >= max_paths:
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    return pd.DataFrame(path_rows, columns=path_cols), pd.DataFrame(detail_rows, columns=event_cols)


def compute_blast_radius(graph: nx.DiGraph | nx.MultiDiGraph, max_hops: int = 5, top_n_sources: int = 10) -> pd.DataFrame:
    """Compute exact-hop reachability and cumulative blast radius for top source nodes."""
    if graph.number_of_nodes() == 0 or graph.number_of_edges() == 0:
        return pd.DataFrame(columns=["source_node", "hop", "exact_reachability", "cumulative_reachability"])

    # Source nodes with out-degree > 0
    sources = sorted(graph.nodes(), key=lambda n: graph.out_degree(n), reverse=True)[:top_n_sources]
    records = []
    simple_g = nx.DiGraph(graph)

    for src in sources:
        try:
            lengths = nx.single_source_shortest_path_length(simple_g, src, cutoff=max_hops)
            hop_counts = Counter(lengths.values())
            cumulative = 0
            for h in range(1, max_hops + 1):
                exact = hop_counts.get(h, 0)
                cumulative += exact
                records.append({
                    "source_node": src,
                    "hop": h,
                    "exact_reachability": exact,
                    "cumulative_reachability": cumulative,
                })
        except nx.NetworkXError:
            continue

    return pd.DataFrame(records)


def compute_graph_analytics(events: pd.DataFrame, edges: pd.DataFrame,
                            path_events: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """Calculate empirical graph analytics metrics from the constructed graph."""
    graph = make_event_graph(events, edges)

    # Connected Components (undirected view)
    component_rows = []
    if graph.number_of_nodes():
        undirected = graph.to_undirected()
        for i, comp in enumerate(sorted(nx.connected_components(undirected), key=len, reverse=True), 1):
            component_rows.append({"component_id": f"component_{i:05d}", "node_count": len(comp)})

    # Degrees
    degree_rows = []
    if graph.number_of_nodes():
        for node in graph.nodes():
            degree_rows.append({
                "event_id": node,
                "in_degree": graph.in_degree(node),
                "out_degree": graph.out_degree(node),
                "degree": graph.degree(node),
            })

    # Edge counts by relationship type
    edge_counts = edges["relationship_type"].value_counts().rename_axis("relationship_type").reset_index(name="edge_count") if not edges.empty else pd.DataFrame(columns=["relationship_type", "edge_count"])

    # Evidence type counts
    evidence_counts = edges["evidence_type"].value_counts().rename_axis("evidence_type").reset_index(name="edge_count") if not edges.empty and "evidence_type" in edges.columns else pd.DataFrame(columns=["evidence_type", "edge_count"])

    # Label distribution
    label_counts = events["label"].fillna("UNLABELLED").astype(str).value_counts().rename_axis("label").reset_index(name="event_count") if not events.empty else pd.DataFrame(columns=["label", "event_count"])

    # Events per source file
    file_counts = events["source_file"].value_counts().rename_axis("source_file").reset_index(name="event_count") if not events.empty else pd.DataFrame(columns=["source_file", "event_count"])

    # Inter-event gaps
    timestamp = events.copy()
    if not timestamp.empty:
        timestamp["timestamp_epoch"] = pd.to_numeric(timestamp["timestamp_epoch"], errors="coerce")
        valid = timestamp.dropna(subset=["timestamp_epoch"]).sort_values("timestamp_epoch")
        gaps = valid["timestamp_epoch"].diff().dropna()
        gap_df = pd.DataFrame({"inter_event_gap_seconds": gaps.clip(lower=0)})
    else:
        gap_df = pd.DataFrame(columns=["inter_event_gap_seconds"])

    # Chokepoints (frequency of node visits across paths)
    if not path_events.empty:
        chokepoints = (
            path_events.groupby(["event_id", "source_file"], dropna=False)
            .size()
            .reset_index(name="path_occurrences")
            .sort_values("path_occurrences", ascending=False)
        )
    else:
        chokepoints = pd.DataFrame(columns=["event_id", "source_file", "path_occurrences"])

    # Blast radius table
    blast_radius_df = compute_blast_radius(graph, max_hops=5, top_n_sources=10)

    # Attack label density by hop in paths
    if not path_events.empty:
        hop_attack_df = (
            path_events.groupby(["position", "label"])
            .size()
            .reset_index(name="count")
            .rename(columns={"position": "hop_position"})
        )
    else:
        hop_attack_df = pd.DataFrame(columns=["hop_position", "label", "count"])

    return {
        "components": pd.DataFrame(component_rows),
        "node_degrees": pd.DataFrame(degree_rows),
        "relationship_counts": edge_counts,
        "evidence_counts": evidence_counts,
        "label_counts": label_counts,
        "events_by_file": file_counts,
        "inter_event_gaps": gap_df,
        "chokepoints": chokepoints,
        "blast_radius": blast_radius_df,
        "attack_density_by_hop": hop_attack_df,
    }
