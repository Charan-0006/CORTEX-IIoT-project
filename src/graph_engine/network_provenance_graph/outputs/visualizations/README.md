# CORTEX Layer 3B: Master Unified Network Provenance Graph Visualizations Guide

This folder contains the **5 essential, presentation-quality PNG visualizations** generated from **ALL 23 Processed Network Datasets** (`Network_dataset_1.csv` through `Network_dataset_23.csv`) in the ToN-IoT benchmark suite.

---

## Preprocessing & Merged Dataset Verification Summary

Before constructing the unified Network Provenance Graph (NPG), all 23 processed CSV files were ingested, validated, merged, and deduplicated:

- **Source Dataset Directory**: `data/raw/Processed_datasets/Processed_Network_dataset/`
- **CSV Dataset Files Loaded**: **23 Files** (`Network_dataset_1.csv` .. `Network_dataset_23.csv`)
- **Total Raw Rows Ingested**: **46,000 Rows**
- **Unique Rows After Deduplication**: **39,066 Flow Records**
- **Duplicate Rows Removed**: **6,934 Rows**
- **Schema Validation & Missing Value Summary**:
  - `src_ip`: 0 missing
  - `dst_ip`: 0 missing
  - `dst_port`: 0 missing
  - `proto`: 0 missing
  - `label`: 0 missing
  - `type`: 0 missing
  - `ts`: 0 missing
  - **Schema Compliance**: 100% Passed

---

## Unified Layer 3B Graph Metrics Summary

- **Total Unified Graph Nodes**: **41,644 Nodes**
  - **Host Nodes (Royal Blue)**: 286
  - **Service Nodes (Emerald Green)**: 4,795
  - **Alert Nodes (Crimson Red)**: 36,563
- **Total Directed Provenance Edges**: **190,324 Edges**
- **Reconstructed Causal Attack Paths**: **17 Attack Chains**
- **Correlated Security Incident Clusters**: **22 Incident Clusters**

---

## Index of Visualizations

| Figure File | Image Title | Primary Focus |
| :--- | :--- | :--- |
| `01_graph_schema.png` | Graph Schema Blueprint | Master blueprint of Node & Relationship types |
| `02_simplified_npg.png` | Simplified Network Provenance Graph | Representative top-hub subgraph from 23 merged files |
| `03_attack_path_reconstruction.png` | Attack Path Reconstruction | Highlighted multi-hop causal intrusion chain in red |
| `04_event_correlation_graph.png` | Event Correlation Graph | Threat events & host IP target mapping |
| `05_graph_metrics_dashboard.png` | Master Graph Metrics Dashboard | Executive summary card of dataset files, nodes, edges & density |

---

## Detailed Figure-by-Figure Review Guide

### 1. Figure 1: Graph Schema Blueprint (`01_graph_schema.png`)
1. **What it represents**: The master structural schema blueprint defining entity types (`Host`, `Service`, `Alert`) and directional relationships in the CORTEX Layer 3B graph engine.
2. **How it was generated**: Derived by specifying formal schema mapping contracts: `src_ip`/`dst_ip` $\rightarrow$ `HostNode`, `dst_port`/`proto` $\rightarrow$ `ServiceNode`, and `label`/`type` $\rightarrow$ `AlertNode`.
3. **What the nodes represent**:
   - `Host`: Network endpoints identified by IP addresses.
   - `Service`: Listening network services defined by port and protocol.
   - `Alert`: Security threat events generated from malicious flows.
4. **What the edges represent**:
   - `COMMUNICATED_WITH`: Host-to-Host direct flow.
   - `ACCESSED_SERVICE`: Host accessing a Service.
   - `EXPLOITED_ON` / `HOSTED_ON`: Service binding to Host.
   - `GENERATED_ALERT`: Host triggering an Alert.
   - `TARGETS_HOST`: Alert targeting a Host.
5. **What each color means**:
   - **Royal Blue (#1f77b4)**: Host Node (IP Entity)
   - **Emerald Green (#2ca02c)**: Service Node (Port/Protocol)
   - **Crimson Red (#d62728)**: Alert Node (Security Threat)
6. **Why this figure is important**: Establishes the foundational schema contract used across NetworkX graph memory and Neo4j graph storage.
7. **How to explain during project review**: *"This blueprint illustrates our formal graph schema contract. We model network devices as Hosts, listening ports as Services, and security detections as Alerts, connected by 5 typed relationships."*

---

### 2. Figure 2: Simplified Network Provenance Graph (`02_simplified_npg.png`)
1. **What it represents**: A clean, high-density representative subgraph showcasing top hub hosts, active network services, and alert nodes across all 23 merged network datasets.
2. **How it was generated**: Formed by extracting top-degree hub nodes from the unified 39,066-flow graph across 23 CSV files to prevent visual "hairball" clutter.
3. **What the nodes represent**: Active Host IP entities, network service endpoints, and threat alert nodes.
4. **What the edges represent**: Provenance connections showing directional network communications and service access.
5. **What each color means**:
   - **Royal Blue (#1f77b4)**: Host IP Node
   - **Emerald Green (#2ca02c)**: Service Endpoint Node
   - **Crimson Red (#d62728)**: Alert Event Node
6. **Why this figure is important**: Demonstrates clean multi-file graph construction and structural topology without unreadable hairball clutter.
7. **How to explain during project review**: *"Because a 41,644-node graph cannot be visually interpreted as a raw image without forming an unreadable 'hairball', we render this representative subgraph containing the top hub entities across all 23 dataset files."*

---

### 3. Figure 3: Attack Path Reconstruction (`03_attack_path_reconstruction.png`)
1. **What it represents**: Reconstructed multi-hop causal attack path highlighted against the background network graph.
2. **How it was generated**: Reconstructed using the `CausalTemporalPathFinder` enforcing strict chronological causality ($t_{i+1} \ge t_i$) over ToN-IoT flow timestamps across 23 files.
3. **What the nodes represent**: Source adversary host IP, intermediate service/host hops, and victim target host IP.
4. **What the edges represent**: Directed, time-ordered attack transitions (`COMMUNICATED_WITH`, `EXPLOITED_ON`, `GENERATED_ALERT`).
5. **What each color means**:
   - **Muted Gray**: Benign background network traffic
   - **Bold Crimson Red**: Active intrusion path and attacker steps
6. **Why this figure is important**: Isolates the specific attack chain from tens of thousands of background network flows for automated threat response.
7. **How to explain during project review**: *"This figure shows Causal Attack Path Reconstruction. Our algorithm filters out thousands of benign background connections to trace the exact multi-hop path used by the attacker in red."*

---

### 4. Figure 4: Event Correlation Graph (`04_event_correlation_graph.png`)
1. **What it represents**: Focused subgraph mapping security threat alerts directly to targeted victim host IP endpoints.
2. **How it was generated**: Extracted by sliding time-window alert correlation (`GraphEventCorrelator`) across merged alert logs.
3. **What the nodes represent**: Crimson Red = Alert Threat Events (DoS, DDoS, Scanning, Injection, Password attack); Royal Blue = Targeted Victim Host IPs.
4. **What the edges represent**: `TARGETS_HOST` directional edges linking security alerts to victim hosts.
5. **What each color means**:
   - **Crimson Red (#d62728)**: Threat Event Node
   - **Royal Blue (#1f77b4)**: Target Victim Host IP Node
   - **Orange Lines**: Target Relationship Vectors
6. **Why this figure is important**: Aggregates disparate alert logs into unified security incident clusters.
7. **How to explain during project review**: *"This graph shows Event Correlation, displaying how threat events occurring within a sliding time window are mapped directly to their targeted IP endpoints."*

---

### 5. Figure 5: Master Graph Metrics Dashboard (`05_graph_metrics_dashboard.png`)
1. **What it represents**: Executive summary metrics card displaying quantitative scale metrics of Layer 3B graph construction across all 23 processed datasets.
2. **How it was generated**: Calculated directly from NetworkX graph properties and data loader summary stats.
3. **What the nodes/edges represent**: Summary of Total Files (23), Raw Rows (46,000), Deduplicated Rows (39,066), Total Nodes (41,644), Host Nodes (286), Service Nodes (4,795), Alert Nodes (36,563), and Total Edges (190,324).
4. **What each color means**: Professional blue border and card background with monospace text formatting.
5. **Why this figure is important**: Provides empirical verification of data ingestion scale and graph schema integrity across the entire dataset.
6. **How to explain during project review**: *"This dashboard provides quantitative verification for our project guide, confirming that 23 processed network dataset files yielding 39,066 unique records were converted into 41,644 nodes and 190,324 edges with 100% schema compliance."*

---

## Adaptive Graph Intelligence Layer (Layer 3B) Summary

The **CORTEX Layer 3B Adaptive Graph Intelligence Engine** provides:
1. **Multi-File Automated Preprocessing**: Ingests, validates, merges, and deduplicates all 23 ToN-IoT Network CSV dataset files seamlessly.
2. **Unified Provenance Graph Memory**: Transforms tabular network flow records into a unified 41,644-node, 190,324-edge in-memory NetworkX MultiDiGraph.
3. **Causal Attack Path Reconstruction**: Enforces temporal reachability constraints to reconstruct 17 multi-hop intrusion paths.
4. **Sliding-Window Event Correlation**: Clusters 36,563 alert nodes into 22 incident clusters.
5. **Agentic Payload Hand-off**: Exports structured graph intelligence payloads to downstream Layer 4 CrewAI agents for automated threat reasoning and remediation.
