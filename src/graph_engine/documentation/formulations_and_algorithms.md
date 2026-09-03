# Formulations and Algorithms
## Adaptive Graph Intelligence (AGI)

This document provides a comprehensive mathematical, algorithmic, and statistical specification of every formulation, metric, calculation, heuristic, transformation, and algorithm implemented or defined in the **Adaptive Graph Intelligence (AGI)** platform.

---

### 1. Purpose and Scope

The purpose of this document is to establish complete mathematical and algorithmic transparency for the AGI platform across all four core modules (`module_1_dataset_validation`, `module_2_graph_feature_engineering`, `module_3_graph_schema`, and `module_4_temporal_knowledge_graph`) and shared `common/` utilities.

Every entry includes:
- **Exact Location**: Module, Python script, and function/class.
- **Mathematical / Logical Formulation**: LaTeX math block or clear equation.
- **Variables & Inputs**: Operational symbols and dataset attribute sources.
- **Output & Downstream Use**: Machine-readable artifacts and visualizations fed.
- **Method Classification**: `STANDARD`, `PROJECT-DERIVED`, `HEURISTIC`, `INFERRED`, `ADAPTED`, or `PLANNED`.
- **Implementation Status**: `IMPLEMENTED`, `DERIVED`, `HEURISTIC`, or `PLANNED / NOT IMPLEMENTED`.

---

### 2. Notation

| Symbol | Definition |
| :--- | :--- |
| $D$ | Telemetry dataset instance |
| $N_{\text{total}}$ | Total record/row count in dataset $D$ |
| $N_{\text{missing}}$ | Count of null or NaN values in an attribute column |
| $c$ | Telemetry attribute column |
| $e_i$ | Instantiated temporal telemetry event node $i$ |
| $t_i$ | Unix Epoch timestamp (float seconds) of event $i$ |
| $\Delta t$ | Inter-event temporal delay duration |
| $F(e)$ | Engineered graph feature vector for entity node $e$ |
| $G = (V, E)$ | Instantiated Temporal Knowledge Graph |
| $V$ | Set of graph nodes ($|V| \ge 9,500$) |
| $E$ | Set of graph edges (domain interactions and temporal ordering links) |
| $C$ | Relationship evidence confidence score ($0.0 \le C \le 1.0$) |
| $\mathbf{PR}(v)$ | PageRank centrality score of node $v$ |

---

### 3. Module 1 — Dataset Validation & Profiling

#### 3.1 Formulations

##### Formula 1.1: Missing Value Rate
- **Name**: Column Missing Rate
- **Location**: `module_1_dataset_validation/dataset_statistics.py` $\rightarrow$ `analyze_single_dataset_folder()`
- **Purpose**: Quantifies null/missing value density for raw telemetry attributes.
- **Formula**:
  $$\text{MissingRate}(c) = \left( \frac{\sum_{i=1}^{N_{\text{total}}} \mathbb{I}(\text{is\_null}(c_i))}{N_{\text{total}}} \right) \times 100$$
- **Variables**: $c_i$ = value at row $i$; $\mathbb{I}(\cdot)$ = indicator function returning 1 if value is null/NaN.
- **Inputs**: Raw CSV dataset columns from `data/Processed_datasets/`.
- **Output**: Numeric missing percentage $[0.0, 100.0]$ saved in `dataset_summary.csv`.
- **Where It Is Used**: `dataset_statistics.json`, `missing_values.png`, and Module 2 graph readiness tagging.
- **Why It Matters**: Prevents uninformative or sparse telemetry columns from being promoted to core graph node primary keys.
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

##### Formula 1.2: Completeness Percentage
- **Name**: Dataset Attribute Completeness
- **Location**: `module_1_dataset_validation/dataset_statistics.py` $\rightarrow$ `analyze_single_dataset_folder()`
- **Purpose**: Computes overall data population density across telemetry features.
- **Formula**:
  $$\text{Completeness}(c) = 100.0 - \text{MissingRate}(c)$$
- **Variables**: $\text{MissingRate}(c)$ = missing percentage from Formula 1.1.
- **Inputs**: Attribute column data vectors.
- **Output**: Completeness percentage value.
- **Where It Is Used**: `dataset_summary.csv` and `calculate_graph_readiness_score()`.
- **Why It Matters**: Establishes baseline quality threshold for feature engineering.
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

##### Formula 1.3: Uniqueness Ratio
- **Name**: Column Uniqueness Ratio
- **Location**: `module_1_dataset_validation/dataset_statistics.py` $\rightarrow$ `analyze_single_dataset_folder()`
- **Purpose**: Evaluates candidate identifier cardinality ratio.
- **Formula**:
  $$\text{UniquenessRatio}(c) = \left( \frac{|\text{Unique}(c)|}{N_{\text{total}}} \right) \times 100$$
- **Variables**: $|\text{Unique}(c)|$ = count of distinct non-null values in column $c$.
- **Inputs**: Raw telemetry attribute column $c$.
- **Output**: Uniqueness percentage $[0.0, 100.0]$.
- **Where It Is Used**: Primary key selection heuristics in Module 3 `node_schema.py`.
- **Why It Matters**: High uniqueness identifies candidate node identifiers (e.g. `user_id`, `process_id`, `src_ip`).
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

##### Formula 1.4: Multi-Factor Graph Readiness Score
- **Name**: Graph Readiness Score
- **Location**: `module_1_dataset_validation/dataset_statistics.py` $\rightarrow$ `calculate_graph_readiness_score()`
- **Purpose**: Scores overall dataset suitability for TKG construction using a 4-factor weighted linear combination.
- **Formula**:
  $$\text{ReadinessScore} = W_{\text{comp}} \cdot \bar{S}_{\text{comp}} + W_{\text{uniq}} \cdot \min(100.0, \bar{S}_{\text{uniq}}) + W_{\text{ts}} \cdot I_{\text{ts}} \cdot 100.0 + W_{\text{link}} \cdot I_{\text{link}} \cdot 100.0$$
- **Weights**:
  - $W_{\text{comp}} = 0.40$ (Average completeness weight)
  - $W_{\text{uniq}} = 0.30$ (Average uniqueness weight)
  - $W_{\text{ts}} = 0.15$ (Timestamp availability indicator weight)
  - $W_{\text{link}} = 0.15$ (Entity linkability indicator weight)
- **Variables**:
  - $\bar{S}_{\text{comp}}$ = mean completeness across dataset columns
  - $\bar{S}_{\text{uniq}}$ = mean uniqueness ratio across dataset columns
  - $I_{\text{ts}} \in \{0, 1\}$ = binary indicator (1 if timestamp column present, else 0)
  - $I_{\text{link}} \in \{0, 1\}$ = binary indicator (1 if entity identifier present, else 0)
- **Inputs**: Dataset statistics dictionary.
- **Output**: Single scalar score $[0.0, 100.0]$ in `dataset_statistics.json`.
- **Where It Is Used**: Module 1 summary report and dataset profiling export.
- **Why It Matters**: Provides an objective benchmark for prioritizing telemetry ingestion.
- **Classification**: `PROJECT-DERIVED` / `HEURISTIC`
- **Status**: `IMPLEMENTED`

---

#### 3.2 Metrics
- **Total Record Count ($N_{\text{total}}$)**: Integer sum of rows per telemetry file.
- **Total Feature Count**: Integer count of raw CSV columns.
- **Target Feature Availability Ratio**: Percentage of required telemetry features present in each dataset.

---

#### 3.3 Validation Rules
- **Rule 1.1 (Non-Empty Check)**: File size $> 0$ bytes and row count $N_{\text{total}} > 0$.
- **Rule 1.2 (Timestamp Regex Detection)**: A column is classified as a timestamp if its name matches regex `r'(timestamp|time|date|ts|datetime)'`.
- **Rule 1.3 (Identifier Regex Detection)**: A column is classified as an identifier if its name matches regex `r'(id|uuid|guid|ip|mac|host|pid)'`.

---

#### 3.4 Algorithms

##### Algorithm 1.1: Automated Dataset Validation and Profiling
- **Module / File**: `module_1_dataset_validation/dataset_validation.py` $\rightarrow$ `run_module_1_validation()`
- **Purpose**: Discovers, profiles, validates, and exports quality metrics for all input telemetry CSVs.
- **Inputs**: Directory path `data/Processed_datasets/`.
- **Processing Steps**:
  1. Recursively discover all `.csv` telemetry files across IoT, Linux, Network, and Windows subfolders.
  2. For each dataset file, compute row count $N_{\text{total}}$ and column count.
  3. Calculate per-column missing rate (Formula 1.1), completeness (Formula 1.2), and uniqueness ratio (Formula 1.3).
  4. Execute schema detection rules (Rules 1.2 & 1.3) to classify candidate timestamps and identifiers.
  5. Compute multi-factor graph readiness score (Formula 1.4).
  6. Save output artifacts `dataset_summary.csv`, `dataset_statistics.json`, and `validation_report.txt`.
  7. Render visualization plots `dataset_distribution.png`, `feature_availability.png`, and `missing_values.png`.
- **Pseudocode**:
```python
def run_module_1_validation():
    datasets = discover_processed_datasets(processed_dir)
    stats = {}
    for ds_path in datasets:
        df = pd.read_csv(ds_path)
        missing = df.isnull().sum() / len(df) * 100
        uniqueness = df.nunique() / len(df) * 100
        readiness = calculate_graph_readiness_score(missing, uniqueness)
        stats[ds_name] = {...}
    export_json(stats, 'dataset_statistics.json')
    render_plots(stats)
```
- **Output**: `dataset_summary.csv`, `dataset_statistics.json`, 3 visualization plots.
- **Complexity**: Time: $\mathcal{O}(F \cdot N)$ where $F$ is number of files and $N$ is average row count; Space: $\mathcal{O}(N)$ for DataFrame loading.
- **Actual Implementation Status**: `directly implemented`

---

### 4. Module 2 — Graph Feature & Relationship Engineering

#### 4.1 Feature Formulations

##### Formula 2.1: Semantic Entity Feature Vector $F(e)$
- **Name**: Entity Feature Vector Construction
- **Location**: `module_2_graph_feature_engineering/feature_engineering.py` $\rightarrow$ `build_entity_feature_vectors()`
- **Purpose**: Maps raw telemetry entity attributes into structured 5-tuple graph feature vectors.
- **Formula**:
  $$F(e) = \langle \text{EntityID}, \text{EntityType}, \text{SourceDataset}, \text{CompletenessScore}, \text{ReadinessTag} \rangle$$
- **Variables**:
  - $\text{EntityID}$ = Canonical semantic identifier (e.g. `SRCIP_001`, `PROC_001`, `HOST_001`)
  - $\text{EntityType} \in \{\text{User}, \text{Process}, \text{Host}, \text{Service}, \text{Device}, \text{Event}, \text{Session}\}$
  - $\text{CompletenessScore} = 100.0 - \text{MissingRate}$
  - $\text{ReadinessTag} \in \{\text{Ready}, \text{Conditional}, \text{Metadata Only}\}$
- **Inputs**: Deduplicated entity DataFrames and Module 1 `dataset_statistics.json`.
- **Output**: CSV file `entity_features.csv`.
- **Where It Is Used**: Module 3 node schema derivation and catalog tables.
- **Why It Matters**: Standardizes heterogeneous entity columns into clean graph-ready feature vectors.
- **Classification**: `PROJECT-DERIVED`
- **Status**: `IMPLEMENTED`

##### Formula 2.2: 3-Level Graph Readiness Assignment Rule
- **Name**: Feature Graph Readiness Categorization Rule
- **Location**: `module_2_graph_feature_engineering/feature_engineering.py` $\rightarrow$ `build_entity_feature_vectors()`
- **Purpose**: Categorizes engineered features into 3 operational readiness levels.
- **Formula / Rule**:
  $$\text{ReadinessTag}(c) = \begin{cases} \text{'Ready'} & \text{if } \text{MissingRate}(c) \le 10.0\% \text{ and (Primary Key or Core Entity Role)} \\ \text{'Conditional'} & \text{if } 10.0\% < \text{MissingRate}(c) \le 50.0\% \text{ or Context Attribute} \\ \text{'Metadata Only'} & \text{if } \text{MissingRate}(c) > 50.0\% \text{ or Non-semantic Metadata} \end{cases}$$
- **Inputs**: Column missing rate and classification role.
- **Output**: String tag assigned to each attribute in `entity_features.csv`.
- **Where It Is Used**: `entity_summary.json` and Module 3 schema readiness evaluation.
- **Why It Matters**: Prevents low-quality telemetry features from corrupting TKG topology.
- **Classification**: `HEURISTIC`
- **Status**: `IMPLEMENTED`

---

#### 4.2 Entity Mapping Rules
- **Rule 2.1 (Host Category Rule)**: If column matches `r'(host|hostname|ip|mac|device_id)'`, map to `Host` or `Device` entity node.
- **Rule 2.2 (Process Category Rule)**: If column matches `r'(process|pid|cmd|exe|command)'`, map to `Process` entity node.
- **Rule 2.3 (User Category Rule)**: If column matches `r'(user|username|uid|account)'`, map to `User` entity node.
- **Rule 2.4 (Event Category Rule)**: If column matches `r'(event|alert|label|type|action)'`, map to `Event` entity node.

---

#### 4.3 Relationship Construction & Confidence Scoring

##### Formula 2.3: Candidate Relationship Confidence Scoring
- **Name**: Relationship Evidence Confidence Function
- **Location**: `module_2_graph_feature_engineering/relationship_extraction.py` $\rightarrow$ `infer_relationships_for_file()`
- **Purpose**: Assigns evidence-based confidence scores $C(r) \in [0.0, 1.0]$ to candidate relationship types.
- **Formula**:
  $$C(\text{RelationshipType}) = \begin{cases} 1.00 & \text{for } \text{COMMUNICATES\_WITH} \text{ (Observed direct IPv4/IPv6 packet flows)} \\ 1.00 & \text{for } \text{EXECUTES} \text{ (Observed OS user/process execution telemetry)} \\ 0.95 & \text{for } \text{RUNS\_ON} \text{ (Observed process-to-host table allocation)} \\ 0.90 & \text{for } \text{ACCESSES} \text{ (Observed process I/O \& page fault counters)} \\ 1.00 & \text{for } \text{MEASURES} \text{ (Observed BRIDG-ICS sensor Modbus telemetry)} \\ 1.00 & \text{for } \text{OBSERVED\_AT} \text{ (Observed timestamped geospatial GPS coordinates)} \\ 0.85 & \text{for } \text{CO\_LOCATED\_ON} \text{ (Inferred device-host co-location)} \end{cases}$$
- **Inputs**: Dataset column pairs (`src_ip`/`dst_ip`, `user`/`process`, `PID`/`host`).
- **Output**: Saved in `relationships.csv` and `candidate_relationships_v2.csv`.
- **Where It Is Used**: `CANDIDATE_RELATIONSHIP_EVIDENCE.png` and Module 3 edge schema derivation.
- **Why It Matters**: Quantifies structural confidence in inferred graph links.
- **Classification**: `PROJECT-DERIVED` / `HEURISTIC`
- **Status**: `IMPLEMENTED`

---

#### 4.4 Algorithms

##### Algorithm 2.1: Unified Feature Role Classification
- **Module / File**: `module_2_graph_feature_engineering/feature_mapping.py` $\rightarrow$ `classify_column_feature_mapping()`
- **Purpose**: Classifies every raw dataset column into 1 of 5 canonical graph roles.
- **Inputs**: Attribute column name $c$ and parent dataset name.
- **Processing Steps**:
  1. Inspect column name string against entity keyword regex. If match, assign `Graph Entity`.
  2. Inspect column name against numerical telemetry patterns (e.g. `CPU_pct`, `orig_bytes`, `temp`). If match, assign `Graph Attribute`.
  3. Inspect column name against link metadata (e.g. `proto`, `service`, `port`). If match, assign `Relationship Attribute`.
  4. Inspect column name against logging tags (e.g. `timestamp`, `log_id`). If match, assign `Metadata Attribute`.
  5. If uninformative or constant junk column, assign `Ignored Attribute`.
- **Output**: `feature_mapping.csv` and `ATTRIBUTE_TO_GRAPH_MAPPING_V2.csv`.
- **Complexity**: Time: $\mathcal{O}(C)$ per dataset where $C$ is column count; Space: $\mathcal{O}(C)$.
- **Actual Implementation Status**: `directly implemented`

---

### 5. Module 3 — Data-Driven Graph Schema Construction

#### 5.1 Node Construction Formulations

##### Formula 3.1: Primary Key Selection Heuristic
- **Name**: Node Primary Key Selection Algorithm
- **Location**: `module_3_graph_schema/node_schema.py` $\rightarrow$ `derive_primary_key_for_node()`
- **Purpose**: Selects the primary identifier attribute for each graph node type.
- **Formula / Rule**:
  $$\text{PrimaryKey}(\text{NodeType}) = \arg\max_{c \in \text{Attrs}(\text{NodeType})} \left( \mathbb{I}_{\text{ID\_Tag}}(c) \cdot 1000.0 + \text{UniquenessRatio}(c) \right)$$
- **Inputs**: Candidate node attributes and uniqueness scores.
- **Output**: String primary key column name saved in `graph_node_schema.csv`.
- **Where It Is Used**: `graph_schema.json` and catalog tables.
- **Why It Matters**: Ensures unique node instantiation during Module 4 TKG building.
- **Classification**: `HEURISTIC`
- **Status**: `IMPLEMENTED`

---

#### 5.2 Relationship Construction Formulations

##### Formula 3.2: Edge Cardinality Derivation Rule
- **Name**: Graph Edge Cardinality Inference Rule
- **Location**: `module_3_graph_schema/edge_schema.py` $\rightarrow$ `derive_edge_cardinality()`
- **Purpose**: Determines structural cardinality (`1:1`, `1:N`, `N:M`) for schema edge types.
- **Formula / Rule**:
  $$\text{Cardinality}(\text{src}, \text{tgt}) = \begin{cases} \text{'1:N'} & \text{if } \text{NodeType}(\text{src}) = \text{'User'} \text{ and } \text{NodeType}(\text{tgt}) = \text{'Process'} \\ \text{'1:N'} & \text{if } \text{NodeType}(\text{src}) = \text{'Host'} \text{ and } \text{NodeType}(\text{tgt}) = \text{'Process'} \\ \text{'N:M'} & \text{if } \text{NodeType}(\text{src}) = \text{'Host'} \text{ and } \text{NodeType}(\text{tgt}) = \text{'Host'} \\ \text{'1:N'} & \text{otherwise} \end{cases}$$
- **Inputs**: Source and target node types from `relationships.csv`.
- **Output**: String cardinality tag in `graph_edge_schema.csv`.
- **Where It Is Used**: `cardinality_distribution.png` and schema master tables.
- **Classification**: `PROJECT-DERIVED`
- **Status**: `IMPLEMENTED`

---

#### 5.3 Schema Validation Formulations

##### Formula 3.3: Schema Referential Integrity Percentage
- **Name**: Schema Referential Integrity Score
- **Location**: `module_3_graph_schema/schema_validator.py` $\rightarrow$ `validate_graph_schema()`
- **Purpose**: Computes referential validity percentage of edge endpoints against defined node schemas.
- **Formula**:
  $$\text{ReferentialIntegrity} = \left( \frac{\sum_{e \in E_{\text{schema}}} \mathbb{I}(\text{src}(e) \in V_{\text{schema}} \land \text{tgt}(e) \in V_{\text{schema}})}{|E_{\text{schema}}|} \right) \times 100.0$$
- **Variables**: $V_{\text{schema}}$ = set of defined node types; $E_{\text{schema}}$ = set of defined edge relationships.
- **Inputs**: `graph_node_schema.csv` and `graph_edge_schema.csv`.
- **Output**: Referential integrity percentage (e.g. $100.0\%$) saved in `schema_validation_report.txt` and `graph_schema.json`.
- **Where It Is Used**: Blueprint validation reports and Module 3 summary.
- **Why It Matters**: Guarantees zero dangling edges in the schema definition.
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

---

#### 5.4 Algorithms

##### Algorithm 3.1: Data-Driven Graph Schema Construction
- **Module / File**: `module_3_graph_schema/schema_builder.py` $\rightarrow$ `run_module_3_schema_construction()`
- **Purpose**: Assembles node and edge schema blueprints from Module 2 outputs, validates integrity, and generates master catalog tables.
- **Inputs**: Module 2 CSV files (`entities.csv`, `entity_features.csv`, `feature_mapping.csv`, `relationships.csv`).
- **Processing Steps**:
  1. Call `derive_node_schemas()` to extract unique node types, primary keys, and property lists.
  2. Call `derive_edge_schemas()` to extract directed edge relationships, source/target pairs, and cardinalities.
  3. Execute `validate_graph_schema()` to check 100% referential integrity (Formula 3.3).
  4. Save CSV outputs (`graph_node_schema.csv`, `graph_edge_schema.csv`) and JSON blueprint (`graph_schema.json`).
  5. Render 16 schema visualization diagrams and catalog master tables.
- **Output**: 3 schema files, 16 visualizations.
- **Complexity**: Time: $\mathcal{O}(|V_{\text{schema}}| + |E_{\text{schema}}|)$; Space: $\mathcal{O}(|V_{\text{schema}}| + |E_{\text{schema}}|)$.
- **Actual Implementation Status**: `directly implemented`

---

### 6. Module 4 — Temporal Knowledge Graph & Stage 3 Analytics

#### 6.1 Temporal Formulations

##### Formula 4.1: Unix Epoch Timestamp Normalization
- **Name**: Timestamp Parsing \& Epoch Conversion
- **Location**: `module_4_temporal_knowledge_graph/event_ordering.py` $\rightarrow$ `parse_timestamp()`
- **Purpose**: Converts heterogeneous raw date strings into numeric Unix Epoch seconds.
- **Formula**:
  $$t_{\text{epoch}} = \text{to\_seconds}(\text{ISO8601\_parse}(\text{timestamp\_str}))$$
- **Inputs**: Raw string or numeric timestamp from dataset telemetry.
- **Output**: Float value $t_{\text{epoch}} \ge 0.0$.
- **Where It Is Used**: Event sorting and inter-event delay calculation.
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

##### Formula 4.2: Inter-Event Temporal Delay ($\Delta t$)
- **Name**: Relative Inter-Event Time Difference
- **Location**: `module_4_temporal_knowledge_graph/event_ordering.py` $\rightarrow$ `build_temporal_ordering_edges()`
- **Purpose**: Computes elapsed time between chronologically consecutive telemetry events $e_i$ and $e_{i+1}$.
- **Formula**:
  $$\Delta t_{\text{sec}} = \max(0.0, t_{i+1} - t_i)$$
  $$\Delta t_{\text{ms}} = \text{round}(\Delta t_{\text{sec}} \times 1000.0, 2)$$
- **Variables**: $t_i$ = epoch timestamp of event $i$; $t_{i+1}$ = epoch timestamp of event $i+1$.
- **Inputs**: Chronologically sorted node event records.
- **Output**: Inter-event delay $\Delta t_{\text{ms}}$ attached to directed `PRECEDES` edges in `temporal_edges.csv`.
- **Where It Is Used**: `event_sequence.csv`, `timeline.txt`, and `temporal_graph_preview.png`.
- **Why It Matters**: Enables fine-grained temporal causality reasoning across attack steps.
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

##### Formula 4.3: Sequence Duration Formula
- **Name**: Total Event Sequence Duration
- **Location**: `module_4_temporal_knowledge_graph/event_ordering.py` $\rightarrow$ `build_event_sequences()`
- **Purpose**: Computes total elapsed duration for an ordered event sequence $S = (e_1, e_2, \dots, e_k)$.
- **Formula**:
  $$T_{\text{seq}} = \max(0.0, t_k - t_1)$$
- **Inputs**: Start epoch $t_1$ and end epoch $t_k$ of sequence.
- **Output**: Sequence duration in seconds saved in `event_sequence.csv`.
- **Classification**: `STANDARD`
- **Status**: `IMPLEMENTED`

---

#### 6.2 Event Ordering Rules
- **Rule 4.1 (Chronological Sequence Sort)**: Within each telemetry source dataset, sort nodes by `numeric_ts` in non-decreasing order:
  $$e_1 \le e_2 \le \dots \le e_k \iff t_1 \le t_2 \le \dots \le t_k$$
- **Rule 4.2 (Temporal PRECEDES Link Rule)**: For any consecutive pair $(e_i, e_{i+1})$, construct a directed temporal ordering edge:
  $$e_i \xrightarrow[\Delta t, C=0.95]{\text{PRECEDES}} e_{i+1}$$

---

#### 6.3 Temporal Relationships & Edge Construction
- **Observed Domain Edges**: Instantiated from domain schema (e.g. `User -> EXECUTES -> Process`, `Host -> COMMUNICATES_WITH -> Host`) with confidence $C \in [0.90, 1.00]$.
- **Temporal Ordering Edges**: Instantiated between consecutive events with relationship type `PRECEDES` and confidence $C = 0.95$.

---

#### 6.4 TKG Construction & Instance Node Mapping

##### Formula 4.4: Canonical Node Unique ID Instantiation
- **Name**: Unique Instance Node ID Formula
- **Location**: `module_4_temporal_knowledge_graph/temporal_graph_builder.py` $\rightarrow$ `instantiate_temporal_nodes()`
- **Purpose**: Generates deterministic, globally unique node string IDs for 9,500+ graph nodes.
- **Formula**:
  $$\text{unique\_id} = \text{NodeType}_{\text{short}} \text{\_} \text{Dataset}_{\text{short}} \text{\_} \text{RowIndex}$$
  Example: `SRCIP_NET_0001`, `PROC_LIN_0042`, `USER_WIN_0012`.
- **Inputs**: Node type, dataset name, and row index.
- **Output**: Saved in `temporal_nodes.csv`.
- **Classification**: `PROJECT-DERIVED`
- **Status**: `IMPLEMENTED`

---

#### 6.5 Graph Algorithms & Analytics

##### Algorithm 4.1: NetworkX PageRank Centrality Analytics
- **Name**: NetworkX Directed PageRank Centrality
- **Location**: `module_4_temporal_knowledge_graph/stage3_graph_enrichment.py` $\rightarrow$ Lines 110–145
- **Purpose**: Computes PageRank importance scores $\mathbf{PR}(v)$ across the instantiated NetworkX DiGraph ($N \ge 9,500$ nodes).
- **Mathematical Formulation**:
  $$\mathbf{PR}(v) = \frac{1 - \alpha}{|V|} + \alpha \sum_{u \in M(v)} \frac{\mathbf{PR}(u)}{L(u)}$$
  Where $\alpha = 0.85$ (damping factor), $M(v)$ is set of nodes linking to $v$, and $L(u)$ is out-degree of $u$.
- **Inputs**: NetworkX `DiGraph` loaded from `temporal_nodes.csv` and `temporal_edges.csv`.
- **Processing Steps**:
  1. Load instantiated temporal nodes and edges into `nx.DiGraph()`.
  2. Compute degree centrality `nx.degree_centrality(G)`.
  3. Compute in-degree centrality `nx.in_degree_centrality(G)` and out-degree centrality `nx.out_degree_centrality(G)`.
  4. Execute NetworkX PageRank `nx.pagerank(G, alpha=0.85, max_iter=100)`.
  5. Compute estimated betweenness proxy score:
     $$C_B(v) \approx C_D(v) \times 0.85$$
  6. Rank nodes by PageRank score and save top 100 to `graph_analytics_v3.csv`.
  7. Render `GRAPH_CENTRALITY_V3.png` bar chart.
- **Pseudocode**:
```python
def compute_stage3_networkx_analytics(m4_out):
    G = nx.DiGraph()
    for _, r in df_nodes.iterrows(): G.add_node(r['unique_id'])
    for _, r in df_edges.iterrows(): G.add_edge(r['source_node'], r['destination_node'])
    pr_cent = nx.pagerank(G, alpha=0.85, max_iter=100)
    in_deg = nx.in_degree_centrality(G)
    # Save top nodes to graph_analytics_v3.csv
```
- **Output**: `graph_analytics_v3.csv`, `GRAPH_CENTRALITY_V3.png`.
- **Complexity**: Time: $\mathcal{O}(k \cdot (|V| + |E|))$ for PageRank power iteration ($k \le 100$); Space: $\mathcal{O}(|V| + |E|)$.
- **Classification**: `STANDARD` / `ADAPTED`
- **Actual Implementation Status**: `directly implemented`

---

##### Algorithm 4.2: 5-Step Heuristic Attack Path Traversal
- **Name**: Multi-Hop Attack Path Reconstruction
- **Location**: `module_4_temporal_knowledge_graph/stage3_graph_enrichment.py` $\rightarrow$ Lines 150–225
- **Purpose**: Traces a 5-step heuristic compromise path through instantiated telemetry nodes.
- **Processing Steps**:
  1. **Step 1 (Network Ingress)**: Identify external source IP node (`SRCIP_NET_001`, $C = 1.00$).
  2. **Step 2 (Credential Abuse)**: Connect to compromised user account (`USER_WIN_001`, $C = 1.00$).
  3. **Step 3 (Process Execution)**: Connect to privileged process execution (`PROC_WIN_012`, $C = 1.00$).
  4. **Step 4 (Resource Access)**: Connect to host file / disk write access (`HOST_LIN_004`, $C = 0.90$).
  5. **Step 5 (Alert Generation)**: Connect to security alert ground truth node (`EVT_IOT_099`, $C = 1.00$).
  6. Export path steps to `attack_path_trace_v3.csv` and render `EVIDENCE_BASED_ATTACK_PATH_V3.png`.
- **Output**: `attack_path_trace_v3.csv`, `EVIDENCE_BASED_ATTACK_PATH_V3.png`.
- **Classification**: `HEURISTIC`
- **Actual Implementation Status**: `directly implemented`

---

### 7. Cross-Module Formulations & Data Flows

The mathematical and logical data flow between modules is structured as follows:

$$\begin{array}{rcccl}
\text{Module 1 Data Profiling} & \longrightarrow & \text{MissingRate}(c), \text{ReadinessScore} & \longrightarrow & \text{Module 2 Feature Vector } F(e) \\
\text{Module 2 Features} & \longrightarrow & \text{Entities}, \text{Relationships}, C(r) & \longrightarrow & \text{Module 3 Node/Edge Schemas} \\
\text{Module 3 Schemas} & \longrightarrow & \text{NodeTypes}, \text{PrimaryKeys}, \text{Cardinality} & \longrightarrow & \text{Module 4 TKG Node Instantiation } (N \ge 9,500) \\
\text{Module 4 TKG Nodes/Edges} & \longrightarrow & \text{NetworkX DiGraph } G = (V, E) & \longrightarrow & \text{Stage 3 PageRank } \mathbf{PR}(v) \text{ \& Attack Paths}
\end{array}$$

---

### 8. Standard vs Project-Derived vs Heuristic Methods

| Method / Formulation | Module | Type Classification | Rationale / Origin | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Missing Value Rate (Formula 1.1)** | Module 1 | `STANDARD` | Conventional missing data ratio formula | `IMPLEMENTED` |
| **Completeness Ratio (Formula 1.2)** | Module 1 | `STANDARD` | Conventional data population density | `IMPLEMENTED` |
| **Uniqueness Ratio (Formula 1.3)** | Module 1 | `STANDARD` | Distinct values divided by total rows | `IMPLEMENTED` |
| **Graph Readiness Score (Formula 1.4)** | Module 1 | `PROJECT-DERIVED` / `HEURISTIC` | Formulated specifically for AGI dataset profiling | `IMPLEMENTED` |
| **Entity Feature Vector $F(e)$ (Formula 2.1)** | Module 2 | `PROJECT-DERIVED` | Formulated for multi-source telemetry feature vectors | `IMPLEMENTED` |
| **Readiness Assignment Rule (Formula 2.2)** | Module 2 | `HEURISTIC` | Rule-based thresholding ($10\%, 50\%$) | `IMPLEMENTED` |
| **Relationship Confidence Score (Formula 2.3)** | Module 2 | `PROJECT-DERIVED` / `HEURISTIC` | Formulated evidence weights ($0.85 - 1.00$) | `IMPLEMENTED` |
| **Primary Key Derivation (Formula 3.1)** | Module 3 | `HEURISTIC` | Selection by highest uniqueness \& identifier tag | `IMPLEMENTED` |
| **Edge Cardinality Derivation (Formula 3.2)** | Module 3 | `PROJECT-DERIVED` | Data-driven $1:1, 1:N, N:M$ mapping rules | `IMPLEMENTED` |
| **Referential Integrity Score (Formula 3.3)** | Module 3 | `STANDARD` | Percentage of valid edge endpoint references | `IMPLEMENTED` |
| **Unix Epoch Parsing (Formula 4.1)** | Module 4 | `STANDARD` | Standard datetime to float epoch seconds | `IMPLEMENTED` |
| **Inter-Event Delta Time $\Delta t$ (Formula 4.2)** | Module 4 | `STANDARD` | Non-negative relative time difference | `IMPLEMENTED` |
| **Sequence Duration $T_{\text{seq}}$ (Formula 4.3)** | Module 4 | `STANDARD` | Sequence end minus start timestamp | `IMPLEMENTED` |
| **Unique Node ID Instantiation (Formula 4.4)** | Module 4 | `PROJECT-DERIVED` | Deterministic node ID string formatting | `IMPLEMENTED` |
| **NetworkX PageRank Centrality (Alg. 4.1)** | Module 4 | `STANDARD` / `ADAPTED` | Standard PageRank power iteration ($\alpha = 0.85$) | `IMPLEMENTED` |
| **5-Step Attack Path Traversal (Alg. 4.2)** | Module 4 | `HEURISTIC` | Multi-hop domain heuristic compromise path | `IMPLEMENTED` |

---

### 9. Implemented vs Planned

| Formulation / Algorithm | Implementation File | Status | Verification Evidence |
| :--- | :--- | :---: | :--- |
| **Missing \& Uniqueness Profiling** | `module_1/dataset_statistics.py` | `IMPLEMENTED` | Verified in `dataset_summary.csv` |
| **Multi-Factor Readiness Scoring** | `module_1/dataset_statistics.py` | `IMPLEMENTED` | Verified in `dataset_statistics.json` |
| **Entity \& Feature Vector Extraction** | `module_2/feature_engineering.py` | `IMPLEMENTED` | Verified in `entity_features.csv` |
| **Candidate Link Confidence Scoring** | `module_2/relationship_extraction.py` | `IMPLEMENTED` | Verified in `candidate_relationships_v2.csv` |
| **Node \& Edge Schema Derivation** | `module_3/node_schema.py`, `edge_schema.py` | `IMPLEMENTED` | Verified in `graph_node_schema.csv` |
| **Referential Integrity Validation** | `module_3/schema_validator.py` | `IMPLEMENTED` | Verified in `schema_validation_report.txt` |
| **Epoch Parsing \& Inter-Event $\Delta t$** | `module_4/event_ordering.py` | `IMPLEMENTED` | Verified in `event_sequence.csv` |
| **NetworkX PageRank Centrality** | `module_4/stage3_graph_enrichment.py` | `IMPLEMENTED` | Verified in `graph_analytics_v3.csv` |
| **5-Step Compromise Path Tracing** | `module_4/stage3_graph_enrichment.py` | `IMPLEMENTED` | Verified in `attack_path_trace_v3.csv` |
| **Graph Neural Networks (GNN / GraphSAGE)** | None | `PLANNED` | Mentioned in docs; NOT in code |
| **Louvain Community Detection** | None | `PLANNED` | Mentioned in notes; NOT in code |
| **Yen's K-Shortest Paths** | None | `PLANNED` | Mentioned in notes; NOT in code |
| **Risk Weight Scoring ($W_{\text{risk}}$)** | None | `PLANNED` | Conceptual; NOT in code |

---

### 10. Complete Formula Index

| ID | Formulation | Module | Status | Source File \& Function |
| :--- | :--- | :--- | :---: | :--- |
| **F-01** | Column Missing Rate | Module 1 | `IMPLEMENTED` | `dataset_statistics.py` $\rightarrow$ `analyze_single_dataset_folder()` |
| **F-02** | Attribute Completeness Percentage | Module 1 | `IMPLEMENTED` | `dataset_statistics.py` $\rightarrow$ `analyze_single_dataset_folder()` |
| **F-03** | Column Uniqueness Ratio | Module 1 | `IMPLEMENTED` | `dataset_statistics.py` $\rightarrow$ `analyze_single_dataset_folder()` |
| **F-04** | Multi-Factor Graph Readiness Score | Module 1 | `IMPLEMENTED` | `dataset_statistics.py` $\rightarrow$ `calculate_graph_readiness_score()` |
| **F-05** | Entity Feature Vector $F(e)$ | Module 2 | `IMPLEMENTED` | `feature_engineering.py` $\rightarrow$ `build_entity_feature_vectors()` |
| **F-06** | 3-Level Graph Readiness Categorization | Module 2 | `IMPLEMENTED` | `feature_engineering.py` $\rightarrow$ `build_entity_feature_vectors()` |
| **F-07** | Relationship Confidence Function $C(r)$ | Module 2 | `IMPLEMENTED` | `relationship_extraction.py` $\rightarrow$ `infer_relationships_for_file()` |
| **F-08** | Node Primary Key Derivation Rule | Module 3 | `IMPLEMENTED` | `node_schema.py` $\rightarrow$ `derive_primary_key_for_node()` |
| **F-09** | Edge Cardinality Inference Rule | Module 3 | `IMPLEMENTED` | `edge_schema.py` $\rightarrow$ `derive_edge_cardinality()` |
| **F-10** | Schema Referential Integrity Score | Module 3 | `IMPLEMENTED` | `schema_validator.py` $\rightarrow$ `validate_graph_schema()` |
| **F-11** | Timestamp Epoch Parsing | Module 4 | `IMPLEMENTED` | `event_ordering.py` $\rightarrow$ `parse_timestamp()` |
| **F-12** | Inter-Event Temporal Delta Time ($\Delta t$) | Module 4 | `IMPLEMENTED` | `event_ordering.py` $\rightarrow$ `build_temporal_ordering_edges()` |
| **F-13** | Sequence Total Duration ($T_{\text{seq}}$) | Module 4 | `IMPLEMENTED` | `event_ordering.py` $\rightarrow$ `build_event_sequences()` |
| **F-14** | Node Instance Unique ID Generator | Module 4 | `IMPLEMENTED` | `temporal_graph_builder.py` $\rightarrow$ `instantiate_temporal_nodes()` |
| **F-15** | NetworkX Degree \& PageRank Centrality | Module 4 | `IMPLEMENTED` | `stage3_graph_enrichment.py` $\rightarrow$ Lines 110–145 |

---

### 11. Complete Algorithm Index

| ID | Algorithm Name | Module | Type | Status | Source File |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **ALG-01** | Automated Dataset Profiling \& Validation | Module 1 | `STANDARD` | `IMPLEMENTED` | `dataset_validation.py` |
| **ALG-02** | Telemetry Entity Extraction | Module 2 | `HEURISTIC` | `IMPLEMENTED` | `entity_extraction.py` |
| **ALG-03** | Candidate Link Inference Engine | Module 2 | `HEURISTIC` | `IMPLEMENTED` | `relationship_extraction.py` |
| **ALG-04** | Unified Feature Role Classifier | Module 2 | `HEURISTIC` | `IMPLEMENTED` | `feature_mapping.py` |
| **ALG-05** | Data-Driven Schema Construction | Module 3 | `PROJECT-DERIVED` | `IMPLEMENTED` | `schema_builder.py` |
| **ALG-06** | Temporal Event Sequence Builder | Module 4 | `STANDARD` | `IMPLEMENTED` | `event_ordering.py` |
| **ALG-07** | PRECEDES Edge Generation Engine | Module 4 | `PROJECT-DERIVED` | `IMPLEMENTED` | `event_ordering.py` |
| **ALG-08** | Temporal Knowledge Graph Builder | Module 4 | `PROJECT-DERIVED` | `IMPLEMENTED` | `temporal_graph_builder.py` |
| **ALG-09** | NetworkX PageRank Centrality Analytics | Module 4 | `STANDARD` | `IMPLEMENTED` | `stage3_graph_enrichment.py` |
| **ALG-10** | 5-Step Compromise Path Traversal | Module 4 | `HEURISTIC` | `IMPLEMENTED` | `stage3_graph_enrichment.py` |

---

### 12. Limitations and Unimplemented Methods

The following mathematical methods and algorithms are referenced in conceptual ontologies or background documentation but are **NOT currently implemented** in the active Python codebase:

1. **Graph Neural Network (GNN) Node Embeddings**:
   - *Status*: `PLANNED / NOT IMPLEMENTED`
   - *Details*: GraphSAGE / GAT embeddings are discussed in ontology documents as potential future extensions but are not present in any python script.
2. **Louvain / Leiden Community Detection**:
   - *Status*: `PLANNED / NOT IMPLEMENTED`
   - *Details*: Graph clustering algorithms are planned for modularity analysis but not currently executed.
3. **Yen's K-Shortest Paths Algorithm**:
   - *Status*: `PLANNED / NOT IMPLEMENTED`
   - *Details*: Multi-path network routing algorithm planned for advanced pathfinding; currently replaced by the 5-step heuristic traversal algorithm (Algorithm 4.2).
4. **Quantitative Cyber Risk Scoring ($W_{\text{risk}}, p_{\text{exploit}}$)**:
   - *Status*: `PLANNED / NOT IMPLEMENTED`
   - *Details*: Mathematical risk weight formulations combining vulnerability scores ($V$) and exploit probabilities ($p$) are theoretical specifications not implemented in active python code.
