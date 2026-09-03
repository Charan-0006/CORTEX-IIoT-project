# CORTEX — Contextual Intelligence Engine

The **Contextual Intelligence Engine** is the core telemetry ingestion, normalization, and behavioral baseline profiling component of the **CORTEX** (Context-Aware Real-Time Threat Observation and Risk Tracking Framework) cybersecurity architecture.

It parses raw, heterogeneous telemetry streams (Network flows, physical IoT sensors, and OS host metrics), standardizes variables across 6 primary Context Dimensions, and dynamically builds online behavioral profiles using Welford's algorithm and sliding window reorder buffers.

---

## Implemented Architecture & Stages

```
   Raw Telemetry Streams (Network, IoT, Linux, Windows)
                         │
                         ▼
        ┌──────────────────────────────────┐
        │     CSVDataLoader (Chunked)      │
        └──────────────────────────────────┘
                         │
                         ▼
  ┌──────────────────────────────────────────────┐
  │   Stage 1: Multi-Source Context Extraction   │
  │   - Standardizes Timestamps to UTC           │
  │   - Maps fields via ContextAttributeRepo     │
  │   - Groups into 6 Context Dimensions         │
  └──────────────────────────────────────────────┘
                         │
               StructuredContext Record
                         │
                         ▼
  ┌──────────────────────────────────────────────┐
  │   Stage 2: Dynamic Context Profile Gen.      │
  │   - Entity key routing per source            │
  │   - Welford's Online Statistics (Mean/Std)   │
  │   - Sliding Window Out-of-Order Reordering    │
  │   - Alert-Label-Aware Baseline vs Deviation  │
  └──────────────────────────────────────────────┘
```

### Implemented Stages
- **Stage 1: Multi-Source Context Extraction**
  - Normalizes heterogeneous columns into standard attribute metadata.
  - Groups metrics into 6 Core Dimensions: `TEMPORAL`, `ASSET`, `NETWORK`, `DEVICE`, `OPERATIONAL`, and `SECURITY`.
  - Supports 12+ sub-sources across Zeek Network logs, IoT sensors (Fridge, Garage, GPS, Modbus, Thermostat, Weather, Motion Light), Linux host logs (Process, Memory, Disk), and Windows performance counters.
- **Stage 2: Dynamic Context Profile Generation**
  - Generates real-time behavioral profiles (`DynamicContextProfile`) per entity.
  - Uses **Welford's Algorithm** for incremental $O(1)$ numerical mean and variance calculation without storing historical raw windows.
  - Features bounded **Sliding-Window Sorted Buffers** to handle out-of-order log arrival for categorical state-transition matrix generation.
  - Implements **Alert-Label-Aware Updates**: Normal telemetry (`security_alert_label == 0`) updates running baselines; Attack telemetry (`security_alert_label == 1`) triggers read-only anomaly scoring (z-scores and categorical state probabilities) without polluting normal behavioral baselines.

### Roadmap / Future Stages (Not Yet Implemented)
- **Stage 3**: Threat Graph Construction & Multi-Entity Context Fusion
- **Stage 4**: Dynamic Contextual Risk Assessment Engine
- **Stage 5**: Automated Context-Aware Mitigation & Response Engine

---

## Directory Structure

```
CORTEX/
├── context_engine/                     # Core Engine Package
│   ├── __init__.py                     # Package exports
│   ├── context_attribute_repository.py # Centralized attribute dictionary & mappings
│   ├── context_extraction.py           # Stage 1 Multi-Source Extractor & StructuredContext
│   ├── context_profile.py              # Stage 2 Dynamic Profile Generator & Welford stats
│   └── data_loader.py                  # Chunked CSV streaming data loader
├── docs/                               # Architecture & Project Documentation
│   ├── architecture/
│   │   ├── context_attribute_mapping.md
│   │   ├── feature_dictionary.md
│   │   ├── stage1_technical_summary.md
│   │   ├── stage2_design_decisions.md
│   │   └── reference/                  # Raw feature list references
│   │       ├── iot_features_raw.txt
│   │       ├── linux_features_raw.txt
│   │       └── network_features_raw.txt
│   └── weekly_reports/
│       └── assets/                     # Evaluation plot image assets (stage2_*.png)
├── preprocessing/                      # Preprocessing utilities
│   └── data_loader.py                  # Re-export wrapper for backward compatibility
├── scripts/                            # Inspection & benchmarking utility scripts
│   ├── __init__.py
│   ├── generate_report_assets.py       # Evaluation plot figure generation script
│   ├── inspect_datasets.py             # Dataset row count & schema inventory script
│   ├── inspect_performance.py          # Pipeline throughput & RSS memory benchmark
│   └── print_keys.py                   # Profile entity key inspection script
├── tests/                              # Unit test suite
│   ├── __init__.py
│   ├── test_context_extraction.py      # Stage 1 & Loader tests
│   └── test_context_profile.py         # Stage 2 & Welford algorithm tests
├── run_demo.py                         # End-to-end demonstration script
├── requirements.txt                    # Project dependencies
├── .gitignore                          # Git ignore rules
└── README.md                           # Project documentation
```

---

## Utility Scripts (`scripts/`)

The `scripts/` directory contains helper tools for environment diagnostic, benchmarking, and asset generation:

- **`python scripts/inspect_datasets.py`**: Scans all TON-IoT CSV dataset files, counts total records using fast buffer reads, extracts column headers, and generates a full inventory report in `results/dataset_inventory.txt`.
- **`python scripts/inspect_performance.py`**: Measures RAM usage (RSS memory) and streaming processing speed (records/second) across Stage 1 & Stage 2 pipelines over 100,000 telemetry records.
- **`python scripts/print_keys.py`**: Inspects generated profile entity keys for network telemetry and categorizes IP roles (Gateway, PLC, IoT Device, HMI).
- **`python scripts/generate_report_assets.py`**: Generates high-resolution evaluation charts (profile coverage, throughput scaling, deviation distributions, baseline bands, state transition heatmaps) saved directly to `docs/weekly_reports/assets/`.

---

## Installation & Setup

### 1. Requirements
- Python **3.9+**
- Dependencies listed in `requirements.txt`

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Demonstration

To run the end-to-end demonstration script:

```bash
python run_demo.py
```

The demo script will:
1. Dynamically locate the TON-IoT dataset directory relative to the project root.
2. Stream raw telemetry records through Stage 1 Context Extractors.
3. Update Stage 2 Dynamic Context Profiles.
4. Score a simulated attack record against established normal baselines and generate a `DeviationReport`.
5. Flush remaining reorder buffers and print compiled profile summaries.

---

## Running Unit Tests

Execute the full unit test suite using `pytest`:

```bash
python -m pytest
```

To run with verbose output:

```bash
python -m pytest -v
```

---

## Key Design Decisions

1. **Entity-Keying Strategy per Source**:
   - **Network**: Keyed by `source_ip` to aggregate host network footprints across individual ephemeral 5-tuple flows.
   - **IoT**: Keyed by static physical device type (`fridge`, `garage`, `modbus`, etc.).
   - **Linux Hosts**: Keyed by process executable name (`process_name` from `CMD` column) rather than `PID` (which recycles rapidly over time).
   - **Windows Hosts**: Keyed by `entity_id` (`PID` or `windows_host`).

2. **Baseline-vs-Deviation Split**:
   - Telemetry marked as normal (`security_alert_label == 0`) mutatively updates the running baseline statistics.
   - Telemetry marked as an attack (`security_alert_label == 1`) performs read-only z-score and probability scoring. This prevents malicious activity from shifting or poisoning normal operational baselines.

3. **Order-Robustness & Online Memory Efficiency**:
   - Numerical metrics use Welford's algorithm, which is mathematically invariant to arrival order and requires $O(1)$ memory per attribute.
   - Categorical state transitions use a bounded sliding reorder buffer that sorts out-of-order timestamps prior to emitting transitions into state transition matrices.
