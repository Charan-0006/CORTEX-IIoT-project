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
## Installation & Setup

### 1. Requirements
- Python **3.9+**
- Dependencies listed in `requirements.txt`

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

---