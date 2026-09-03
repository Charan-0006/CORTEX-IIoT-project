# Stage 2 (Dynamic Context Profile Generation) Design Resolutions

This document establishes the architectural design resolutions for Stage 2 (Dynamic Context Profile Generation) of the CORTEX engine, based on inspections of Stage 1 implementations and the TON-IoT dataset.

---

## 1. Entity Key Granularity

We resolve to use different entity-key strategies per telemetry source to avoid high cardinality or process restarts causing baseline mismatches.

### A. Network Source
*   **Stage 1 Implementation**: Maps unique connection flows (5-tuples) as `entity_id` in [NetworkContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L195-L226).
*   **Resolution**: Keying baselines on the full 5-tuple flow results in single-observation profiles. Stage 2 will extract `source_ip` from the `asset_context` (which is reliably mapped from raw `src_ip` columns) to profile host behavior over time.
*   **Key Source**: `asset_context["source_ip"]`

### B. IoT Source
*   **Stage 1 Implementation**: Maps the static device type string (e.g., `"fridge"`) as `entity_id` in [IoTContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L229-L284).
*   **Resolution**: Since the TON-IoT datasets contain telemetry for exactly one physical device per file (with no individual MAC or hardware ID columns), using the static type string as the key is correct.
*   **Key Source**: `entity_id`

### C. Linux Source
*   **Stage 1 Implementation**: Maps `f"{pid}:{cmd}"` as `entity_id` in [LinuxContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L287-L322).
*   **Resolution**: PIDs are short-lived and recycled, making baseline tracking across restarts impossible if keyed by PID. Stage 2 will key host process baselines on the `process_name` (derived from the raw `CMD` column).
*   **Key Source**: `asset_context["process_name"]`

### D. Windows Source
*   **Stage 1 Implementation**: Maps `"PID_{pid}"` as `entity_id` in [WindowsContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L325-L351).
*   **Resolution**: Since Windows telemetry lacks command/process names (only capturing PIDs), profiles will be built at the host level (`"windows_host"`) or keyed on system totals.
*   **Key Source**: `entity_id`
*   **Identified Bug in Stage 1**: In [context_extraction.py:L341-L343](file:///d:/CORTEX/context_engine/context_extraction.py#L341-L343):
    ```python
    pid = raw_row.get("Process_ID Process") or raw_row.get("Process(_Total) ID Process") or raw_row.get("Process_ID_Process")
    ```
    If `Process_ID Process` is `0` (the idle process or total system metrics), Python's `or` logic treats it as falsy and continues checking, returning `None`. This forces `entity_id` to evaluate to `"windows_host"` and `entity_type` to `"DEVICE"`.

---

## 2. Empty Context Dimensions

It is normal and expected for certain context dimensions to be empty (`{}`) depending on the source type. Stage 2 profile update routines will check if the relevant dictionary contains entries before performing calculation updates:

| Telemetry Source | Temporal Context | Asset Context | Network Context | Device Context | Operational Context | Security Context |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Network** | **Populated** | **Populated** | **Populated** | *Empty* | *Empty* | **Populated** |
| **IoT** | **Populated** | **Populated** | *Empty* | **Populated** | *Empty* | **Populated** |
| **Linux** | **Populated** | **Populated** | *Empty* | *Empty* | **Populated** | **Populated** |
| **Windows** | **Populated** | **Populated** | *Empty* | *Empty* | **Populated** | **Populated** |

---

## 3. Timestamp Ordering Guarantee

*   **Observation**: Raw dataset files are streamed by [CSVDataLoader](file:///d:/CORTEX/preprocessing/data_loader.py#L16-L102) in their raw row order.
*   **Resolution**: The TON-IoT logs are not sorted chronologically per entity. Out-of-order records will occur.
*   **Resolution**: Stage 2's incremental statistics (like exponential moving averages) and state-transition-matrix updates must be designed to be robust to out-of-order timestamps or employ a sliding buffer window to sort records per entity before update.

---

## 4. Security Context in Baselining

*   **Risk**: Including attack-labeled records (`security_alert_label == 1`) in normal baselines skew mean and standard deviation limits (e.g., inflating CPU usage or traffic volume), making subsequent anomaly detection ineffective.
*   **Resolution**: Stage 2 will establish behavioral profiles strictly from records where `security_alert_label == 0`. Attack records will bypass the baseline update step, but will be evaluated against the active normal baseline to compute deviation metrics.
