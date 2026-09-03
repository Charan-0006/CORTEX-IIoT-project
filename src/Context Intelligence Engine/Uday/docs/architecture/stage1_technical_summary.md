# Stage 1 (Multi-Source Context Extraction) Technical Summary

This document provides a detailed technical summary of what is currently implemented in **Stage 1 (Multi-Source Context Extraction)** of the CORTEX Contextual Intelligence Engine.

---

## 1. File Structure

Stage 1 is composed of the following modules and files inside the CORTEX codebase:

*   **Context Extractor Core & Implementations**: [context_extraction.py](file:///d:/CORTEX/context_engine/context_extraction.py)
    *   Defines the unified output container [StructuredContext](file:///d:/CORTEX/context_engine/context_extraction.py#L18-L44).
    *   Defines the base class [BaseContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L47-L192) containing common mapping, label/class parsing, and validation utility methods.
    *   Implements source-specific extractors:
        *   [NetworkContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L195-L226) (Processes Zeek/Bro logs).
        *   [IoTContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L229-L284) (Processes Fridge, Garage, GPS, Modbus, Motion Light, Thermostat, and Weather sensors).
        *   [LinuxContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L287-L322) (Processes Linux CPU/process scheduling, Disk IO, and Memory logs).
        *   [WindowsContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L325-L351) (Processes Windows Performance Monitor counters).
    *   Implements [MultiSourceContextExtractor](file:///d:/CORTEX/context_engine/context_extraction.py#L354-L402) which acts as the orchestrator/router to dispatch raw telemetry rows to the correct source extractor.
*   **Semantic Data Dictionary**: [context_attribute_repository.py](file:///d:/CORTEX/context_engine/context_attribute_repository.py)
    *   Contains [ContextAttributeRepository](file:///d:/CORTEX/context_engine/context_attribute_repository.py#L35-L341), which registers all semantic attributes, data types, descriptions, and maps raw CSV column headers to the standardized internal context keys.
*   **Data Streaming Loader**: [data_loader.py](file:///d:/CORTEX/preprocessing/data_loader.py)
    *   Defines [CSVDataLoader](file:///d:/CORTEX/preprocessing/data_loader.py#L16-L102), which streams large CSV telemetry files chunk-by-chunk using `pandas` to optimize memory load, cleaning up headers and converting missing values (`NaN`) to `None`.
*   **Unit Tests & Demonstration**:
    *   [test_context_extraction.py](file:///d:/CORTEX/tests/test_context_extraction.py): Verifies semantic mappings, extractor logic, timestamp parser formats, and loaders.
    *   [run_demo.py](file:///d:/CORTEX/run_demo.py): An execution script that runs Stage 1 over the active TON-IoT datasets.

---

## 2. Input Schema & Mapped Fields

The extractors expect raw telemetry data as a Python dictionary (`Dict[str, Any]`), where keys are the column headers of the dataset row (whitespace stripped). 

Below is the mapping registry code from [context_attribute_repository.py](file:///d:/CORTEX/context_engine/context_attribute_repository.py#L209-L340) detailing exactly which raw fields from the TON-IoT datasets are registered for mapping:

```python
        # --- LOAD RAW FEATURE TO STANDARD KEY MAPS ---
        
        # Network mappings
        net_mappings = {
            "ts": "timestamp", "src_ip": "source_ip", "src_port": "source_port",
            "dst_ip": "dest_ip", "dst_port": "dest_port", "proto": "network_protocol",
            "service": "app_service", "duration": "session_duration",
            "src_bytes": "bytes_sent", "dst_bytes": "bytes_received",
            "conn_state": "connection_state", "src_pkts": "packets_sent",
            "dst_pkts": "packets_received", "src_ip_bytes": "ip_bytes_sent",
            "dst_ip_bytes": "ip_bytes_received",
            "weird_name": "protocol_anomaly_name",
            "weird_notice": "anomaly_notice_triggered", "dns_rejected": "dns_query_rejected",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in net_mappings.items():
            self.register_mapping(raw, "network", std)

        # IoT Fridge mappings
        fridge_mappings = {
            "fridge_temperature": "device_temperature",
            "temp_condition": "status_condition",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in fridge_mappings.items():
            self.register_mapping(raw, "fridge", std)

        # IoT Garage mappings
        garage_mappings = {
            "door_state": "actuator_state",
            "sphone_signal": "signal_active",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in garage_mappings.items():
            self.register_mapping(raw, "garage", std)

        # IoT GPS mappings
        gps_mappings = {
            "latitude": "geo_latitude", "longitude": "geo_longitude",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in gps_mappings.items():
            self.register_mapping(raw, "gps", std)

        # IoT Modbus mappings
        modbus_mappings = {
            "FC1_Read_Input_Register": "modbus_reg_fc1",
            "FC2_Read_Discrete_Value": "modbus_reg_fc2",
            "FC3_Read_Holding_Register": "modbus_reg_fc3",
            "FC4_Read_Coil": "modbus_reg_fc4",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in modbus_mappings.items():
            self.register_mapping(raw, "modbus", std)

        # IoT Motion Light mappings
        motion_mappings = {
            "motion_status": "sensor_binary_status",
            "light_status": "actuator_state",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in motion_mappings.items():
            self.register_mapping(raw, "motion_light", std)

        # IoT Thermostat mappings
        thermo_mappings = {
            "current_temperature": "ambient_temperature",
            "thermostat_status": "actuator_binary_status",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in thermo_mappings.items():
            self.register_mapping(raw, "thermostat", std)

        # IoT Weather mappings
        weather_mappings = {
            "temperature": "weather_temp",
            "pressure": "weather_pressure",
            "humidity": "weather_humidity",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in weather_mappings.items():
            self.register_mapping(raw, "weather", std)

        # Linux Process scheduling mappings
        linux_proc_mappings = {
            "ts": "timestamp", "PID": "process_id", "CMD": "process_name",
            "CPU": "cpu_usage_pct", "State": "thread_state",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in linux_proc_mappings.items():
            self.register_mapping(raw, "linux_process", std)

        # Linux Disk mappings
        linux_disk_mappings = {
            "ts": "timestamp", "PID": "process_id", "CMD": "process_name",
            "RDDSK": "disk_read_kb_s", "WRDSK": "disk_write_kb_s",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in linux_disk_mappings.items():
            self.register_mapping(raw, "linux_disk", std)

        # Linux Memory mappings
        linux_mem_mappings = {
            "ts": "timestamp", "PID": "process_id", "CMD": "process_name",
            "MEM": "memory_usage_pct", "VSIZE": "virtual_mem_mb",
            "RSIZE": "resident_mem_mb", "VGROW": "virtual_mem_growth_mb",
            "RGROW": "resident_mem_growth_mb",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in linux_mem_mappings.items():
            self.register_mapping(raw, "linux_memory", std)

        # Windows dataset mappings (handles Windows 10 & 7 processor/process/memory/disk counters)
        windows_mappings = {
            "ts": "timestamp",
            "Process_Elapsed_Time": "process_elapsed_time",
            "Process(_Total) Elapsed Time": "process_elapsed_time",
            "Processor_pct_ Processor_Time": "cpu_usage_pct",
            "Processor(_Total) pct_ Processor_Time": "cpu_usage_pct",
            "Memory_Available_Bytes": "memory_available_bytes",
            "Memory Available Bytes": "memory_available_bytes",
            "Process_Working_Set_ Private": "process_memory_bytes",
            "Process_Working_Set_Private": "process_memory_bytes",
            "Process(_Total) Working Set - Private": "process_memory_bytes",
            "LogicalDisk(_Total) Disk Read Bytes sec": "disk_read_bytes_s",
            "LogicalDisk(_Total) Disk Write Bytes sec": "disk_write_bytes_s",
            "Process_ID Process": "process_id",
            "Process(_Total) ID Process": "process_id",
            "label": "security_alert_label", "type": "attack_class"
        }
        for raw, std in windows_mappings.items():
            self.register_mapping(raw, "windows", std)
```

---

## 3. Processing & Mapping Logic

The extraction process maps metadata, standardizes timestamps, casts data types, and resolves telemetry entity identifiers before grouping variables into the six primary Context Dimensions.

### A. Core Multi-Dimension Mapping Loop
The exact mapping method in [BaseContextExtractor._extract_structured_context](file:///d:/CORTEX/context_engine/context_extraction.py#L76-L164) is:

```python
    def _extract_structured_context(
        self, raw_row: Dict[str, Any], mapped_source_type: str,
        timestamp: float, entity_type: str, entity_id: str
    ) -> StructuredContext:
        """Maps raw row columns, validates and casts types, and groups into 6 dimensions."""
        temporal = {"timestamp": timestamp}
        asset = {}
        network = {}
        device = {}
        operational = {}
        security = {}

        # Resolve ground truth label and class
        label, attack_class = self._parse_label_and_class(raw_row)
        security["security_alert_label"] = label
        security["attack_class"] = attack_class

        # Map all other raw fields
        for raw_col, val in raw_row.items():
            std_name = self.repository.map_raw_field(raw_col, mapped_source_type)
            if not std_name:
                continue

            attr_meta = self.repository.get_attribute(std_name)
            if not attr_meta:
                continue

            # Ignore ground truth labels and primary timestamp mapping here as they are handled explicitly
            if std_name in ("security_alert_label", "attack_class", "timestamp"):
                continue

            # Cast type
            casted_val = None
            if val is not None:
                try:
                    if attr_meta.data_type == "int":
                        casted_val = int(float(str(val).strip()))
                    elif attr_meta.data_type == "float":
                        casted_val = float(str(val).strip())
                    elif attr_meta.data_type == "bool":
                        val_str = str(val).strip().lower()
                        casted_val = val_str in ("true", "1", "t", "on")
                    else:
                        casted_val = str(val).strip()
                except (ValueError, TypeError):
                    logger.warning(
                        "Failed to cast attribute '%s' value '%s' to %s",
                        std_name, val, attr_meta.data_type
                    )
                    casted_val = val

            # Place in the correct grouped dictionary based on dimension
            dim = attr_meta.dimension
            if dim == ContextDimension.TEMPORAL:
                temporal[std_name] = casted_val
            elif dim == ContextDimension.ASSET:
                asset[std_name] = casted_val
            elif dim == ContextDimension.NETWORK:
                network[std_name] = casted_val
            elif dim == ContextDimension.DEVICE:
                device[std_name] = casted_val
            elif dim == ContextDimension.OPERATIONAL:
                operational[std_name] = casted_val
            elif dim == ContextDimension.SECURITY:
                security[std_name] = casted_val

        # Guarantee entity IDs inside asset context
        if entity_type == "DEVICE" and "device_id" not in asset:
            asset["device_id"] = entity_id
        elif entity_type == "HOST_PROCESS" and "process_id" not in asset:
            pid = raw_row.get("PID") or raw_row.get("Process_ID Process") or raw_row.get("Process(_Total) ID Process")
            if pid is not None:
                try:
                    asset["process_id"] = int(float(str(pid).strip()))
                except Exception:
                    pass

        return StructuredContext(
            timestamp=timestamp,
            source=self.source_name,
            entity_type=entity_type,
            entity_id=entity_id,
            temporal_context=temporal,
            asset_context=asset,
            network_context=network,
            device_context=device,
            operational_context=operational,
            security_context=security
        )
```

### B. Label and Class Extraction
Raw ground-truth anomaly labels and attack types are extracted via [BaseContextExtractor._parse_label_and_class](file:///d:/CORTEX/context_engine/context_extraction.py#L166-L192):

```python
    def _parse_label_and_class(self, raw_row: Dict[str, Any]) -> tuple[int, str]:
        """Extracts label and attack type from the raw row.

        Args:
            raw_row: Raw telemetry dictionary.

        Returns:
            A tuple of (label, attack_class).
        """
        # Search for typical label headers
        label = 0
        for k in ("label", "Label"):
            if k in raw_row and raw_row[k] is not None:
                try:
                    label = int(raw_row[k])
                except (ValueError, TypeError):
                    label = 0
                break

        # Search for typical attack type headers
        attack_class = "normal"
        for k in ("type", "Type"):
            if k in raw_row and raw_row[k] is not None:
                attack_class = str(raw_row[k]).strip()
                break

        return label, attack_class
```

### C. IoT Datetime Combined Parsing
For IoT sub-sources, Unix epoch timestamps are parsed from raw `date` and `time` columns using [IoTContextExtractor._parse_iot_timestamp](file:///d:/CORTEX/context_engine/context_extraction.py#L242-L262):

```python
    def _parse_iot_timestamp(self, date_val: Any, time_val: Any) -> float:
        """Parses combined IoT date and time strings into a Unix epoch timestamp."""
        if not date_val or not time_val:
            raise ValueError(f"Missing date ('{date_val}') or time ('{time_val}') value.")

        date_str = str(date_val).strip()
        time_str = str(time_val).strip()

        # Combine date and time
        datetime_str = f"{date_str} {time_str}"
        
        # Try primary formats
        for fmt in ("%d-%b-%y %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.datetime.strptime(datetime_str, fmt)
                # Assume UTC timezone for security datasets
                return dt.replace(tzinfo=datetime.timezone.utc).timestamp()
            except ValueError:
                continue

        raise ValueError(f"Failed to parse IoT datetime string: '{datetime_str}'")
```

### D. Validation & Error Handling
*   **Mandatory Field Presence**: Extractors raise `ValueError` if key identifiers (`ts` or `date`/`time`) are missing or unparseable.
*   **Casting Failures**: If casting fails inside `_extract_structured_context`, it logs a warning using `logger.warning` and falls back to the original raw value.
*   **Null Data Handling**: Empty CSV fields (`NaN`) are processed as `None` by [CSVDataLoader](file:///d:/CORTEX/preprocessing/data_loader.py#L16-L102) before extractors execute.

### E. Stubs & Hardcoded Values
*   **Timezone Assumption**: All IoT timestamp conversions explicitly append `.replace(tzinfo=datetime.timezone.utc)`, assuming the input logs are UTC.
*   **Static IoT Entity Identification**: IoT extractors set static entity IDs named after the device type (e.g., `"fridge"`, `"garage"`).
*   No explicit `TODO` or `FIXME` comments are currently present in the codebase.

---

## 4. Output Schema & Example Context Record

### A. StructuredContext Dataclass Definition
The output from Stage 1 is a frozen Python dataclass [StructuredContext](file:///d:/CORTEX/context_engine/context_extraction.py#L18-L44):

```python
@dataclass(frozen=True)
class StructuredContext:
    """Grouped standardized context representing a single telemetry record.

    Attributes:
        timestamp: Standardized UTC Unix epoch timestamp.
        source: Name of the telemetry source (e.g. 'fridge', 'network', 'linux_process').
        entity_type: Classification of the entity ('DEVICE', 'NETWORK_FLOW', 'HOST_PROCESS').
        entity_id: Unique string identifier of the entity.
        temporal_context: Grouped temporal metadata.
        asset_context: Grouped identifying and asset classification data.
        network_context: Grouped network-layer interaction metrics.
        device_context: Grouped physical IoT sensor and actuator states.
        operational_context: Grouped host OS and system performance load metrics.
        security_context: Grouped labels and anomaly warnings.
    """

    timestamp: float
    source: str
    entity_type: str
    entity_id: str
    temporal_context: Dict[str, Any] = field(default_factory=dict)
    asset_context: Dict[str, Any] = field(default_factory=dict)
    network_context: Dict[str, Any] = field(default_factory=dict)
    device_context: Dict[str, Any] = field(default_factory=dict)
    operational_context: Dict[str, Any] = field(default_factory=dict)
    security_context: Dict[str, Any] = field(default_factory=dict)
```

### B. Real Output Example (Network Source)
```json
{
  "timestamp": 1554198358.0,
  "source": "network",
  "entity_type": "NETWORK_FLOW",
  "entity_id": "3.122.49.24:1883->192.168.1.152:52976[tcp]",
  "temporal_context": {
    "timestamp": 1554198358.0,
    "session_duration": 80549.53026
  },
  "asset_context": {
    "source_ip": "3.122.49.24",
    "source_port": 1883,
    "dest_ip": "192.168.1.152",
    "dest_port": 52976
  },
  "network_context": {
    "network_protocol": "tcp",
    "app_service": "-",
    "bytes_sent": 1762852,
    "bytes_received": 41933215,
    "connection_state": "OTH",
    "packets_sent": 252181,
    "ip_bytes_sent": 14911156,
    "packets_received": 2,
    "ip_bytes_received": 236
  },
  "device_context": {},
  "operational_context": {},
  "security_context": {
    "security_alert_label": 0,
    "attack_class": "normal",
    "dns_query_rejected": false,
    "protocol_anomaly_name": "bad_TCP_checksum",
    "anomaly_notice_triggered": false
  }
}
```

---

## 5. Integration Points

### Invoking Stage 1
The pipeline is invoked programmatically using the following steps:
```python
from context_engine.context_attribute_repository import ContextAttributeRepository
from context_engine.context_extraction import MultiSourceContextExtractor

# 1. Initialize repositories and orchestrator
repo = ContextAttributeRepository()
extractor = MultiSourceContextExtractor(repository=repo)

# 2. Extract context from a raw CSV record dictionary
context_record = extractor.extract(raw_row, source_type="network")
```

### Downstream Consumption
Downstream stages (such as Stage 2) consume the returning `StructuredContext` dataclass directly. Downstream layers key off of `entity_id` and `entity_type` to build semantic profiles, establish relationships, or trace anomalies over time.

---

## 6. Gaps & Known Limitations

1.  **Windows Process Name Absence**: The raw Windows telemetry dataset contains no binary/command execution names. Only process ID (`PID`) is captured, leaving `process_name` empty.
2.  **Hardcoded Source Map Registry**: Mappings are hardcoded directly into [ContextAttributeRepository](file:///d:/CORTEX/context_engine/context_attribute_repository.py#L35-L341) instead of using an external configuration file (like JSON/YAML).
3.  **Static IoT Device Identification**: Devices are keyed strictly on their dataset type (e.g. `fridge`, `garage`), which prevents distinguishing multiple sensors of the same category.
4.  **UTC Assumption**: Timestamp strings are converted under the assumption that they are in UTC.
5.  **Rigid Dispatch Validation**: Unknown source types trigger an immediate `ValueError` inside the orchestrator rather than gracefully parsing generic features.
