"""Stage 1: Multi-Source Context Extraction for CORTEX.

This module parses raw telemetry from various sources (Network, IoT, Linux, Windows),
extracts and maps variables into standardized context attributes, standardizes timestamps,
and outputs unified StructuredContext objects grouped by the 6 primary Context Dimensions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import datetime
import logging
from typing import Any, Dict, Optional
from context_engine.context_attribute_repository import ContextAttributeRepository, ContextDimension

logger = logging.getLogger("CORTEX.ContextExtraction")


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


class BaseContextExtractor(ABC):
    """Abstract base class for all context source extractors."""

    def __init__(self, repository: ContextAttributeRepository, source_name: str) -> None:
        """Initializes the base context extractor.

        Args:
            repository: Centralized ContextAttributeRepository instance.
            source_name: Unique name of the telemetry source.
        """
        self.repository = repository
        self.source_name = source_name

    @abstractmethod
    def extract(self, raw_row: Dict[str, Any]) -> StructuredContext:
        """Extracts and standardizes context attributes from a raw data row.

        Args:
            raw_row: Dictionary representing a raw row from the source CSV.

        Returns:
            A standardized StructuredContext.

        Raises:
            ValueError: If critical data (like timestamp or entity identifiers)
                        is missing or invalid.
        """
        pass

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
            pid = None
            for key in ("PID", "Process_ID Process", "Process(_Total) ID Process"):
                if key in raw_row and raw_row[key] is not None:
                    pid = raw_row[key]
                    break
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


class NetworkContextExtractor(BaseContextExtractor):
    """Extractor for network-level telemetry data (Zeek/Bro logs)."""

    def __init__(self, repository: ContextAttributeRepository) -> None:
        super().__init__(repository, "network")

    def extract(self, raw_row: Dict[str, Any]) -> StructuredContext:
        """Extracts and maps network flow telemetry into a StructuredContext object.

        Args:
            raw_row: Raw dictionary row from network log dataset.

        Returns:
            StructuredContext with network entity 5-tuple identifier.

        Raises:
            ValueError: If 'ts' timestamp column is missing or invalid.
        """
        if "ts" not in raw_row or raw_row["ts"] is None:
            raise ValueError("Network record missing critical timestamp ('ts')")

        try:
            timestamp = float(raw_row["ts"])
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid network timestamp format: {raw_row['ts']}") from e

        # Extract 5-tuple for network flow entity identification
        src_ip = raw_row.get("src_ip", "-").strip()
        src_port = raw_row.get("src_port", "-")
        dst_ip = raw_row.get("dst_ip", "-").strip()
        dst_port = raw_row.get("dst_port", "-")
        proto = raw_row.get("proto", "-").strip()

        entity_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}[{proto}]"
        entity_type = "NETWORK_FLOW"

        return self._extract_structured_context(
            raw_row=raw_row,
            mapped_source_type="network",
            timestamp=timestamp,
            entity_type=entity_type,
            entity_id=entity_id
        )


class IoTContextExtractor(BaseContextExtractor):
    """Extractor for IoT device telemetry (Fridge, Garage, GPS, Modbus, etc.)."""

    def __init__(self, repository: ContextAttributeRepository, device_type: str) -> None:
        """Initializes the IoT extractor.

        Args:
            repository: Centralized ContextAttributeRepository.
            device_type: Sub-type of device (e.g. 'fridge', 'modbus', 'gps').
        """
        super().__init__(repository, f"iot_{device_type}")
        self.device_type = device_type

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

    def extract(self, raw_row: Dict[str, Any]) -> StructuredContext:
        """Extracts and maps IoT sensor telemetry into a StructuredContext object.

        Args:
            raw_row: Raw dictionary row from IoT device dataset.

        Returns:
            StructuredContext with static device type identifier.

        Raises:
            ValueError: If date or time columns are missing or unparseable.
        """
        # Resolve timestamp from date and time
        date_col = next((k for k in raw_row if k.lower() == "date"), None)
        time_col = next((k for k in raw_row if k.lower() == "time"), None)

        if not date_col or not time_col:
            raise ValueError("IoT record missing date or time columns")

        timestamp = self._parse_iot_timestamp(raw_row[date_col], raw_row[time_col])

        # Entity identification: The physical device class
        entity_id = self.device_type
        entity_type = "DEVICE"

        return self._extract_structured_context(
            raw_row=raw_row,
            mapped_source_type=self.device_type,
            timestamp=timestamp,
            entity_type=entity_type,
            entity_id=entity_id
        )


class LinuxContextExtractor(BaseContextExtractor):
    """Extractor for Linux system activity logs (Process, Memory, Disk)."""

    def __init__(self, repository: ContextAttributeRepository, activity_type: str) -> None:
        """Initializes the Linux extractor.

        Args:
            repository: Centralized ContextAttributeRepository.
            activity_type: Sub-type of log: 'process', 'memory', or 'disk'.
        """
        super().__init__(repository, f"linux_{activity_type}")
        self.activity_type = activity_type
        self.repo_source_key = f"linux_{activity_type}"

    def extract(self, raw_row: Dict[str, Any]) -> StructuredContext:
        """Extracts and maps Linux OS system telemetry into a StructuredContext object.

        Args:
            raw_row: Raw dictionary row from Linux system log dataset.

        Returns:
            StructuredContext with PID and command entity identifier.

        Raises:
            ValueError: If 'ts' timestamp column is missing or invalid.
        """
        if "ts" not in raw_row or raw_row["ts"] is None:
            raise ValueError("Linux host record missing timestamp ('ts')")

        try:
            timestamp = float(raw_row["ts"])
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid Linux host timestamp: {raw_row['ts']}") from e

        # Entity identification: PID is process-level context, else fallback to host
        pid = raw_row.get("PID")
        cmd = raw_row.get("CMD", "unknown").strip()
        entity_id = f"{pid}:{cmd}" if pid is not None else "linux_host"
        entity_type = "HOST_PROCESS" if pid is not None else "DEVICE"

        return self._extract_structured_context(
            raw_row=raw_row,
            mapped_source_type=self.repo_source_key,
            timestamp=timestamp,
            entity_type=entity_type,
            entity_id=entity_id
        )


class WindowsContextExtractor(BaseContextExtractor):
    """Extractor for Windows system performance counter logs."""

    def __init__(self, repository: ContextAttributeRepository) -> None:
        super().__init__(repository, "windows")

    def extract(self, raw_row: Dict[str, Any]) -> StructuredContext:
        """Extracts and maps Windows performance counter telemetry into a StructuredContext object.

        Args:
            raw_row: Raw dictionary row from Windows performance log dataset.

        Returns:
            StructuredContext with Process ID entity identifier.

        Raises:
            ValueError: If 'ts' timestamp column is missing or invalid.
        """
        if "ts" not in raw_row or raw_row["ts"] is None:
            raise ValueError("Windows host record missing timestamp ('ts')")

        try:
            timestamp = float(raw_row["ts"])
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid Windows host timestamp: {raw_row['ts']}") from e

        pid = None
        for key in ("Process_ID Process", "Process(_Total) ID Process", "Process_ID_Process"):
            if key in raw_row and raw_row[key] is not None:
                pid = raw_row[key]
                break
        entity_id = f"PID_{int(float(pid))}" if pid is not None else "windows_host"
        entity_type = "HOST_PROCESS" if pid is not None else "DEVICE"

        return self._extract_structured_context(
            raw_row=raw_row,
            mapped_source_type="windows",
            timestamp=timestamp,
            entity_type=entity_type,
            entity_id=entity_id
        )


class MultiSourceContextExtractor:
    """Orchestrates multi-source context extraction across all telemetry sources.

    Maintains instances of specific extractors and dispatches records
    accordingly based on the specified source type.
    """

    def __init__(self, repository: Optional[ContextAttributeRepository] = None) -> None:
        """Initializes the multi-source extractor.

        Args:
            repository: Optional ContextAttributeRepository instance. If None,
                        creates a new repository.
        """
        self.repository = repository or ContextAttributeRepository()
        self._extractors: Dict[str, BaseContextExtractor] = {
            "network": NetworkContextExtractor(self.repository),
            "fridge": IoTContextExtractor(self.repository, "fridge"),
            "garage": IoTContextExtractor(self.repository, "garage"),
            "gps": IoTContextExtractor(self.repository, "gps"),
            "modbus": IoTContextExtractor(self.repository, "modbus"),
            "motion_light": IoTContextExtractor(self.repository, "motion_light"),
            "thermostat": IoTContextExtractor(self.repository, "thermostat"),
            "weather": IoTContextExtractor(self.repository, "weather"),
            "linux_process": LinuxContextExtractor(self.repository, "process"),
            "linux_disk": LinuxContextExtractor(self.repository, "disk"),
            "linux_memory": LinuxContextExtractor(self.repository, "memory"),
            "windows": WindowsContextExtractor(self.repository),
        }

    def extract(self, raw_row: Dict[str, Any], source_type: str) -> StructuredContext:
        """Dispatches the raw record to the matching extractor.

        Args:
            raw_row: Raw row dictionary.
            source_type: Telemetry source name matching registered keys.

        Returns:
            A standardized StructuredContext.

        Raises:
            ValueError: If source_type is unknown or has no registered extractor.
        """
        extractor = self._extractors.get(source_type.strip().lower())
        if not extractor:
            logger.error("No registered context extractor for source type: %s", source_type)
            raise ValueError(f"Unknown telemetry source type: {source_type}")
            
        return extractor.extract(raw_row)
