"""Context Attribute Repository for CORTEX.

This module provides the registry and metadata for all semantic context variables
used in the Contextual Intelligence Engine. It maps raw dataset columns to standardized
internal context keys grouped by the 6 core context dimensions.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class ContextDimension(str, Enum):
    """Enumeration of the 6 core context dimensions in CORTEX."""

    TEMPORAL = "TEMPORAL"
    ASSET = "ASSET"
    NETWORK = "NETWORK"
    DEVICE = "DEVICE"
    OPERATIONAL = "OPERATIONAL"
    SECURITY = "SECURITY"


@dataclass(frozen=True)
class ContextAttribute:
    """Metadata schema defining a standardized context attribute."""

    name: str
    dimension: ContextDimension
    data_type: str
    description: str
    source_type: str  # e.g., "network", "fridge", "modbus", "linux_disk", etc.


class ContextAttributeRepository:
    """Repository managing mappings from raw columns to standardized context variables.

    Acting as a centralized semantic dictionary, it allows extractors to map
    heterogeneous data fields to unified keys.
    """

    def __init__(self) -> None:
        """Initializes the repository with predefined attribute registries."""
        self._attributes: Dict[str, ContextAttribute] = {}
        # Mapping from (raw_column_name, source_type) -> standard_attribute_name
        self._raw_mappings: Dict[tuple[str, str], str] = {}
        
        self._load_predefined_attributes()

    def register_attribute(self, attribute: ContextAttribute) -> None:
        """Registers a new context attribute metadata definition.

        Args:
            attribute: ContextAttribute object to register.
        """
        self._attributes[attribute.name] = attribute

    def register_mapping(self, raw_col: str, source_type: str, standard_name: str) -> None:
        """Registers a mapping from raw column to standard context attribute.

        Args:
            raw_col: Column header in raw CSV file.
            source_type: Telemetry source identifier (e.g., "network", "fridge").
            standard_name: Standardized attribute key name.
        """
        cleaned_col = raw_col.strip()
        self._raw_mappings[(cleaned_col, source_type)] = standard_name

    def get_attribute(self, name: str) -> Optional[ContextAttribute]:
        """Retrieves metadata for a standardized attribute by name.

        Args:
            name: Standardized context attribute name.

        Returns:
            The ContextAttribute metadata if registered, else None.
        """
        return self._attributes.get(name)

    def map_raw_field(self, raw_col: str, source_type: str) -> Optional[str]:
        """Maps a raw column name to its standardized attribute name.

        Args:
            raw_col: Raw CSV column header name.
            source_type: Telemetry source identifier.

        Returns:
            Standardized name if mapping exists, else None.
        """
        cleaned_col = raw_col.strip()
        return self._raw_mappings.get((cleaned_col, source_type))

    def get_attributes_by_dimension(self, dimension: ContextDimension) -> List[ContextAttribute]:
        """Retrieves all attributes belonging to a specific context dimension.

        Args:
            dimension: Target ContextDimension.

        Returns:
            A list of matching ContextAttribute definitions.
        """
        return [attr for attr in self._attributes.values() if attr.dimension == dimension]

    def _load_predefined_attributes(self) -> None:
        """Prepopulates the repository with TON-IoT telemetry metadata."""
        # 1. Temporal Context
        self.register_attribute(ContextAttribute(
            name="timestamp",
            dimension=ContextDimension.TEMPORAL,
            data_type="float",
            description="UTC Unix Epoch timestamp of the event",
            source_type="common"
        ))
        self.register_attribute(ContextAttribute(
            name="session_duration",
            dimension=ContextDimension.TEMPORAL,
            data_type="float",
            description="Connection flow duration in seconds",
            source_type="network"
        ))
        self.register_attribute(ContextAttribute(
            name="process_elapsed_time",
            dimension=ContextDimension.TEMPORAL,
            data_type="float",
            description="Elapsed running time of the process in seconds",
            source_type="windows"
        ))
        
        # 2. Asset Context
        asset_attrs = [
            ("source_ip", "string", "Source IP address originating connection", "network"),
            ("dest_ip", "string", "Destination IP address responding to connection", "network"),
            ("source_port", "int", "Source connection port", "network"),
            ("dest_port", "int", "Destination connection port", "network"),
            ("process_id", "int", "OS Kernel Process Identifier", "host"),
            ("process_name", "string", "Name of active command/process", "host"),
            ("device_id", "string", "Standardized physical device identification", "common"),
        ]
        for name, dtype, desc, src in asset_attrs:
            self.register_attribute(ContextAttribute(name, ContextDimension.ASSET, dtype, desc, src))

        # 3. Network Context
        net_attrs = [
            ("network_protocol", "string", "Transport protocol (tcp, udp, icmp)", "network"),
            ("app_service", "string", "Application protocol (dns, http, ssl, etc.)", "network"),
            ("bytes_sent", "int", "Bytes transmitted from source to destination", "network"),
            ("bytes_received", "int", "Bytes transmitted from destination to source", "network"),
            ("connection_state", "string", "Zeek connection flags (S0, S1, SF, etc.)", "network"),
            ("packets_sent", "int", "Number of packets originating from source", "network"),
            ("packets_received", "int", "Number of packets originating from destination", "network"),
            ("ip_bytes_sent", "int", "Total IP header bytes sent from source", "network"),
            ("ip_bytes_received", "int", "Total IP header bytes returned from destination", "network")
        ]
        for name, dtype, desc, src in net_attrs:
            self.register_attribute(ContextAttribute(name, ContextDimension.NETWORK, dtype, desc, src))

        # 4. Device Context (IoT Sensors/Actuators)
        device_attrs = [
            ("device_temperature", "float", "Internal temperature sensor measurement", "fridge"),
            ("status_condition", "string", "State indicator category (high, low, normal)", "fridge"),
            ("actuator_state", "string", "Actuator state (open/closed or on/off)", "garage/light"),
            ("signal_active", "bool", "Device mobile connection status", "garage"),
            ("geo_latitude", "float", "GPS latitude coordinate value", "gps"),
            ("geo_longitude", "float", "GPS longitude coordinate value", "gps"),
            ("sensor_binary_status", "int", "Binary sensor alert status (0 or 1)", "motion"),
            ("ambient_temperature", "float", "Thermostat temperature measurement", "thermostat"),
            ("actuator_binary_status", "int", "Thermostat activity state (0 or 1)", "thermostat"),
            ("weather_temp", "float", "Weather temperature reading", "weather"),
            ("weather_pressure", "float", "Atmospheric pressure reading", "weather"),
            ("weather_humidity", "float", "Humidity percentage reading", "weather"),
            ("modbus_reg_fc1", "int", "Modbus Input Register value", "modbus"),
            ("modbus_reg_fc2", "int", "Modbus Discrete Input status", "modbus"),
            ("modbus_reg_fc3", "int", "Modbus Holding Register analog output", "modbus"),
            ("modbus_reg_fc4", "int", "Modbus Coil register value", "modbus"),
        ]
        for name, dtype, desc, src in device_attrs:
            self.register_attribute(ContextAttribute(name, ContextDimension.DEVICE, dtype, desc, src))

        # 5. Operational Context (System Performance and Resources)
        op_attrs = [
            ("cpu_usage_pct", "float", "CPU utilization percentage", "host"),
            ("memory_usage_pct", "float", "Memory utilization percentage", "host"),
            ("virtual_mem_mb", "float", "Virtual memory size allocated (MB)", "host"),
            ("resident_mem_mb", "float", "Resident set RAM size allocated (MB)", "host"),
            ("virtual_mem_growth_mb", "float", "Growth in virtual memory size", "host"),
            ("resident_mem_growth_mb", "float", "Growth in physical RAM resident size", "host"),
            ("disk_read_kb_s", "float", "Disk read throughput rate (KB/s)", "host"),
            ("disk_write_kb_s", "float", "Disk write throughput rate (KB/s)", "host"),
            ("thread_state", "string", "Current process/thread execution state", "host"),
            ("memory_available_bytes", "int", "Available free system physical memory", "host_win"),
            ("process_memory_bytes", "int", "Process physical RAM working bytes", "host_win"),
            ("disk_read_bytes_s", "float", "Logical disk read byte throughput rate", "host_win"),
            ("disk_write_bytes_s", "float", "Logical disk write byte throughput rate", "host_win"),
        ]
        for name, dtype, desc, src in op_attrs:
            self.register_attribute(ContextAttribute(name, ContextDimension.OPERATIONAL, dtype, desc, src))

        # 6. Security Context
        sec_attrs = [
            ("security_alert_label", "int", "Security label: 0 for normal, 1 for attack", "common"),
            ("attack_class", "string", "Categorized attack signature name (or normal)", "common"),
            ("protocol_anomaly_name", "string", "Zeek-reported protocol parsing violation", "network"),
            ("anomaly_notice_triggered", "bool", "Indicates if protocol anomaly triggered notice", "network"),
            ("dns_query_rejected", "bool", "Flag showing if DNS query was rejected by resolver", "network"),
        ]
        for name, dtype, desc, src in sec_attrs:
            self.register_attribute(ContextAttribute(name, ContextDimension.SECURITY, dtype, desc, src))

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
