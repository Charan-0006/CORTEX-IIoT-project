"""
CORTEX: Context & Graph-Aware Multi-Agent Framework for Explainable IIoT Threat Intelligence
Layer 3B: Adaptive Graph Intelligence Engine
Module: Multi-Domain Heterogeneous Graph Schema Definition
"""

from dataclasses import dataclass
from typing import Dict, Any


# ==============================================================================
# PROVENANCE GRAPH SCHEMA DEFINITION MODULE
# Objective: Defines dataclasses for Host, Service, and Alert entities.
# ==============================================================================

# Data Mapping Explanation:
# 1. HostNode:
#    - Mapped from ToN-IoT 'src_ip' (initiating host) and 'dst_ip' (target host).
#    - Canonical ID format: 'Host:<IP_ADDRESS>'
# 2. ServiceNode:
#    - Mapped from ToN-IoT 'proto' (protocol) and 'dst_port' (destination port).
#    - Canonical ID format: 'Service:<protocol>:<port>'
# 3. AlertNode:
#    - Mapped from ToN-IoT 'label' (1 = Attack) and 'type' (attack category name).
#    - Canonical ID format: 'Alert:Network:<attack_type>'


@dataclass(frozen=True)
class HostNode:
    """
    Host Entity Representation:
    Represents an IP-enabled entity initiating or receiving network flows (e.g., Workstation, Server, Gateway).
    Mapped from 'src_ip' and 'dst_ip' dataset fields.
    """
    ip: str
    subnet: str = "192.168.1.0/24"
    role: str = "IIoT_Node"
    node_type: str = "Host"

    def get_id(self) -> str:
        return f"Host:{self.ip}"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.get_id(), "ip": self.ip, "subnet": self.subnet, "role": self.role, "node_type": self.node_type}


@dataclass(frozen=True)
class ServiceNode:
    """
    Service Entity Representation:
    Represents a network protocol service endpoint (e.g., Modbus/502, HTTP/80, SSH/22).
    Mapped from 'proto' and 'dst_port' dataset fields.
    """
    port: int
    protocol: str
    service_name: str = "Unknown"
    node_type: str = "Service"

    def get_id(self) -> str:
        return f"Service:{self.protocol.lower()}:{self.port}"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.get_id(), "port": self.port, "protocol": self.protocol, "service_name": self.service_name, "node_type": self.node_type}


@dataclass(frozen=True)
class IoTDeviceNode:
    """Represents an IIoT physical sensor or actuator device (e.g., Modbus_PLC, Fridge, Thermostat, Weather)."""
    device_id: str
    device_type: str                              # 'Modbus_PLC', 'Fridge', 'Thermostat', 'GPS', 'Garage_Door'
    location: str = "Factory_Floor_Zone_1"
    node_type: str = "IoTDevice"

    def get_id(self) -> str:
        return f"IoTDevice:{self.device_type}:{self.device_id}"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.get_id(), "device_id": self.device_id, "device_type": self.device_type, "location": self.location, "node_type": self.node_type}


@dataclass(frozen=True)
class SystemProcessNode:
    """Represents an OS system process execution node from Linux/Windows telemetry logs."""
    pid: int
    command: str                                 # e.g., 'Web-Content', 'firefox', 'compiz', 'Xorg'
    os_type: str = "Linux"                       # 'Linux', 'Windows'
    node_type: str = "SystemProcess"

    def get_id(self) -> str:
        return f"Process:{self.os_type}:{self.pid}:{self.command}"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.get_id(), "pid": self.pid, "command": self.command, "os_type": self.os_type, "node_type": self.node_type}


@dataclass(frozen=True)
class AlertNode:
    """
    Alert Entity Representation:
    Represents a threat detection event or attack alert triggered by a network flow.
    Mapped from 'label' (1 = Attack) and 'type' dataset fields.
    """
    alert_id: str
    attack_type: str
    severity: str
    confidence: float
    timestamp: float
    domain: str = "Network"                       # 'Network', 'IoT', 'Linux', 'Windows'
    node_type: str = "Alert"

    def get_id(self) -> str:
        return f"Alert:{self.domain}:{self.alert_id}"

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.get_id(), "alert_id": self.alert_id, "attack_type": self.attack_type, "severity": self.severity, "confidence": self.confidence, "timestamp": self.timestamp, "domain": self.domain, "node_type": self.node_type}

