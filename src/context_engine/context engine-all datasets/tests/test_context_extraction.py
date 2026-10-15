"""Unit tests for CORTEX Context Extraction modules.

Verifies the accuracy of repositories, loaders, extractors, and coordinate schemas.
"""

import os
import tempfile
import pytest
from context_engine.context_attribute_repository import ContextAttributeRepository
from context_engine.context_extraction import (
    MultiSourceContextExtractor,
    NetworkContextExtractor,
    IoTContextExtractor,
    LinuxContextExtractor,
    WindowsContextExtractor,
    StructuredContext
)
from context_engine.data_loader import CSVDataLoader


@pytest.fixture
def repo() -> ContextAttributeRepository:
    """Fixture returning a pre-populated ContextAttributeRepository."""
    return ContextAttributeRepository()


@pytest.fixture
def multi_extractor(repo) -> MultiSourceContextExtractor:
    """Fixture returning a MultiSourceContextExtractor."""
    return MultiSourceContextExtractor(repository=repo)


def test_repository_mappings(repo):
    """Verifies that the repository contains expected variables and mappings."""
    # Check that critical attributes are registered
    assert repo.get_attribute("timestamp") is not None
    assert repo.get_attribute("source_ip") is not None
    assert repo.get_attribute("device_temperature") is not None
    assert repo.get_attribute("cpu_usage_pct") is not None
    assert repo.get_attribute("security_alert_label") is not None

    # Check mapping lookup
    assert repo.map_raw_field("ts", "network") == "timestamp"
    assert repo.map_raw_field("src_ip", "network") == "source_ip"
    assert repo.map_raw_field("fridge_temperature", "fridge") == "device_temperature"
    assert repo.map_raw_field("door_state", "garage") == "actuator_state"
    assert repo.map_raw_field("CPU", "linux_process") == "cpu_usage_pct"


def test_network_context_extractor(repo):
    """Tests the parsing and entity resolution of network telemetry."""
    extractor = NetworkContextExtractor(repo)
    raw_row = {
        "ts": "1554198358",
        "src_ip": "3.122.49.24",
        "src_port": "1883",
        "dst_ip": "192.168.1.152",
        "dst_port": "52976",
        "proto": "tcp",
        "service": "-",
        "duration": "80549.5",
        "src_bytes": "1762852",
        "dst_bytes": "41933215",
        "conn_state": "OTH",
        "label": "1",
        "type": "backdoor"
    }

    record = extractor.extract(raw_row)
    
    assert isinstance(record, StructuredContext)
    assert record.timestamp == 1554198358.0
    assert record.source == "network"
    assert record.entity_type == "NETWORK_FLOW"
    assert record.entity_id == "3.122.49.24:1883->192.168.1.152:52976[tcp]"
    assert record.security_context["security_alert_label"] == 1
    assert record.security_context["attack_class"] == "backdoor"
    
    # Attributes mapped correctly into 6 dimensions
    assert record.asset_context["source_ip"] == "3.122.49.24"
    assert record.asset_context["source_port"] == 1883
    assert record.temporal_context["session_duration"] == 80549.5
    assert record.network_context["bytes_sent"] == 1762852
    assert record.network_context["connection_state"] == "OTH"
    assert "timestamp" not in record.network_context  # Separated in temporal


def test_iot_timestamp_parsing(repo):
    """Tests that various IoT date and time formats parse into UTC epochs."""
    extractor = IoTContextExtractor(repo, "fridge")
    
    # Space-padded fridge time format
    ts_fridge = extractor._parse_iot_timestamp("31-Mar-19", "   12:36:52   ")
    # Date starts with single digit day
    ts_garage = extractor._parse_iot_timestamp("1-Apr-19", "  20:53:44 ")
    
    assert ts_fridge > 0
    assert ts_garage > 0
    assert ts_fridge != ts_garage


def test_iot_context_extractor(repo):
    """Tests context extraction from an IoT Fridge telemetry record."""
    extractor = IoTContextExtractor(repo, "fridge")
    raw_row = {
        "date": "31-Mar-19",
        "time": "12:36:52",
        "fridge_temperature": "13.1",
        "temp_condition": "high",
        "label": "0",
        "type": "normal"
    }

    record = extractor.extract(raw_row)
    assert record.entity_type == "DEVICE"
    assert record.entity_id == "fridge"
    assert record.source == "iot_fridge"
    assert record.security_context["security_alert_label"] == 0
    assert record.security_context["attack_class"] == "normal"
    assert record.device_context["device_temperature"] == 13.1
    assert record.device_context["status_condition"] == "high"


def test_linux_context_extractor(repo):
    """Tests context extraction from Linux host telemetry."""
    extractor = LinuxContextExtractor(repo, "process")
    raw_row = {
        "ts": "1554218915",
        "PID": "3257",
        "CPU": "0.13",
        "CMD": "Web-Content",
        "State": "S",
        "label": "0",
        "type": "normal"
    }

    record = extractor.extract(raw_row)
    assert record.entity_type == "HOST_PROCESS"
    assert record.entity_id == "3257:Web-Content"
    assert record.operational_context["cpu_usage_pct"] == 0.13
    assert record.operational_context["thread_state"] == "S"
    assert record.asset_context["process_id"] == 3257
    assert record.asset_context["process_name"] == "Web-Content"


def test_windows_context_extractor(repo):
    """Tests context extraction from Windows performance counters."""
    extractor = WindowsContextExtractor(repo)
    raw_row = {
        "ts": "1554206309",
        "Processor_pct_ Processor_Time": "66.20",
        "Process_Working_Set_ Private": "1185267712",
        "Process_ID Process": "1024",
        "label": "0",
        "type": "normal"
    }

    record = extractor.extract(raw_row)
    assert record.entity_type == "HOST_PROCESS"
    assert record.entity_id == "PID_1024"
    assert record.operational_context["cpu_usage_pct"] == 66.20
    assert record.operational_context["process_memory_bytes"] == 1185267712
    assert record.asset_context["process_id"] == 1024


def test_multi_source_orchestrator(multi_extractor):
    """Tests the MultiSourceContextExtractor router."""
    raw_fridge = {
        "date": "31-Mar-19",
        "time": "12:36:52",
        "fridge_temperature": "13.1",
        "temp_condition": "high",
        "label": "0",
        "type": "normal"
    }
    
    record = multi_extractor.extract(raw_fridge, "fridge")
    assert record.source == "iot_fridge"
    assert record.device_context["device_temperature"] == 13.1


def test_data_loader_streaming():
    """Tests CSVDataLoader using a temporary file."""
    data = (
        "date,time,fridge_temperature,temp_condition,label,type\n"
        "31-Mar-19, 12:36:52 ,13.1,high ,0,normal\n"
        "31-Mar-19, 12:36:53 ,12.9,normal,0,normal\n"
    )
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as temp:
        temp.write(data)
        temp_path = temp.name

    try:
        loader = CSVDataLoader(temp_path)
        records = list(loader.stream_records(chunk_size=1))
        assert len(records) == 2
        assert records[0]["fridge_temperature"] == 13.1
        assert records[0]["temp_condition"] == "high"
        # Check space stripping of headers
        assert "fridge_temperature" in records[0]
    finally:
        os.remove(temp_path)
