"""Unit tests for CORTEX Stage 3 (Operational Context Modeling)."""

import pytest
from context_engine.context_attribute_repository import ContextAttributeRepository
from context_engine.context_extraction import StructuredContext
from context_engine.operational_context import (
    OperationalContextObject,
    OperationalContextEvaluator,
    OperationalContextModeler,
)


@pytest.fixture
def repo() -> ContextAttributeRepository:
    """Pre-populated ContextAttributeRepository."""
    return ContextAttributeRepository()


@pytest.fixture
def modeler(repo) -> OperationalContextModeler:
    """OperationalContextModeler instance."""
    return OperationalContextModeler(repository=repo)


def test_operational_context_object_cold_start(modeler):
    """Verify first observation triggers COLD_START with empty pre-update baseline."""
    ctx = StructuredContext(
        timestamp=100.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": 12.5, "status_condition": "high"},
        security_context={"security_alert_label": 0}
    )

    obj = modeler.process(ctx)

    assert isinstance(obj, OperationalContextObject)
    assert obj.profile_key == "fridge"
    assert obj.baseline_maturity == "COLD_START"
    assert obj.numeric_baseline == {}  # Empty pre-update baseline
    assert obj.categorical_baseline == {}
    assert obj.deviations["device_temperature"]["z_score_valid"] is False
    assert obj.deviations["device_temperature"]["z_score"] is None
    assert obj.deviations["device_temperature"]["sample_count"] == 0
    assert obj.deviations["status_condition"]["is_new"] is True


def test_pre_update_ordering_and_maturity_progression(modeler):
    """Verify strict execution order: pre-update baseline is read BEFORE mutation.

    Observation 1: Sees N=0 (COLD_START) -> updates baseline (N becomes 1)
    Observation 2: Sees N=1 (MATURING, z_score_valid=False) -> updates baseline (N becomes 2)
    Observation 3: Sees N=2 (MATURE, z_score_valid=True) -> updates baseline (N becomes 3)
    """
    temps = [10.0, 12.0, 11.0]

    # Observation 1
    ctx1 = StructuredContext(
        timestamp=100.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": temps[0]},
        security_context={"security_alert_label": 0}
    )
    obj1 = modeler.process(ctx1)
    assert obj1.baseline_maturity == "COLD_START"
    assert obj1.numeric_baseline == {}

    # Observation 2
    ctx2 = StructuredContext(
        timestamp=101.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": temps[1]},
        security_context={"security_alert_label": 0}
    )
    obj2 = modeler.process(ctx2)
    assert obj2.baseline_maturity == "MATURING"
    assert obj2.numeric_baseline["device_temperature"]["count"] == 1
    assert obj2.deviations["device_temperature"]["z_score_valid"] is False
    assert obj2.deviations["device_temperature"]["z_score"] is None

    # Observation 3
    ctx3 = StructuredContext(
        timestamp=102.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": temps[2]},
        security_context={"security_alert_label": 0}
    )
    obj3 = modeler.process(ctx3)
    assert obj3.baseline_maturity == "MATURE"
    assert obj3.numeric_baseline["device_temperature"]["count"] == 2
    assert obj3.deviations["device_temperature"]["z_score_valid"] is True
    assert obj3.deviations["device_temperature"]["z_score"] is not None
    assert obj3.deviations["device_temperature"]["sample_count"] == 2


def test_snapshot_cost_and_inner_dict_isolation(modeler):
    """Verify inner dict isolation and count stability under subsequent updates."""
    ctx1 = StructuredContext(
        timestamp=100.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge",
        device_context={"device_temperature": 10.0}, security_context={"security_alert_label": 0}
    )
    ctx2 = StructuredContext(
        timestamp=101.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge",
        device_context={"device_temperature": 12.0}, security_context={"security_alert_label": 0}
    )
    ctx3 = StructuredContext(
        timestamp=102.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge",
        device_context={"device_temperature": 11.0}, security_context={"security_alert_label": 0}
    )

    modeler.process(ctx1)
    modeler.process(ctx2)
    obj3 = modeler.process(ctx3)

    profile = modeler.generator.get_profile("fridge")
    # Inner-dict identity check
    assert obj3.numeric_baseline["device_temperature"] is not profile.numeric_stats["device_temperature"]
    assert obj3.numeric_baseline["device_temperature"]["count"] == 2

    # Later record update
    ctx4 = StructuredContext(
        timestamp=103.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge",
        device_context={"device_temperature": 15.0}, security_context={"security_alert_label": 0}
    )
    modeler.process(ctx4)

    # obj3 count remains unchanged
    assert obj3.numeric_baseline["device_temperature"]["count"] == 2
    assert profile.numeric_stats["device_temperature"]["count"] == 4


def test_idempotency_pure_model_context(modeler):
    """Verify model_context is pure and calling it twice does not double-count baseline."""
    ctx = StructuredContext(
        timestamp=100.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge_pure",
        device_context={"device_temperature": 10.0}, security_context={"security_alert_label": 0}
    )

    obj1 = modeler.model_context(ctx)
    obj2 = modeler.model_context(ctx)

    profile = modeler.generator.get_profile("fridge_pure")
    assert profile is None

    modeler.commit(ctx)
    profile_after = modeler.generator.get_profile("fridge_pure")
    assert profile_after.numeric_stats["device_temperature"]["count"] == 1


def test_categorical_maturity_garage(modeler):
    """Verify categorical-only sources (like Garage) reach MATURE by record 3."""
    for i in range(3):
        ctx = StructuredContext(
            timestamp=100.0 + i, source="garage", entity_type="DEVICE", entity_id="garage",
            device_context={"actuator_state": "open", "signal_active": True},
            security_context={"security_alert_label": 0}
        )
        obj = modeler.process(ctx)
        if i == 0:
            assert obj.baseline_maturity == "COLD_START"
        elif i == 1:
            assert obj.baseline_maturity == "MATURING"
        elif i == 2:
            assert obj.baseline_maturity == "MATURE"


def test_zero_variance_detection(repo):
    """Verify ZERO_VARIANCE status and deviates_from_constant flag."""
    modeler = OperationalContextModeler(repository=repo)
    for i in range(10):
        ctx = StructuredContext(
            timestamp=100.0 + i, source="iot_fridge", entity_type="DEVICE", entity_id="fridge_const",
            device_context={"device_temperature": 10.0}, security_context={"security_alert_label": 0}
        )
        modeler.process(ctx)

    # Same value (10.0)
    ctx_same = StructuredContext(
        timestamp=111.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge_const",
        device_context={"device_temperature": 10.0}, security_context={"security_alert_label": 0}
    )
    obj_same = modeler.process(ctx_same)
    dev_same = obj_same.deviations["device_temperature"]
    assert dev_same["status"] == "ZERO_VARIANCE"
    assert dev_same["z_score_valid"] is False
    assert dev_same["z_score"] is None
    assert dev_same["deviates_from_constant"] is False

    # Changed value (15.0)
    ctx_diff = StructuredContext(
        timestamp=112.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge_const",
        device_context={"device_temperature": 15.0}, security_context={"security_alert_label": 0}
    )
    obj_diff = modeler.process(ctx_diff)
    dev_diff = obj_diff.deviations["device_temperature"]
    assert dev_diff["status"] == "ZERO_VARIANCE"
    assert dev_diff["z_score_valid"] is False
    assert dev_diff["z_score"] is None
    assert dev_diff["deviates_from_constant"] is True


def test_invalid_value_handling(modeler):
    """Verify non-numeric values populate INVALID_VALUE status instead of silently dropping."""
    ctx = StructuredContext(
        timestamp=100.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge",
        device_context={"device_temperature": "NOT_A_FLOAT"}, security_context={"security_alert_label": 0}
    )
    obj = modeler.process(ctx)
    dev = obj.deviations["device_temperature"]
    assert dev["status"] == "INVALID_VALUE"
    assert dev["z_score_valid"] is False
    assert dev["z_score"] is None


def test_unbaselined_temporal_attribute_tracking(modeler):
    """Verify session_duration and process_elapsed_time are tracked in unbaselined_attributes."""
    ctx_net = StructuredContext(
        timestamp=1554198358.0,
        source="network",
        entity_type="NETWORK_FLOW",
        entity_id="192.168.1.5:1234->10.0.0.1:80[tcp]",
        temporal_context={"timestamp": 1554198358.0, "session_duration": 80549.5},
        asset_context={"source_ip": "192.168.1.5", "dest_ip": "10.0.0.1"},
        network_context={"network_protocol": "tcp", "bytes_sent": 1000},
        security_context={"security_alert_label": 0}
    )

    obj = modeler.process(ctx_net)

    assert "session_duration" in obj.unbaselined_attributes
    assert obj.deviations["session_duration"]["status"] == "UNBASELINED"
    assert obj.deviations["session_duration"]["z_score_valid"] is False
    assert obj.deviations["session_duration"]["z_score"] is None


def test_multi_source_operational_context_modeling(modeler):
    """Verify context fusion for Linux and Windows telemetry sources."""
    # Linux process
    ctx_linux = StructuredContext(
        timestamp=100.0,
        source="linux_process",
        entity_type="HOST_PROCESS",
        entity_id="3257:Web-Content",
        asset_context={"process_id": 3257, "process_name": "Web-Content"},
        operational_context={"cpu_usage_pct": 0.13, "thread_state": "S"},
        security_context={"security_alert_label": 0}
    )
    obj_linux = modeler.process(ctx_linux)
    assert obj_linux.profile_key == "Web-Content"
    assert obj_linux.entity_type == "HOST_PROCESS"
    assert obj_linux.current_operational["cpu_usage_pct"] == 0.13

    # Windows process
    ctx_win = StructuredContext(
        timestamp=100.0,
        source="windows",
        entity_type="HOST_PROCESS",
        entity_id="PID_1024",
        asset_context={"process_id": 1024},
        operational_context={"cpu_usage_pct": 66.20, "process_memory_bytes": 1185267712},
        security_context={"security_alert_label": 0}
    )
    obj_win = modeler.process(ctx_win)
    assert obj_win.profile_key == "PID_1024"
    assert obj_win.current_operational["process_memory_bytes"] == 1185267712

