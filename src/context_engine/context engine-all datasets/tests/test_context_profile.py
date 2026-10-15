"""Unit tests for CORTEX Stage 2 (Dynamic Context Profile Generation)."""

import math
import numpy as np
import pytest
from context_engine.context_attribute_repository import ContextAttributeRepository
from context_engine.context_extraction import StructuredContext
from context_engine.context_profile import (
    DynamicContextProfile,
    DynamicContextProfileGenerator,
    InMemoryProfileStorage,
    derive_profile_key,
    DeviationReport
)


@pytest.fixture
def repo() -> ContextAttributeRepository:
    """Pre-populated ContextAttributeRepository."""
    return ContextAttributeRepository()


@pytest.fixture
def generator(repo) -> DynamicContextProfileGenerator:
    """DynamicContextProfileGenerator with default in-memory storage."""
    return DynamicContextProfileGenerator(repository=repo, buffer_maxlen=3)


def test_derive_profile_key_network():
    """Verify network profile key uses source_ip from asset_context."""
    ctx = StructuredContext(
        timestamp=1000.0,
        source="network",
        entity_type="NETWORK_FLOW",
        entity_id="192.168.1.5:1234->10.0.0.1:80[tcp]",
        asset_context={"source_ip": "192.168.1.5", "dest_ip": "10.0.0.1"}
    )
    assert derive_profile_key(ctx) == "192.168.1.5"


def test_derive_profile_key_iot():
    """Verify IoT profile key uses entity_id (static device type)."""
    ctx = StructuredContext(
        timestamp=1000.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": 12.5}
    )
    assert derive_profile_key(ctx) == "fridge"


def test_derive_profile_key_linux():
    """Verify Linux profile key uses process_name (from CMD column)."""
    ctx = StructuredContext(
        timestamp=1000.0,
        source="linux_process",
        entity_type="HOST_PROCESS",
        entity_id="1234:Web-Content",
        asset_context={"process_name": "Web-Content", "process_id": 1234}
    )
    assert derive_profile_key(ctx) == "Web-Content"


def test_derive_profile_key_windows():
    """Verify Windows profile key uses entity_id."""
    ctx = StructuredContext(
        timestamp=1000.0,
        source="windows",
        entity_type="DEVICE",
        entity_id="windows_host"
    )
    assert derive_profile_key(ctx) == "windows_host"


def test_derive_profile_key_fallback(caplog):
    """Verify fallback to entity_id when required key is missing."""
    ctx = StructuredContext(
        timestamp=1000.0,
        source="network",
        entity_type="NETWORK_FLOW",
        entity_id="fallback_flow",
        asset_context={}  # Missing source_ip
    )
    assert derive_profile_key(ctx) == "fallback_flow"
    assert "Missing 'source_ip' in network record" in caplog.text


def test_welford_accuracy(generator):
    """Verify Welford's online variance algorithm accuracy vs NumPy."""
    values = [10.5, 12.2, 8.4, 15.1, 9.9, 11.0]
    
    # Calculate ground truth with NumPy
    np_mean = np.mean(values)
    np_std = np.std(values, ddof=1)  # Sample standard deviation (ddof=1)
    np_min = min(values)
    np_max = max(values)

    # Process sequentially with generator
    for v in values:
        ctx = StructuredContext(
            timestamp=100.0,
            source="iot_fridge",
            entity_type="DEVICE",
            entity_id="fridge",
            device_context={"device_temperature": v},
            security_context={"security_alert_label": 0}
        )
        generator.update(ctx)

    profile = generator.get_profile("fridge")
    assert profile is not None
    
    stats = profile.numeric_stats["device_temperature"]
    assert stats["count"] == len(values)
    assert math.isclose(stats["mean"], np_mean, rel_tol=1e-9)
    assert math.isclose(stats["std"], np_std, rel_tol=1e-9)
    assert stats["min"] == np_min
    assert stats["max"] == np_max


def test_welford_out_of_order(generator):
    """Verify that out-of-order updates yield the identical mean and standard deviation."""
    values1 = [1.0, 5.0, 10.0, 20.0]
    values2 = [20.0, 1.0, 10.0, 5.0]  # Scrambled order

    # Run Generator 1
    storage1 = InMemoryProfileStorage()
    gen1 = DynamicContextProfileGenerator(repository=generator.repository, storage=storage1)
    for v in values1:
        ctx = StructuredContext(
            timestamp=100.0,
            source="iot_fridge",
            entity_type="DEVICE",
            entity_id="fridge",
            device_context={"device_temperature": v},
            security_context={"security_alert_label": 0}
        )
        gen1.update(ctx)

    # Run Generator 2
    storage2 = InMemoryProfileStorage()
    gen2 = DynamicContextProfileGenerator(repository=generator.repository, storage=storage2)
    for v in values2:
        ctx = StructuredContext(
            timestamp=100.0,
            source="iot_fridge",
            entity_type="DEVICE",
            entity_id="fridge",
            device_context={"device_temperature": v},
            security_context={"security_alert_label": 0}
        )
        gen2.update(ctx)

    prof1 = gen1.get_profile("fridge")
    prof2 = gen2.get_profile("fridge")

    stats1 = prof1.numeric_stats["device_temperature"]
    stats2 = prof2.numeric_stats["device_temperature"]

    assert stats1["count"] == stats2["count"]
    assert math.isclose(stats1["mean"], stats2["mean"], rel_tol=1e-9)
    assert math.isclose(stats1["std"], stats2["std"], rel_tol=1e-9)
    assert stats1["min"] == stats2["min"]
    assert stats1["max"] == stats2["max"]


def test_empty_dimensions(generator):
    """Verify that records with empty dimensions do not reset or corrupt existing stats."""
    # Step 1: Update with full data
    ctx1 = StructuredContext(
        timestamp=100.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": 10.0, "status_condition": "normal"},
        security_context={"security_alert_label": 0}
    )
    generator.update(ctx1)

    profile = generator.get_profile("fridge")
    assert "device_temperature" in profile.numeric_stats
    assert "status_condition" in profile.categorical_stats

    # Step 2: Update with empty device_context
    ctx2 = StructuredContext(
        timestamp=101.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={},  # Empty dimension
        security_context={"security_alert_label": 0}
    )
    generator.update(ctx2)

    # Ensure count remains 1 and is not deleted or set to zero
    assert profile.numeric_stats["device_temperature"]["count"] == 1
    assert profile.categorical_stats["status_condition"]["frequencies"]["normal"] == 1


def test_security_alert_scoring(generator):
    """Verify that attack records score deviations but do not mutate the baseline profile."""
    # Step 1: Establish baseline with normal records (alert == 0)
    for v in [10.0, 12.0, 11.0]:
        ctx = StructuredContext(
            timestamp=100.0,
            source="iot_fridge",
            entity_type="DEVICE",
            entity_id="fridge",
            device_context={"device_temperature": v},
            security_context={"security_alert_label": 0}
        )
        generator.update(ctx)

    profile = generator.get_profile("fridge")
    initial_count = profile.numeric_stats["device_temperature"]["count"]
    initial_mean = profile.numeric_stats["device_temperature"]["mean"]

    # Step 2: Update with attack record (alert == 1)
    attack_ctx = StructuredContext(
        timestamp=101.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": 50.0},  # Extreme anomaly
        security_context={"security_alert_label": 1}
    )
    report = generator.update(attack_ctx)

    assert isinstance(report, DeviationReport)
    assert "device_temperature" in report.deviations
    
    dev_details = report.deviations["device_temperature"]
    assert dev_details["value"] == 50.0
    assert dev_details["mean"] == initial_mean
    assert dev_details["z_score"] > 0.0

    # Ensure profile remains unmutated
    assert profile.numeric_stats["device_temperature"]["count"] == initial_count
    assert profile.numeric_stats["device_temperature"]["mean"] == initial_mean


def test_sliding_reorder_buffer(repo):
    """Verify state transition buffer reorders out-of-order timestamps before updating transition matrix."""
    # Bounded sorted buffer of size 3
    storage = InMemoryProfileStorage()
    gen = DynamicContextProfileGenerator(repository=repo, storage=storage, buffer_maxlen=3)

    # Sequence of updates out of order
    # Chronological: 1.0: A -> 2.0: B -> 3.0: A -> 4.0: B -> 5.0: C
    updates = [
        (3.0, "A"),
        (1.0, "A"),
        (2.0, "B"),
        (5.0, "C"),
        (4.0, "B"),
    ]

    for ts, val in updates:
        ctx = StructuredContext(
            timestamp=ts,
            source="iot_fridge",
            entity_type="DEVICE",
            entity_id="fridge",
            device_context={"status_condition": val},
            security_context={"security_alert_label": 0}
        )
        gen.update(ctx)

    profile = gen.get_profile("fridge")
    transitions = profile.categorical_stats["status_condition"]["transition_matrix"]

    # The buffer window size is 3. Let's trace how elements are flushed:
    # 1. (3.0, A): Buffer: [(3.0, A)]
    # 2. (1.0, A): Buffer: [(1.0, A), (3.0, A)]
    # 3. (2.0, B): Buffer: [(1.0, A), (2.0, B), (3.0, A)]
    # 4. (5.0, C): Buffer: [(1.0, A), (2.0, B), (3.0, A), (5.0, C)] -> exceeds 3
    #    - pop index 0: (1.0, A)
    #    - new index 0: (2.0, B)
    #    - record transition: A -> B
    #    - Buffer becomes: [(2.0, B), (3.0, A), (5.0, C)]
    # 5. (4.0, B): Buffer: [(2.0, B), (3.0, A), (4.0, B), (5.0, C)] -> exceeds 3
    #    - pop index 0: (2.0, B)
    #    - new index 0: (3.0, A)
    #    - record transition: B -> A
    #    - Buffer becomes: [(3.0, A), (4.0, B), (5.0, C)]

    # We expect transitions recorded: A -> B (1 time) and B -> A (1 time)
    assert transitions["A"]["B"] == 1
    assert transitions["B"]["A"] == 1


def test_derive_profile_entity_type():
    """Verify that profiles get mapped to correct aggregated entity classifications."""
    # 1. Network -> NETWORK_HOST
    ctx_net = StructuredContext(
        timestamp=1000.0, source="network", entity_type="NETWORK_FLOW", entity_id="flow_id"
    )
    from context_engine.context_profile import derive_profile_entity_type
    assert derive_profile_entity_type(ctx_net) == "NETWORK_HOST"

    # 2. Linux -> HOST_PROCESS
    ctx_linux = StructuredContext(
        timestamp=1000.0, source="linux_process", entity_type="HOST_PROCESS", entity_id="proc_id"
    )
    assert derive_profile_entity_type(ctx_linux) == "HOST_PROCESS"

    # 3. IoT -> keeps DEVICE
    ctx_iot = StructuredContext(
        timestamp=1000.0, source="iot_fridge", entity_type="DEVICE", entity_id="fridge"
    )
    assert derive_profile_entity_type(ctx_iot) == "DEVICE"


def test_entity_type_mismatch_warning(generator, caplog):
    """Verify generator logs a warning if a key is updated with a conflicting entity type."""
    ctx1 = StructuredContext(
        timestamp=100.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": 10.0},
        security_context={"security_alert_label": 0}
    )
    generator.update(ctx1)

    # conflicting update with same key 'fridge' but different source/entity_type
    ctx2 = StructuredContext(
        timestamp=101.0,
        source="windows",  # resolves key to entity_id 'fridge' if we mock entity_id
        entity_type="HOST_PROCESS",
        entity_id="fridge",
        security_context={"security_alert_label": 0}
    )
    generator.update(ctx2)

    assert "entity type mismatch" in caplog.text


def test_flush_all_buffers(repo):
    """Verify flush_all_buffers commits all remaining sorted transition elements from buffers."""
    storage = InMemoryProfileStorage()
    gen = DynamicContextProfileGenerator(repository=repo, storage=storage, buffer_maxlen=10)

    # 1.0: A -> 2.0: B -> 3.0: C (buffer is size 10, so none are size-flushed during updates)
    for ts, val in [(1.0, "A"), (2.0, "B"), (3.0, "C")]:
        ctx = StructuredContext(
            timestamp=ts,
            source="iot_fridge",
            entity_type="DEVICE",
            entity_id="fridge",
            device_context={"status_condition": val},
            security_context={"security_alert_label": 0}
        )
        gen.update(ctx)

    profile = gen.get_profile("fridge")
    transitions = profile.categorical_stats["status_condition"]["transition_matrix"]
    assert len(transitions) == 0  # No transitions recorded yet since buffer size (3) <= maxlen (10)

    # Call flush
    gen.flush_all_buffers()

    # Verify transitions are now recorded sequentially
    assert transitions["A"]["B"] == 1
    assert transitions["B"]["C"] == 1
    assert len(profile.reorder_buffers["status_condition"]) == 0  # Buffer fully emptied

