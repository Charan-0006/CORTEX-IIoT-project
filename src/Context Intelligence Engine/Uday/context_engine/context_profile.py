"""Stage 2: Dynamic Context Profile Generation for CORTEX.

Generates online behavioral profiles for telemetry entities using Welford's
algorithm for numeric stats, sliding-window sorted buffers for out-of-order state
transitions, and security-label-aware baseline updates.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
import math
from typing import Any, Dict, List, Optional
from context_engine.context_extraction import StructuredContext
from context_engine.context_attribute_repository import ContextAttributeRepository

logger = logging.getLogger("CORTEX.ContextProfile")


@dataclass
class DynamicContextProfile:
    """Standardized context profile representing the behavior of a telemetry entity."""

    profile_key: str
    entity_type: str
    numeric_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    categorical_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    communication_stats: Dict[str, Any] = field(default_factory=dict)
    operational_stats: Dict[str, Any] = field(default_factory=dict)
    last_updated: float = 0.0
    reorder_buffers: Dict[str, List[tuple[float, Any]]] = field(default_factory=dict)


@dataclass(frozen=True)
class DeviationReport:
    """Report generated when scoring an anomalous or attack record against baseline profiles."""

    profile_key: str
    timestamp: float
    source: str
    deviations: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class ProfileStorageInterface(ABC):
    """Abstract interface for DynamicContextProfile persistent storage."""

    @abstractmethod
    def save_profile(self, profile: DynamicContextProfile) -> None:
        """Saves or updates a context profile."""
        pass

    @abstractmethod
    def get_profile(self, profile_key: str) -> Optional[DynamicContextProfile]:
        """Retrieves a context profile by its unique key."""
        pass

    @abstractmethod
    def get_all_profiles(self) -> Dict[str, DynamicContextProfile]:
        """Retrieves all stored context profiles."""
        pass


class InMemoryProfileStorage(ProfileStorageInterface):
    """In-memory dictionary implementation of profile storage."""

    def __init__(self) -> None:
        """Initializes an empty in-memory profile storage store."""
        self._store: Dict[str, DynamicContextProfile] = {}

    def save_profile(self, profile: DynamicContextProfile) -> None:
        """Saves or updates a context profile in the in-memory store.

        Args:
            profile: DynamicContextProfile instance to persist.
        """
        self._store[profile.profile_key] = profile

    def get_profile(self, profile_key: str) -> Optional[DynamicContextProfile]:
        """Retrieves a context profile by key from the in-memory store.

        Args:
            profile_key: Target profile string identifier.

        Returns:
            Matching DynamicContextProfile if present, else None.
        """
        return self._store.get(profile_key)

    def get_all_profiles(self) -> Dict[str, DynamicContextProfile]:
        """Retrieves a shallow copy of all stored profiles.

        Returns:
            Dictionary mapping profile keys to DynamicContextProfile instances.
        """
        return self._store.copy()


def derive_profile_key(context: StructuredContext) -> str:
    """Derives the standardized profile key for an incoming telemetry record.

    Entity keys are routed per source type:
    - Network: source_ip
    - IoT sub-sources: entity_id (static device type)
    - Linux host logs: process_name (from CMD column)
    - Windows host logs: entity_id (PID-based or windows_host)

    Defensively falls back to entity_id if required fields are missing.
    """
    source = context.source.lower().strip()

    # 1. Network: key on source IP address
    if source == "network":
        ip = context.asset_context.get("source_ip")
        if ip:
            return str(ip).strip()
        logger.warning(
            "Missing 'source_ip' in network record asset context. Falling back to entity_id: %s",
            context.entity_id,
        )
        return context.entity_id

    # 2. IoT: key on static device type string (e.g. 'fridge')
    if source.startswith("iot_") or source in (
        "fridge",
        "garage",
        "gps",
        "modbus",
        "motion_light",
        "thermostat",
        "weather",
    ):
        return context.entity_id

    # 3. Linux: key on process command name (not PID, which recycles)
    if source in ("linux_process", "linux_disk", "linux_memory"):
        name = context.asset_context.get("process_name")
        if name:
            return str(name).strip()
        logger.warning(
            "Missing 'process_name' in Linux record asset context. Falling back to entity_id: %s",
            context.entity_id,
        )
        return context.entity_id

    # 4. Windows: key on entity_id (already resolved in Stage 1)
    if source == "windows":
        return context.entity_id

    # Fallback for unexpected source names
    logger.warning(
        "Unknown telemetry source '%s'. Falling back to entity_id: %s",
        context.source,
        context.entity_id,
    )
    return context.entity_id


def derive_profile_entity_type(context: StructuredContext) -> str:
    """Derives the profile-level entity classification post-key-derivation.

    Mappings:
    - Network (keyed by source_ip) -> "NETWORK_HOST"
    - IoT sub-sources (keyed by entity_id) -> "DEVICE"
    - Linux (keyed by process_name) -> "HOST_PROCESS"
    - Windows (keyed by entity_id) -> keeps original entity_type
    """
    source = context.source.lower().strip()
    if source == "network":
        return "NETWORK_HOST"
    if source in ("linux_process", "linux_disk", "linux_memory"):
        return "HOST_PROCESS"
    return context.entity_type


class DynamicContextProfileGenerator:
    """Orchestrates dynamic profile baseline updates and read-only anomaly scoring."""

    def __init__(
        self,
        repository: Optional[ContextAttributeRepository] = None,
        storage: Optional[ProfileStorageInterface] = None,
        buffer_maxlen: int = 50,
    ) -> None:
        """Initializes the generator.

        Args:
            repository: ContextAttributeRepository instance.
            storage: ProfileStorageInterface storage handler.
            buffer_maxlen: Bounded capacity of the sliding state-transition buffer.
        """
        self.repository = repository or ContextAttributeRepository()
        self.storage = storage or InMemoryProfileStorage()
        self.buffer_maxlen = buffer_maxlen

    def get_profile(self, profile_key: str) -> Optional[DynamicContextProfile]:
        """Retrieves a profile by key from storage."""
        return self.storage.get_profile(profile_key)

    def get_all_profiles(self) -> Dict[str, DynamicContextProfile]:
        """Retrieves all profiles from storage."""
        return self.storage.get_all_profiles()

    def update(self, context: StructuredContext) -> Optional[DeviationReport]:
        """Processes an incoming StructuredContext record.

        - If security_alert_label == 0 (normal): Updates baseline stats (mutative).
        - If security_alert_label == 1 (attack): Scores record against baseline (read-only).
        """
        key = derive_profile_key(context)
        profile = self.storage.get_profile(key)
        profile_entity_type = derive_profile_entity_type(context)

        if not profile:
            profile = DynamicContextProfile(profile_key=key, entity_type=profile_entity_type)
            self.storage.save_profile(profile)
        else:
            if profile.entity_type != profile_entity_type:
                logger.warning(
                    "Profile key '%s' entity type mismatch: existing is '%s', incoming is '%s'",
                    key,
                    profile.entity_type,
                    profile_entity_type,
                )

        alert_label = context.security_context.get("security_alert_label", 0)

        if alert_label == 0:
            self._update_baseline(context, profile)
            return None
        else:
            deviation_report = self._score_against_baseline(context, profile)
            logger.info(
                "Scored attack record for key '%s' (Deviations in %d attributes)",
                key,
                len(deviation_report.deviations),
            )
            return deviation_report

    def flush_all_buffers(self) -> None:
        """Flushes all remaining elements in the sliding transition buffers.

        Commits all remaining transitions sequentially in chronological order,
        ensuring that no state transitions are lost when the telemetry stream ends.
        """
        for profile in self.storage.get_all_profiles().values():
            for attr_name, buffer in profile.reorder_buffers.items():
                stats = profile.categorical_stats.setdefault(
                    attr_name, {"frequencies": {}, "transition_matrix": {}}
                )
                while len(buffer) > 1:
                    old_ts, old_val = buffer.pop(0)
                    new_ts, new_val = buffer[0]
                    transitions = stats["transition_matrix"].setdefault(old_val, {})
                    transitions[new_val] = transitions.get(new_val, 0) + 1
                if buffer:
                    buffer.pop(0)
            self.storage.save_profile(profile)

    def _update_baseline(self, context: StructuredContext, profile: DynamicContextProfile) -> None:
        """Mutates context baseline stats using normal (security_alert_label == 0) records."""
        profile.last_updated = max(profile.last_updated, context.timestamp)

        # Loop through non-temporal dimensions
        dimensions = {
            "asset_context": context.asset_context,
            "network_context": context.network_context,
            "device_context": context.device_context,
            "operational_context": context.operational_context,
            "security_context": context.security_context,
        }

        for dim_name, dim_dict in dimensions.items():
            if not dim_dict:
                continue

            for attr_name, val in dim_dict.items():
                if val is None:
                    continue

                if attr_name in ("security_alert_label", "attack_class", "timestamp"):
                    continue

                attr_meta = self.repository.get_attribute(attr_name)
                if not attr_meta:
                    continue

                # Process based on metadata data_type
                if attr_meta.data_type in ("int", "float"):
                    try:
                        num_val = float(val)
                        self._update_numeric_attribute(profile, attr_name, num_val)
                    except (ValueError, TypeError):
                        pass
                elif attr_meta.data_type in ("str", "string", "bool"):
                    str_val = str(val)
                    self._update_categorical_attribute(
                        profile, attr_name, str_val, context.timestamp
                    )

        # Update specialized summary stats
        self._update_communication_stats(context, profile)
        self._update_operational_stats(context, profile)

        # Save mutated profile
        self.storage.save_profile(profile)

    def _update_numeric_attribute(
        self, profile: DynamicContextProfile, attr_name: str, val: float
    ) -> None:
        """Updates numeric baseline metrics using Welford's online variance algorithm."""
        stats = profile.numeric_stats.setdefault(
            attr_name,
            {
                "count": 0,
                "mean": 0.0,
                "M2": 0.0,
                "variance": 0.0,
                "std": 0.0,
                "min": float("inf"),
                "max": float("-inf"),
            },
        )

        stats["count"] += 1
        k = stats["count"]

        if k == 1:
            stats["mean"] = val
            stats["M2"] = 0.0
            stats["variance"] = 0.0
            stats["std"] = 0.0
            stats["min"] = val
            stats["max"] = val
        else:
            delta = val - stats["mean"]
            stats["mean"] += delta / k
            delta2 = val - stats["mean"]
            stats["M2"] += delta * delta2
            stats["variance"] = stats["M2"] / (k - 1)
            stats["std"] = math.sqrt(stats["variance"])
            stats["min"] = min(stats["min"], val)
            stats["max"] = max(stats["max"], val)

    def _update_categorical_attribute(
        self, profile: DynamicContextProfile, attr_name: str, val: str, timestamp: float
    ) -> None:
        """Updates frequencies and sorted sliding transition buffer for state transition matrix."""
        stats = profile.categorical_stats.setdefault(
            attr_name, {"frequencies": {}, "transition_matrix": {}}
        )

        # 1. Frequency Counter
        stats["frequencies"][val] = stats["frequencies"].get(val, 0) + 1

        # 2. Sliding State-Transition Buffer
        buffer = profile.reorder_buffers.setdefault(attr_name, [])
        buffer.append((timestamp, val))
        buffer.sort(key=lambda item: item[0])

        # Flush oldest record if window size is exceeded
        if len(buffer) > self.buffer_maxlen:
            old_ts, old_val = buffer.pop(0)
            new_ts, new_val = buffer[0]

            # Record transition from popped state to next oldest state in the buffer window
            transitions = stats["transition_matrix"].setdefault(old_val, {})
            transitions[new_val] = transitions.get(new_val, 0) + 1

    def _update_communication_stats(
        self, context: StructuredContext, profile: DynamicContextProfile
    ) -> None:
        """Aggregates communication metadata for network-layer records."""
        if not context.network_context:
            return

        comm = profile.communication_stats
        comm["total_records"] = comm.get("total_records", 0) + 1

        # Sum up volumes
        for key in ("bytes_sent", "bytes_received", "packets_sent", "packets_received"):
            val = context.network_context.get(key)
            if val is not None:
                try:
                    comm[f"total_{key}"] = comm.get(f"total_{key}", 0) + int(val)
                except (ValueError, TypeError):
                    pass

        # Increment connection state counter
        state = context.network_context.get("connection_state")
        if state is not None:
            state_str = str(state).strip()
            states_dict = comm.setdefault("connection_states", {})
            states_dict[state_str] = states_dict.get(state_str, 0) + 1

    def _update_operational_stats(
        self, context: StructuredContext, profile: DynamicContextProfile
    ) -> None:
        """Aggregates resource execution profiles for host-layer records."""
        if not context.operational_context:
            return

        op = profile.operational_stats
        op["total_records"] = op.get("total_records", 0) + 1

        # Increment OS execution state counts
        thread_state = context.operational_context.get("thread_state")
        if thread_state is not None:
            t_str = str(thread_state).strip()
            t_dict = op.setdefault("thread_states", {})
            t_dict[t_str] = t_dict.get(t_str, 0) + 1

    def _score_against_baseline(
        self, context: StructuredContext, profile: DynamicContextProfile
    ) -> DeviationReport:
        """Calculates standard deviations (z-scores) or probabilities against the baseline profile.

        Strictly read-only; does not mutate any baseline profile records.
        """
        deviations = {}

        dimensions = {
            "asset_context": context.asset_context,
            "network_context": context.network_context,
            "device_context": context.device_context,
            "operational_context": context.operational_context,
            "security_context": context.security_context,
        }

        for dim_name, dim_dict in dimensions.items():
            if not dim_dict:
                continue

            for attr_name, val in dim_dict.items():
                if val is None:
                    continue

                if attr_name in ("security_alert_label", "attack_class", "timestamp"):
                    continue

                attr_meta = self.repository.get_attribute(attr_name)
                if not attr_meta:
                    continue

                # 1. Numeric deviation
                if attr_meta.data_type in ("int", "float"):
                    try:
                        num_val = float(val)
                        if attr_name in profile.numeric_stats:
                            stats = profile.numeric_stats[attr_name]
                            mean = stats["mean"]
                            std = stats["std"]
                            z_score = (num_val - mean) / std if std > 0.0 else 0.0
                            deviations[attr_name] = {
                                "value": num_val,
                                "mean": mean,
                                "std": std,
                                "z_score": z_score,
                            }
                    except (ValueError, TypeError):
                        pass

                # 2. Categorical probability
                elif attr_meta.data_type in ("str", "string", "bool"):
                    str_val = str(val)
                    if attr_name in profile.categorical_stats:
                        stats = profile.categorical_stats[attr_name]
                        frequencies = stats.get("frequencies", {})
                        total = sum(frequencies.values())
                        val_count = frequencies.get(str_val, 0)
                        probability = val_count / total if total > 0.0 else 0.0
                        deviations[attr_name] = {
                            "value": str_val,
                            "probability": probability,
                            "is_new": val_count == 0,
                        }

        return DeviationReport(
            profile_key=profile.profile_key,
            timestamp=context.timestamp,
            source=context.source,
            deviations=deviations,
        )
