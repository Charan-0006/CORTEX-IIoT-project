"""Stage 3: Operational Context Modeling for CORTEX.

Synthesizes real-time telemetry from Stage 1 (StructuredContext) and dynamic behavioral
profiles from Stage 2 (DynamicContextProfile) into unified OperationalContextObject
representations, enriched with baseline maturity indicators and explicit temporal attribute tracking.

Prepares fused context objects for downstream Stage 4 (DCCR - Dynamic Contextual Risk Assessment)
and Stage 5 (CCFS - Context-Aware Countermeasure System).
"""

from dataclasses import dataclass, field
import logging
from typing import Any, Dict, List, Optional
from context_engine.context_attribute_repository import ContextAttributeRepository
from context_engine.context_extraction import StructuredContext
from context_engine.context_profile import (
    DynamicContextProfile,
    DynamicContextProfileGenerator,
    derive_profile_key,
    derive_profile_entity_type
)

logger = logging.getLogger("CORTEX.OperationalContext")


@dataclass(frozen=True)
class OperationalContextObject:
    """Stage 3 Fused Operational Context Object.

    Synthesizes real-time telemetry observations, historical behavioral baselines,
    cumulative traffic/system summaries, and baseline maturity metadata into a single
    structured object for downstream Stage 4 (DCCR) and Stage 5 (CCFS).

    Selective, non-aliased baselines are snapshotted strictly for attributes present in the
    incoming telemetry record to optimize memory and processing efficiency.
    """

    # 1. Entity & Telemetry Identifiers
    profile_key: str
    entity_type: str
    source: str
    timestamp: float

    # 2. Current Real-Time Observations (Stage 1 StructuredContext dimensions)
    current_asset: Dict[str, Any] = field(default_factory=dict)
    current_network: Dict[str, Any] = field(default_factory=dict)
    current_device: Dict[str, Any] = field(default_factory=dict)
    current_operational: Dict[str, Any] = field(default_factory=dict)
    current_security: Dict[str, Any] = field(default_factory=dict)
    current_temporal: Dict[str, Any] = field(default_factory=dict)

    # 3. Selective Historical Behavioral Baselines (Snapshotted pre-update statistics)
    numeric_baseline: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    categorical_baseline: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # 4. Cumulative Aggregated Summaries (Referenced directly from Stage 2)
    communication_summary: Dict[str, Any] = field(default_factory=dict)
    operational_summary: Dict[str, Any] = field(default_factory=dict)

    # 5. Computed Anomaly & Deviation Metrics
    deviations: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # 6. Stage 3 Baseline Maturity & Quality Flags
    baseline_maturity: str = "COLD_START"  # 'COLD_START', 'MATURING', or 'MATURE'
    unbaselined_attributes: List[str] = field(default_factory=list)


class OperationalContextEvaluator:
    """Evaluates attribute deviations and baseline validity between a StructuredContext

    record and an entity's DynamicContextProfile.
    """

    def __init__(self, repository: Optional[ContextAttributeRepository] = None) -> None:
        """Initializes the evaluator.

        Args:
            repository: ContextAttributeRepository instance.
        """
        self.repository = repository or ContextAttributeRepository()

    def evaluate_deviations(
        self, context: StructuredContext, profile: Optional[DynamicContextProfile]
    ) -> tuple[Dict[str, Dict[str, Any]], str, List[str]]:
        """Evaluates deviations, baseline maturity, and un-baselined attributes.

        Args:
            context: Incoming Stage 1 StructuredContext record.
            profile: Current Stage 2 DynamicContextProfile PRE-UPDATE baseline snapshot.

        Returns:
            A tuple of (deviations_dict, baseline_maturity_str, unbaselined_attributes_list).
        """
        deviations: Dict[str, Dict[str, Any]] = {}
        unbaselined_attributes: List[str] = []

        # 1. Determine Baseline Maturity based on max of numeric counts & categorical totals
        num_count = (
            max((stats.get("count", 0) for stats in profile.numeric_stats.values()), default=0)
            if profile and profile.numeric_stats
            else 0
        )
        cat_count = (
            max(
                (
                    stats.get("total", sum(stats.get("frequencies", {}).values()))
                    for stats in profile.categorical_stats.values()
                ),
                default=0
            )
            if profile and profile.categorical_stats
            else 0
        )
        sample_count = max(num_count, cat_count)

        if sample_count == 0:
            baseline_maturity = "COLD_START"
        elif sample_count == 1:
            baseline_maturity = "MATURING"
        else:
            baseline_maturity = "MATURE"

        # 2. Inspect Temporal Context (Identify Un-baselined Operational Metrics)
        if context.temporal_context:
            for k, val in context.temporal_context.items():
                if k != "timestamp" and val is not None:
                    unbaselined_attributes.append(k)
                    deviations[k] = {
                        "value": val,
                        "status": "UNBASELINED",
                        "reason": "Temporal duration metric excluded from online Welford baselining",
                        "z_score_valid": False,
                        "z_score": None,
                    }

        # 3. Evaluate Attribute Deviations across Dimensions against PRE-UPDATE profile
        dimensions = {
            "asset_context": context.asset_context,
            "network_context": context.network_context,
            "device_context": context.device_context,
            "operational_context": context.operational_context,
            "security_context": context.security_context,
        }

        for dim_dict in dimensions.values():
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

                # 3a. Numeric Evaluation
                if attr_meta.data_type in ("int", "float"):
                    try:
                        num_val = float(val)
                        if profile and attr_name in profile.numeric_stats:
                            stats = profile.numeric_stats[attr_name]
                            mean = stats["mean"]
                            std = stats["std"]
                            count = stats.get("count", 0)

                            if count >= 2 and std > 0.0:
                                z_score_valid = True
                                z_score = (num_val - mean) / std
                                deviations[attr_name] = {
                                    "value": num_val,
                                    "mean": mean,
                                    "std": std,
                                    "z_score": z_score,
                                    "z_score_valid": z_score_valid,
                                    "sample_count": count,
                                    "status": "BASELINED",
                                    "reason": "Valid",
                                }
                            elif count >= 2 and std == 0.0:
                                z_score_valid = False
                                z_score = None
                                deviations[attr_name] = {
                                    "value": num_val,
                                    "mean": mean,
                                    "std": std,
                                    "z_score": z_score,
                                    "z_score_valid": z_score_valid,
                                    "sample_count": count,
                                    "status": "ZERO_VARIANCE",
                                    "reason": f"Zero variance baseline established (count={count}, constant_mean={mean:.3f})",
                                    "deviates_from_constant": num_val != mean,
                                }
                            else:
                                z_score_valid = False
                                z_score = None
                                deviations[attr_name] = {
                                    "value": num_val,
                                    "mean": mean,
                                    "std": std,
                                    "z_score": z_score,
                                    "z_score_valid": z_score_valid,
                                    "sample_count": count,
                                    "status": "BASELINED",
                                    "reason": f"Insufficient baseline samples (count={count}, std={std:.3f})",
                                }
                        else:
                            deviations[attr_name] = {
                                "value": num_val,
                                "z_score": None,
                                "z_score_valid": False,
                                "sample_count": 0,
                                "status": "COLD_START",
                                "reason": "No historical profile baseline established for entity",
                            }
                    except (ValueError, TypeError):
                        deviations[attr_name] = {
                            "value": val,
                            "z_score": None,
                            "z_score_valid": False,
                            "status": "INVALID_VALUE",
                            "reason": f"Failed to cast numeric attribute value '{val}' to float",
                        }

                # 3b. Categorical Evaluation
                elif attr_meta.data_type in ("str", "string", "bool"):
                    str_val = str(val)
                    if profile and attr_name in profile.categorical_stats:
                        stats = profile.categorical_stats[attr_name]
                        frequencies = stats.get("frequencies", {})
                        total = stats.get("total", sum(frequencies.values()))
                        val_count = stats.get("count", frequencies.get(str_val, 0))
                        probability = val_count / total if total > 0.0 else 0.0

                        deviations[attr_name] = {
                            "value": str_val,
                            "probability": probability,
                            "is_new": val_count == 0,
                            "sample_count": total,
                            "status": "BASELINED",
                        }
                    else:
                        deviations[attr_name] = {
                            "value": str_val,
                            "probability": 0.0,
                            "is_new": True,
                            "sample_count": 0,
                            "status": "COLD_START",
                        }

        return deviations, baseline_maturity, unbaselined_attributes


class OperationalContextModeler:
    """Orchestrates Stage 3 Operational Context Modeling.

    Fuses incoming Stage 1 StructuredContext objects and Stage 2 DynamicContextProfiles
    into unified OperationalContextObjects while strictly preventing self-inclusion bias.
    """

    def __init__(
        self,
        repository: Optional[ContextAttributeRepository] = None,
        generator: Optional[DynamicContextProfileGenerator] = None,
    ) -> None:
        """Initializes the modeler.

        Args:
            repository: ContextAttributeRepository instance.
            generator: Stage 2 DynamicContextProfileGenerator instance.
        """
        self.repository = repository or ContextAttributeRepository()
        self.generator = generator or DynamicContextProfileGenerator(repository=self.repository)
        self.evaluator = OperationalContextEvaluator(repository=self.repository)

    def model_context(self, context: StructuredContext) -> OperationalContextObject:
        """PURE function: Models context against pre-update profile baseline.

        Does NOT mutate the underlying Stage 2 profile. Calling this method repeatedly
        on the identical record is idempotent and leaves profile statistics unchanged.

        Args:
            context: Incoming Stage 1 StructuredContext object.

        Returns:
            A fused Stage 3 OperationalContextObject built against pre-update history.
        """
        key = derive_profile_key(context)
        entity_type = derive_profile_entity_type(context)

        # Read pre-update profile snapshot
        profile_before = self.generator.get_profile(key)

        # Evaluate deviations and baseline quality using PRE-UPDATE history only
        deviations, maturity, unbaselined = self.evaluator.evaluate_deviations(
            context, profile_before
        )

        # Extract selective baselines for attributes present in the current record
        num_baseline: Dict[str, Dict[str, Any]] = {}
        cat_baseline: Dict[str, Dict[str, Any]] = {}
        comm_summary: Dict[str, Any] = {}
        op_summary: Dict[str, Any] = {}

        if profile_before:
            dimensions = {
                "asset_context": context.asset_context,
                "network_context": context.network_context,
                "device_context": context.device_context,
                "operational_context": context.operational_context,
                "security_context": context.security_context,
            }

            present_attrs = set()
            for dim_dict in dimensions.values():
                if dim_dict:
                    present_attrs.update(dim_dict.keys())

            # Selective 2-level copy for numeric stats present in current record
            for attr_name in present_attrs:
                if attr_name in profile_before.numeric_stats:
                    num_baseline[attr_name] = profile_before.numeric_stats[attr_name].copy()

                if attr_name in profile_before.categorical_stats:
                    stats = profile_before.categorical_stats[attr_name]
                    freq = stats.get("frequencies", {})
                    tot = sum(freq.values())
                    val = None
                    for dim_dict in dimensions.values():
                        if dim_dict and attr_name in dim_dict:
                            val = dim_dict[attr_name]
                            break
                    str_val = str(val) if val is not None else ""
                    cnt = freq.get(str_val, 0)
                    cat_baseline[attr_name] = {
                        "total": tot,
                        "count": cnt,
                        "frequencies": {str_val: cnt},
                    }

            if profile_before.communication_stats:
                comm_summary = profile_before.communication_stats.copy()
                if "connection_states" in comm_summary and isinstance(comm_summary["connection_states"], dict):
                    comm_summary["connection_states"] = comm_summary["connection_states"].copy()

            if profile_before.operational_stats:
                op_summary = profile_before.operational_stats.copy()
                if "thread_states" in op_summary and isinstance(op_summary["thread_states"], dict):
                    op_summary["thread_states"] = op_summary["thread_states"].copy()

        # Construct OperationalContextObject
        return OperationalContextObject(
            profile_key=key,
            entity_type=entity_type,
            source=context.source,
            timestamp=context.timestamp,
            current_asset=context.asset_context.copy(),
            current_network=context.network_context.copy(),
            current_device=context.device_context.copy(),
            current_operational=context.operational_context.copy(),
            current_security=context.security_context.copy(),
            current_temporal=context.temporal_context.copy(),
            numeric_baseline=num_baseline,
            categorical_baseline=cat_baseline,
            communication_summary=comm_summary,
            operational_summary=op_summary,
            deviations=deviations,
            baseline_maturity=maturity,
            unbaselined_attributes=unbaselined,
        )

    def commit(self, context: StructuredContext) -> None:
        """Mutates the underlying Stage 2 profile baseline using the incoming record.

        Args:
            context: Incoming Stage 1 StructuredContext object to commit into baseline.
        """
        self.generator.update(context)

    def process(self, context: StructuredContext) -> OperationalContextObject:
        """Convenience pipeline method: models context pre-update, then commits baseline mutation.

        Args:
            context: Incoming Stage 1 StructuredContext record.

        Returns:
            The fused Stage 3 OperationalContextObject built against pre-update history.
        """
        obj = self.model_context(context)
        self.commit(context)
        return obj

