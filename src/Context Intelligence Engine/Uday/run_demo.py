"""Demonstration script for CORTEX Stage 1.

1. Streams raw TON-IoT CSV data and parses them into StructuredContext (Stage 1).
"""

import os
import logging
import datetime
from context_engine.data_loader import CSVDataLoader
from context_engine.context_attribute_repository import ContextAttributeRepository
from context_engine.context_extraction import MultiSourceContextExtractor, StructuredContext
from context_engine.context_profile import DynamicContextProfileGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("CORTEX.Demo")


def print_record(record: StructuredContext) -> None:
    """Pretty prints a standardized StructuredContext object."""
    label = record.security_context.get("security_alert_label", 0)
    attack_class = record.security_context.get("attack_class", "normal")
    
    print(f"\nIncoming StructuredContext: {record.source.upper()}")
    print("-" * 65)
    print(f"  Timestamp   : {record.timestamp}")
    print(f"  Entity Type : {record.entity_type}")
    print(f"  Entity ID   : {record.entity_id}")
    print(f"  Alert Label : {label} ({'ATTACK' if label == 1 else 'NORMAL'})")
    print(f"  Attack Type : {attack_class}")
    
    print("\n  Grouped Context Dimensions:")
    
    if record.temporal_context:
        print("    [Temporal Context]")
        for k, v in record.temporal_context.items():
            print(f"      - {k}: {v}")
            
    if record.asset_context:
        print("    [Asset Context]")
        for k, v in record.asset_context.items():
            print(f"      - {k}: {v}")
            
    if record.network_context:
        print("    [Network Context]")
        for k, v in record.network_context.items():
            print(f"      - {k}: {v}")
            
    if record.device_context:
        print("    [Device Context]")
        for k, v in record.device_context.items():
            print(f"      - {k}: {v}")
            
    if record.operational_context:
        print("    [Operational Context]")
        for k, v in record.operational_context.items():
            print(f"      - {k}: {v}")
            
    if record.security_context:
        print("    [Security Context]")
        for k, v in record.security_context.items():
            print(f"      - {k}: {v}")
            
    print("-" * 65)


def main() -> None:
    """Main execution entry point."""
    logger.info("Initializing CORTEX Stage 1 Demo Engine...")

    # Dynamically resolve dataset path relative to project root for portability
    project_root = os.path.dirname(os.path.abspath(__file__))
    base_dataset_dir = os.path.join(
        project_root, "TON_IoT Datasets", "Processed_datasets", "Processed_datasets"
    )
    
    required_targets = {
        "network": os.path.join(base_dataset_dir, "Processed_Network_dataset", "Network_dataset_1.csv"),
        "fridge": os.path.join(base_dataset_dir, "Processed_IoT_dataset", "IoT_Fridge.csv"),
    }
    
    optional_targets = {
        "linux_process": os.path.join(base_dataset_dir, "Processed_Linux_dataset", "Linux_process_1.csv"),
        "windows": os.path.join(base_dataset_dir, "Processed_Windows_dataset", "windows10_dataset.csv"),
    }

    active_targets = {}
    # Verify required targets exist
    for source, path in required_targets.items():
        if not os.path.exists(path):
            logger.error("Required dataset file not found: %s", path)
            logger.error("Please ensure the TON-IoT dataset is correctly placed in '%s'", base_dataset_dir)
            return
        active_targets[source] = path

    # Check optional targets and load if present
    for source, path in optional_targets.items():
        if os.path.exists(path):
            logger.info("Optional dataset file found: %s. Including in demo.", source)
            active_targets[source] = path
        else:
            logger.info("Optional dataset file not found: %s. Skipping.", source)

    # Initialize Repositories, Extractors, and Stage 2 Profile Generator
    attr_repo = ContextAttributeRepository()
    extractor = MultiSourceContextExtractor(repository=attr_repo)
    profile_gen = DynamicContextProfileGenerator(repository=attr_repo, buffer_maxlen=5)

    print("\n" + "="*50)
    print("DEMO PHASE 1: STAGE 1 CONTEXT EXTRACTION STREAMING & STAGE 2 PROFILE UPDATES")
    print("="*50)

    # Process first 2 rows from each active source for context serialization demonstration
    for source_key, file_path in active_targets.items():
        logger.info("Loading records from source: %s", source_key)
        try:
            loader = CSVDataLoader(file_path)
            records_stream = loader.stream_records(chunk_size=1, max_rows=2)
            
            for raw_row in records_stream:
                try:
                    context_record = extractor.extract(raw_row, source_key)
                    print_record(context_record)
                    
                    # Update or score profile in Stage 2
                    deviation = profile_gen.update(context_record)
                    if deviation:
                        print(f"    [Anomaly Score / Deviation Report]")
                        for attr, details in deviation.deviations.items():
                            if "z_score" in details:
                                print(f"      - {attr}: val={details['value']}, z_score={details['z_score']:.3f} (mean={details['mean']:.3f}, std={details['std']:.3f})")
                            elif "probability" in details:
                                print(f"      - {attr}: val={details['value']}, probability={details['probability']:.3f} (is_new={details['is_new']})")
                except Exception as ex:
                    logger.error("Failed to extract context in %s: %s", source_key, ex)
                    
        except Exception as e:
            logger.error("Failed to load file %s: %s", file_path, e)

    # Demonstrate Scoring an Attack Record against the "fridge" baseline
    print("\n" + "="*50)
    print("DEMO PHASE 1.5: SCORING AN ATTACK RECORD (security_alert_label == 1)")
    print("="*50)
    
    fridge_attack = StructuredContext(
        timestamp=1554035815.0,
        source="iot_fridge",
        entity_type="DEVICE",
        entity_id="fridge",
        device_context={"device_temperature": 99.0, "status_condition": "critical_error"},
        security_context={"security_alert_label": 1}
    )
    
    deviation = profile_gen.update(fridge_attack)
    if deviation:
        print(f"\nDeviationReport Generated for key: '{deviation.profile_key}'")
        print(f"  Timestamp: {deviation.timestamp}")
        print(f"  Source: {deviation.source}")
        print("  Deviations:")
        for attr, details in deviation.deviations.items():
            if "z_score" in details:
                print(f"    - {attr}: z_score={details['z_score']:.3f} (value={details['value']}, mean={details['mean']:.3f}, std={details['std']:.3f})")
            elif "probability" in details:
                print(f"    - {attr}: probability={details['probability']:.3f} (value='{details['value']}', is_new={details['is_new']})")

    # Flush all remaining reorder window buffers
    profile_gen.flush_all_buffers()

    # Print summary of all generated profiles at the end
    print("\n" + "="*50)
    print("DEMO PHASE 2: COMPILED STAGE 2 DYNAMIC CONTEXT PROFILES")
    print("="*50)
    for key, profile in profile_gen.get_all_profiles().items():
        print(f"\nProfile Key: {key}")
        print(f"  Entity Type: {profile.entity_type}")
        print(f"  Last Updated: {datetime.datetime.fromtimestamp(profile.last_updated, datetime.timezone.utc).isoformat()}")
        
        if profile.numeric_stats:
            print("  Numeric Attributes Baseline:")
            for attr, stats in profile.numeric_stats.items():
                print(f"    - {attr}: count={stats['count']}, mean={stats['mean']:.3f}, std={stats['std']:.3f}, range=[{stats['min']:.3f}, {stats['max']:.3f}]")
                
        if profile.categorical_stats:
            print("  Categorical Attributes Baseline:")
            for attr, stats in profile.categorical_stats.items():
                freqs = ", ".join(f"'{k}': {v}" for k, v in stats["frequencies"].items())
                print(f"    - {attr}: frequencies=({freqs})")
                
        if profile.communication_stats:
            print(f"  Communication Summary: {profile.communication_stats}")
            
        if profile.operational_stats:
            print(f"  Operational Summary: {profile.operational_stats}")
        print("-" * 50)


if __name__ == "__main__":
    main()
