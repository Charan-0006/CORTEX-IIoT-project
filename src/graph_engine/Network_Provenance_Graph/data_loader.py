"""
CORTEX Layer 3B Robust Data Loader Module
Loads, validates, merges, and deduplicates ALL 23 processed ToN-IoT Network dataset files (Network_dataset_1.csv through Network_dataset_23.csv).
"""

import os
import glob
import pandas as pd
from typing import Dict, Any, Tuple, Optional


# ==============================================================================
# DATA LOADING & PREPROCESSING MODULE
# Objective: Ingest raw ToN-IoT network CSV files, validate schema columns,
# remove duplicate network flows, and clean missing values.
# ==============================================================================

def load_data(network_data_dir: str = "data/raw/Processed_datasets/Processed_Network_dataset", 
              sample_per_file: Optional[int] = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Function: load_data
    -------------------
    Why it exists: Loads raw ToN-IoT CSV files from disk into memory.
    Input: Directory path containing Network_dataset_*.csv files and optional sample row limit.
    Output: Tuple of (merged pandas DataFrame, summary metadata dict).
    Contribution to NPG: Serves as the data ingestion entry point for Network Provenance Graph construction.
    """
    loader = TonIotDataLoader(network_data_dir=network_data_dir)
    return loader.load_and_merge_all_network_datasets(sample_per_file=sample_per_file)


def preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Function: preprocess_data
    -------------------------
    Why it exists: Cleans missing critical fields (src_ip, dst_ip, dst_port) and drops duplicate flow records.
    Input: Merged raw pandas DataFrame.
    Output: Tuple of (cleaned pandas DataFrame, preprocessing metrics dict).
    Contribution to NPG: Ensures node extraction receives non-null IP addresses and unique flow tuples.
    """
    # Dataset Field Explanation:
    # 'src_ip'   -> Originating Host IP address
    # 'dst_ip'   -> Target Host IP address
    # 'dst_port' -> Destination Service Port number
    # 'proto'    -> Network Protocol (e.g., tcp, udp, modbus, http)
    # 'label'    -> Binary classification (0: Normal, 1: Attack)
    # 'type'     -> Fine-grained attack category (e.g., dos, ddos, password, scanning)

    # 1. Clean missing core identifier fields
    cleaned_df = df.dropna(subset=['src_ip', 'dst_ip', 'dst_port']).copy()

    # 2. Deduplicate network flows based on canonical flow attributes
    dedup_cols = [c for c in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'ts', 'label', 'type'] if c in cleaned_df.columns]
    rows_before = len(cleaned_df)
    cleaned_df.drop_duplicates(subset=dedup_cols, keep='first', inplace=True)
    rows_after = len(cleaned_df)

    metrics = {
        "rows_before": rows_before,
        "rows_after": rows_after,
        "duplicates_removed": rows_before - rows_after
    }
    return cleaned_df, metrics


class TonIotDataLoader:
    """
    Handles loading, validating, merging, and deduplicating all ToN-IoT Network CSV dataset files.
    """

    def __init__(self, network_data_dir: str = "data/raw/Processed_datasets/Processed_Network_dataset"):
        self.network_data_dir = network_data_dir

    def get_network_csv_files(self) -> list:
        """Finds all Network_dataset_*.csv files in the configured directory."""
        if not os.path.exists(self.network_data_dir):
            fallback = glob.glob("data/raw/**/Network_dataset_*.csv", recursive=True)
            return sorted(fallback)

        files = glob.glob(os.path.join(self.network_data_dir, "Network_dataset_*.csv"))
        return sorted(files)

    def load_and_merge_all_network_datasets(self, sample_per_file: Optional[int] = None) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Loads network CSV files, verifies column schemas, merges them, removes duplicates,
        and returns the unified DataFrame alongside a preprocessing summary dict.
        """
        csv_files = self.get_network_csv_files()
        if not csv_files:
            raise FileNotFoundError(f"No Network_dataset_*.csv files found in '{self.network_data_dir}'.")

        required_columns = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'service', 'duration', 'label', 'type'}
        
        dataframes = []
        total_rows_raw = 0
        missing_values_summary = {}

        print(f"[+] Found {len(csv_files)} Network CSV dataset files in '{self.network_data_dir}'.")
        print("[+] Loading and verifying dataset schemas across all files...")

        for filepath in csv_files:
            try:
                if sample_per_file is not None and sample_per_file > 0:
                    df_curr = pd.read_csv(filepath, nrows=sample_per_file)
                else:
                    df_curr = pd.read_csv(filepath)
                curr_cols = set(df_curr.columns)
                missing_cols = required_columns - curr_cols
                if missing_cols:
                    print(f"  [!] Warning: {os.path.basename(filepath)} missing columns: {missing_cols}")

                total_rows_raw += len(df_curr)
                dataframes.append(df_curr)
            except Exception as e:
                print(f"  [!] Skipping {os.path.basename(filepath)} due to read error: {e}")

        # Merge all loaded datasets into a single contiguous DataFrame
        merged_df = pd.concat(dataframes, ignore_index=True)

        # Count missing values for audit
        for col in ['src_ip', 'dst_ip', 'dst_port', 'proto', 'label', 'type', 'ts']:
            if col in merged_df.columns:
                missing_values_summary[col] = int(merged_df[col].isna().sum())

        # Drop rows where essential IP and port fields are missing
        merged_df = merged_df.dropna(subset=['src_ip', 'dst_ip', 'dst_port'])

        # Remove identical row entries (duplicate flow records)
        dedup_cols = [c for c in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 'ts', 'label', 'type'] if c in merged_df.columns]
        rows_before_dedup = len(merged_df)
        merged_df = merged_df.drop_duplicates(subset=dedup_cols, keep='first')
        rows_after_dedup = len(merged_df)
        dedup_removed = rows_before_dedup - rows_after_dedup

        preprocessing_summary = {
            "num_files_loaded": len(dataframes),
            "file_list": [os.path.basename(f) for f in csv_files],
            "total_rows_loaded": total_rows_raw,
            "rows_after_dedup": rows_after_dedup,
            "duplicate_rows_removed": dedup_removed,
            "missing_values_summary": missing_values_summary
        }

        print(f"[+] Preprocessing Complete: {rows_after_dedup:,} unique flow records merged across {len(dataframes)} files.")
        return merged_df, preprocessing_summary

