"""
config.py
================
Centralized configuration module for CORTEX Context Intelligence Engine (Akshara).
Defines base paths, results subdirectories, and raw data source paths.
"""

import os
from pathlib import Path

# Base directory for Akshara (folder location, not cwd)
BASE_DIR = Path(__file__).resolve().parent

# Results directory
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Raw data path configuration
env_raw_path = os.getenv("CORTEX_RAW_DATA_PATH")
if env_raw_path:
    RAW_DATA_PATH = Path(env_raw_path)
else:
    # Relative default in repo structure: repo_root/data/train_test_network.csv
    default_path = BASE_DIR.parent.parent.parent / "data" / "train_test_network.csv"
    if default_path.exists():
        RAW_DATA_PATH = default_path
    else:
        # Local workspace fallback if present
        local_fallback = BASE_DIR.parent / "Train_Test_datasets" / "Train_Test_Network_dataset" / "train_test_network.csv"
        if local_fallback.exists():
            RAW_DATA_PATH = local_fallback
        else:
            RAW_DATA_PATH = default_path

if not RAW_DATA_PATH.exists():
    print(f"[ERROR] Raw data file not found at: {RAW_DATA_PATH}")
    print("        Please set the environment variable CORTEX_RAW_DATA_PATH to point to your train_test_network.csv file.")
