# ToN-IoT Dataset

## Overview

CORTEX uses the **ToN-IoT (Telemetry, Operating Systems, and Network Traffic Internet of Things) dataset** for cybersecurity research and network threat analysis.

The dataset was developed by UNSW Canberra and contains heterogeneous data from IoT/IIoT telemetry, network traffic, and operating-system activities. It supports research into intrusion detection, threat intelligence, and AI-based cybersecurity applications.

## Official Dataset Download

- **Dataset:** ToN-IoT
- **Provider:** UNSW Canberra Cyber
- **Official download page:** https://research.unsw.edu.au/projects/toniot-datasets

Visit the official page and select the appropriate dataset category to download the required files.

## Dataset Used in CORTEX

The current Network Provenance Graph (NPG) preprocessing pipeline uses the **processed network dataset**.

Expected local directory structure:

```text
data/
└── raw/
    └── Processed_datasets/
        └── Processed_Network_dataset/
            ├── Network_dataset_1.csv
            ├── Network_dataset_2.csv
            ├── ...
            └── Network_dataset_23.csv
```

The dataset files are stored locally and are not included in this GitHub repository because of their size.

## Preprocessing Summary

The current preprocessing results recorded for the NPG pipeline are:

- CSV files loaded: 23
- Raw rows ingested: 46,000
- Records remaining after duplicate removal: 39,066
- Duplicate rows removed: 6,934
- Reported schema validation: 100% passed
- Missing values in the validated core fields: 0

These figures describe the recorded preprocessing run and should be updated if the pipeline or dataset changes.

## Usage

1. Download the ToN-IoT dataset from the official source.
2. Extract the processed network dataset files.
3. Place them in the local directory shown above.
4. Run the NPG preprocessing and graph-construction pipeline according to the project instructions.

## Data Management

- Do not commit large dataset files to GitHub.
- Keep downloaded data in the local `data/` directory.
- Use this README to document dataset sources, expected paths, and preprocessing details.
- Follow the dataset provider's usage and citation requirements.

## Citation

For academic use, consult the official ToN-IoT dataset page for the associated research publications and citation requirements.

Official source: https://research.unsw.edu.au/projects/toniot-datasets
