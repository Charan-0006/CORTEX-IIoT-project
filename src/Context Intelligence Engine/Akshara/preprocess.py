"""
preprocess.py
=============
Data Preprocessing Pipeline for the TON-IoT Dataset.

This script performs end-to-end preprocessing on the TON-IoT benchmark dataset:
1. Loads the specified dataset CSV file.
2. Removes duplicate rows to prevent data leakage.
3. Cleans whitespace and handles missing values (e.g., '-' placeholders in Zeek logs).
4. Drops non-informative high-cardinality identifiers (IP addresses, ports).
5. Encodes categorical features using One-Hot Encoding.
6. Encodes target labels ('label' for binary classification and 'type' for multi-class).
7. Normalizes numerical features using StandardScaler.
8. Performs a stratified train-test split (80% train, 20% test).
9. Saves the cleaned data as 'cleaned_train.csv' and 'cleaned_test.csv'.
"""

import os
import argparse
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

def preprocess_ton_iot(
    input_file: str,
    output_dir: str = '.',
    test_size: float = 0.2,
    random_state: int = 42
):
    print(f"[+] Loading dataset from: {input_file}")
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Dataset file not found: {input_file}")
    
    # Load dataset
    df = pd.read_csv(input_file, low_memory=False)
    initial_rows, initial_cols = df.shape
    print(f"    Initial shape: {initial_rows} rows x {initial_cols} columns")

    # ---------------------------------------------------------
    # STEP 1: Remove Duplicate Rows
    # ---------------------------------------------------------
    print("\n[+] Step 1: Removing duplicate rows...")
    df = df.drop_duplicates().reset_index(drop=True)
    num_duplicates_removed = initial_rows - len(df)
    print(f"    Removed {num_duplicates_removed} duplicate rows. Remaining rows: {len(df)}")

    # ---------------------------------------------------------
    # STEP 2: Handle Missing Values & String Cleaning
    # ---------------------------------------------------------
    print("\n[+] Step 2: Cleaning string fields & handling missing values...")
    
    # Strip whitespace from string columns
    str_cols = df.select_dtypes(include=['object', 'string']).columns
    for col in str_cols:
        df[col] = df[col].astype(str).str.strip()

    # In Zeek/Bro logs, '-' indicates missing values
    df = df.replace(['-', 'nan', 'None'], np.nan)

    # Check missing values
    missing_summary = df.isnull().sum()
    cols_with_missing = missing_summary[missing_summary > 0]
    if not cols_with_missing.empty:
        print(f"    Columns with missing values:\n{cols_with_missing}")
    else:
        print("    No missing values found after string normalization.")

    # ---------------------------------------------------------
    # STEP 3: Identify & Separate Targets and Identifiers
    # ---------------------------------------------------------
    print("\n[+] Step 3: Extracting targets and dropping high-cardinality identifiers...")
    
    # Identify target columns
    target_cols = [c for c in ['label', 'type', 'attack'] if c in df.columns]
    if 'label' not in df.columns and 'attack' not in df.columns:
        raise ValueError("No valid binary target column ('label' or 'attack') found in dataset!")
    
    primary_label_col = 'label' if 'label' in df.columns else 'attack'
    y_binary = df[primary_label_col].astype(int).values
    
    y_multiclass = None
    if 'type' in df.columns:
        le_type = LabelEncoder()
        y_multiclass = le_type.fit_transform(df['type'].astype(str))
        print(f"    Multi-class 'type' target encoded ({len(le_type.classes_)} classes): {list(le_type.classes_)}")

    # Drop non-informative features / identifiers (IPs, Ports, Timestamps, Target columns)
    cols_to_drop = set(target_cols)
    identifier_keywords = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'ts', 'date', 'time', 'PID', 'CMD']
    for col in df.columns:
        if any(kw.lower() == col.lower() for kw in identifier_keywords):
            cols_to_drop.add(col)

    features_df = df.drop(columns=list(cols_to_drop), errors='ignore').copy()
    print(f"    Dropped columns: {list(cols_to_drop)}")
    print(f"    Remaining feature count: {features_df.shape[1]}")

    # ---------------------------------------------------------
    # STEP 4: Handle Missing Values & High-Cardinality Text Features
    # ---------------------------------------------------------
    # For numerical columns, fill missing with median; for categorical, fill with 'missing'
    num_feature_cols = features_df.select_dtypes(include=[np.number]).columns
    cat_feature_cols = features_df.select_dtypes(include=['object', 'category', 'string']).columns

    for col in num_feature_cols:
        if features_df[col].isnull().sum() > 0:
            median_val = features_df[col].median()
            features_df[col] = features_df[col].fillna(median_val)

    low_card_cat_cols = []
    high_card_cat_cols = []
    
    for col in cat_feature_cols:
        features_df[col] = features_df[col].fillna('missing')
        num_unique = features_df[col].nunique()
        if num_unique > 50:
            high_card_cat_cols.append(col)
        else:
            low_card_cat_cols.append(col)

    if high_card_cat_cols:
        print(f"    Dropping high-cardinality text columns (>50 unique values): {high_card_cat_cols}")
        features_df = features_df.drop(columns=high_card_cat_cols)

    # ---------------------------------------------------------
    # STEP 5: Categorical Encoding (One-Hot Encoding)
    # ---------------------------------------------------------
    print("\n[+] Step 5: Encoding categorical features...")
    if len(low_card_cat_cols) > 0:
        print(f"    Categorical columns to one-hot encode: {low_card_cat_cols}")
        features_df = pd.get_dummies(features_df, columns=low_card_cat_cols, drop_first=True)
    else:
        print("    No low-cardinality categorical feature columns required encoding.")

    # Convert all boolean columns resulting from get_dummies to numeric int
    bool_cols = features_df.select_dtypes(include=['bool']).columns
    features_df[bool_cols] = features_df[bool_cols].astype(int)

    # Convert any remaining non-numeric columns
    for col in features_df.columns:
        features_df[col] = pd.to_numeric(features_df[col], errors='coerce').fillna(0)

    # ---------------------------------------------------------
    # STEP 6: Normalize Numerical Features with StandardScaler
    # ---------------------------------------------------------
    print("\n[+] Step 6: Normalizing features with StandardScaler...")
    scaler = StandardScaler()
    scaled_feature_matrix = scaler.fit_transform(features_df)
    
    scaled_features_df = pd.DataFrame(
        scaled_feature_matrix,
        columns=features_df.columns
    )

    # Re-attach target columns
    scaled_features_df['label'] = y_binary
    if y_multiclass is not None:
        scaled_features_df['type'] = df['type'].values

    # ---------------------------------------------------------
    # STEP 7: Stratified Train-Test Split
    # ---------------------------------------------------------
    print(f"\n[+] Step 7: Performing stratified train-test split ({int((1-test_size)*100)}% train, {int(test_size*100)}% test)...")
    train_df, test_df = train_test_split(
        scaled_features_df,
        test_size=test_size,
        random_state=random_state,
        stratify=scaled_features_df['label']
    )

    print(f"    Train set shape: {train_df.shape[0]} rows x {train_df.shape[1]} columns")
    print(f"    Test set shape:  {test_df.shape[0]} rows x {test_df.shape[1]} columns")

    # ---------------------------------------------------------
    # STEP 8: Save Cleaned Datasets
    # ---------------------------------------------------------
    print("\n[+] Step 8: Saving cleaned datasets...")
    train_output_path = os.path.join(output_dir, 'cleaned_train.csv')
    test_output_path = os.path.join(output_dir, 'cleaned_test.csv')

    train_df.to_csv(train_output_path, index=False)
    test_df.to_csv(test_output_path, index=False)

    print(f"    Saved cleaned training dataset to: {train_output_path}")
    print(f"    Saved cleaned test dataset to:     {test_output_path}")
    print("\n[SUCCESS] Preprocessing pipeline completed successfully!")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="TON-IoT Dataset Preprocessing Script")
    parser.add_argument(
        '--input',
        type=str,
        default=os.path.join('Train_Test_datasets', 'Train_Test_Network_dataset', 'train_test_network.csv'),
        help="Path to input TON-IoT CSV file (default: Train_Test_Network_dataset/train_test_network.csv)"
    )
    parser.add_argument(
        '--output_dir',
        type=str,
        default='.',
        help="Directory to save cleaned_train.csv and cleaned_test.csv (default: current directory)"
    )
    parser.add_argument(
        '--test_size',
        type=float,
        default=0.2,
        help="Fraction of data for test split (default: 0.2)"
    )
    
    args = parser.parse_args()
    preprocess_ton_iot(input_file=args.input, output_dir=args.output_dir, test_size=args.test_size)
