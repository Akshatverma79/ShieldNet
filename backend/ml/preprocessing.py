"""
ShieldNet Dataset Preprocessing
Run from project ROOT:  python -m backend.ml.preprocessing

Reads ALL available CICIDS2017 CSVs in the dataset/ directory and merges
them into cleaned_network_data.csv used by train.py.

Using only the Monday CSV (normal traffic only) is a known bug — the model
would never see attack patterns and always classify everything as normal.
This script processes all CSVs including attack days.
"""
import os
import glob

import pandas as pd

_HERE       = os.path.dirname(os.path.abspath(__file__))
_ROOT       = os.path.dirname(os.path.dirname(_HERE))
DATASET_DIR = os.path.join(_ROOT, "dataset")
OUTPUT_CSV  = os.path.join(DATASET_DIR, "cleaned_network_data.csv")


def preprocess_dataset() -> None:
    # Find all CICIDS2017 CSVs in the dataset directory
    csv_files = sorted(glob.glob(os.path.join(DATASET_DIR, "*.csv")))
    # Exclude already-cleaned output file
    csv_files = [f for f in csv_files if "cleaned" not in os.path.basename(f).lower()]

    if not csv_files:
        raise FileNotFoundError(
            f"No CICIDS2017 CSV files found in {DATASET_DIR}.\n"
            "Download the CICIDS2017 dataset and place the CSVs in the dataset/ folder."
        )

    print(f"Found {len(csv_files)} CSV file(s):")
    for f in csv_files:
        print(f"  - {os.path.basename(f)}")

    dfs = []
    for path in csv_files:
        print(f"\nLoading: {os.path.basename(path)}")
        df = pd.read_csv(path, dtype=str, low_memory=False)
        df.columns = df.columns.str.strip()
        df.replace(["Infinity", "-Infinity"], pd.NA, inplace=True)
        df.dropna(inplace=True)
        print(f"  Shape after cleaning: {df.shape}")
        if "Label" in df.columns:
            print(f"  Labels: {df['Label'].value_counts().to_dict()}")
        dfs.append(df)

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\nCombined shape: {combined.shape}")

    if "Label" in combined.columns:
        print("\nOverall label distribution:")
        print(combined["Label"].value_counts())

    combined.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved → {OUTPUT_CSV} ✅")


if __name__ == "__main__":
    preprocess_dataset()
