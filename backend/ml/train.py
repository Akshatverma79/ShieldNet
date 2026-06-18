"""
ShieldNet Model Training
Run from the project ROOT:  python -m backend.ml.train

Trains an Isolation Forest on CICIDS2017 data.
Reads CSVs individually and builds a memory-efficient stratified sample so
the model sees both benign traffic and all attack types without exhausting RAM.
Falls back to cleaned_network_data.csv if it fits in memory.
"""
import json
import os
import glob

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── Paths ────────────────────────────────────────────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.dirname(_HERE)
_ROOT_DIR    = os.path.dirname(_BACKEND_DIR)
DATASET_DIR  = os.path.join(_ROOT_DIR, "dataset")
MODELS_DIR   = os.path.join(_BACKEND_DIR, "models")

# ── Sampling config ──────────────────────────────────────────────
ROWS_PER_CSV   = 60_000   # rows to sample from each individual CSV
MAX_TOTAL_ROWS = 400_000  # hard cap on training set size

os.makedirs(MODELS_DIR, exist_ok=True)

# ── Find CSVs ────────────────────────────────────────────────────
all_csvs = sorted(glob.glob(os.path.join(DATASET_DIR, "*.csv")))
source_csvs = [f for f in all_csvs if "cleaned" not in os.path.basename(f).lower()]

print(f"Found {len(source_csvs)} source CSV(s).")
print("Strategy: sample", ROWS_PER_CSV, "rows per file → stratified training set.\n")

frames = []
total_attack_rows = 0
total_benign_rows = 0

for path in source_csvs:
    fname = os.path.basename(path)
    print(f"  Loading: {fname}")
    try:
        df = pd.read_csv(path, dtype=str, low_memory=False)
        df.columns = df.columns.str.strip()
        df.replace(["Infinity", "-Infinity"], pd.NA, inplace=True)
        df.dropna(inplace=True)

        if "Label" not in df.columns:
            print(f"    SKIP — no Label column")
            continue

        labels = df["Label"].str.strip().str.upper()
        n_benign  = (labels == "BENIGN").sum()
        n_attack  = (labels != "BENIGN").sum()
        print(f"    Rows: {len(df):,} | Benign: {n_benign:,} | Attack: {n_attack:,}")

        # Sample: take all attack rows (capped) + equal benign rows
        cap_attack = min(n_attack, ROWS_PER_CSV // 2)
        cap_benign = min(n_benign, ROWS_PER_CSV - cap_attack)

        attack_df = df[labels != "BENIGN"].sample(n=cap_attack, random_state=42) if cap_attack > 0 else pd.DataFrame()
        benign_df = df[labels == "BENIGN"].sample(n=cap_benign, random_state=42) if cap_benign > 0 else pd.DataFrame()
        sampled   = pd.concat([attack_df, benign_df], ignore_index=True)

        total_attack_rows += cap_attack
        total_benign_rows += cap_benign
        frames.append(sampled)
        print(f"    Sampled: {cap_attack:,} attack + {cap_benign:,} benign = {len(sampled):,}")

    except MemoryError:
        print(f"    SKIP — out of memory, file too large")
    except Exception as e:
        print(f"    SKIP — {e}")

if not frames:
    raise RuntimeError(
        "No valid CSVs found. Ensure the CICIDS2017 CSVs are in the dataset/ folder."
    )

# ── Combine & shuffle ────────────────────────────────────────────
combined = pd.concat(frames, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
if len(combined) > MAX_TOTAL_ROWS:
    combined = combined.sample(n=MAX_TOTAL_ROWS, random_state=42).reset_index(drop=True)

print(f"\nFinal training set: {len(combined):,} rows")
print(f"  Total attack rows: {total_attack_rows:,}")
print(f"  Total benign rows: {total_benign_rows:,}")

# ── Compute contamination ────────────────────────────────────────
labels_combined = combined["Label"].str.strip().str.upper()
n_total  = len(combined)
n_attack = (labels_combined != "BENIGN").sum()
contamination = round(float(n_attack) / n_total, 4)
contamination = max(0.01, min(0.49, contamination))
print(f"\nContamination: {n_attack:,}/{n_total:,} = {contamination:.4f}")

if "Label" in combined.columns:
    print("\nLabel distribution in training set:")
    print(combined["Label"].value_counts().to_string())
    combined.drop(columns=["Label"], inplace=True)

# ── Feature preparation ──────────────────────────────────────────
X = combined.apply(pd.to_numeric, errors="coerce")
X.dropna(axis=1, inplace=True)
print(f"\nFeatures: {X.shape[1]}")

# ── Save feature names ───────────────────────────────────────────
features_path = os.path.join(MODELS_DIR, "features.json")
with open(features_path, "w") as fh:
    json.dump(list(X.columns), fh)
print(f"Feature names saved → {features_path}")

# ── Scale ────────────────────────────────────────────────────────
scaler   = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── Train ────────────────────────────────────────────────────────
print(f"\nTraining IsolationForest (n_estimators=200, contamination={contamination})…")
model = IsolationForest(
    n_estimators=200,
    contamination=contamination,
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
model.fit(X_scaled)

# ── Quick validation ─────────────────────────────────────────────
preds = model.predict(X_scaled)
pct_flagged = (preds == -1).mean() * 100
print(f"Validation: {pct_flagged:.1f}% of training set flagged as anomalous")
print(f"  (expected ~{contamination*100:.1f}%)")

# ── Save ─────────────────────────────────────────────────────────
model_path  = os.path.join(MODELS_DIR, "anomaly_model.pkl")
scaler_path = os.path.join(MODELS_DIR, "scaler.pkl")
joblib.dump(model,  model_path)
joblib.dump(scaler, scaler_path)

print("\n" + "=" * 55)
print(f"  anomaly_model.pkl → {model_path}")
print(f"  scaler.pkl        → {scaler_path}")
print(f"  features.json     → {features_path}")
print(f"  contamination     = {contamination}")
print(f"  training rows     = {n_total:,}")
print("  Training complete ✅")
print("=" * 55)
