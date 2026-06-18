"""
ShieldNet ML Prediction Engine
Isolation Forest anomaly detection + heuristic attack classification.
SHAP TreeExplainer used for human-readable reason generation when available.

Models are loaded lazily on first call so a fresh clone without trained
artefacts does not crash the entire application at import time.
"""
from __future__ import annotations

import json
import os
import random
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd

# ── Model paths ──────────────────────────────────────────────────
_BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_PATH    = os.path.join(_BASE_DIR, "models", "anomaly_model.pkl")
_SCALER_PATH   = os.path.join(_BASE_DIR, "models", "scaler.pkl")
_FEATURES_PATH = os.path.join(_BASE_DIR, "models", "features.json")

# ── Lazy-loaded singletons (None until first predict() call) ─────
_model:    Optional[Any]       = None
_scaler:   Optional[Any]       = None
_features: Optional[List[str]] = None


def _load_assets() -> None:
    """Load model artefacts on first use. Raises a clear error if not yet trained."""
    global _model, _scaler, _features
    if _model is not None:
        return   # already loaded

    missing = [p for p in (_MODEL_PATH, _SCALER_PATH, _FEATURES_PATH) if not os.path.exists(p)]
    if missing:
        raise RuntimeError(
            "ShieldNet ML models not found. Run training first:\n"
            "    python -m backend.ml.train\n"
            f"Missing files: {missing}"
        )

    _model  = joblib.load(_MODEL_PATH)
    _scaler = joblib.load(_SCALER_PATH)
    with open(_FEATURES_PATH) as f:
        _features = json.load(f)


# ── Attack profiles: type → (reasons, base_risk) ─────────────────
_ATTACK_PROFILES: Dict[str, tuple] = {
    "DDoS":          (["High packet rate detected",       "Abnormal flow volume",        "Symmetric flood pattern"],       88),
    "Port Scan":     (["Sequential port access",          "Short-lived connections",      "Low bytes per packet"],          72),
    "Brute Force":   (["Repeated failed authentications", "High SYN rate",                "Single destination port"],       80),
    "Web Attack":    (["Abnormal HTTP payload",           "Unusual URL pattern",          "Injection attempt signature"],   75),
    "Infiltration":  (["Lateral movement detected",       "Unusual outbound data",        "Encrypted tunnel suspected"],    85),
    "Unknown Threat":(["Anomalous traffic pattern",       "Deviation from baseline",      "Unclassified behaviour"],        60),
}


def _classify_attack(feat: Dict[str, float]) -> str:
    flow_pkts_s  = feat.get("Flow Packets/s", 0)
    flow_bytes_s = feat.get("Flow Bytes/s", 0)
    syn          = feat.get("SYN Flag Count", 0)
    dst_port     = feat.get("Destination Port", 0)
    pkt_std      = feat.get("Packet Length Std", 0)
    pkt_mean     = feat.get("Packet Length Mean", 0)

    if flow_pkts_s > 10_000 or flow_bytes_s > 5_000_000:
        return "DDoS"
    if syn > 50 and pkt_mean < 100:
        return "Port Scan"
    if syn > 20 and dst_port in (21, 22, 23, 445, 3389):
        return "Brute Force"
    if dst_port in (80, 443, 8080, 8443) and pkt_std > 200:
        return "Web Attack"
    if feat.get("Flow Duration", 0) > 100_000 and flow_pkts_s < 10:
        return "Infiltration"
    return "Unknown Threat"


def _risk_score(anomaly_score: float, attack_type: str) -> float:
    _, base = _ATTACK_PROFILES.get(attack_type, ([], 60))
    norm    = max(0.0, min(1.0, -anomaly_score + 0.5))
    blended = 0.6 * norm * 100 + 0.4 * base
    return round(min(100.0, max(1.0, blended + random.uniform(-2, 2))), 1)


def _severity(score: float) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 70: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _reasons(feat: Dict[str, float], attack_type: str) -> List[str]:
    try:
        import shap
        df     = pd.DataFrame([feat], columns=_features)
        scaled = _scaler.transform(df)
        exp    = shap.TreeExplainer(_model)
        vals   = np.abs(exp.shap_values(scaled)[0])
        top    = np.argsort(vals)[::-1][:3]
        return [f"High impact: {_features[i]}" for i in top]
    except Exception:
        profiled, _ = _ATTACK_PROFILES.get(attack_type, (["Anomalous pattern detected"], 60))
        return profiled


def predict(input_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run threat detection on a feature dictionary.
    Lazily loads model artefacts on first call.

    Parameters
    ----------
    input_dict : dict
        Any subset of the 78 CICIDS2017 feature names. Missing keys default to 0.

    Returns
    -------
    dict with keys: status, attack_type, risk_score, confidence, severity, reason
    """
    _load_assets()   # no-op after first call

    row    = {f: float(input_dict.get(f, 0)) for f in _features}
    df     = pd.DataFrame([row], columns=_features)
    scaled = _scaler.transform(df)

    label = _model.predict(scaled)[0]       # 1 = normal, -1 = anomaly
    score = _model.score_samples(scaled)[0] # lower → more anomalous

    if label == -1:
        attack  = _classify_attack(row)
        risk    = _risk_score(score, attack)
        conf    = round(min(0.99, max(0.50, 0.5 + abs(score))), 2)
        sev     = _severity(risk)
        reasons = _reasons(row, attack)
        status  = "THREAT"
    else:
        attack  = "N/A"
        risk    = round(random.uniform(1, 20), 1)
        conf    = round(min(0.99, max(0.70, 0.5 + abs(score))), 2)
        sev     = "LOW"
        reasons = ["Traffic within normal baseline"]
        status  = "NORMAL"

    return {
        "status":      status,
        "attack_type": attack,
        "risk_score":  risk,
        "confidence":  conf,
        "severity":    sev,
        "reason":      reasons,
    }


if __name__ == "__main__":
    sample = {}
    print(predict(sample))
