"""
ShieldNet - Generate a sample predict payload
Run from project ROOT: python -m backend.ml.make_payload
Prints a JSON payload with all features set to 0, ready for POST /api/predict.
"""
import json
import os

_HERE          = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR   = os.path.dirname(_HERE)
_FEATURES_PATH = os.path.join(_BACKEND_DIR, "models", "features.json")

with open(_FEATURES_PATH) as f:
    features = json.load(f)

payload = {
    "src_ip":   "10.0.0.1",
    "dst_ip":   "192.168.1.1",
    "src_port": 12345,
    "dst_port": 80,
    "protocol": "TCP",
    "features": {feat: 0 for feat in features},
}

print(json.dumps(payload, indent=2))
