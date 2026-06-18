"""
ShieldNet API smoke-test
Run from project ROOT: python -m backend.ml.auto_test
Sends a zero-value payload to POST /api/predict and prints the result.
"""
import json
import os
import requests

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_FEATURES_PATH = os.path.join(_BASE, "models", "features.json")

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

url = "http://127.0.0.1:8000/api/predict"

print(f"POST {url}")
resp = requests.post(url, json=payload, timeout=10)
print("Status :", resp.status_code)
print("Response:", json.dumps(resp.json(), indent=2))
