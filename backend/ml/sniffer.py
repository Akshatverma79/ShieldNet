"""
ShieldNet Live Sniffer (legacy standalone script)
Run from the project ROOT with: python -m backend.ml.sniffer
Requires admin/root privileges for raw packet capture.
"""
import requests
from scapy.all import sniff

from backend.network.feature_extractor import FeatureExtractor   # production extractor

API_URL   = "http://127.0.0.1:8000/api/predict"
extractor = FeatureExtractor()


def process_packet(pkt) -> None:
    feat = extractor.extract(pkt)
    if feat is None:
        return

    # Strip internal metadata keys
    ml_input = {k: v for k, v in feat.items() if not k.startswith("_")}
    meta     = {k: v for k, v in feat.items() if     k.startswith("_")}

    payload = {
        "src_ip":   meta.get("_src_ip",  "0.0.0.0"),
        "dst_ip":   meta.get("_dst_ip",  "0.0.0.0"),
        "src_port": meta.get("_sport",   0),
        "dst_port": meta.get("_dport",   0),
        "protocol": meta.get("_proto",   "UNKNOWN"),
        "features": ml_input,
    }

    try:
        resp = requests.post(API_URL, json=payload, timeout=5)
        print(f"[{meta.get('_src_ip')} → {meta.get('_dst_ip')}]  {resp.json()}")
    except Exception as exc:
        print(f"[sniffer] request error: {exc}")


if __name__ == "__main__":
    print("🚀 ShieldNet Live Packet Monitoring  (Ctrl+C to stop)")
    sniff(prn=process_packet, store=False)
