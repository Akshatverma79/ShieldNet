"""
ShieldNet DDoS Simulator
Generates synthetic DDoS-like feature vectors for testing the detection pipeline.
NOT for use against real targets — testing/demo only.
"""
import random
from typing import Dict


def generate_ddos_payload(target_ip: str = "192.168.1.100") -> Dict:
    """
    Return a feature dict that mimics a UDP/TCP flood (CICIDS2017 DDoS profile).
    """
    return {
        "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst_ip": target_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 53]),
        "protocol": "UDP",
        "features": {
            "Destination Port":             random.choice([80, 443, 53]),
            "Flow Duration":                random.uniform(100, 5000),
            "Total Fwd Packets":            random.randint(5000, 50000),
            "Total Backward Packets":       random.randint(0, 100),
            "Total Length of Fwd Packets":  random.randint(500000, 5000000),
            "Total Length of Bwd Packets":  random.randint(0, 1000),
            "Fwd Packet Length Max":        random.randint(1400, 1500),
            "Fwd Packet Length Min":        random.randint(40, 60),
            "Fwd Packet Length Mean":       random.uniform(800, 1400),
            "Fwd Packet Length Std":        random.uniform(10, 50),
            "Bwd Packet Length Max":        0,
            "Bwd Packet Length Min":        0,
            "Bwd Packet Length Mean":       0,
            "Bwd Packet Length Std":        0,
            "Flow Bytes/s":                 random.uniform(1_000_000, 10_000_000),
            "Flow Packets/s":               random.uniform(10000, 100000),
            "Flow IAT Mean":                random.uniform(0.00001, 0.001),
            "Flow IAT Std":                 random.uniform(0.00001, 0.0001),
            "Flow IAT Max":                 random.uniform(0.001, 0.01),
            "Flow IAT Min":                 random.uniform(0.000001, 0.00001),
            "SYN Flag Count":               random.randint(100, 2000),
            "ACK Flag Count":               random.randint(0, 50),
            "FIN Flag Count":               0,
            "RST Flag Count":               random.randint(0, 20),
            "PSH Flag Count":               0,
            "URG Flag Count":               0,
            "Packet Length Mean":           random.uniform(800, 1400),
            "Packet Length Std":            random.uniform(10, 50),
            "Packet Length Variance":       random.uniform(100, 2500),
        }
    }
