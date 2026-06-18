"""
ShieldNet Port Scan Simulator
Generates synthetic port-scan feature vectors for testing.
"""
import random
from typing import Dict


def generate_portscan_payload(target_ip: str = "192.168.1.100") -> Dict:
    """
    Return a feature dict mimicking a TCP SYN port scan (CICIDS2017 PortScan profile).
    """
    return {
        "src_ip": f"192.168.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst_ip": target_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.randint(1, 65535),
        "protocol": "TCP",
        "features": {
            "Destination Port":             random.randint(1, 65535),
            "Flow Duration":                random.uniform(1, 100),
            "Total Fwd Packets":            random.randint(1, 5),
            "Total Backward Packets":       random.randint(0, 2),
            "Total Length of Fwd Packets":  random.randint(40, 120),
            "Total Length of Bwd Packets":  random.randint(0, 60),
            "Fwd Packet Length Max":        random.randint(40, 80),
            "Fwd Packet Length Min":        random.randint(20, 40),
            "Fwd Packet Length Mean":       random.uniform(40, 70),
            "Fwd Packet Length Std":        random.uniform(0, 10),
            "Bwd Packet Length Max":        0,
            "Bwd Packet Length Min":        0,
            "Bwd Packet Length Mean":       0,
            "Bwd Packet Length Std":        0,
            "Flow Bytes/s":                 random.uniform(100, 5000),
            "Flow Packets/s":               random.uniform(10, 500),
            "Flow IAT Mean":                random.uniform(0.001, 0.1),
            "Flow IAT Std":                 random.uniform(0.0001, 0.01),
            "Flow IAT Max":                 random.uniform(0.05, 0.5),
            "Flow IAT Min":                 random.uniform(0.0001, 0.001),
            "SYN Flag Count":               random.randint(100, 5000),
            "ACK Flag Count":               random.randint(0, 10),
            "FIN Flag Count":               0,
            "RST Flag Count":               random.randint(50, 2000),
            "PSH Flag Count":               0,
            "URG Flag Count":               0,
            "Packet Length Mean":           random.uniform(40, 70),
            "Packet Length Std":            random.uniform(0, 10),
            "Packet Length Variance":       random.uniform(0, 100),
        }
    }
