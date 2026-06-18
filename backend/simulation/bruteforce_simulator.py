"""
ShieldNet Brute Force Simulator
Generates synthetic brute-force feature vectors for testing.
"""
import random
from typing import Dict


def generate_bruteforce_payload(target_ip: str = "192.168.1.100") -> Dict:
    """
    Return a feature dict mimicking SSH/FTP brute-force (CICIDS2017 Brute-Force profile).
    """
    target_port = random.choice([22, 21, 3389, 23])
    return {
        "src_ip": f"172.16.{random.randint(0,255)}.{random.randint(1,254)}",
        "dst_ip": target_ip,
        "src_port": random.randint(1024, 65535),
        "dst_port": target_port,
        "protocol": "TCP",
        "features": {
            "Destination Port":             target_port,
            "Flow Duration":                random.uniform(10000, 500000),
            "Total Fwd Packets":            random.randint(100, 2000),
            "Total Backward Packets":       random.randint(100, 2000),
            "Total Length of Fwd Packets":  random.randint(10000, 200000),
            "Total Length of Bwd Packets":  random.randint(10000, 200000),
            "Fwd Packet Length Max":        random.randint(200, 600),
            "Fwd Packet Length Min":        random.randint(40, 80),
            "Fwd Packet Length Mean":       random.uniform(100, 400),
            "Fwd Packet Length Std":        random.uniform(50, 150),
            "Bwd Packet Length Max":        random.randint(200, 600),
            "Bwd Packet Length Min":        random.randint(40, 80),
            "Bwd Packet Length Mean":       random.uniform(100, 400),
            "Bwd Packet Length Std":        random.uniform(50, 150),
            "Flow Bytes/s":                 random.uniform(1000, 50000),
            "Flow Packets/s":               random.uniform(10, 200),
            "Flow IAT Mean":                random.uniform(0.01, 1.0),
            "Flow IAT Std":                 random.uniform(0.001, 0.1),
            "Flow IAT Max":                 random.uniform(0.5, 5.0),
            "Flow IAT Min":                 random.uniform(0.001, 0.01),
            "SYN Flag Count":               random.randint(20, 500),
            "ACK Flag Count":               random.randint(100, 2000),
            "FIN Flag Count":               random.randint(10, 200),
            "RST Flag Count":               random.randint(5, 100),
            "PSH Flag Count":               random.randint(50, 1000),
            "URG Flag Count":               0,
            "Packet Length Mean":           random.uniform(100, 400),
            "Packet Length Std":            random.uniform(50, 150),
            "Packet Length Variance":       random.uniform(2500, 22500),
        }
    }
