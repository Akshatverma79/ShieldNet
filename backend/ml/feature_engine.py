"""
ShieldNet Legacy Feature Engine
This module is kept for reference only.
The production packet capture pipeline uses backend.network.feature_extractor,
which is the correct, fully-featured implementation.

This file is NOT imported by any production code.
"""
import time
import statistics
from collections import defaultdict


class FeatureExtractor:
    """
    Legacy feature extractor — superseded by backend.network.feature_extractor.
    Kept here for historical reference only.

    KNOWN LIMITATIONS (not fixed here since this file is unused):
    - Stores full Scapy packet objects in memory (memory leak under load).
    - Only computes a subset of the 78 required CICIDS2017 features.
    - Uses incorrect Scapy attribute access for port numbers.
    Use backend.network.feature_extractor.FeatureExtractor for all live capture.
    """

    def __init__(self):
        # Store only packet sizes, NOT full packet objects, to avoid memory leak
        self.flows = defaultdict(
            lambda: {
                "start":   time.time(),
                "count":   0,
                "bytes":   0,
                "lengths": [],
            }
        )

    def flow_key(self, packet):
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not packet.haslayer(IP):
                return None
            ip    = packet[IP]
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
            sport = int(packet[TCP].sport) if packet.haslayer(TCP) else (
                    int(packet[UDP].sport) if packet.haslayer(UDP) else 0)
            dport = int(packet[TCP].dport) if packet.haslayer(TCP) else (
                    int(packet[UDP].dport) if packet.haslayer(UDP) else 0)
            return (ip.src, ip.dst, sport, dport, proto)
        except Exception:
            return None

    def extract(self, packet):
        key = self.flow_key(packet)
        if not key:
            return None

        flow = self.flows[key]
        now  = time.time()
        dur  = now - flow["start"]
        size = len(packet)

        # Store only the size — NOT the full packet object (avoids memory leak)
        flow["count"]  += 1
        flow["bytes"]  += size
        flow["lengths"].append(size)

        count   = flow["count"]
        lengths = flow["lengths"]

        features = {
            "Destination Port":            key[3],
            "Flow Duration":               dur,
            "Total Fwd Packets":           count,
            "Total Backward Packets":      0,
            "Total Length of Fwd Packets": flow["bytes"],
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max":       max(lengths),
            "Fwd Packet Length Min":       min(lengths),
            "Fwd Packet Length Mean":      statistics.mean(lengths),
            "Fwd Packet Length Std":       statistics.stdev(lengths) if len(lengths) > 1 else 0,
            "Packet Length Mean":          statistics.mean(lengths),
            "Packet Length Std":           statistics.stdev(lengths) if len(lengths) > 1 else 0,
            "Packet Length Variance":      statistics.variance(lengths) if len(lengths) > 1 else 0,
            "Flow Bytes/s":                flow["bytes"] / dur if dur > 0 else 0,
            "Flow Packets/s":              count / dur if dur > 0 else 0,
        }

        # Fill remaining required features with 0
        for name in self.required_features:
            if name not in features:
                features[name] = 0

        return features

    @property
    def required_features(self):
        return [
            "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
            "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
            "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count",
            "PSH Flag Count", "URG Flag Count",
            "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "Down/Up Ratio",
            "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean",   "Idle Std",   "Idle Max",   "Idle Min",
        ]
