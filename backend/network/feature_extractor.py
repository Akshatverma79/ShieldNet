"""
ShieldNet Network Feature Extractor
Converts raw Scapy packets into the 78-feature CICIDS2017 vector.
Per-flow state is kept in memory; flows expire after `flow_timeout` seconds.
"""
from __future__ import annotations

import statistics
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

# Type alias — (src_ip, dst_ip, src_port, dst_port, proto)
FlowKey = Tuple[str, str, int, int, str]


class FlowRecord:
    """Mutable per-flow state accumulated as packets arrive."""

    def __init__(self) -> None:
        self.start_time:     float      = time.time()
        self.last_time:      float      = time.time()
        self.pkt_lengths:    List[int]  = []
        self.fwd_lengths:    List[int]  = []
        self.bwd_lengths:    List[int]  = []
        self.fwd_iat:        List[float] = []
        self.bwd_iat:        List[float] = []
        self.flow_iat:       List[float] = []
        self.last_fwd:       float      = 0.0
        self.last_bwd:       float      = 0.0
        self.syn_count:      int        = 0
        self.ack_count:      int        = 0
        self.fin_count:      int        = 0
        self.rst_count:      int        = 0
        self.psh_count:      int        = 0
        self.urg_count:      int        = 0
        self.cwe_count:      int        = 0
        self.ece_count:      int        = 0
        self.init_fwd_win:   int        = 0
        self.init_bwd_win:   int        = 0
        self.fwd_header_len: int        = 0
        self.bwd_header_len: int        = 0
        self.act_data_fwd:   int        = 0
        self.min_seg_fwd:    int        = 65535

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    @property
    def total_pkts(self) -> int:
        return len(self.pkt_lengths)

    @property
    def total_bytes(self) -> int:
        return sum(self.pkt_lengths)


# ── Safe stat helpers ────────────────────────────────────────────

def _mean(lst: List) -> float:
    return statistics.mean(lst) if lst else 0.0

def _std(lst: List) -> float:
    return statistics.stdev(lst) if len(lst) > 1 else 0.0

def _max(lst: List) -> float:
    return float(max(lst)) if lst else 0.0

def _min(lst: List) -> float:
    return float(min(lst)) if lst else 0.0

def _var(lst: List) -> float:
    return statistics.variance(lst) if len(lst) > 1 else 0.0


class FeatureExtractor:
    """
    Stateful feature extractor.
    Call ``extract(packet)`` for every captured Scapy packet.
    Returns a feature dict on success, None for non-IP packets.
    """

    def __init__(self, flow_timeout: float = 60.0) -> None:
        self._flows: Dict[FlowKey, FlowRecord] = defaultdict(FlowRecord)
        self._timeout = flow_timeout

    # ── Internal helpers ─────────────────────────────────────────

    def _flow_key(self, pkt) -> Optional[FlowKey]:
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not pkt.haslayer(IP):
                return None
            ip    = pkt[IP]
            proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
            sport = int(pkt.sport) if hasattr(pkt, "sport") else 0
            dport = int(pkt.dport) if hasattr(pkt, "dport") else 0
            return (ip.src, ip.dst, sport, dport, proto)
        except Exception:
            return None

    def _update_tcp_flags(self, pkt, flow: FlowRecord) -> None:
        try:
            from scapy.layers.inet import TCP
            if pkt.haslayer(TCP):
                f = pkt[TCP].flags
                if f & 0x02: flow.syn_count += 1
                if f & 0x10: flow.ack_count += 1
                if f & 0x01: flow.fin_count += 1
                if f & 0x04: flow.rst_count += 1
                if f & 0x08: flow.psh_count += 1
                if f & 0x20: flow.urg_count += 1
                if f & 0x40: flow.cwe_count += 1
                if f & 0x80: flow.ece_count += 1
                if flow.total_pkts == 1:             # capture initial window
                    flow.init_fwd_win = pkt[TCP].window
        except Exception:
            pass

    # ── Public API ───────────────────────────────────────────────

    def extract(self, pkt) -> Optional[Dict[str, Any]]:
        """
        Update flow state and return a complete CICIDS2017 feature dict.
        Metadata keys prefixed with '_' are for logging only (not fed to ML).
        Returns None if the packet is not IP.
        """
        key = self._flow_key(pkt)
        if key is None:
            return None

        flow  = self._flows[key]
        now   = time.time()
        size  = len(pkt)
        src, dst, sport, dport, proto = key

        # Inter-arrival time
        if flow.total_pkts > 0:
            flow.flow_iat.append(now - flow.last_time)
        flow.last_time = now
        flow.pkt_lengths.append(size)
        flow.fwd_lengths.append(size)   # simplified: all treated as forward

        if flow.last_fwd > 0:
            flow.fwd_iat.append(now - flow.last_fwd)
        flow.last_fwd = now

        self._update_tcp_flags(pkt, flow)

        try:
            from scapy.layers.inet import IP
            if pkt.haslayer(IP):
                flow.fwd_header_len += pkt[IP].ihl * 4
        except Exception:
            pass

        flow.min_seg_fwd = min(flow.min_seg_fwd, size)
        if size > 0:
            flow.act_data_fwd += 1

        dur  = flow.duration
        np_  = flow.total_pkts
        nb_  = flow.total_bytes
        fwd  = flow.fwd_lengths
        bwd  = flow.bwd_lengths   # always empty in this simplified extractor
        all_ = flow.pkt_lengths

        feat: Dict[str, Any] = {
            # ── metadata (stripped before ML inference) ──────────
            "_src_ip":  src,
            "_dst_ip":  dst,
            "_sport":   sport,
            "_dport":   dport,
            "_proto":   proto,
            # ── CICIDS2017 features ──────────────────────────────
            "Destination Port":             dport,
            "Flow Duration":                dur * 1_000_000,
            "Total Fwd Packets":            len(fwd),
            "Total Backward Packets":       len(bwd),
            "Total Length of Fwd Packets":  sum(fwd),
            "Total Length of Bwd Packets":  sum(bwd),
            "Fwd Packet Length Max":        _max(fwd),
            "Fwd Packet Length Min":        _min(fwd),
            "Fwd Packet Length Mean":       _mean(fwd),
            "Fwd Packet Length Std":        _std(fwd),
            "Bwd Packet Length Max":        _max(bwd),
            "Bwd Packet Length Min":        _min(bwd),
            "Bwd Packet Length Mean":       _mean(bwd),
            "Bwd Packet Length Std":        _std(bwd),
            "Flow Bytes/s":                 nb_ / dur if dur > 0 else 0,
            "Flow Packets/s":               np_ / dur if dur > 0 else 0,
            "Flow IAT Mean":                _mean(flow.flow_iat),
            "Flow IAT Std":                 _std(flow.flow_iat),
            "Flow IAT Max":                 _max(flow.flow_iat),
            "Flow IAT Min":                 _min(flow.flow_iat),
            "Fwd IAT Total":                sum(flow.fwd_iat),
            "Fwd IAT Mean":                 _mean(flow.fwd_iat),
            "Fwd IAT Std":                  _std(flow.fwd_iat),
            "Fwd IAT Max":                  _max(flow.fwd_iat),
            "Fwd IAT Min":                  _min(flow.fwd_iat),
            "Bwd IAT Total":                0,
            "Bwd IAT Mean":                 0,
            "Bwd IAT Std":                  0,
            "Bwd IAT Max":                  0,
            "Bwd IAT Min":                  0,
            "Fwd PSH Flags":                flow.psh_count,
            "Bwd PSH Flags":                0,
            "Fwd URG Flags":                flow.urg_count,
            "Bwd URG Flags":                0,
            "Fwd Header Length":            flow.fwd_header_len,
            "Bwd Header Length":            0,
            "Fwd Packets/s":                len(fwd) / dur if dur > 0 else 0,
            "Bwd Packets/s":                0,
            "Min Packet Length":            _min(all_),
            "Max Packet Length":            _max(all_),
            "Packet Length Mean":           _mean(all_),
            "Packet Length Std":            _std(all_),
            "Packet Length Variance":       _var(all_),
            "FIN Flag Count":               flow.fin_count,
            "SYN Flag Count":               flow.syn_count,
            "RST Flag Count":               flow.rst_count,
            "PSH Flag Count":               flow.psh_count,
            "ACK Flag Count":               flow.ack_count,
            "URG Flag Count":               flow.urg_count,
            "CWE Flag Count":               flow.cwe_count,
            "ECE Flag Count":               flow.ece_count,
            "Down/Up Ratio":                0,
            "Average Packet Size":          _mean(all_),
            "Avg Fwd Segment Size":         _mean(fwd),
            "Avg Bwd Segment Size":         0,
            "Fwd Header Length.1":          flow.fwd_header_len,
            "Fwd Avg Bytes/Bulk":           0,
            "Fwd Avg Packets/Bulk":         0,
            "Fwd Avg Bulk Rate":            0,
            "Bwd Avg Bytes/Bulk":           0,
            "Bwd Avg Packets/Bulk":         0,
            "Bwd Avg Bulk Rate":            0,
            "Subflow Fwd Packets":          len(fwd),
            "Subflow Fwd Bytes":            sum(fwd),
            "Subflow Bwd Packets":          0,
            "Subflow Bwd Bytes":            0,
            "Init_Win_bytes_forward":       flow.init_fwd_win,
            "Init_Win_bytes_backward":      0,
            "act_data_pkt_fwd":             flow.act_data_fwd,
            "min_seg_size_forward":         flow.min_seg_fwd if flow.min_seg_fwd < 65535 else 0,
            "Active Mean":                  0,
            "Active Std":                   0,
            "Active Max":                   0,
            "Active Min":                   0,
            "Idle Mean":                    0,
            "Idle Std":                     0,
            "Idle Max":                     0,
            "Idle Min":                     0,
        }

        if len(self._flows) > 10_000:
            self._purge_expired()

        return feat

    def _purge_expired(self) -> None:
        now     = time.time()
        expired = [k for k, v in self._flows.items() if now - v.last_time > self._timeout]
        for k in expired:
            del self._flows[k]
