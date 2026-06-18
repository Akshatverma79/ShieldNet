"""
ShieldNet Shared Constants
Canonical MITRE ATT&CK mapping and incident playbooks used across modules.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# ── MITRE ATT&CK mapping ────────────────────────────────────────
MITRE_MAP: Dict[str, Dict[str, str]] = {
    "DDoS":          {"id": "T1498", "tactic": "Impact",              "name": "Network Denial of Service"},
    "Port Scan":     {"id": "T1046", "tactic": "Discovery",           "name": "Network Service Discovery"},
    "Brute Force":   {"id": "T1110", "tactic": "Credential Access",   "name": "Brute Force"},
    "Web Attack":    {"id": "T1190", "tactic": "Initial Access",      "name": "Exploit Public-Facing Application"},
    "Infiltration":  {"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol"},
    "Unknown Threat":{"id": "T1059", "tactic": "Execution",           "name": "Command and Scripting Interpreter"},
}

# ── Recommended actions per attack type ─────────────────────────
ACTIONS_MAP: Dict[str, List[str]] = {
    "DDoS":        ["Rate-limit inbound traffic from source IP", "Enable upstream scrubbing / CDN protection", "Notify NOC team immediately", "Create incident report"],
    "Port Scan":   ["Block source IP at firewall", "Enable IDS signatures for reconnaissance", "Review open services on target host", "Log for threat intel feed"],
    "Brute Force": ["Lock account after N failed attempts", "Block source IP", "Enable MFA on targeted service", "Audit authentication logs"],
    "Web Attack":  ["Block malicious request pattern in WAF", "Patch identified vulnerability", "Review application access logs", "Isolate affected endpoint"],
    "Infiltration":["Isolate affected host from network", "Capture memory dump for forensics", "Revoke compromised credentials", "Escalate to IR team"],
    "Unknown Threat":["Quarantine source", "Capture full packet trace", "Submit sample for analysis", "Elevate monitoring sensitivity"],
}

# ── Incident playbooks ─────────────────────────────────────────
PLAYBOOK_MAP: Dict[str, List[str]] = {
    "DDoS":        ["Analyse inbound traffic volume", "Block source IPs at perimeter", "Activate upstream scrubbing", "Generate executive report", "Notify NOC"],
    "Port Scan":   ["Identify scanning source", "Block at firewall", "Review exposed service list", "Enable IDS signatures", "Document findings"],
    "Brute Force": ["Identify targeted account/service", "Lock account / block IP", "Enable MFA", "Audit auth logs", "Notify account owner"],
    "Web Attack":  ["Identify exploited endpoint", "Block in WAF", "Patch vulnerability", "Review access logs", "Assess data exposure"],
    "Infiltration":["Isolate host", "Capture forensic image", "Revoke credentials", "Escalate to IR team", "Preserve evidence chain"],
    "Unknown Threat":["Quarantine source", "Capture full packet trace", "Submit for analysis", "Elevate monitoring", "Create IR ticket"],
}

# ── Severity to response urgency ────────────────────────────────
URGENCY_MAP: Dict[str, str] = {
    "CRITICAL": "IMMEDIATE",
    "HIGH":     "URGENT",
    "MEDIUM":   "ELEVATED",
    "LOW":      "ROUTINE",
}
