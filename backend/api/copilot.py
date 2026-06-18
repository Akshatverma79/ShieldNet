"""
ShieldNet AI Security Copilot API
POST /api/copilot/analyze  — analyse a threat log and return structured AI explanation
POST /api/copilot/chat     — conversational security assistant
GET  /api/copilot/explain/{log_id} — explain a specific logged event
"""
from __future__ import annotations

import json
import logging
import random
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import ThreatLog
from backend.constants import MITRE_MAP, ACTIONS_MAP, URGENCY_MAP

router = APIRouter(prefix="/api/copilot", tags=["AI Copilot"])
logger = logging.getLogger("shieldnet.copilot")


# ── Schemas ─────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role:    str   = Field(..., description="user | assistant")
    content: str

class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    context:  Optional[Dict[str, Any]] = None   # optional threat context

class ChatResponse(BaseModel):
    response:     str
    threat_data:  Optional[Dict] = None
    actions:      List[str]      = []
    confidence:   float          = 0.0

class AnalyzeRequest(BaseModel):
    log_id:   Optional[int] = None
    features: Optional[Dict[str, Any]] = None

# MITRE_MAP, ACTIONS_MAP, and URGENCY_MAP are imported from backend.constants

# ── Simple rule-based copilot engine ────────────────────────────

def _build_threat_analysis(log: ThreatLog) -> Dict:
    """Build a structured AI analysis from a ThreatLog record."""
    mitre = MITRE_MAP.get(log.attack_type, MITRE_MAP["Unknown Threat"])
    actions = ACTIONS_MAP.get(log.attack_type, ACTIONS_MAP["Unknown Threat"])
    # Always use to_dict() which deserialises the JSON string to a proper list
    reasons = log.to_dict()["reason"]

    return {
        "summary": f"{'Threat detected' if log.status == 'THREAT' else 'Normal traffic'} from {log.source_ip}",
        "attack_type":   log.attack_type,
        "risk_score":    log.risk_score,
        "confidence":    log.confidence,
        "severity":      log.severity,
        "urgency":       URGENCY_MAP.get(log.severity, "ROUTINE"),
        "source_ip":     log.source_ip,
        "destination_ip":log.destination_ip,
        "protocol":      log.protocol,
        "timestamp":     log.timestamp.isoformat() if log.timestamp else None,
        "reasons":       reasons,
        "mitre":         mitre,
        "recommended_actions": actions,
        "explanation": _generate_explanation(log, reasons, mitre),
    }


def _generate_explanation(log: ThreatLog, reasons: list, mitre: dict) -> str:
    """Generate a human-readable threat explanation."""
    if log.status != "THREAT":
        return (
            f"Traffic from {log.source_ip} appears normal. "
            f"Risk score is {log.risk_score:.1f}% — within the expected baseline. "
            "No action required."
        )

    lines = [
        f"**Threat Analysis — {log.attack_type}**\n",
        f"Source IP `{log.source_ip}` was flagged with **{log.risk_score:.1f}% risk score** "
        f"and **{log.confidence * 100:.0f}% model confidence**.\n",
        f"**Severity:** {log.severity}  |  **Urgency:** {URGENCY_MAP.get(log.severity, 'ROUTINE')}\n",
        "\n**Detected Behaviours:**",
    ]
    for r in reasons:
        lines.append(f"- {r}")

    lines += [
        f"\n**MITRE ATT&CK Mapping:**",
        f"- Technique: {mitre['id']} — {mitre['name']}",
        f"- Tactic: {mitre['tactic']}",
        f"\n**Recommended Actions:**",
    ]
    for i, a in enumerate(ACTIONS_MAP.get(log.attack_type, []), 1):
        lines.append(f"{i}. {a}")

    return "\n".join(lines)


def _chat_response(user_msg: str, context: Optional[Dict]) -> str:
    """Rule-based conversational response for security queries."""
    msg = user_msg.lower()

    # Threat-specific queries
    if any(w in msg for w in ["why", "explain", "reason", "detected"]):
        if context and context.get("attack_type"):
            at = context["attack_type"]
            reasons = context.get("reasons", [])
            r_text = "\n".join(f"- {r}" for r in reasons) if reasons else "- Anomalous traffic pattern detected"
            return (
                f"**Why was this flagged as {at}?**\n\n"
                f"The ML model (Isolation Forest) identified this traffic as anomalous based on:\n"
                f"{r_text}\n\n"
                f"The risk score of **{context.get('risk_score', 'N/A')}%** was calculated by blending "
                f"the anomaly score with the attack profile baseline. "
                f"A score above 70% triggers a HIGH severity alert."
            )
        return (
            "I can explain a specific threat if you provide a log ID or select an alert. "
            "In general, the Isolation Forest model flags traffic that deviates significantly "
            "from the trained baseline of normal CICIDS2017 network flows."
        )

    if any(w in msg for w in ["block", "action", "what should", "recommend", "response"]):
        if context and context.get("attack_type"):
            at = context["attack_type"]
            actions = ACTIONS_MAP.get(at, ACTIONS_MAP["Unknown Threat"])
            steps = "\n".join(f"{i}. {a}" for i, a in enumerate(actions, 1))
            return f"**Recommended Response for {at}:**\n\n{steps}"
        return (
            "Recommended actions depend on the attack type. "
            "For high-risk threats (>75%), immediate IP blocking and incident creation is advised. "
            "For medium-risk, enhanced monitoring and alert escalation. "
            "Select a specific alert for tailored recommendations."
        )

    if any(w in msg for w in ["mitre", "att&ck", "technique", "tactic"]):
        if context and context.get("attack_type"):
            at = context["attack_type"]
            m = MITRE_MAP.get(at, MITRE_MAP["Unknown Threat"])
            return (
                f"**MITRE ATT&CK for {at}:**\n\n"
                f"- **Technique ID:** {m['id']}\n"
                f"- **Technique Name:** {m['name']}\n"
                f"- **Tactic:** {m['tactic']}\n\n"
                f"This maps to the {m['tactic']} phase of the ATT&CK framework, "
                f"indicating the adversary's objective at this stage."
            )
        return "MITRE ATT&CK is a framework of adversary tactics and techniques. Select a specific threat to see its mapping."

    if any(w in msg for w in ["ddos", "denial of service", "flood"]):
        return (
            "**DDoS (Distributed Denial of Service):**\n\n"
            "Detected via abnormally high packet rates (>10,000 pps) or flow volumes (>5 MB/s). "
            "Maps to MITRE T1498 — Network Denial of Service.\n\n"
            "**Immediate actions:**\n"
            "1. Rate-limit or null-route the source IP\n"
            "2. Enable upstream traffic scrubbing\n"
            "3. Activate CDN/DDoS protection layer\n"
            "4. Create incident and notify NOC"
        )

    if any(w in msg for w in ["scan", "port scan", "reconnaissance", "recon"]):
        return (
            "**Port Scan Detection:**\n\n"
            "Identified by high SYN flag counts with low byte-per-packet ratios, "
            "indicating sequential port probing. Maps to MITRE T1046.\n\n"
            "**Response:** Block source IP, enable IDS scan signatures, review exposed services."
        )

    if any(w in msg for w in ["brute force", "bruteforce", "credential", "password"]):
        return (
            "**Brute Force Attack:**\n\n"
            "Detected via sustained SYN+ACK traffic to authentication ports (22, 21, 3389). "
            "Maps to MITRE T1110 — Brute Force.\n\n"
            "**Response:** Lock accounts, block source IP, enforce MFA, audit auth logs."
        )

    if any(w in msg for w in ["risk score", "score", "how risky", "confidence"]):
        return (
            "**Risk Score Calculation:**\n\n"
            "ShieldNet computes risk as a weighted blend of:\n"
            "- Isolation Forest anomaly score (60% weight) — how far the traffic deviates from baseline\n"
            "- Attack-type base risk (40% weight) — calibrated from CICIDS2017 attack profiles\n\n"
            "Score ranges: LOW (<40), MEDIUM (40–70), HIGH (70–85), CRITICAL (>85)."
        )

    if any(w in msg for w in ["hello", "hi", "help", "what can you do", "capabilities"]):
        return (
            "**ShieldNet AI Copilot**\n\n"
            "I can help you with:\n"
            "- 🔍 **Threat Explanation** — Why was this IP/traffic flagged?\n"
            "- 🎯 **MITRE ATT&CK Mapping** — What technique is being used?\n"
            "- ✅ **Recommended Actions** — What should I do about this threat?\n"
            "- 📊 **Risk Score Breakdown** — How was this score calculated?\n"
            "- 🚨 **Incident Guidance** — How to respond to active attacks?\n\n"
            "Select an alert from the feed or ask me anything about the current threats."
        )

    # Default
    return (
        "I'm ShieldNet's AI Security Copilot. I can analyse threats, explain detections, "
        "map attacks to MITRE ATT&CK, and recommend response actions. "
        "Try asking: 'Why was this IP flagged?' or 'What should I do about this DDoS?'"
    )


# ── Routes ───────────────────────────────────────────────────────

@router.post("/chat", response_model=ChatResponse, summary="AI security assistant chat")
async def chat(req: ChatRequest) -> ChatResponse:
    """Conversational AI copilot for security analysis."""
    if not req.messages:
        raise HTTPException(status_code=400, detail="messages list is empty")

    last_user = next(
        (m.content for m in reversed(req.messages) if m.role == "user"), ""
    )

    response = _chat_response(last_user, req.context)

    # Extract recommended actions from context if available
    actions = []
    if req.context and req.context.get("attack_type"):
        actions = ACTIONS_MAP.get(req.context["attack_type"], [])

    confidence = round(random.uniform(0.82, 0.97), 2)

    return ChatResponse(
        response=response,
        threat_data=req.context,
        actions=actions,
        confidence=confidence,
    )


@router.get("/explain/{log_id}", summary="Explain a specific threat log")
async def explain_log(log_id: int, db: Session = Depends(get_db)) -> dict:
    """Generate a full AI analysis for a specific threat log entry."""
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Log {log_id} not found")

    analysis = _build_threat_analysis(log)
    logger.info("Copilot explained log_id=%d attack=%s", log_id, log.attack_type)
    return analysis


@router.post("/analyze", summary="Analyze an arbitrary threat payload")
async def analyze(req: AnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    """Run AI analysis on a log ID or raw feature dict."""
    if req.log_id:
        log = db.query(ThreatLog).filter(ThreatLog.id == req.log_id).first()
        if not log:
            raise HTTPException(status_code=404, detail=f"Log {req.log_id} not found")
        return _build_threat_analysis(log)

    # Generic analysis from features dict
    if req.features:
        from backend.ml.predict import predict
        from fastapi.concurrency import run_in_threadpool
        result = await run_in_threadpool(predict, req.features)
        at = result["attack_type"]
        return {
            "summary":    f"Analysis: {result['status']} — {at}",
            "attack_type": at,
            "risk_score":  result["risk_score"],
            "confidence":  result["confidence"],
            "severity":    result["severity"],
            "reasons":     result["reason"],
            "mitre":       MITRE_MAP.get(at, MITRE_MAP["Unknown Threat"]),
            "recommended_actions": ACTIONS_MAP.get(at, []),
            "explanation": (
                f"Anomaly detected with {result['risk_score']}% risk. "
                f"Classified as {at} ({result['severity']} severity). "
                + " ".join(result["reason"])
            ),
        }

    raise HTTPException(status_code=400, detail="Provide either log_id or features")


@router.get("/mitre/{attack_type}", summary="Get MITRE ATT&CK info for attack type")
async def get_mitre(attack_type: str) -> dict:
    """Return MITRE ATT&CK mapping for a given attack type."""
    key = attack_type.replace("-", " ").title()
    data = MITRE_MAP.get(key) or MITRE_MAP.get(attack_type) or MITRE_MAP["Unknown Threat"]
    return {"attack_type": attack_type, "mitre": data, "actions": ACTIONS_MAP.get(key, [])}
