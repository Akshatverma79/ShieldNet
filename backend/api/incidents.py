"""
ShieldNet Incident Management API
GET    /api/incidents           — list all incidents (paginated)
POST   /api/incidents           — create incident manually
GET    /api/incidents/{id}      — get single incident
PATCH  /api/incidents/{id}      — update status / notes
DELETE /api/incidents/{id}      — delete incident
POST   /api/incidents/auto      — auto-create from a threat log
GET    /api/incidents/stats     — summary counts
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Incident, ThreatLog
from backend.api.websocket import manager

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])
logger = logging.getLogger("shieldnet.incidents")

# MITRE map (shared constant — copied here to avoid circular import)
_MITRE_MAP = {
    "DDoS":        {"id": "T1498", "tactic": "Impact",              "name": "Network Denial of Service"},
    "Port Scan":   {"id": "T1046", "tactic": "Discovery",           "name": "Network Service Discovery"},
    "Brute Force": {"id": "T1110", "tactic": "Credential Access",   "name": "Brute Force"},
    "Web Attack":  {"id": "T1190", "tactic": "Initial Access",      "name": "Exploit Public-Facing Application"},
    "Infiltration":{"id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol"},
    "Unknown Threat":{"id":"T1059","tactic": "Execution",           "name": "Command and Scripting Interpreter"},
}

_PLAYBOOK = {
    "DDoS":        ["Analyse inbound traffic volume", "Block source IPs at perimeter", "Activate upstream scrubbing", "Generate executive report", "Notify NOC"],
    "Port Scan":   ["Identify scanning source", "Block at firewall", "Review exposed service list", "Enable IDS signatures", "Document findings"],
    "Brute Force": ["Identify targeted account/service", "Lock account / block IP", "Enable MFA", "Audit auth logs", "Notify account owner"],
    "Web Attack":  ["Identify exploited endpoint", "Block in WAF", "Patch vulnerability", "Review access logs", "Assess data exposure"],
    "Infiltration":["Isolate host", "Capture forensic image", "Revoke credentials", "Escalate to IR team", "Preserve evidence chain"],
    "Unknown Threat":["Quarantine source", "Capture full packet trace", "Submit for analysis", "Elevate monitoring", "Create IR ticket"],
}


# ── Schemas ─────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title:       str
    description: str              = ""
    severity:    str              = "MEDIUM"
    attack_type: str              = "Unknown Threat"
    source_ip:   str              = "0.0.0.0"
    log_id:      Optional[int]    = None

class IncidentUpdate(BaseModel):
    status:      Optional[str] = None   # OPEN | INVESTIGATING | RESOLVED | CLOSED
    notes:       Optional[str] = None
    assigned_to: Optional[str] = None


# ── Routes ───────────────────────────────────────────────────────

@router.get("/stats", summary="Incident summary counts")
def get_stats(db: Session = Depends(get_db)) -> dict:
    total       = db.query(func.count(Incident.id)).scalar() or 0
    open_cnt    = db.query(func.count(Incident.id)).filter(Incident.status == "OPEN").scalar() or 0
    invest_cnt  = db.query(func.count(Incident.id)).filter(Incident.status == "INVESTIGATING").scalar() or 0
    resolved    = db.query(func.count(Incident.id)).filter(Incident.status.in_(["RESOLVED","CLOSED"])).scalar() or 0
    critical    = db.query(func.count(Incident.id)).filter(Incident.severity == "CRITICAL").scalar() or 0
    return {
        "total": total, "open": open_cnt, "investigating": invest_cnt,
        "resolved": resolved, "critical": critical,
    }


@router.get("", summary="List incidents")
def list_incidents(
    page:     int           = Query(1, ge=1),
    per_page: int           = Query(20, ge=1, le=100),
    status:   Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> dict:
    q = db.query(Incident).order_by(desc(Incident.created_at))
    if status:
        q = q.filter(Incident.status == status.upper())
    if severity:
        q = q.filter(Incident.severity == severity.upper())
    total  = q.count()
    items  = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total, "page": page, "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "incidents": [i.to_dict() for i in items],
    }


@router.get("/{incident_id}", summary="Get single incident")
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> dict:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc.to_dict()


@router.post("", summary="Create incident manually", status_code=201)
async def create_incident(body: IncidentCreate, db: Session = Depends(get_db)) -> dict:
    mitre    = _MITRE_MAP.get(body.attack_type, _MITRE_MAP["Unknown Threat"])
    playbook = _PLAYBOOK.get(body.attack_type, _PLAYBOOK["Unknown Threat"])

    inc = Incident(
        title        = body.title,
        description  = body.description,
        severity     = body.severity.upper(),
        status       = "OPEN",
        attack_type  = body.attack_type,
        source_ip    = body.source_ip,
        mitre_id     = mitre["id"],
        mitre_tactic = mitre["tactic"],
        playbook     = json.dumps(playbook),
        log_id       = body.log_id,
        created_at   = datetime.utcnow(),
        updated_at   = datetime.utcnow(),
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    inc_dict = inc.to_dict()

    await manager.broadcast({"event": "incident_created", "data": inc_dict})
    logger.info("Incident created id=%d title=%s", inc.id, inc.title)
    return inc_dict


@router.post("/auto", summary="Auto-create incident from threat log")
async def auto_create(log_id: int, db: Session = Depends(get_db)) -> dict:
    """Automatically create an incident from a ThreatLog entry."""
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"ThreatLog {log_id} not found")
    if log.status != "THREAT":
        raise HTTPException(status_code=400, detail="Log is not a THREAT — no incident needed")

    mitre    = _MITRE_MAP.get(log.attack_type, _MITRE_MAP["Unknown Threat"])
    playbook = _PLAYBOOK.get(log.attack_type, _PLAYBOOK["Unknown Threat"])

    inc = Incident(
        title        = f"{log.attack_type} from {log.source_ip}",
        description  = (
            f"Automated incident from ThreatLog #{log_id}. "
            f"Risk score: {log.risk_score:.1f}%. "
            f"Protocol: {log.protocol}. "
            f"Destination: {log.destination_ip}:{log.destination_port}."
        ),
        severity     = log.severity,
        status       = "OPEN",
        attack_type  = log.attack_type,
        source_ip    = log.source_ip,
        mitre_id     = mitre["id"],
        mitre_tactic = mitre["tactic"],
        playbook     = json.dumps(playbook),
        log_id       = log.id,
        created_at   = datetime.utcnow(),
        updated_at   = datetime.utcnow(),
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)

    await manager.broadcast({"event": "incident_created", "data": inc.to_dict()})
    return inc.to_dict()


@router.patch("/{incident_id}", summary="Update incident status or notes")
async def update_incident(
    incident_id: int, body: IncidentUpdate, db: Session = Depends(get_db)
) -> dict:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if body.status:
        inc.status = body.status.upper()
    if body.notes is not None:
        inc.notes = body.notes
    if body.assigned_to is not None:
        inc.assigned_to = body.assigned_to
    inc.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(inc)
    await manager.broadcast({"event": "incident_updated", "data": inc.to_dict()})
    return inc.to_dict()


@router.delete("/{incident_id}", summary="Delete incident")
def delete_incident(incident_id: int, db: Session = Depends(get_db)) -> Response:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(inc)
    db.commit()
    return Response(status_code=204)
