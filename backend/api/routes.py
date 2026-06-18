"""
ShieldNet REST API Routes
All non-prediction endpoints: dashboard stats, threat logs,
simulation triggers, threat intelligence, health check.
"""
from __future__ import annotations

import json
import logging
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.api.websocket import manager
from backend.database.database import get_db
from backend.database.models import ThreatLog

router = APIRouter(prefix="/api", tags=["Dashboard"])
logger = logging.getLogger("shieldnet.routes")


# ── WebSocket ────────────────────────────────────────────────────

@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keep-alive; data pushed via broadcast()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception:
        await manager.disconnect(ws)


# ── Dashboard stats ──────────────────────────────────────────────

@router.get("/stats", summary="Real-time dashboard summary")
def get_stats(db: Session = Depends(get_db)) -> dict:
    total          = db.query(func.count(ThreatLog.id)).scalar() or 0
    threats        = db.query(func.count(ThreatLog.id)).filter(ThreatLog.status == "THREAT").scalar() or 0
    normal         = total - threats
    avg_risk       = db.query(func.avg(ThreatLog.risk_score)).scalar() or 0.0
    security_score = max(0.0, round(100 - (threats / max(total, 1)) * 100, 1))

    threat_pct = (threats / max(total, 1)) * 100
    if   threat_pct > 30: threat_level = "CRITICAL"
    elif threat_pct > 15: threat_level = "HIGH"
    elif threat_pct >  5: threat_level = "MEDIUM"
    else:                 threat_level = "LOW"

    return {
        "total_packets":      total,
        "threats_detected":   threats,
        "normal_traffic":     normal,
        "average_risk":       round(avg_risk, 1),
        "security_score":     security_score,
        "threat_level":       threat_level,
        "active_connections": manager.client_count,
    }


# ── Threat logs ──────────────────────────────────────────────────

@router.get("/logs", summary="Paginated threat log history")
def get_logs(
    page:     int           = Query(1,  ge=1),
    per_page: int           = Query(50, ge=1, le=200),
    status:   Optional[str] = Query(None, description="THREAT | NORMAL"),
    severity: Optional[str] = Query(None, description="LOW | MEDIUM | HIGH | CRITICAL"),
    search:   Optional[str] = Query(None, description="Search src/dst IP or attack type"),
    db: Session = Depends(get_db),
) -> dict:
    q = db.query(ThreatLog).order_by(desc(ThreatLog.timestamp))
    if status:
        q = q.filter(ThreatLog.status == status.upper())
    if severity:
        q = q.filter(ThreatLog.severity == severity.upper())
    if search:
        like = f"%{search}%"
        q = q.filter(
            ThreatLog.source_ip.like(like)      |
            ThreatLog.destination_ip.like(like) |
            ThreatLog.attack_type.like(like)
        )
    total  = q.count()
    offset = (page - 1) * per_page
    items  = q.offset(offset).limit(per_page).all()
    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    (total + per_page - 1) // per_page,
        "logs":     [log.to_dict() for log in items],
    }


@router.get("/logs/{log_id}", summary="Single threat log detail")
def get_log(log_id: int, db: Session = Depends(get_db)) -> dict:
    log = db.query(ThreatLog).filter(ThreatLog.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log.to_dict()


# ── Chart data ───────────────────────────────────────────────────

@router.get("/charts/traffic", summary="Traffic volume (last N minutes)")
def get_traffic_chart(
    minutes: int = Query(60, ge=5, le=1440),
    db: Session  = Depends(get_db),
) -> dict:
    since   = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    rows    = db.query(ThreatLog).filter(ThreatLog.timestamp >= since).order_by(ThreatLog.timestamp).all()
    buckets: dict = {}
    for row in rows:
        key = row.timestamp.strftime("%H:%M")
        if key not in buckets:
            buckets[key] = {"time": key, "normal": 0, "threats": 0}
        if row.status == "THREAT":
            buckets[key]["threats"] += 1
        else:
            buckets[key]["normal"]  += 1
    return {"data": list(buckets.values())}


@router.get("/charts/attack-types", summary="Attack type distribution")
def get_attack_distribution(db: Session = Depends(get_db)) -> dict:
    rows = (
        db.query(ThreatLog.attack_type, func.count(ThreatLog.id))
        .filter(ThreatLog.status == "THREAT")
        .group_by(ThreatLog.attack_type)
        .all()
    )
    return {"data": [{"name": r[0], "value": r[1]} for r in rows]}


@router.get("/charts/risk-timeline", summary="Risk score over last N events")
def get_risk_timeline(
    limit: int = Query(50, ge=10, le=200),
    db: Session = Depends(get_db),
) -> dict:
    rows = db.query(ThreatLog).order_by(desc(ThreatLog.timestamp)).limit(limit).all()
    rows.reverse()
    return {
        "data": [
            {"time": r.timestamp.strftime("%H:%M:%S"), "risk": r.risk_score, "status": r.status}
            for r in rows
        ]
    }


# ── Simulation ───────────────────────────────────────────────────

@router.post("/simulate/{attack_type}", summary="Trigger attack simulation")
async def simulate_attack(
    attack_type: str,
    count: int = Query(5, ge=1, le=50),
) -> dict:
    """
    Inject synthetic attack events into the pipeline and broadcast via WS.
    attack_type: ddos | portscan | bruteforce
    """
    from backend.ml.predict import predict as ml_predict

    at = attack_type.lower()
    if   at == "ddos":
        from backend.simulation.ddos_simulator      import generate_ddos_payload       as gen
    elif at == "portscan":
        from backend.simulation.portscan_simulator  import generate_portscan_payload   as gen
    elif at == "bruteforce":
        from backend.simulation.bruteforce_simulator import generate_bruteforce_payload as gen
    else:
        raise HTTPException(
            status_code=400,
            detail="Unknown attack_type. Valid values: ddos, portscan, bruteforce",
        )

    created_ids: list = []

    # Create a fresh session inside the threadpool worker — SQLAlchemy sessions
    # are NOT thread-safe and must not be shared across threads.
    from backend.database.database import SessionLocal

    def _create_logs() -> list:
        worker_db = SessionLocal()
        logs: list = []
        try:
            for _ in range(count):
                payload = gen()
                result  = ml_predict(payload["features"])
                log = ThreatLog(
                    timestamp        = datetime.now(timezone.utc),
                    source_ip        = payload["src_ip"],
                    destination_ip   = payload["dst_ip"],
                    source_port      = payload["src_port"],
                    destination_port = payload["dst_port"],
                    protocol         = payload["protocol"],
                    status           = result["status"],
                    attack_type      = result["attack_type"],
                    risk_score       = result["risk_score"],
                    confidence       = result["confidence"],
                    severity         = result["severity"],
                    reason           = json.dumps(result["reason"]),
                    packet_size      = random.randint(64, 1500),
                    flow_duration    = random.uniform(0.001, 10.0),
                )
                worker_db.add(log)
                worker_db.commit()
                worker_db.refresh(log)
                logs.append(log.to_dict())
        finally:
            worker_db.close()
        return logs

    log_dicts = await run_in_threadpool(_create_logs)

    for log_dict in log_dicts:
        created_ids.append(log_dict["id"])
        await manager.broadcast({"event": "simulation", "data": log_dict})

    return {"message": f"Simulated {count} {at} events", "ids": created_ids}


# ── Threat Intelligence ──────────────────────────────────────────

_BLACKLIST = {
    "45.33.32.156", "198.51.100.1", "203.0.113.42", "192.0.2.1",
    "10.0.0.255",   "172.16.254.1", "185.220.101.1", "91.108.4.1",
}
_IP_REPUTATIONS = {
    "45.33.32.156":  {"label": "Known Scanner",  "country": "US", "threat_type": "Port Scanner"},
    "198.51.100.1":  {"label": "Malware C2",     "country": "RU", "threat_type": "Command & Control"},
    "203.0.113.42":  {"label": "Botnet Node",    "country": "CN", "threat_type": "DDoS Botnet"},
    "185.220.101.1": {"label": "Tor Exit Node",  "country": "DE", "threat_type": "Anonymizer"},
}


@router.get("/threat-intel/{ip}", summary="IP reputation lookup")
def threat_intel(ip: str) -> dict:
    is_blacklisted = ip in _BLACKLIST
    reputation     = _IP_REPUTATIONS.get(ip)
    return {
        "ip":          ip,
        "blacklisted": is_blacklisted,
        "reputation":  reputation or ("Unknown" if not is_blacklisted else "Malicious"),
        "risk_level":  "HIGH" if is_blacklisted else "LOW",
        "details":     reputation or {},
    }


# ── Health ───────────────────────────────────────────────────────

@router.get("/health", summary="System health check")
def health_check() -> dict:
    return {
        "status":    "operational",
        "service":   "ShieldNet",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
