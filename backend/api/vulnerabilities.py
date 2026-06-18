"""
ShieldNet Vulnerability Scanner API
GET  /api/vulnerabilities        — list all findings
POST /api/vulnerabilities/scan   — run a simulated scan
GET  /api/vulnerabilities/stats  — summary stats
"""
from __future__ import annotations

import logging
import random
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.database.database import get_db
from backend.database.models import Vulnerability

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])
logger = logging.getLogger("shieldnet.vulnerabilities")

# ── Simulated vulnerability templates ───────────────────────────
_VULN_TEMPLATES = [
    {"name": "Open SSH Port",           "port": 22,   "service": "SSH",    "severity": "HIGH",
     "description": "SSH port is publicly accessible. Exposed to brute-force attacks.",
     "recommendation": "Restrict SSH access to known IPs. Use key-based auth only. Disable password login."},
    {"name": "Open Telnet Port",         "port": 23,   "service": "Telnet", "severity": "CRITICAL",
     "description": "Telnet transmits data in plaintext including credentials.",
     "recommendation": "Disable Telnet immediately. Replace with SSH."},
    {"name": "Open FTP Port",            "port": 21,   "service": "FTP",    "severity": "HIGH",
     "description": "FTP transfers credentials in plaintext.",
     "recommendation": "Replace FTP with SFTP or FTPS. Block port 21 externally."},
    {"name": "HTTP Without TLS",         "port": 80,   "service": "HTTP",   "severity": "MEDIUM",
     "description": "Web service running without encryption.",
     "recommendation": "Redirect all HTTP traffic to HTTPS. Install valid TLS certificate."},
    {"name": "Open RDP Port",            "port": 3389, "service": "RDP",    "severity": "CRITICAL",
     "description": "Remote Desktop exposed to internet. High risk of credential attacks.",
     "recommendation": "Place RDP behind VPN. Enable NLA. Block 3389 from public internet."},
    {"name": "Open SMB Port",            "port": 445,  "service": "SMB",    "severity": "HIGH",
     "description": "SMB exposed externally. Vulnerable to EternalBlue / ransomware.",
     "recommendation": "Block SMB on perimeter firewall. Ensure patching is current."},
    {"name": "Outdated OpenSSL Version", "port": 443,  "service": "HTTPS",  "severity": "HIGH",
     "description": "Running a version of OpenSSL with known CVEs.",
     "recommendation": "Update OpenSSL to latest stable version immediately."},
    {"name": "MySQL Exposed Externally", "port": 3306, "service": "MySQL",  "severity": "CRITICAL",
     "description": "Database port accessible from the internet.",
     "recommendation": "Restrict MySQL to localhost or internal network only. Use firewall rules."},
    {"name": "Redis Without Auth",       "port": 6379, "service": "Redis",  "severity": "HIGH",
     "description": "Redis instance running without authentication.",
     "recommendation": "Enable requirepass in redis.conf. Bind to localhost only."},
    {"name": "Weak TLS Cipher Suite",    "port": 443,  "service": "HTTPS",  "severity": "MEDIUM",
     "description": "TLS 1.0/1.1 still enabled, supporting weak cipher suites.",
     "recommendation": "Disable TLS 1.0 and 1.1. Enforce TLS 1.2+ with strong cipher suites."},
]

# ── Schemas ─────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str = "127.0.0.1"
    scan_type: str = "quick"   # quick | full


# ── Routes ───────────────────────────────────────────────────────

@router.get("/stats", summary="Vulnerability summary")
def get_stats(db: Session = Depends(get_db)) -> dict:
    total    = db.query(func.count(Vulnerability.id)).scalar() or 0
    critical = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "CRITICAL").scalar() or 0
    high     = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "HIGH").scalar() or 0
    medium   = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "MEDIUM").scalar() or 0
    low      = db.query(func.count(Vulnerability.id)).filter(Vulnerability.severity == "LOW").scalar() or 0
    open_cnt = db.query(func.count(Vulnerability.id)).filter(Vulnerability.status == "OPEN").scalar() or 0
    return {
        "total": total, "critical": critical, "high": high,
        "medium": medium, "low": low, "open": open_cnt,
        "risk_score": min(100, critical * 25 + high * 10 + medium * 3 + low),
    }


@router.get("", summary="List vulnerability findings")
def list_vulns(
    page:     int           = Query(1, ge=1),
    per_page: int           = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status:   Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> dict:
    q = db.query(Vulnerability).order_by(desc(Vulnerability.discovered_at))
    if severity:
        q = q.filter(Vulnerability.severity == severity.upper())
    if status:
        q = q.filter(Vulnerability.status == status.upper())
    total = q.count()
    items = q.offset((page - 1) * per_page).limit(per_page).all()
    return {
        "total": total, "page": page, "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "vulnerabilities": [v.to_dict() for v in items],
    }


@router.post("/scan", summary="Run simulated vulnerability scan", status_code=201)
def run_scan(req: ScanRequest, db: Session = Depends(get_db)) -> dict:
    """
    Runs a simulated port/vulnerability scan against the target.
    In a real deployment this would invoke nmap via subprocess.
    """
    logger.info("Scan requested: target=%s type=%s", req.target, req.scan_type)

    # Determine how many findings to simulate
    n = random.randint(2, 5) if req.scan_type == "quick" else random.randint(4, 8)
    templates = random.sample(_VULN_TEMPLATES, min(n, len(_VULN_TEMPLATES)))

    created = []
    for t in templates:
        v = Vulnerability(
            target          = req.target,
            name            = t["name"],
            port            = t["port"],
            service         = t["service"],
            severity        = t["severity"],
            description     = t["description"],
            recommendation  = t["recommendation"],
            status          = "OPEN",
            discovered_at   = datetime.now(timezone.utc),
        )
        db.add(v)
        db.commit()
        db.refresh(v)
        created.append(v.to_dict())

    return {
        "target":   req.target,
        "scan_type": req.scan_type,
        "findings": len(created),
        "results":  created,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


@router.patch("/{vuln_id}/status", summary="Update vulnerability status")
def update_status(
    vuln_id: int,
    status:  str = Query(..., description="OPEN | MITIGATED | ACCEPTED | FALSE_POSITIVE"),
    db: Session = Depends(get_db),
) -> dict:
    v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    v.status = status.upper()
    db.commit()
    db.refresh(v)
    return v.to_dict()
