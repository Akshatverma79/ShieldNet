"""
ShieldNet Database Models
SQLAlchemy ORM models for all persistent data.
`reason` is stored as a JSON string in the DB and always returned
as a parsed Python list from to_dict() so all consumers get a consistent type.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ThreatLog(Base):
    """Every analysed network event — normal or malicious."""
    __tablename__ = "threat_logs"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    timestamp        = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    source_ip        = Column(String(45), nullable=False, default="0.0.0.0")
    destination_ip   = Column(String(45), nullable=False, default="0.0.0.0")
    source_port      = Column(Integer, default=0)
    destination_port = Column(Integer, default=0)
    protocol         = Column(String(16), default="UNKNOWN")
    status           = Column(String(32), nullable=False)        # NORMAL | THREAT
    attack_type      = Column(String(64), default="N/A")
    risk_score       = Column(Float, default=0.0)
    confidence       = Column(Float, default=0.0)
    severity         = Column(String(16), default="LOW")         # LOW | MEDIUM | HIGH | CRITICAL
    reason           = Column(Text, default="[]")                # stored as JSON string
    packet_size      = Column(Integer, default=0)
    flow_duration    = Column(Float, default=0.0)

    def to_dict(self) -> dict:
        # Always deserialise reason so callers always receive a list, never a raw string
        try:
            reason_list = json.loads(self.reason or "[]")
        except (ValueError, TypeError):
            reason_list = []

        return {
            "id":               self.id,
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
            "source_ip":        self.source_ip,
            "destination_ip":   self.destination_ip,
            "source_port":      self.source_port,
            "destination_port": self.destination_port,
            "protocol":         self.protocol,
            "status":           self.status,
            "attack_type":      self.attack_type,
            "risk_score":       self.risk_score,
            "confidence":       self.confidence,
            "severity":         self.severity,
            "reason":           reason_list,   # ← always a list now
            "packet_size":      self.packet_size,
            "flow_duration":    self.flow_duration,
        }


class SystemStats(Base):
    """Periodic aggregated snapshot used for traffic trend charts."""
    __tablename__ = "system_stats"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    timestamp        = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    packets_analysed = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    normal_traffic   = Column(Integer, default=0)
    security_score   = Column(Float, default=100.0)

    def to_dict(self) -> dict:
        return {
            "id":               self.id,
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
            "packets_analysed": self.packets_analysed,
            "threats_detected": self.threats_detected,
            "normal_traffic":   self.normal_traffic,
            "security_score":   self.security_score,
        }


class Incident(Base):
    """Security incident created manually or auto-generated from a ThreatLog."""
    __tablename__ = "incidents"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    title        = Column(String(200), nullable=False)
    description  = Column(Text, default="")
    severity     = Column(String(16), default="MEDIUM")    # LOW|MEDIUM|HIGH|CRITICAL
    status       = Column(String(24), default="OPEN")      # OPEN|INVESTIGATING|RESOLVED|CLOSED
    attack_type  = Column(String(64), default="Unknown Threat")
    source_ip    = Column(String(45), default="0.0.0.0")
    mitre_id     = Column(String(16), default="")
    mitre_tactic = Column(String(64), default="")
    playbook     = Column(Text, default="[]")              # JSON list of steps
    notes        = Column(Text, default="")
    assigned_to  = Column(String(64), default="Unassigned")
    log_id       = Column(Integer, nullable=True)          # FK to threat_logs (soft ref)
    created_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        try:
            playbook_list = json.loads(self.playbook or "[]")
        except (ValueError, TypeError):
            playbook_list = []
        return {
            "id":           self.id,
            "title":        self.title,
            "description":  self.description,
            "severity":     self.severity,
            "status":       self.status,
            "attack_type":  self.attack_type,
            "source_ip":    self.source_ip,
            "mitre_id":     self.mitre_id,
            "mitre_tactic": self.mitre_tactic,
            "playbook":     playbook_list,
            "notes":        self.notes,
            "assigned_to":  self.assigned_to,
            "log_id":       self.log_id,
            "created_at":   self.created_at.isoformat() if self.created_at else None,
            "updated_at":   self.updated_at.isoformat() if self.updated_at else None,
        }


class Vulnerability(Base):
    """A vulnerability finding from a port/service scan."""
    __tablename__ = "vulnerabilities"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    target          = Column(String(45), nullable=False)
    name            = Column(String(200), nullable=False)
    port            = Column(Integer, default=0)
    service         = Column(String(64), default="")
    severity        = Column(String(16), default="MEDIUM")  # LOW|MEDIUM|HIGH|CRITICAL
    description     = Column(Text, default="")
    recommendation  = Column(Text, default="")
    status          = Column(String(32), default="OPEN")    # OPEN|MITIGATED|ACCEPTED|FALSE_POSITIVE
    discovered_at   = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "target":         self.target,
            "name":           self.name,
            "port":           self.port,
            "service":        self.service,
            "severity":       self.severity,
            "description":    self.description,
            "recommendation": self.recommendation,
            "status":         self.status,
            "discovered_at":  self.discovered_at.isoformat() if self.discovered_at else None,
        }
