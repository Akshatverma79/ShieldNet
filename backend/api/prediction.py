"""
ShieldNet Prediction API
POST /api/predict  —  run the ML pipeline on a feature vector.

predict() is CPU-bound (sklearn inference) so it runs in FastAPI's
thread-pool via run_in_threadpool to avoid blocking the event loop.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database.database import get_db, SessionLocal
from backend.database.models import ThreatLog
from backend.ml.predict import predict
from backend.api.websocket import manager

router = APIRouter(prefix="/api", tags=["Prediction"])
logger = logging.getLogger("shieldnet.prediction")


# ── Schemas ─────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    src_ip:   str  = Field(default="0.0.0.0")
    dst_ip:   str  = Field(default="0.0.0.0")
    src_port: int  = Field(default=0)
    dst_port: int  = Field(default=0)
    protocol: str  = Field(default="UNKNOWN")
    features: Dict = Field(default_factory=dict)

    class Config:
        extra = "allow"


class PredictResponse(BaseModel):
    status:      str
    attack_type: str
    risk_score:  float
    confidence:  float
    severity:    str
    reason:      List[str]
    log_id:      int


# ── Route ────────────────────────────────────────────────────────

@router.post("/predict", response_model=PredictResponse, summary="Run threat detection")
async def run_prediction(payload: PredictRequest):
    """
    Runs Isolation Forest + heuristic classifier, persists the result,
    and broadcasts it to all WebSocket clients.

    predict() is CPU-bound — executed in a thread-pool worker so the
    event loop is never blocked.
    """
    try:
        feature_input = dict(payload.features)
        if payload.dst_port:
            feature_input.setdefault("Destination Port", payload.dst_port)

        # ── Run CPU-bound ML work in a thread ────────────────────
        def _infer_and_persist() -> tuple:
            result = predict(feature_input)

            # Own session inside the thread — not thread-safe to share
            db = SessionLocal()
            try:
                log = ThreatLog(
                    timestamp        = datetime.now(timezone.utc),
                    source_ip        = payload.src_ip,
                    destination_ip   = payload.dst_ip,
                    source_port      = payload.src_port,
                    destination_port = payload.dst_port,
                    protocol         = payload.protocol,
                    status           = result["status"],
                    attack_type      = result["attack_type"],
                    risk_score       = result["risk_score"],
                    confidence       = result["confidence"],
                    severity         = result["severity"],
                    reason           = json.dumps(result["reason"]),
                    packet_size      = int(feature_input.get("Max Packet Length", 0)),
                    flow_duration    = float(feature_input.get("Flow Duration", 0)),
                )
                db.add(log)
                db.commit()
                db.refresh(log)
                return result, log.to_dict()
            finally:
                db.close()

        result, log_dict = await run_in_threadpool(_infer_and_persist)

        # ── Broadcast on the event loop ──────────────────────────
        await manager.broadcast({"event": "prediction", "data": log_dict})

        logger.info(
            "Prediction: %s | risk=%.1f | id=%d",
            result["status"], result["risk_score"], log_dict["id"],
        )

        return PredictResponse(
            status      = result["status"],
            attack_type = result["attack_type"],
            risk_score  = result["risk_score"],
            confidence  = result["confidence"],
            severity    = result["severity"],
            reason      = result["reason"],
            log_id      = log_dict["id"],
        )

    except Exception as exc:
        logger.error("Prediction error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))
