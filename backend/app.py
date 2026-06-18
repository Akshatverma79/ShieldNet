"""
ShieldNet — Main FastAPI Application
Entry point. Registers all routers, middleware, startup/shutdown hooks.
"""
from __future__ import annotations
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import APP_NAME, APP_VERSION, CORS_ORIGINS, HOST, PORT, DEBUG
from backend.utils.logger import setup_logging
import json
from datetime import datetime, timezone
from fastapi.concurrency import run_in_threadpool

from backend.database.database import init_db, get_db_session
from backend.database.models import ThreatLog
from backend.api.websocket import manager
from backend.network.packet_capture import PacketCapture
from backend.api.routes import router as main_router
from backend.api.prediction import router as predict_router
from backend.api.copilot import router as copilot_router
from backend.api.incidents import router as incidents_router
from backend.api.vulnerabilities import router as vulns_router
from backend.api.advanced import router as advanced_router

# ─── Logging ────────────────────────────────────────────────────
setup_logging("DEBUG" if DEBUG else "INFO")
logger = logging.getLogger("shieldnet.app")


# ─── Lifespan (replaces deprecated @app.on_event) ───────────────
def _save_packet_log(result: dict) -> dict:
    try:
        with get_db_session() as db:
            log = ThreatLog(
                timestamp        = datetime.now(timezone.utc),
                source_ip        = result.get("src_ip", "0.0.0.0"),
                destination_ip   = result.get("dst_ip", "0.0.0.0"),
                source_port      = result.get("src_port", 0),
                destination_port = result.get("dst_port", 0),
                protocol         = result.get("protocol", "UNKNOWN"),
                status           = result.get("status", "NORMAL"),
                attack_type      = result.get("attack_type", "N/A"),
                risk_score       = result.get("risk_score", 0.0),
                confidence       = result.get("confidence", 0.0),
                severity         = result.get("severity", "LOW"),
                reason           = json.dumps(result.get("reasons", [])),
                packet_size      = result.get("packet_size", 0),
                flow_duration    = result.get("flow_duration", 0.0),
            )
            db.add(log)
            db.flush()
            db.refresh(log)
            return log.to_dict()
    except Exception as e:
        logger.error(f"Error saving packet log: {e}")
        return {}

async def on_packet_result(result: dict):
    if not result:
        return
    log_dict = await run_in_threadpool(_save_packet_log, result)
    if log_dict:
        await manager.broadcast({"event": "new_threat", "data": log_dict})

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("=" * 50)
    logger.info("  %s v%s  starting up", APP_NAME, APP_VERSION)
    logger.info("=" * 50)
    init_db()
    logger.info("Database initialised.")
    
    capture = PacketCapture(on_result=on_packet_result)
    capture.start()
    
    yield
    # Shutdown
    capture.stop()
    logger.info("ShieldNet shutting down…")


# ─── FastAPI instance ────────────────────────────────────────────
app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description=(
        "ShieldNet — AI-powered cybersecurity monitoring platform. "
        "Real-time threat detection, classification, and SOC dashboard."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ─── CORS ────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ─────────────────────────────────────────────────────
app.include_router(main_router)
app.include_router(predict_router)
app.include_router(copilot_router)
app.include_router(incidents_router)
app.include_router(vulns_router)
app.include_router(advanced_router)


# ─── Root ────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status":  "operational 🚀",
        "docs":    "/docs",
    }


# ─── Dev runner ──────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app:app", host=HOST, port=PORT, reload=DEBUG)
