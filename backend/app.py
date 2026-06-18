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
from backend.database.database import init_db
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
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("=" * 50)
    logger.info("  %s v%s  starting up", APP_NAME, APP_VERSION)
    logger.info("=" * 50)
    init_db()
    logger.info("Database initialised ✅")
    yield
    # Shutdown
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
