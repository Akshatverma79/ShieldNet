"""
ShieldNet Configuration
Central config loaded from environment variables with sane defaults.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ─── Application ────────────────────────────────────────────────
APP_NAME = "ShieldNet"
APP_VERSION = "3.0.0"
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# ─── Server ─────────────────────────────────────────────────────
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", 8000))

# ─── Database ───────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'shieldnet.db')}"
)

# ─── ML Model Paths ─────────────────────────────────────────────
MODELS_DIR = os.path.join(BASE_DIR, "models")
ANOMALY_MODEL_PATH = os.path.join(MODELS_DIR, "anomaly_model.pkl")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.pkl")
FEATURES_PATH = os.path.join(MODELS_DIR, "features.json")

# ─── CORS ───────────────────────────────────────────────────────
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

# ─── Threat Thresholds ──────────────────────────────────────────
RISK_HIGH_THRESHOLD = 75
RISK_MEDIUM_THRESHOLD = 40

# ─── Simulation ─────────────────────────────────────────────────
SIMULATION_INTERVAL = float(os.getenv("SIMULATION_INTERVAL", "1.0"))  # seconds
