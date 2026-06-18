# 🛡 ShieldNet — Autonomous AI Security Operations Platform

Enterprise-grade cybersecurity monitoring platform with real-time threat detection,
AI-powered analysis, and a comprehensive SOC dashboard.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11 · FastAPI · SQLAlchemy · SQLite |
| ML | Scikit-learn 1.4.2 · Isolation Forest · SHAP |
| Network | Scapy (live packet capture) |
| Frontend | React 18 · Vite · Tailwind CSS · Recharts · Framer Motion |
| Real-time | FastAPI WebSockets (native, no Socket.IO) |

---

## 🚀 Quick Start Guide

Welcome to ShieldNet! Follow these steps to get everything running on your local machine.

### Prerequisites
- Python 3.11+
- Node.js & npm (latest LTS)
- **(Windows Only)**: To use the real-time packet capture feature, you MUST install [Npcap](https://npcap.com/) (install it with "WinPcap API-compatible mode" enabled). Without this, the system will only run in simulation mode.

---

### Step 1: Start the Backend (AI & API)

Open your first terminal and run:

```bash
# 1. Clone the repository and enter the folder
git clone https://github.com/Akshatverma79/ShieldNet.git
cd ShieldNet

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # On Windows
# source venv/bin/activate     # On Linux / macOS

# 3. Install all required Python packages
pip install -r backend/requirements.txt

# 4. Start the FastAPI server (runs on port 8000)
python run.py
```
*API Docs will be available at: http://localhost:8000/docs*

---

### Step 2: Start the Frontend (React Dashboard)

Open a **second** terminal window and run:

```bash
# 1. Enter the frontend folder
cd frontend

# 2. Install all Node dependencies
npm install

# 3. Start the Vite development server
npm run dev
```
*Dashboard will be available at: http://localhost:3000*

---

### Step 3: Generating Threats!
Once both servers are running, open `http://localhost:3000` in your browser. 
- You will see live network traffic if you installed Npcap.
- To generate attacks manually, go to the **Simulation Lab** tab and click the DDoS, Port Scan, or Brute Force buttons!

---

### Step 4 (Optional): Share Your Dashboard via ngrok
If you want to share your locally-running dashboard with someone over the internet:
1. Download `ngrok` and authenticate it with your free token.
2. Open a **third** terminal and run: `ngrok http 3000`
3. Send the generated `https://...ngrok-free.app` link to your friends! 
*(Note: Both `python run.py` and `npm run dev` must be running for the link to work).*

---

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/dashboard` | Dashboard | SOC overview — 5 live charts + threat feed + attack prediction |
| `/incidents` | Incidents | Create/track/resolve security incidents with MITRE mapping |
| `/history` | Threat Logs | Searchable, filterable, paginated log of all events |
| `/copilot` | AI Copilot | Conversational AI for threat analysis and recommendations |
| `/xai` | XAI Dashboard | Model explainability — feature importance + per-prediction SHAP |
| `/intel` | Threat Intel | IP reputation lookup and blacklist checking |
| `/vulnerabilities` | Vulnerabilities | Port/service vulnerability scanner |
| `/user-risk` | User Risk | Device and user behaviour risk scoring |
| `/honeypot` | Honeypot | Fake service traps — capture attacker behaviour |
| `/compliance` | Compliance | NIST · ISO 27001 · CIS Controls scoring |
| `/simulation` | Simulation Lab | Inject synthetic DDoS/PortScan/BruteForce attacks |
| `/redblue` | Red vs Blue | Adversarial team exercise mode |
| `/learning` | ML Pipeline | Continuous learning pipeline status |
| `/reports` | Reports | Executive report generation with CSV/TXT export |
| `/settings` | Settings | Platform configuration |

---

## Architecture

```
ShieldNet/
├── backend/
│   ├── app.py                 ← FastAPI entry point (v3.0.0)
│   ├── config.py              ← Central configuration
│   ├── run.py                 ← Dev launcher with hot-reload (at project root)
│   ├── api/
│   │   ├── routes.py          ← Dashboard, logs, charts, sim, threat intel, WebSocket
│   │   ├── prediction.py      ← POST /api/predict (thread-pool, non-blocking)
│   │   ├── copilot.py         ← AI Copilot chat + threat analysis
│   │   ├── incidents.py       ← Incident management CRUD
│   │   ├── vulnerabilities.py ← Vulnerability scanner
│   │   ├── advanced.py        ← Prediction, risk scoring, honeypot, compliance, XAI, Red/Blue, ML pipeline
│   │   └── websocket.py       ← Async-safe connection manager
│   ├── database/
│   │   ├── models.py          ← ThreatLog, SystemStats, Incident, Vulnerability
│   │   └── database.py        ← SQLAlchemy engine (SQLite / PostgreSQL)
│   ├── ml/
│   │   ├── predict.py         ← Lazy-loaded Isolation Forest + heuristic classifier
│   │   ├── train.py           ← Training script (run with python -m backend.ml.train)
│   │   └── preprocessing.py   ← CICIDS2017 multi-CSV preprocessor
│   ├── simulation/            ← DDoS / PortScan / BruteForce payload generators
│   ├── network/               ← Live Scapy packet capture + CICIDS feature extractor
│   └── models/                ← Trained .pkl artefacts
└── frontend/
    └── src/
        ├── pages/             ← 15 full-featured pages
        ├── components/        ← Layout, AlertFeed, StatCard, SeverityBadge
        └── services/          ← Axios API client + WebSocket singleton
```

---

## Key Features

- **Real-time threat detection** — Isolation Forest anomaly detection on 78 CICIDS2017 features
- **Attack classification** — DDoS, Port Scan, Brute Force, Web Attack, Infiltration, Unknown Threat
- **Risk scoring** — 0–100 blended from anomaly score + attack profile calibration
- **SHAP explainability** — Human-readable feature contributions (with heuristic fallback)
- **WebSocket live feed** — All threat events pushed instantly to the dashboard
- **AI Copilot** — Rule-based security assistant with MITRE ATT&CK mapping
- **Incident management** — Full CRUD, playbook steps, analyst notes, status workflow
- **Compliance** — NIST CSF, ISO 27001, CIS Controls live scoring
- **Red vs Blue** — Interactive adversarial exercise with scoring
- **ML Pipeline** — Continuous learning status with retrain trigger

---

## Security Notes

- Model `.pkl` files must be trained with the **same scikit-learn version** as the venv (`1.4.2`).
  If you see `InconsistentVersionWarning`, run: `python -m backend.ml.train`
- Live packet capture (`/network/packet_capture.py`) requires admin/root privileges.
- The simulation module generates **synthetic** traffic — no real packets are sent.
