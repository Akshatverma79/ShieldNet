/**
 * ShieldNet API Service — v3.0
 * Central axios instance + all endpoint helpers.
 */
import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_URL || "";

const api = axios.create({
  baseURL: BASE_URL,
  timeout: 15_000,
  headers: { "Content-Type": "application/json" },
});

// ── Response interceptor for consistent error handling ───────────
api.interceptors.response.use(
  (res) => res,
  (err) => {
    const msg = err?.response?.data?.detail || err.message || "Request failed";
    console.error(`[API] ${err?.config?.url} → ${msg}`);
    return Promise.reject(err);
  }
);

// ── Dashboard ─────────────────────────────────────────────────
export const fetchStats         = ()             => api.get("/api/stats");
export const fetchTrafficChart  = (minutes = 60) => api.get(`/api/charts/traffic?minutes=${minutes}`);
export const fetchAttackDist    = ()             => api.get("/api/charts/attack-types");
export const fetchRiskTimeline  = (limit = 50)   => api.get(`/api/charts/risk-timeline?limit=${limit}`);

// ── Threat Logs ───────────────────────────────────────────────
export const fetchLogs = (params = {}) => {
  const q = new URLSearchParams();
  if (params.page)     q.set("page",     params.page);
  if (params.per_page) q.set("per_page", params.per_page);
  if (params.status)   q.set("status",   params.status);
  if (params.severity) q.set("severity", params.severity);
  if (params.search)   q.set("search",   params.search);
  return api.get(`/api/logs?${q.toString()}`);
};
export const fetchLog = (id) => api.get(`/api/logs/${id}`);

// ── Prediction ────────────────────────────────────────────────
export const runPrediction = (payload) => api.post("/api/predict", payload);

// ── Simulation ────────────────────────────────────────────────
export const triggerSimulation = (type, count = 5) =>
  api.post(`/api/simulate/${type}?count=${count}`);

// ── Threat Intel ──────────────────────────────────────────────
export const lookupIP = (ip) => api.get(`/api/threat-intel/${ip}`);

// ── AI Copilot ────────────────────────────────────────────────
export const copilotChat    = (messages, context = null) =>
  api.post("/api/copilot/chat", { messages, context });
export const explainLog     = (log_id) => api.get(`/api/copilot/explain/${log_id}`);
export const analyzePayload = (payload) => api.post("/api/copilot/analyze", payload);
export const getMitre       = (attack_type) => api.get(`/api/copilot/mitre/${encodeURIComponent(attack_type)}`);

// ── Incidents ─────────────────────────────────────────────────
export const fetchIncidentStats  = ()          => api.get("/api/incidents/stats");
export const fetchIncidents      = (params={}) => {
  const q = new URLSearchParams();
  if (params.page)     q.set("page",     params.page);
  if (params.per_page) q.set("per_page", params.per_page);
  if (params.status)   q.set("status",   params.status);
  if (params.severity) q.set("severity", params.severity);
  return api.get(`/api/incidents?${q.toString()}`);
};
export const fetchIncident       = (id)        => api.get(`/api/incidents/${id}`);
export const createIncident      = (body)      => api.post("/api/incidents", body);
export const autoCreateIncident  = (log_id)    => api.post(`/api/incidents/auto?log_id=${log_id}`);
export const updateIncident      = (id, body)  => api.patch(`/api/incidents/${id}`, body);
export const deleteIncident      = (id)        => api.delete(`/api/incidents/${id}`);

// ── Vulnerabilities ───────────────────────────────────────────
export const fetchVulnStats    = ()         => api.get("/api/vulnerabilities/stats");
export const fetchVulns        = (params={}) => {
  const q = new URLSearchParams();
  if (params.page)     q.set("page",     params.page);
  if (params.per_page) q.set("per_page", params.per_page);
  if (params.severity) q.set("severity", params.severity);
  if (params.status)   q.set("status",   params.status);
  return api.get(`/api/vulnerabilities?${q.toString()}`);
};
export const runVulnScan       = (target, scan_type = "quick") =>
  api.post("/api/vulnerabilities/scan", { target, scan_type });
export const updateVulnStatus  = (id, status) =>
  api.patch(`/api/vulnerabilities/${id}/status?status=${status}`);

// ── Health ────────────────────────────────────────────────────
export const healthCheck = () => api.get("/api/health");

// ── Advanced: Attack Prediction ──────────────────────────────
export const fetchForecast     = (w = 30) => api.get(`/api/predict/forecast?window_minutes=${w}`);

// ── Advanced: User/Device Risk ───────────────────────────────
export const fetchUserRisk     = ()       => api.get("/api/risk/users");
export const fetchUserRiskDetail = (ip)   => api.get(`/api/risk/users/${encodeURIComponent(ip)}`);

// ── Advanced: Honeypot ────────────────────────────────────────
export const fetchHoneypotLogs = (limit = 50) => api.get(`/api/honeypot/logs?limit=${limit}`);
export const simulateHoneypot  = ()       => api.post("/api/honeypot/simulate");
export const clearHoneypot     = ()       => api.delete("/api/honeypot/logs");

// ── Advanced: Knowledge Graph ─────────────────────────────────
export const fetchGraphData    = (limit=30) => api.get(`/api/graph/data?limit=${limit}`);

// ── Advanced: Compliance ──────────────────────────────────────
export const fetchCompliance   = ()       => api.get("/api/compliance");

// ── Advanced: XAI ────────────────────────────────────────────
export const fetchFeatureImportance = ()  => api.get("/api/xai/feature-importance");
export const explainPrediction = (id)     => api.get(`/api/xai/explain-prediction?log_id=${id}`);

// ── Advanced: Red/Blue Team ───────────────────────────────────
export const fetchRedBlueState  = ()          => api.get("/api/redblue/state");
export const startRedBlue       = (mode)      => api.post(`/api/redblue/start?mode=${mode}`);
export const redAttack          = (type)      => api.post(`/api/redblue/red-attack?attack_type=${type}`);
export const blueDefend         = (action)    => api.post(`/api/redblue/blue-defend?action=${action}`);
export const stopRedBlue        = ()          => api.post("/api/redblue/stop");

// ── Advanced: Continuous Learning ────────────────────────────
export const fetchLearningStatus = ()         => api.get("/api/learning/status");
export const triggerRetrain      = ()         => api.post("/api/learning/trigger-retrain");

// ── Advanced: Additional Charts ──────────────────────────────
export const fetchProtocolChart  = ()         => api.get("/api/charts/protocols");
export const fetchNetworkHealth  = ()         => api.get("/api/charts/network-health");

export default api;
