import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldAlert, Play, RefreshCw, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle, Loader, Target, Lock
} from "lucide-react";
import {
  fetchVulns, fetchVulnStats, runVulnScan, updateVulnStatus
} from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import { format } from "date-fns";

const STATUS_STYLES = {
  OPEN:           "bg-red-500/20 text-red-400 border-red-500/30",
  MITIGATED:      "bg-green-500/20 text-green-400 border-green-500/30",
  ACCEPTED:       "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  FALSE_POSITIVE: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

function VulnCard({ vuln, onStatusChange }) {
  const [expanded, setExpanded] = useState(false);
  const [updating, setUpdating] = useState(false);

  const change = async (status) => {
    setUpdating(true);
    try { await onStatusChange(vuln.id, status); } finally { setUpdating(false); }
  };

  return (
    <motion.div
      layout
      className="glass border border-cyber-border rounded-xl overflow-hidden"
    >
      <div
        className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-white/3 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Severity dot */}
        <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${
          vuln.severity === "CRITICAL" ? "bg-red-500" :
          vuln.severity === "HIGH"     ? "bg-orange-500" :
          vuln.severity === "MEDIUM"   ? "bg-yellow-500" : "bg-green-500"
        }`} />

        {/* Main info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-semibold text-white">{vuln.name}</p>
            <span className="text-xs font-mono text-cyber-muted bg-cyber-border/40 px-2 py-0.5 rounded">
              :{vuln.port} {vuln.service}
            </span>
          </div>
          <div className="flex items-center gap-3 mt-0.5 text-[11px] font-mono text-cyber-muted">
            <span>Target: {vuln.target}</span>
            <span>·</span>
            <span>{vuln.discovered_at ? format(new Date(vuln.discovered_at), "MMM d, HH:mm") : "—"}</span>
          </div>
        </div>

        <SeverityBadge label={vuln.severity} />

        <span className={`px-2 py-1 rounded-lg border text-xs font-mono ${STATUS_STYLES[vuln.status] || STATUS_STYLES.OPEN}`}>
          {vuln.status}
        </span>

        {expanded ? <ChevronUp className="w-4 h-4 text-cyber-muted" /> : <ChevronDown className="w-4 h-4 text-cyber-muted" />}
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-cyber-border"
          >
            <div className="px-5 py-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div>
                  <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-1">Description</p>
                  <p className="text-xs text-cyber-muted leading-relaxed">{vuln.description}</p>
                </div>
                <div>
                  <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-1 flex items-center gap-1">
                    <Lock className="w-3 h-3 text-cyber-accent" /> Recommendation
                  </p>
                  <p className="text-xs text-cyber-accent leading-relaxed">{vuln.recommendation}</p>
                </div>
              </div>

              <div className="space-y-3">
                <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider">Update Status</p>
                <div className="flex flex-wrap gap-2">
                  {["OPEN", "MITIGATED", "ACCEPTED", "FALSE_POSITIVE"].map(s => (
                    <button
                      key={s}
                      onClick={() => change(s)}
                      disabled={updating || vuln.status === s}
                      className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors disabled:opacity-40 ${
                        vuln.status === s
                          ? STATUS_STYLES[s]
                          : "border-cyber-border text-cyber-muted hover:text-white hover:border-cyber-accent/40"
                      }`}
                    >
                      {updating && vuln.status !== s ? <Loader className="w-3 h-3 animate-spin inline mr-1" /> : null}
                      {s.replace("_", " ")}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function Vulnerabilities() {
  const [vulns,     setVulns]     = useState([]);
  const [stats,     setStats]     = useState({});
  const [loading,   setLoading]   = useState(true);
  const [scanning,  setScanning]  = useState(false);
  const [target,    setTarget]    = useState("192.168.1.1");
  const [scanType,  setScanType]  = useState("quick");
  const [filter,    setFilter]    = useState("");
  const [scanMsg,   setScanMsg]   = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [v, s] = await Promise.all([fetchVulns({ per_page: 100 }), fetchVulnStats()]);
      setVulns(v.data.vulnerabilities || []);
      setStats(s.data || {});
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleScan = async () => {
    setScanning(true);
    setScanMsg(null);
    try {
      const res = await runVulnScan(target, scanType);
      setScanMsg(`Scan complete — ${res.data.findings} findings on ${target}`);
      load();
    } catch (e) {
      setScanMsg("Scan failed. Check backend connection.");
    } finally {
      setScanning(false);
    }
  };

  const handleStatusChange = async (id, status) => {
    await updateVulnStatus(id, status);
    setVulns(prev => prev.map(v => v.id === id ? { ...v, status } : v));
    // refresh stats
    fetchVulnStats().then(r => setStats(r.data)).catch(() => {});
  };

  const filtered = filter ? vulns.filter(v => v.severity === filter || v.status === filter) : vulns;

  const StatBox = ({ label, value, color }) => (
    <div className="glass border border-cyber-border rounded-xl px-4 py-3 text-center">
      <p className={`text-xl font-bold font-mono ${color}`}>{value ?? 0}</p>
      <p className="text-xs text-cyber-muted mt-0.5">{label}</p>
    </div>
  );

  return (
    <div className="p-6 space-y-5 min-h-full">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-orange-400" /> Vulnerability Scanner
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {stats.open || 0} open · Risk score: {stats.risk_score || 0}
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        <StatBox label="Total"    value={stats.total}    color="text-white" />
        <StatBox label="Critical" value={stats.critical} color="text-red-400" />
        <StatBox label="High"     value={stats.high}     color="text-orange-400" />
        <StatBox label="Medium"   value={stats.medium}   color="text-yellow-400" />
        <StatBox label="Open"     value={stats.open}     color="text-red-400" />
      </div>

      {/* Scan panel */}
      <div className="glass border border-cyber-border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Target className="w-4 h-4 text-cyber-accent" />
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider">Run Vulnerability Scan</h2>
        </div>
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex-1 min-w-48">
            <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">Target IP / Host</label>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              className="w-full mt-1 bg-transparent border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-accent/50"
            />
          </div>
          <div>
            <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">Scan Type</label>
            <select
              value={scanType}
              onChange={e => setScanType(e.target.value)}
              className="w-full mt-1 bg-cyber-card border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-accent/50"
            >
              <option value="quick">Quick Scan</option>
              <option value="full">Full Scan</option>
            </select>
          </div>
          <button
            onClick={handleScan}
            disabled={scanning}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-orange-500/10 border border-orange-500/30 text-orange-400 text-sm font-semibold hover:bg-orange-500/20 disabled:opacity-40 transition-colors"
          >
            {scanning ? <Loader className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            {scanning ? "Scanning…" : "Start Scan"}
          </button>
        </div>
        {scanMsg && (
          <motion.p
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            className="mt-3 text-xs font-mono text-cyber-accent"
          >
            ✓ {scanMsg}
          </motion.p>
        )}
        <p className="mt-2 text-xs text-cyber-muted/60 font-mono">
          Note: This uses simulated findings. In production, integrate with Nmap or OpenVAS.
        </p>
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        {["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "OPEN", "MITIGATED"].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
              filter === f
                ? "bg-cyber-accent/10 border-cyber-accent/30 text-cyber-accent"
                : "border-cyber-border text-cyber-muted hover:text-white"
            }`}
          >
            {f || "All"}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-cyber-muted font-mono text-sm">
          <Loader className="w-5 h-5 animate-spin mr-2" /> Loading findings…
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 space-y-2 text-cyber-muted">
          <ShieldAlert className="w-10 h-10 opacity-30" />
          <p className="text-sm font-mono">No vulnerabilities found</p>
          <p className="text-xs font-mono opacity-60">Run a scan to discover open ports and weak services</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(v => (
            <VulnCard key={v.id} vuln={v} onStatusChange={handleStatusChange} />
          ))}
        </div>
      )}
    </div>
  );
}
