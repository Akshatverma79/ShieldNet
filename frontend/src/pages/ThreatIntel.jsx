import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Globe, Search, Shield, AlertTriangle,
  CheckCircle, Loader, MapPin, Tag, Info
} from "lucide-react";
import { lookupIP } from "../services/api";

const KNOWN_IPS = [
  "45.33.32.156", "198.51.100.1", "203.0.113.42",
  "185.220.101.1", "8.8.8.8", "1.1.1.1",
];

function ResultCard({ result }) {
  const { ip, blacklisted, risk_level, details } = result;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass border rounded-xl p-5 space-y-4 ${
        blacklisted
          ? "border-red-500/30 shadow-glow-red"
          : "border-green-500/30 shadow-glow-green"
      }`}
    >
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-cyber-muted font-mono uppercase tracking-wider">IP Address</p>
          <p className="text-2xl font-mono font-bold text-white mt-0.5">{ip}</p>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm font-bold ${
          blacklisted
            ? "bg-red-500/10 border-red-500/30 text-red-400"
            : "bg-green-500/10 border-green-500/30 text-green-400"
        }`}>
          {blacklisted
            ? <><AlertTriangle className="w-4 h-4" /> MALICIOUS</>
            : <><CheckCircle   className="w-4 h-4" /> CLEAN</>
          }
        </div>
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-cyber-bg/50 rounded-lg p-3">
          <p className="text-xs text-cyber-muted font-mono uppercase tracking-wider mb-1">Risk Level</p>
          <p className={`text-sm font-bold font-mono ${
            risk_level === "HIGH" ? "text-red-400" : "text-green-400"
          }`}>
            {risk_level}
          </p>
        </div>
        <div className="bg-cyber-bg/50 rounded-lg p-3">
          <p className="text-xs text-cyber-muted font-mono uppercase tracking-wider mb-1">Blacklisted</p>
          <p className={`text-sm font-bold font-mono ${blacklisted ? "text-red-400" : "text-green-400"}`}>
            {blacklisted ? "YES" : "NO"}
          </p>
        </div>
      </div>

      {/* Details */}
      {details && Object.keys(details).length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider">Threat Intelligence</p>
          <div className="grid grid-cols-1 gap-2">
            {details.label && (
              <div className="flex items-center gap-2 text-xs font-mono">
                <Tag className="w-3.5 h-3.5 text-cyber-accent" />
                <span className="text-cyber-muted">Classification:</span>
                <span className="text-white">{details.label}</span>
              </div>
            )}
            {details.country && (
              <div className="flex items-center gap-2 text-xs font-mono">
                <MapPin className="w-3.5 h-3.5 text-cyber-accent" />
                <span className="text-cyber-muted">Origin:</span>
                <span className="text-white">{details.country}</span>
              </div>
            )}
            {details.threat_type && (
              <div className="flex items-center gap-2 text-xs font-mono">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span className="text-cyber-muted">Threat Type:</span>
                <span className="text-red-400">{details.threat_type}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {!blacklisted && (
        <div className="flex items-center gap-2 text-xs text-cyber-muted font-mono bg-cyber-bg/50 rounded p-2">
          <Info className="w-3.5 h-3.5" />
          No threat signatures found in ShieldNet intelligence database.
        </div>
      )}
    </motion.div>
  );
}

export default function ThreatIntel() {
  const [ip,      setIp]      = useState("");
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);

  const lookup = async (target = ip) => {
    const clean = target.trim();
    if (!clean) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await lookupIP(clean);
      setResult(res.data);
      setIp(clean);
    } catch (e) {
      setError(e?.response?.data?.detail || "Lookup failed. Check the IP and try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e) => { if (e.key === "Enter") lookup(); };

  return (
    <div className="p-6 space-y-6 min-h-full">

      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Globe className="w-5 h-5 text-cyber-accent" />
          Threat Intelligence
        </h1>
        <p className="text-xs text-cyber-muted font-mono mt-1">
          IP reputation lookup — check against the ShieldNet threat intelligence database.
        </p>
      </div>

      {/* Search bar */}
      <div className="glass border border-cyber-border rounded-xl p-5 space-y-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              placeholder="Enter IP address (e.g. 45.33.32.156)"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              onKeyDown={handleKey}
              className="w-full pl-9 pr-3 py-2.5 bg-transparent border border-cyber-border rounded-lg text-sm text-white placeholder-cyber-muted font-mono focus:outline-none focus:border-cyber-accent/50 transition-colors"
            />
          </div>
          <button
            onClick={() => lookup()}
            disabled={loading || !ip.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent text-sm font-semibold hover:bg-cyber-accent/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {loading
              ? <><Loader className="w-4 h-4 animate-spin" /> Checking…</>
              : <><Search className="w-4 h-4" /> Lookup</>
            }
          </button>
        </div>

        {/* Quick-select known IPs */}
        <div>
          <p className="text-xs text-cyber-muted font-mono mb-2">Quick lookup — known IPs:</p>
          <div className="flex flex-wrap gap-2">
            {KNOWN_IPS.map(knownIp => (
              <button
                key={knownIp}
                onClick={() => { setIp(knownIp); lookup(knownIp); }}
                className="px-2.5 py-1 rounded border border-cyber-border text-xs font-mono text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 transition-colors"
              >
                {knownIp}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex items-center gap-2 p-3 rounded-lg border border-red-500/30 bg-red-500/5 text-red-400 text-xs font-mono"
          >
            <AlertTriangle className="w-4 h-4 shrink-0" />
            {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Result */}
      <AnimatePresence>
        {result && <ResultCard result={result} />}
      </AnimatePresence>

      {/* Info box */}
      {!result && !loading && (
        <div className="glass border border-cyber-border rounded-xl p-6 text-center space-y-3">
          <Shield className="w-10 h-10 text-cyber-muted mx-auto" />
          <p className="text-sm text-cyber-muted font-mono">
            Enter an IP address above to check it against the ShieldNet threat intelligence database.
          </p>
          <p className="text-xs text-cyber-muted/60 font-mono">
            In production, this integrates with AbuseIPDB, VirusTotal, and Shodan APIs.
          </p>
        </div>
      )}
    </div>
  );
}
