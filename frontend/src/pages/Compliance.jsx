import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { CheckSquare, RefreshCw, Shield, Loader } from "lucide-react";
import { fetchCompliance } from "../services/api";

function ScoreRing({ score, size = 80, label }) {
  const r   = (size / 2) - 8;
  const circ = 2 * Math.PI * r;
  const fill = (score / 100) * circ;
  const color = score >= 80 ? "#00ff99" : score >= 60 ? "#ffd60a" : "#ff3b5c";
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={size} height={size}>
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1a2744" strokeWidth={7} />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={7}
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
          transform={`rotate(-90 ${size/2} ${size/2})`} />
        <text x="50%" y="50%" textAnchor="middle" dy="0.35em" fill={color}
          fontSize={size > 60 ? "18" : "14"} fontWeight="bold" fontFamily="monospace">
          {score}
        </text>
      </svg>
      {label && <p className="text-xs text-cyber-muted font-mono text-center">{label}</p>}
    </div>
  );
}

function ControlBar({ control }) {
  const color = control.score >= 80 ? "bg-green-500" : control.score >= 60 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-3 py-2 border-b border-cyber-border/50 last:border-0">
      <span className="text-xs font-mono text-cyber-muted w-16 shrink-0">{control.id}</span>
      <span className="text-xs text-white flex-1 truncate">{control.name}</span>
      <div className="w-32 h-1.5 bg-cyber-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${control.score}%` }} />
      </div>
      <span className={`text-xs font-mono font-bold w-8 text-right ${
        control.score >= 80 ? "text-green-400" : control.score >= 60 ? "text-yellow-400" : "text-red-400"
      }`}>{control.score}</span>
    </div>
  );
}

export default function Compliance() {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab,     setTab]     = useState("nist");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchCompliance();
      setData(res.data);
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <Loader className="w-6 h-6 animate-spin text-cyber-accent" />
    </div>
  );

  const tabs = [
    { id: "nist", label: "NIST CSF",   score: data?.nist_score, controls: data?.nist_controls },
    { id: "iso",  label: "ISO 27001",  score: data?.iso_score,  controls: data?.iso_controls  },
    { id: "cis",  label: "CIS Controls", score: data?.cis_score, controls: data?.cis_controls },
  ];
  const active = tabs.find(t => t.id === tab);

  return (
    <div className="p-6 space-y-5 min-h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <CheckSquare className="w-5 h-5 text-cyan-400" /> Compliance Dashboard
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            NIST · ISO 27001 · CIS Controls — scores derived from live data
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Overall scores */}
      <div className="glass border border-cyber-border rounded-xl p-6">
        <div className="flex flex-wrap items-center justify-around gap-6">
          <ScoreRing score={data?.overall_score ?? 0} size={100} label="Overall" />
          {tabs.map(t => <ScoreRing key={t.id} score={t.score ?? 0} size={80} label={t.label} />)}
        </div>

        <div className="mt-4 grid grid-cols-3 gap-3 text-xs font-mono text-center">
          <div className="bg-cyber-border/20 rounded-lg p-2">
            <p className="text-cyber-muted">Open Incidents</p>
            <p className="text-red-400 font-bold text-lg">{data?.open_incidents ?? 0}</p>
          </div>
          <div className="bg-cyber-border/20 rounded-lg p-2">
            <p className="text-cyber-muted">Critical Vulns</p>
            <p className="text-red-400 font-bold text-lg">{data?.critical_vulns ?? 0}</p>
          </div>
          <div className="bg-cyber-border/20 rounded-lg p-2">
            <p className="text-cyber-muted">Overall Score</p>
            <p className={`font-bold text-lg ${data?.overall_score >= 70 ? "text-green-400" : "text-red-400"}`}>
              {data?.overall_score ?? 0}
            </p>
          </div>
        </div>
      </div>

      {/* Framework tabs */}
      <div className="glass border border-cyber-border rounded-xl overflow-hidden">
        <div className="flex border-b border-cyber-border">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`flex-1 py-3 text-xs font-semibold uppercase tracking-wider transition-colors ${
                tab === t.id
                  ? "bg-cyber-accent/10 text-cyber-accent border-b-2 border-cyber-accent"
                  : "text-cyber-muted hover:text-white"
              }`}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="p-5">
          <div className="space-y-1">
            {(active?.controls || []).map(c => <ControlBar key={c.id} control={c} />)}
          </div>
        </div>
      </div>

      <p className="text-xs text-cyber-muted/60 font-mono text-center">
        Compliance scores are calculated from real incident, vulnerability, and threat metrics.
        For official certification, engage a qualified auditor.
      </p>
    </div>
  );
}
