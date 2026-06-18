import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Users, RefreshCw, AlertTriangle, Monitor, Loader } from "lucide-react";
import { fetchUserRisk, fetchUserRiskDetail } from "../services/api";

const SEV_COLOR = {
  CRITICAL: "text-red-400 bg-red-500/10 border-red-500/30",
  HIGH:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  MEDIUM:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  LOW:      "text-green-400 bg-green-500/10 border-green-500/30",
};

function RiskBar({ value }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-cyber-border rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${
            value >= 85 ? "bg-red-500" : value >= 70 ? "bg-orange-500" :
            value >= 40 ? "bg-yellow-500" : "bg-green-500"
          }`}
          style={{ width: `${value}%` }}
        />
      </div>
      <span className={`text-sm font-bold font-mono w-10 text-right ${
        value >= 85 ? "text-red-400" : value >= 70 ? "text-orange-400" :
        value >= 40 ? "text-yellow-400" : "text-green-400"
      }`}>{value}%</span>
    </div>
  );
}

function DeviceCard({ profile, selected, onClick }) {
  return (
    <motion.div
      whileHover={{ y: -2 }}
      onClick={onClick}
      className={`glass border rounded-xl p-4 cursor-pointer transition-all ${
        selected ? "border-cyber-accent/40 bg-cyber-accent/5" : "border-cyber-border hover:border-cyber-border/80"
      }`}
    >
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-cyber-border/50 flex items-center justify-center">
            <Monitor className="w-4 h-4 text-cyber-muted" />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">{profile.device}</p>
            <p className="text-[10px] text-cyber-muted font-mono">{profile.user} · {profile.department}</p>
          </div>
        </div>
        <span className={`text-xs px-2 py-0.5 rounded border font-mono font-bold ${SEV_COLOR[profile.severity]}`}>
          {profile.severity}
        </span>
      </div>

      <RiskBar value={profile.risk} />

      <div className="mt-3 space-y-1">
        {profile.reasons.slice(0, 2).map((r, i) => (
          <p key={i} className="text-[10px] text-cyber-muted font-mono flex items-center gap-1">
            <span className="text-red-400">›</span> {r}
          </p>
        ))}
      </div>

      <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-cyber-muted">
        <span>{profile.ip}</span>
        <span>{profile.os}</span>
        <span className="text-cyber-accent">{profile.last_seen}</span>
      </div>
    </motion.div>
  );
}

export default function UserRisk() {
  const [data,     setData]     = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [selected, setSelected] = useState(null);
  const [detail,   setDetail]   = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchUserRisk();
      setData(res.data);
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const selectDevice = async (profile) => {
    setSelected(profile.ip);
    setDetailLoading(true);
    try {
      const res = await fetchUserRiskDetail(profile.ip);
      setDetail(res.data);
    } catch { } finally { setDetailLoading(false); }
  };

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <Loader className="w-6 h-6 animate-spin text-cyber-accent" />
    </div>
  );

  const profiles = data?.profiles || [];
  const highRisk = data?.high_risk || [];

  return (
    <div className="p-6 space-y-5 min-h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-purple-400" /> User & Device Risk
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {profiles.length} devices monitored · {highRisk.length} high-risk
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* High-risk banner */}
      {highRisk.length > 0 && (
        <div className="glass border border-red-500/30 bg-red-500/5 rounded-xl p-3 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs font-semibold text-red-400">HIGH RISK DEVICES</p>
            <p className="text-xs text-cyber-muted mt-0.5">
              {highRisk.map(p => p.device).join(", ")} — immediate investigation recommended.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Device grid */}
        <div className="xl:col-span-2 grid grid-cols-1 lg:grid-cols-2 gap-3">
          {profiles.map(p => (
            <DeviceCard key={p.ip} profile={p} selected={selected === p.ip} onClick={() => selectDevice(p)} />
          ))}
        </div>

        {/* Detail panel */}
        <div className="glass border border-cyber-border rounded-xl p-5">
          {!detail && !detailLoading ? (
            <div className="flex flex-col items-center justify-center h-full min-h-48 text-cyber-muted text-sm font-mono space-y-2">
              <Monitor className="w-8 h-8 opacity-30" />
              <p>Click a device to view details</p>
            </div>
          ) : detailLoading ? (
            <div className="flex items-center justify-center h-48">
              <Loader className="w-5 h-5 animate-spin text-cyber-accent" />
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <p className="text-xs text-cyber-muted uppercase tracking-wider font-mono">Device Detail</p>
                <p className="text-lg font-bold text-white mt-1">{detail.device}</p>
                <p className="text-xs text-cyber-muted font-mono">{detail.user} · {detail.ip} · {detail.os}</p>
              </div>

              <div>
                <p className="text-xs text-cyber-muted uppercase tracking-wider font-mono mb-1">Risk Score</p>
                <RiskBar value={detail.risk} />
              </div>

              <div>
                <p className="text-xs text-cyber-muted uppercase tracking-wider font-mono mb-2">Risk Factors</p>
                <ul className="space-y-1">
                  {detail.reasons.map((r, i) => (
                    <li key={i} className="text-xs text-cyber-muted flex items-start gap-1">
                      <span className="text-red-400 mt-0.5">›</span> {r}
                    </li>
                  ))}
                </ul>
              </div>

              {detail.recent_logs?.length > 0 && (
                <div>
                  <p className="text-xs text-cyber-muted uppercase tracking-wider font-mono mb-2">Recent Threats</p>
                  <div className="space-y-1">
                    {detail.recent_logs.slice(0, 5).map((l, i) => (
                      <div key={i} className="flex items-center justify-between text-[10px] font-mono bg-cyber-border/20 rounded px-2 py-1">
                        <span className="text-red-400">{l.attack_type}</span>
                        <span className="text-cyber-muted">{l.risk_score}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
