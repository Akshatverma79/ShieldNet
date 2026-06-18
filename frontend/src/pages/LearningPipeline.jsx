import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { RefreshCw, Database, Play, CheckCircle, Clock, AlertTriangle, Loader } from "lucide-react";
import { fetchLearningStatus, triggerRetrain } from "../services/api";

const STAGE_ICONS = { active: CheckCircle, manual: AlertTriangle, pending: Clock, idle: Clock };
const STAGE_COLORS = { active: "text-green-400 bg-green-500/10 border-green-500/30",
                       manual: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
                       pending:"text-orange-400 bg-orange-500/10 border-orange-500/30",
                       idle:   "text-cyber-muted bg-cyber-border/20 border-cyber-border" };

export default function LearningPipeline() {
  const [status,   setStatus]   = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [triggering, setTriggering] = useState(false);
  const [msg,      setMsg]      = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try { const res = await fetchLearningStatus(); setStatus(res.data); }
    catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleRetrain = async () => {
    setTriggering(true);
    try {
      const res = await triggerRetrain();
      setMsg(res.data.message);
    } catch { setMsg("Failed to trigger retrain."); }
    finally { setTriggering(false); }
  };

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <Loader className="w-6 h-6 animate-spin text-cyber-accent" />
    </div>
  );

  return (
    <div className="p-6 space-y-5 min-h-full max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cyber-accent" /> Continuous Learning Pipeline
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {status?.model_version} · {status?.algorithm}
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Status cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: "Training Samples", value: status?.training_samples ?? "—", color: "text-white" },
          { label: "New Samples",      value: status?.new_samples_since ?? 0,   color: "text-cyber-accent" },
          { label: "Threat Samples",   value: status?.threat_samples ?? 0,      color: "text-red-400" },
          { label: "Retrain Threshold",value: status?.retrain_threshold ?? 500, color: "text-yellow-400" },
        ].map(c => (
          <div key={c.label} className="glass border border-cyber-border rounded-xl p-4 text-center">
            <p className={`text-lg font-bold font-mono ${c.color}`}>{c.value}</p>
            <p className="text-xs text-cyber-muted mt-0.5">{c.label}</p>
          </div>
        ))}
      </div>

      {/* Retrain status */}
      <div className={`glass border rounded-xl p-4 flex items-center justify-between ${
        status?.retrain_ready ? "border-green-500/30 bg-green-500/5" :
        status?.retrain_recommended ? "border-yellow-500/30 bg-yellow-500/5" :
        "border-cyber-border"
      }`}>
        <div>
          <p className={`text-sm font-semibold ${
            status?.retrain_ready ? "text-green-400" :
            status?.retrain_recommended ? "text-yellow-400" : "text-cyber-muted"
          }`}>
            {status?.retrain_ready ? "✓ Ready to retrain" :
             status?.retrain_recommended ? "⚠ Retrain recommended" :
             "Collecting more data…"}
          </p>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {status?.retrain_threshold - (status?.new_samples_since ?? 0)} more samples needed for threshold
          </p>
        </div>
        <button onClick={handleRetrain} disabled={triggering}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent text-xs font-semibold hover:bg-cyber-accent/20 disabled:opacity-40 transition-colors">
          {triggering ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
          Trigger Retrain
        </button>
      </div>

      {msg && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="glass border border-cyber-accent/30 rounded-xl p-3 text-xs font-mono text-cyber-accent">
          ✓ {msg}
        </motion.div>
      )}

      {/* Pipeline stages */}
      <div className="glass border border-cyber-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Pipeline Stages</h2>
        <div className="space-y-3">
          {(status?.pipeline_stages || []).map((s, i) => {
            const Icon = STAGE_ICONS[s.status] || Clock;
            return (
              <div key={i} className="flex items-center gap-3">
                <div className={`w-6 h-6 rounded-full flex items-center justify-center shrink-0 ${STAGE_COLORS[s.status]}`}>
                  <span className="text-[10px] font-mono font-bold">{i + 1}</span>
                </div>
                <div className="flex-1">
                  <p className="text-xs font-semibold text-white">{s.stage}</p>
                  <p className="text-[10px] text-cyber-muted font-mono">{s.description}</p>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded border font-mono ${STAGE_COLORS[s.status]}`}>
                  {s.status}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Feature drift */}
      {status?.feature_drift && (
        <div className={`glass border rounded-xl p-4 ${
          status.feature_drift.detected ? "border-yellow-500/30 bg-yellow-500/5" : "border-cyber-border"
        }`}>
          <p className="text-xs font-semibold text-white mb-1">Feature Drift Detection</p>
          <p className="text-xs text-cyber-muted font-mono">
            {status.feature_drift.detected
              ? `⚠ Drift detected in ${status.feature_drift.features_drifted} features — ${status.feature_drift.recommendation}`
              : "✓ No significant feature drift detected"}
          </p>
        </div>
      )}
    </div>
  );
}
