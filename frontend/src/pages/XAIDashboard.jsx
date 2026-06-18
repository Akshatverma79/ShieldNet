import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Brain, RefreshCw, Loader, Info } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { fetchFeatureImportance, fetchLogs, explainPrediction } from "../services/api";

const COLORS = ["#ff3b5c","#ff6b35","#ffd60a","#00e5ff","#00ff99","#9d4edd"];

function ImportanceBar({ rank, feature, importance }) {
  const pct = (importance / 0.2) * 100;
  return (
    <div className="flex items-center gap-3 py-1.5">
      <span className="text-[10px] font-mono text-cyber-muted w-5 shrink-0">#{rank}</span>
      <span className="text-xs font-mono text-white w-52 truncate">{feature}</span>
      <div className="flex-1 h-2 bg-cyber-border rounded-full overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(pct, 100)}%` }}
          transition={{ duration: 0.6, delay: rank * 0.03 }}
          className="h-full rounded-full bg-cyber-accent"
        />
      </div>
      <span className="text-xs font-mono text-cyber-accent w-12 text-right">{(importance * 100).toFixed(1)}%</span>
    </div>
  );
}

export default function XAIDashboard() {
  const [features, setFeatures] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [selected,  setSelected]  = useState(null);
  const [explain,   setExplain]   = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [explainLoading, setExplainLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [fi, logs] = await Promise.all([
        fetchFeatureImportance(),
        fetchLogs({ per_page: 10, status: "THREAT" }),
      ]);
      setFeatures(fi.data);
      setRecentLogs(logs.data.logs || []);
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleExplain = async (log) => {
    setSelected(log.id);
    setExplainLoading(true);
    try {
      const res = await explainPrediction(log.id);
      setExplain(res.data);
    } catch { setExplain(null); } finally { setExplainLoading(false); }
  };

  const top20 = features?.top_features?.slice(0, 15) || [];
  const chartData = top20.slice(0, 10).map(f => ({
    name: f.feature.replace(/ /g, "\n").slice(0, 20),
    value: parseFloat((f.importance * 100).toFixed(2)),
    fullName: f.feature,
  }));

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <Loader className="w-6 h-6 animate-spin text-cyber-accent" />
    </div>
  );

  return (
    <div className="p-6 space-y-5 min-h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-400" /> ML Explainability (XAI)
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {features?.model} · {features?.n_features} features · {features?.method}
          </p>
        </div>
        <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

        {/* Bar chart — top 10 features */}
        <div className="glass border border-cyber-border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Top 10 Feature Importance</h2>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 20, left: 10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" horizontal={false} />
              <XAxis type="number" tick={{ fill: "#8aa4c8", fontSize: 9 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: "#8aa4c8", fontSize: 8 }} width={120} />
              <Tooltip
                formatter={(v, _, p) => [`${v}%`, p.payload.fullName]}
                contentStyle={{ background: "#0d1526", border: "1px solid #1a2744", borderRadius: 8, fontSize: 11 }}
                labelFormatter={() => ""}
              />
              <Bar dataKey="value" name="Importance %" radius={[0, 4, 4, 0]}>
                {chartData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Ranked list */}
        <div className="glass border border-cyber-border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-4">Feature Ranking</h2>
          <div className="overflow-y-auto max-h-72 space-y-0.5">
            {top20.map(f => <ImportanceBar key={f.rank} rank={f.rank} feature={f.feature} importance={f.importance} />)}
          </div>
        </div>
      </div>

      {/* Per-prediction explanation */}
      <div className="glass border border-cyber-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-3">Explain a Prediction</h2>
        <div className="flex flex-wrap gap-2 mb-4">
          {recentLogs.length === 0 ? (
            <p className="text-xs text-cyber-muted font-mono">No threat logs yet — run a simulation first.</p>
          ) : (
            recentLogs.map(log => (
              <button key={log.id} onClick={() => handleExplain(log)}
                className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
                  selected === log.id
                    ? "bg-cyber-accent/10 border-cyber-accent/40 text-cyber-accent"
                    : "border-cyber-border text-cyber-muted hover:text-white"
                }`}>
                #{log.id} {log.attack_type}
              </button>
            ))
          )}
        </div>

        {explainLoading ? (
          <div className="flex items-center gap-2 text-cyber-muted font-mono text-sm py-4">
            <Loader className="w-4 h-4 animate-spin" /> Generating explanation…
          </div>
        ) : explain ? (
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="text-sm font-semibold text-white">Log #{explain.log_id} — {explain.attack_type}</span>
              <span className="text-xs font-mono text-orange-400">Risk: {explain.risk_score}%</span>
            </div>
            <div className="space-y-1">
              {(explain.contributions || []).map((c, i) => (
                <div key={i} className="flex items-center gap-3 text-xs font-mono py-1 border-b border-cyber-border/30 last:border-0">
                  <span className={`w-3 h-3 rounded-full shrink-0 ${c.impact === "increases_risk" ? "bg-red-500" : "bg-green-500"}`} />
                  <span className="text-white flex-1 truncate">{c.feature}</span>
                  <span className={`${c.impact === "increases_risk" ? "text-red-400" : "text-green-400"}`}>
                    {c.impact === "increases_risk" ? "↑ risk" : "↓ risk"}
                  </span>
                  <span className="text-cyber-muted">{c.abs_impact?.toFixed(4)}</span>
                </div>
              ))}
            </div>
            {explain.explanation?.length > 0 && (
              <div className="mt-2 p-3 bg-cyber-border/20 rounded-lg">
                <p className="text-xs text-cyber-muted font-mono uppercase tracking-wider mb-1">Detection Reasons</p>
                {explain.explanation.map((r, i) => (
                  <p key={i} className="text-xs text-cyber-accent font-mono">› {r}</p>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2 text-cyber-muted text-xs font-mono">
            <Info className="w-4 h-4" />
            Select a threat log above to see its feature-level explanation.
          </div>
        )}
      </div>
    </div>
  );
}
