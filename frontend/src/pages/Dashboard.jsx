import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Activity, Server,
  RefreshCw, Radio
} from "lucide-react";
import {
  AreaChart, Area, PieChart, Pie, Cell,
  LineChart, Line, BarChart, Bar,
  XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from "recharts";

import StatCard   from "../components/StatCard";
import AlertFeed  from "../components/AlertFeed";
import {
  fetchStats, fetchTrafficChart,
  fetchAttackDist, fetchRiskTimeline,
  fetchProtocolChart, fetchNetworkHealth,
  fetchForecast
} from "../services/api";
import { wsService } from "../services/websocket";

// ─── Chart colours ──────────────────────────────────────────────
const PIE_COLORS = ["#ff3b5c", "#00e5ff", "#ffd60a", "#9d4edd", "#00ff99", "#ff6b35"];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass border border-cyber-border rounded-lg px-3 py-2 text-xs font-mono">
      <p className="text-cyber-muted mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey} style={{ color: p.color }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

// ─── Section header ─────────────────────────────────────────────
function SectionHeader({ title, subtitle }) {
  return (
    <div className="mb-4">
      <h2 className="text-sm font-semibold text-white uppercase tracking-widest">{title}</h2>
      {subtitle && <p className="text-xs text-cyber-muted mt-0.5">{subtitle}</p>}
    </div>
  );
}

// ─── Threat level badge ─────────────────────────────────────────
const LEVEL_STYLE = {
  LOW:      "text-cyber-green  bg-green-500/10  border-green-500/30",
  MEDIUM:   "text-yellow-400   bg-yellow-500/10 border-yellow-500/30",
  HIGH:     "text-orange-400   bg-orange-500/10 border-orange-500/30",
  CRITICAL: "text-cyber-red    bg-red-500/10    border-red-500/30",
};

export default function Dashboard() {
  const [stats,      setStats]      = useState(null);
  const [traffic,    setTraffic]    = useState([]);
  const [attackDist, setAttackDist] = useState([]);
  const [riskLine,   setRiskLine]   = useState([]);
  const [protocols,  setProtocols]  = useState([]);
  const [netHealth,  setNetHealth]  = useState([]);
  const [forecast,   setForecast]   = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [lastRefresh,setLastRefresh]= useState(new Date());

  // ── Fetch all chart data ──────────────────────────────────────
  const loadData = useCallback(async () => {
    try {
      const [s, t, a, r, p, nh, fc] = await Promise.all([
        fetchStats(),
        fetchTrafficChart(60),
        fetchAttackDist(),
        fetchRiskTimeline(50),
        fetchProtocolChart(),
        fetchNetworkHealth(),
        fetchForecast(30),
      ]);
      setStats(s.data);
      setTraffic(t.data.data || []);
      setAttackDist(a.data.data || []);
      setRiskLine(r.data.data || []);
      setProtocols(p.data.data || []);
      setNetHealth(nh.data.data || []);
      setForecast(fc.data);
      setLastRefresh(new Date());
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    // Refresh stats every 15 s
    const iv = setInterval(loadData, 15_000);
    // Also refresh on every WS event
    const u1 = wsService.on("prediction", loadData);
    const u2 = wsService.on("simulation", loadData);
    return () => { clearInterval(iv); u1(); u2(); };
  }, [loadData]);

  const levelStyle = LEVEL_STYLE[stats?.threat_level] || LEVEL_STYLE.LOW;

  // ── Loading skeleton ─────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-3">
          <Shield className="w-10 h-10 text-cyber-accent animate-pulse" />
          <p className="text-cyber-muted text-sm font-mono">Initialising ShieldNet…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 min-h-full">

      {/* ── Top bar ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyber-accent" />
            Security Operations Center
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            Last updated: {lastRefresh.toLocaleTimeString()}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Threat level pill */}
          <span className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-mono font-bold ${levelStyle}`}>
            <span className="w-2 h-2 rounded-full bg-current status-dot" />
            {stats?.threat_level || "LOW"} THREAT LEVEL
          </span>

          {/* Live indicator */}
          <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-cyber-accent/30 bg-cyber-accent/5 text-cyber-accent text-xs font-mono">
            <Radio className="w-3 h-3 animate-pulse" />
            LIVE
          </span>

          {/* Refresh */}
          <button
            onClick={loadData}
            className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* ── Stat cards ──────────────────────────────────────── */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Packets"
          value={stats?.total_packets?.toLocaleString() ?? "0"}
          subtitle="Packets analysed"
          color="cyan"
          icon={<Activity className="w-4 h-4" />}
        />
        <StatCard
          title="Threats Detected"
          value={stats?.threats_detected?.toLocaleString() ?? "0"}
          subtitle={`${(((stats?.threats_detected ?? 0) / Math.max(stats?.total_packets ?? 1, 1)) * 100).toFixed(1)}% of traffic`}
          color="red"
          icon={<AlertTriangle className="w-4 h-4" />}
        />
        <StatCard
          title="Security Score"
          value={`${stats?.security_score ?? 100}%`}
          subtitle="Current posture"
          color={stats?.security_score >= 80 ? "green" : stats?.security_score >= 50 ? "yellow" : "red"}
          icon={<Shield className="w-4 h-4" />}
        />
        <StatCard
          title="Active Connections"
          value={stats?.active_connections ?? "0"}
          subtitle="WebSocket clients"
          color="purple"
          icon={<Server className="w-4 h-4" />}
        />
      </div>

      {/* ── Charts row 1 ────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

        {/* Traffic area chart — spans 2 cols */}
        <div className="xl:col-span-2 glass border border-cyber-border rounded-xl p-5 glow-border">
          <SectionHeader
            title="Network Traffic"
            subtitle="Normal vs threat traffic (last 60 min)"
          />
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={traffic} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gradNormal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00e5ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#00e5ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradThreat" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ff3b5c" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#ff3b5c" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" />
              <XAxis dataKey="time" tick={{ fill: "#8aa4c8", fontSize: 10 }} />
              <YAxis tick={{ fill: "#8aa4c8", fontSize: 10 }} />
              <Tooltip content={<CustomTooltip />} />
              <Legend wrapperStyle={{ fontSize: 11, color: "#8aa4c8" }} />
              <Area type="monotone" dataKey="normal"  name="Normal"  stroke="#00e5ff" fill="url(#gradNormal)" strokeWidth={1.5} />
              <Area type="monotone" dataKey="threats" name="Threats" stroke="#ff3b5c" fill="url(#gradThreat)" strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Attack distribution pie */}
        <div className="glass border border-cyber-border rounded-xl p-5 glow-border">
          <SectionHeader
            title="Attack Types"
            subtitle="Distribution of detected attacks"
          />
          {attackDist.length === 0 ? (
            <div className="flex items-center justify-center h-52 text-cyber-muted text-sm font-mono">
              No attacks recorded yet
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={attackDist}
                  cx="50%" cy="50%"
                  innerRadius={55} outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {attackDist.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) =>
                    active && payload?.[0] ? (
                      <div className="glass border border-cyber-border rounded px-2 py-1 text-xs font-mono">
                        <p className="text-white">{payload[0].name}</p>
                        <p className="text-cyber-accent">{payload[0].value} events</p>
                      </div>
                    ) : null
                  }
                />
                <Legend
                  formatter={(v) => <span style={{ color: "#8aa4c8", fontSize: 10 }}>{v}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* ── Charts row 2 ────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

        {/* Risk score timeline */}
        <div className="glass border border-cyber-border rounded-xl p-5 glow-border">
          <SectionHeader
            title="Risk Score Timeline"
            subtitle="Last 50 analysed events"
          />
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={riskLine} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" />
              <XAxis dataKey="time" tick={{ fill: "#8aa4c8", fontSize: 9 }} interval="preserveStartEnd" />
              <YAxis domain={[0, 100]} tick={{ fill: "#8aa4c8", fontSize: 10 }} />
              <Tooltip content={<CustomTooltip />} />
              <Line
                type="monotone" dataKey="risk" name="Risk Score"
                stroke="#ffd60a" strokeWidth={1.5} dot={false}
                activeDot={{ r: 4, fill: "#ffd60a" }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Live alert feed */}
        <div className="glass border border-cyber-border rounded-xl p-5 glow-border">
          <SectionHeader title="Live Alert Feed" subtitle="Real-time threat events via WebSocket" />
          <AlertFeed maxItems={20} />
        </div>
      </div>

      {/* ── Charts row 3: Protocol + Network Health ──────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

        {/* Protocol usage */}
        <div className="glass border border-cyber-border rounded-xl p-5 glow-border">
          <SectionHeader title="Protocol Usage" subtitle="Traffic by protocol" />
          {protocols.length === 0 ? (
            <div className="flex items-center justify-center h-44 text-cyber-muted text-sm font-mono">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={protocols} cx="50%" cy="50%" innerRadius={45} outerRadius={70} paddingAngle={3} dataKey="value">
                  {protocols.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                </Pie>
                <Tooltip content={({ active, payload }) =>
                  active && payload?.[0] ? (
                    <div className="glass border border-cyber-border rounded px-2 py-1 text-xs font-mono">
                      <p className="text-white">{payload[0].name}</p>
                      <p className="text-cyber-accent">{payload[0].value} events</p>
                    </div>
                  ) : null} />
                <Legend formatter={v => <span style={{ color: "#8aa4c8", fontSize: 10 }}>{v}</span>} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Network health */}
        <div className="xl:col-span-2 glass border border-cyber-border rounded-xl p-5 glow-border">
          <SectionHeader title="Network Health" subtitle="Hourly health score — last 24 hours" />
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={netHealth} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" />
              <XAxis dataKey="hour" tick={{ fill: "#8aa4c8", fontSize: 9 }} interval={3} />
              <YAxis domain={[0, 100]} tick={{ fill: "#8aa4c8", fontSize: 10 }} />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="health" name="Health %" radius={[3, 3, 0, 0]}>
                {netHealth.map((entry, i) => (
                  <Cell key={i} fill={entry.health >= 80 ? "#00ff99" : entry.health >= 50 ? "#ffd60a" : "#ff3b5c"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ── Attack Prediction Banner ─────────────────────────── */}
      {forecast && forecast.predictions?.length > 0 && (
        <div className="glass border border-orange-500/30 bg-orange-500/5 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-orange-400 text-sm font-semibold uppercase tracking-wider">
              ⚠ Attack Prediction — Next {forecast.window_minutes} Minutes
            </span>
            <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold border ${
              forecast.overall_risk === "CRITICAL" ? "text-red-400 border-red-400/40 bg-red-500/10" :
              forecast.overall_risk === "HIGH"     ? "text-orange-400 border-orange-400/40 bg-orange-500/10" :
              "text-yellow-400 border-yellow-400/40 bg-yellow-500/10"
            }`}>{forecast.overall_risk}</span>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            {forecast.predictions.map((p, i) => (
              <div key={i} className="bg-cyber-card border border-cyber-border rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-white">{p.attack_type}</span>
                  <span className={`text-sm font-bold font-mono ${
                    p.probability >= 70 ? "text-red-400" : p.probability >= 50 ? "text-orange-400" : "text-yellow-400"
                  }`}>{p.probability}%</span>
                </div>
                <div className="w-full h-1.5 bg-cyber-border rounded-full overflow-hidden mb-1">
                  <div className={`h-full rounded-full ${
                    p.probability >= 70 ? "bg-red-500" : p.probability >= 50 ? "bg-orange-500" : "bg-yellow-500"
                  }`} style={{ width: `${p.probability}%` }} />
                </div>
                <p className="text-[10px] text-cyber-muted font-mono truncate">{p.basis}</p>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
}
