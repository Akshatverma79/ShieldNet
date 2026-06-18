import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import {
  FileText, Download, RefreshCw, BarChart2,
  Shield, AlertTriangle, TrendingUp, Calendar,
  CheckCircle, Clock, Loader
} from "lucide-react";
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend
} from "recharts";
import {
  fetchStats, fetchAttackDist, fetchRiskTimeline,
  fetchIncidentStats, fetchVulnStats
} from "../services/api";
import { format } from "date-fns";

const PIE_COLORS = ["#ff3b5c", "#00e5ff", "#ffd60a", "#9d4edd", "#00ff99", "#ff6b35"];

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="glass border border-cyber-border rounded-lg px-3 py-2 text-xs font-mono">
      <p className="text-cyber-muted mb-1">{label}</p>
      {payload.map(p => (
        <p key={p.dataKey} style={{ color: p.color }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

function ReportSection({ title, icon: Icon, children }) {
  return (
    <div className="glass border border-cyber-border rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2 pb-3 border-b border-cyber-border">
        <Icon className="w-4 h-4 text-cyber-accent" />
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider">{title}</h2>
      </div>
      {children}
    </div>
  );
}

function MetricRow({ label, value, color = "text-white", bar = null }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-cyber-border/50 last:border-0">
      <span className="text-xs text-cyber-muted font-mono">{label}</span>
      <div className="flex items-center gap-3">
        {bar !== null && (
          <div className="w-24 h-1.5 bg-cyber-border rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full ${
                bar >= 75 ? "bg-red-500" : bar >= 40 ? "bg-yellow-500" : "bg-green-500"
              }`}
              style={{ width: `${Math.min(bar, 100)}%` }}
            />
          </div>
        )}
        <span className={`text-xs font-bold font-mono ${color}`}>{value}</span>
      </div>
    </div>
  );
}

export default function Reports() {
  const [stats,     setStats]     = useState(null);
  const [attacks,   setAttacks]   = useState([]);
  const [risk,      setRisk]      = useState([]);
  const [incStats,  setIncStats]  = useState({});
  const [vulnStats, setVulnStats] = useState({});
  const [loading,   setLoading]   = useState(true);
  const [generated, setGenerated] = useState(null);
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, a, r, inc, vuln] = await Promise.all([
        fetchStats(),
        fetchAttackDist(),
        fetchRiskTimeline(100),
        fetchIncidentStats().catch(() => ({ data: {} })),
        fetchVulnStats().catch(() => ({ data: {} })),
      ]);
      setStats(s.data);
      setAttacks(a.data.data || []);
      setRisk(r.data.data || []);
      setIncStats(inc.data || {});
      setVulnStats(vuln.data || {});
      setGenerated(new Date());
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Build a plain-text report for export
  const exportReport = () => {
    setExporting(true);
    const lines = [
      "=" .repeat(60),
      "  SHIELDNET SECURITY OPERATIONS REPORT",
      "=" .repeat(60),
      `Generated: ${new Date().toLocaleString()}`,
      "",
      "── EXECUTIVE SUMMARY ──────────────────────────────────",
      `Total Events Analysed : ${stats?.total_packets?.toLocaleString() ?? "N/A"}`,
      `Threats Detected      : ${stats?.threats_detected?.toLocaleString() ?? "N/A"}`,
      `Security Score        : ${stats?.security_score ?? "N/A"}%`,
      `Threat Level          : ${stats?.threat_level ?? "N/A"}`,
      "",
      "── INCIDENT SUMMARY ────────────────────────────────────",
      `Total Incidents       : ${incStats?.total ?? 0}`,
      `Open                  : ${incStats?.open ?? 0}`,
      `Investigating         : ${incStats?.investigating ?? 0}`,
      `Resolved              : ${incStats?.resolved ?? 0}`,
      `Critical              : ${incStats?.critical ?? 0}`,
      "",
      "── VULNERABILITY SUMMARY ───────────────────────────────",
      `Total Findings        : ${vulnStats?.total ?? 0}`,
      `Critical              : ${vulnStats?.critical ?? 0}`,
      `High                  : ${vulnStats?.high ?? 0}`,
      `Medium                : ${vulnStats?.medium ?? 0}`,
      `Open                  : ${vulnStats?.open ?? 0}`,
      "",
      "── ATTACK DISTRIBUTION ─────────────────────────────────",
      ...attacks.map(a => `${a.name.padEnd(20)} ${a.value} events`),
      "",
      "── RISK SCORE TREND (last 100 events) ──────────────────",
      `Average Risk: ${risk.length ? (risk.reduce((s, r) => s + r.risk, 0) / risk.length).toFixed(1) : "N/A"}%`,
      `Max Risk    : ${risk.length ? Math.max(...risk.map(r => r.risk)).toFixed(1) : "N/A"}%`,
      "",
      "── RECOMMENDATIONS ──────────────────────────────────────",
      "1. Review and resolve all CRITICAL and HIGH severity incidents.",
      "2. Patch or mitigate all CRITICAL vulnerabilities immediately.",
      "3. Investigate all OPEN incidents within 24 hours.",
      "4. Review firewall rules for detected DDoS / Port Scan sources.",
      "5. Enable MFA on all authentication services.",
      "6. Run a full vulnerability scan on all production hosts.",
      "",
      "=" .repeat(60),
      "  END OF REPORT — ShieldNet Enterprise SOC Platform",
      "=" .repeat(60),
    ];

    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `ShieldNet-Report-${format(new Date(), "yyyy-MM-dd-HHmm")}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    setExporting(false);
  };

  const exportCSV = () => {
    const headers = ["Attack Type", "Events"];
    const rows    = attacks.map(a => `${a.name},${a.value}`);
    const csv     = [headers.join(","), ...rows].join("\n");
    const blob    = new Blob([csv], { type: "text/csv" });
    const url     = URL.createObjectURL(blob);
    const a       = document.createElement("a");
    a.href        = url;
    a.download    = `ShieldNet-AttackData-${format(new Date(), "yyyy-MM-dd")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader className="w-6 h-6 animate-spin text-cyber-accent" />
      </div>
    );
  }

  const avgRisk = risk.length
    ? (risk.reduce((s, r) => s + r.risk, 0) / risk.length).toFixed(1)
    : 0;
  const maxRisk = risk.length ? Math.max(...risk.map(r => r.risk)).toFixed(1) : 0;

  return (
    <div className="p-6 space-y-5 min-h-full">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyber-accent" /> Security Reports
          </h1>
          {generated && (
            <p className="text-xs text-cyber-muted font-mono mt-0.5">
              Last generated: {format(generated, "MMM d, yyyy HH:mm:ss")}
            </p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 text-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={exportReport}
            disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent text-xs font-semibold hover:bg-cyber-accent/20 disabled:opacity-40 transition-colors"
          >
            {exporting ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            Export Report
          </button>
          <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Executive summary cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          { label: "Total Events",      value: stats?.total_packets?.toLocaleString() ?? "0",  icon: BarChart2,   color: "text-cyber-accent" },
          { label: "Threats Detected",  value: stats?.threats_detected?.toLocaleString() ?? "0", icon: AlertTriangle, color: "text-red-400" },
          { label: "Security Score",    value: `${stats?.security_score ?? 100}%`,             icon: Shield,      color: stats?.security_score >= 70 ? "text-green-400" : "text-red-400" },
          { label: "Open Incidents",    value: incStats?.open ?? 0,                            icon: Clock,       color: "text-orange-400" },
        ].map(({ label, value, icon: Icon, color }) => (
          <motion.div
            key={label}
            whileHover={{ y: -2 }}
            className="glass border border-cyber-border rounded-xl p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <p className="text-xs text-cyber-muted uppercase tracking-widest">{label}</p>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
          </motion.div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

        {/* Attack distribution bar chart */}
        <ReportSection title="Attack Distribution" icon={BarChart2}>
          {attacks.length === 0 ? (
            <p className="text-center text-cyber-muted text-sm font-mono py-8">No attack data yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={attacks} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1a2744" />
                <XAxis dataKey="name" tick={{ fill: "#8aa4c8", fontSize: 10 }} />
                <YAxis tick={{ fill: "#8aa4c8", fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" name="Events" radius={[4, 4, 0, 0]}>
                  {attacks.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ReportSection>

        {/* Threat metrics */}
        <ReportSection title="Threat Metrics" icon={TrendingUp}>
          <MetricRow
            label="Threat Detection Rate"
            value={`${(((stats?.threats_detected ?? 0) / Math.max(stats?.total_packets ?? 1, 1)) * 100).toFixed(1)}%`}
            color="text-red-400"
            bar={((stats?.threats_detected ?? 0) / Math.max(stats?.total_packets ?? 1, 1)) * 100}
          />
          <MetricRow label="Average Risk Score"  value={`${avgRisk}%`} color="text-yellow-400" bar={parseFloat(avgRisk)} />
          <MetricRow label="Maximum Risk Score"  value={`${maxRisk}%`} color="text-red-400"    bar={parseFloat(maxRisk)} />
          <MetricRow label="Security Score"      value={`${stats?.security_score ?? 100}%`} color="text-cyber-green" bar={stats?.security_score ?? 100} />
          <MetricRow label="Critical Vulnerabilities" value={vulnStats?.critical ?? 0} color="text-red-400" />
          <MetricRow label="Open Incidents"      value={incStats?.open ?? 0} color="text-orange-400" />
        </ReportSection>
      </div>

      {/* Incident + Vulnerability summary */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <ReportSection title="Incident Summary" icon={AlertTriangle}>
          <MetricRow label="Total Incidents"      value={incStats?.total ?? 0} />
          <MetricRow label="Open"                 value={incStats?.open ?? 0}          color="text-red-400" />
          <MetricRow label="Under Investigation"  value={incStats?.investigating ?? 0} color="text-orange-400" />
          <MetricRow label="Resolved / Closed"    value={incStats?.resolved ?? 0}      color="text-green-400" />
          <MetricRow label="Critical Severity"    value={incStats?.critical ?? 0}      color="text-red-500" />
        </ReportSection>

        <ReportSection title="Vulnerability Summary" icon={Shield}>
          <MetricRow label="Total Findings" value={vulnStats?.total ?? 0} />
          <MetricRow label="Critical"       value={vulnStats?.critical ?? 0} color="text-red-400" />
          <MetricRow label="High"           value={vulnStats?.high    ?? 0} color="text-orange-400" />
          <MetricRow label="Medium"         value={vulnStats?.medium  ?? 0} color="text-yellow-400" />
          <MetricRow label="Open"           value={vulnStats?.open    ?? 0} color="text-red-400" />
          <MetricRow label="Vuln Risk Score" value={`${vulnStats?.risk_score ?? 0}`} color="text-orange-400" bar={vulnStats?.risk_score ?? 0} />
        </ReportSection>
      </div>

      {/* Recommendations */}
      <ReportSection title="Security Recommendations" icon={CheckCircle}>
        <div className="space-y-3">
          {[
            { priority: "CRITICAL", text: "Resolve all CRITICAL and HIGH severity incidents immediately." },
            { priority: "HIGH",     text: "Patch all CRITICAL vulnerabilities on production systems." },
            { priority: "HIGH",     text: "Block source IPs from detected DDoS and port scan events." },
            { priority: "MEDIUM",   text: "Enable multi-factor authentication on all SSH and RDP services." },
            { priority: "MEDIUM",   text: "Review firewall rules and close unnecessary open ports." },
            { priority: "LOW",      text: "Schedule a full vulnerability scan weekly." },
            { priority: "LOW",      text: "Review and update the incident response playbooks quarterly." },
          ].map((r, i) => (
            <div key={i} className="flex items-start gap-3">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border shrink-0 mt-0.5 ${
                r.priority === "CRITICAL" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                r.priority === "HIGH"     ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
                r.priority === "MEDIUM"   ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" :
                                            "bg-green-500/20 text-green-400 border-green-500/30"
              }`}>{r.priority}</span>
              <p className="text-xs text-cyber-muted">{r.text}</p>
            </div>
          ))}
        </div>
      </ReportSection>

    </div>
  );
}
