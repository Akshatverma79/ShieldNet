import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  Search, Filter, RefreshCw, ChevronLeft,
  ChevronRight, Download
} from "lucide-react";
import { fetchLogs } from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import { format } from "date-fns";

const STATUS_OPTIONS   = ["", "THREAT", "NORMAL"];
const SEVERITY_OPTIONS = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];

function ThreatRow({ log, index }) {
  const [expanded, setExpanded] = useState(false);
  const isThreat = log.status === "THREAT";

  let reasons = [];
  try { reasons = Array.isArray(log.reason) ? log.reason : JSON.parse(log.reason || "[]"); } catch { reasons = []; }

  return (
    <>
      <motion.tr
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: index * 0.02 }}
        onClick={() => setExpanded(!expanded)}
        className={`cursor-pointer border-b border-cyber-border transition-colors ${
          isThreat ? "hover:bg-red-500/5" : "hover:bg-green-500/5"
        }`}
      >
        <td className="px-4 py-3 text-xs font-mono text-cyber-muted">
          {log.timestamp ? format(new Date(log.timestamp), "yyyy-MM-dd HH:mm:ss") : "—"}
        </td>
        <td className="px-4 py-3 text-xs font-mono">
          <span className="text-cyber-accent">{log.source_ip}</span>
          <span className="text-cyber-muted mx-1">→</span>
          <span className="text-white">{log.destination_ip}</span>
        </td>
        <td className="px-4 py-3 text-xs font-mono text-cyber-muted">{log.protocol}</td>
        <td className="px-4 py-3">
          <SeverityBadge label={log.status} />
        </td>
        <td className="px-4 py-3 text-xs font-mono text-cyber-muted">
          {isThreat ? log.attack_type : "—"}
        </td>
        <td className="px-4 py-3">
          <SeverityBadge label={log.severity} />
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="w-24 h-1.5 bg-cyber-border rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  log.risk_score >= 75 ? "bg-red-500"
                  : log.risk_score >= 40 ? "bg-yellow-500"
                  : "bg-green-500"
                }`}
                style={{ width: `${log.risk_score}%` }}
              />
            </div>
            <span className="text-xs font-mono text-cyber-muted">{log.risk_score}%</span>
          </div>
        </td>
      </motion.tr>

      {/* Expandable detail row */}
      {expanded && (
        <tr className="bg-cyber-card/50">
          <td colSpan={7} className="px-4 py-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div>
                <p className="text-cyber-muted mb-1">Source Port</p>
                <p className="text-white">{log.source_port}</p>
              </div>
              <div>
                <p className="text-cyber-muted mb-1">Destination Port</p>
                <p className="text-white">{log.destination_port}</p>
              </div>
              <div>
                <p className="text-cyber-muted mb-1">Confidence</p>
                <p className="text-cyber-accent">{(log.confidence * 100).toFixed(1)}%</p>
              </div>
              <div>
                <p className="text-cyber-muted mb-1">Flow Duration</p>
                <p className="text-white">{log.flow_duration?.toFixed(3)}s</p>
              </div>
              {reasons.length > 0 && (
                <div className="col-span-2 md:col-span-4">
                  <p className="text-cyber-muted mb-1">Detection Reasons</p>
                  <ul className="space-y-0.5">
                    {reasons.map((r, i) => (
                      <li key={i} className="text-cyber-accent flex items-center gap-1">
                        <span className="text-cyber-muted">›</span> {r}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

export default function ThreatHistory() {
  const [logs,     setLogs]     = useState([]);
  const [total,    setTotal]    = useState(0);
  const [page,     setPage]     = useState(1);
  const [perPage]               = useState(25);
  const [search,   setSearch]   = useState("");
  const [status,   setStatus]   = useState("");
  const [severity, setSeverity] = useState("");
  const [loading,  setLoading]  = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchLogs({ page, per_page: perPage, search, status, severity });
      setLogs(res.data.logs);
      setTotal(res.data.total);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [page, perPage, search, status, severity]);

  useEffect(() => { load(); }, [load]);

  // Reset to page 1 on filter change
  useEffect(() => { setPage(1); }, [search, status, severity]);

  const totalPages = Math.ceil(total / perPage);

  const exportCSV = () => {
    const headers = ["Timestamp","Source IP","Dest IP","Protocol","Status","Attack Type","Severity","Risk Score"];
    const rows = logs.map(l =>
      [l.timestamp, l.source_ip, l.destination_ip, l.protocol,
       l.status, l.attack_type, l.severity, l.risk_score].join(",")
    );
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = `shieldnet-logs-${Date.now()}.csv`; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-5 min-h-full">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Threat Log History</h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {total.toLocaleString()} total events — click a row to expand details
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={exportCSV}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 text-xs transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> Export CSV
          </button>
          <button
            onClick={load}
            className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="glass border border-cyber-border rounded-xl p-4 flex flex-wrap gap-3 items-center">
        {/* Search */}
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search IP, attack type…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-2 bg-transparent border border-cyber-border rounded-lg text-xs text-white placeholder-cyber-muted font-mono focus:outline-none focus:border-cyber-accent/50 transition-colors"
          />
        </div>

        {/* Status filter */}
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-cyber-muted" />
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="bg-cyber-card border border-cyber-border rounded-lg text-xs text-cyber-muted font-mono px-3 py-2 focus:outline-none focus:border-cyber-accent/50"
          >
            <option value="">All Status</option>
            {STATUS_OPTIONS.filter(Boolean).map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>

        {/* Severity filter */}
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-cyber-card border border-cyber-border rounded-lg text-xs text-cyber-muted font-mono px-3 py-2 focus:outline-none focus:border-cyber-accent/50"
        >
          <option value="">All Severity</option>
          {SEVERITY_OPTIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="glass border border-cyber-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-card/50">
                {["Timestamp","Source → Destination","Protocol","Status","Attack Type","Severity","Risk Score"].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-cyber-muted uppercase tracking-wider">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-cyber-muted text-sm font-mono">
                    Loading logs…
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-cyber-muted text-sm font-mono">
                    No logs match the current filters.
                  </td>
                </tr>
              ) : (
                logs.map((log, i) => <ThreatRow key={log.id} log={log} index={i} />)
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-cyber-border">
            <p className="text-xs text-cyber-muted font-mono">
              Showing {(page - 1) * perPage + 1}–{Math.min(page * perPage, total)} of {total}
            </p>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1.5 rounded border border-cyber-border text-cyber-muted hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                const pg = Math.max(1, Math.min(page - 2, totalPages - 4)) + i;
                return (
                  <button
                    key={pg}
                    onClick={() => setPage(pg)}
                    className={`w-8 h-8 rounded border text-xs font-mono transition-colors ${
                      pg === page
                        ? "bg-cyber-accent/20 border-cyber-accent/40 text-cyber-accent"
                        : "border-cyber-border text-cyber-muted hover:text-white"
                    }`}
                  >
                    {pg}
                  </button>
                );
              })}
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-1.5 rounded border border-cyber-border text-cyber-muted hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
