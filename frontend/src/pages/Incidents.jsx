import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertOctagon, Plus, RefreshCw, ChevronDown,
  ChevronUp, Shield, Clock, User, FileText,
  CheckCircle, XCircle, AlertTriangle, Loader
} from "lucide-react";
import {
  fetchIncidents, fetchIncidentStats,
  createIncident, updateIncident, deleteIncident
} from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import { format } from "date-fns";

const STATUS_COLORS = {
  OPEN:          "bg-red-500/20 text-red-400 border-red-500/30",
  INVESTIGATING: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  RESOLVED:      "bg-green-500/20 text-green-400 border-green-500/30",
  CLOSED:        "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const STATUS_ICONS = {
  OPEN:          AlertOctagon,
  INVESTIGATING: AlertTriangle,
  RESOLVED:      CheckCircle,
  CLOSED:        XCircle,
};

// ── Playbook step list ───────────────────────────────────────────
function Playbook({ steps }) {
  return (
    <div className="space-y-1.5 mt-2">
      {steps.map((step, i) => (
        <div key={i} className="flex items-start gap-2 text-xs font-mono">
          <span className="w-5 h-5 rounded-full bg-cyber-accent/10 border border-cyber-accent/20 text-cyber-accent text-[10px] flex items-center justify-center shrink-0 mt-0.5">
            {i + 1}
          </span>
          <span className="text-cyber-muted">{step}</span>
        </div>
      ))}
    </div>
  );
}

// ── Single incident row ──────────────────────────────────────────
function IncidentRow({ inc, onUpdate, onDelete }) {
  const [expanded,  setExpanded]  = useState(false);
  const [updating,  setUpdating]  = useState(false);
  const [notes,     setNotes]     = useState(inc.notes || "");

  const StatusIcon = STATUS_ICONS[inc.status] || AlertOctagon;
  const steps = Array.isArray(inc.playbook) ? inc.playbook : [];

  const changeStatus = async (status) => {
    setUpdating(true);
    try { await onUpdate(inc.id, { status }); } finally { setUpdating(false); }
  };

  const saveNotes = async () => {
    setUpdating(true);
    try { await onUpdate(inc.id, { notes }); } finally { setUpdating(false); }
  };

  return (
    <div className="glass border border-cyber-border rounded-xl overflow-hidden">
      {/* Header row */}
      <div
        className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-white/3 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={`flex items-center gap-1.5 px-2 py-1 rounded-lg border text-xs font-mono ${STATUS_COLORS[inc.status] || STATUS_COLORS.OPEN}`}>
          {updating ? <Loader className="w-3 h-3 animate-spin" /> : <StatusIcon className="w-3 h-3" />}
          {inc.status}
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-white truncate">#{inc.id} — {inc.title}</p>
          <div className="flex items-center gap-3 mt-0.5 text-[11px] font-mono text-cyber-muted">
            <span>{inc.source_ip}</span>
            <span>·</span>
            <span>{inc.mitre_id} · {inc.mitre_tactic}</span>
            <span>·</span>
            <span>{inc.created_at ? format(new Date(inc.created_at), "MMM d, HH:mm") : "—"}</span>
          </div>
        </div>

        <SeverityBadge label={inc.severity} />

        {expanded ? <ChevronUp className="w-4 h-4 text-cyber-muted" /> : <ChevronDown className="w-4 h-4 text-cyber-muted" />}
      </div>

      {/* Expanded detail */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden border-t border-cyber-border"
          >
            <div className="px-5 py-4 grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left: description + playbook */}
              <div className="space-y-4">
                <div>
                  <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-1">Description</p>
                  <p className="text-xs text-cyber-muted leading-relaxed">{inc.description || "No description."}</p>
                </div>
                <div>
                  <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-1">Response Playbook</p>
                  <Playbook steps={steps} />
                </div>
              </div>

              {/* Right: actions + notes */}
              <div className="space-y-4">
                <div>
                  <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">Update Status</p>
                  <div className="flex flex-wrap gap-2">
                    {["OPEN","INVESTIGATING","RESOLVED","CLOSED"].map(s => (
                      <button
                        key={s}
                        onClick={() => changeStatus(s)}
                        disabled={updating || inc.status === s}
                        className={`px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors disabled:opacity-40 ${
                          inc.status === s
                            ? STATUS_COLORS[s]
                            : "border-cyber-border text-cyber-muted hover:text-white hover:border-cyber-accent/40"
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <p className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">Analyst Notes</p>
                  <textarea
                    value={notes}
                    onChange={e => setNotes(e.target.value)}
                    rows={3}
                    placeholder="Add investigation notes…"
                    className="w-full bg-transparent border border-cyber-border rounded-lg px-3 py-2 text-xs text-white font-mono placeholder-cyber-muted focus:outline-none focus:border-cyber-accent/50 resize-none"
                  />
                  <button
                    onClick={saveNotes}
                    disabled={updating}
                    className="mt-1.5 px-3 py-1.5 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent text-xs font-semibold hover:bg-cyber-accent/20 transition-colors disabled:opacity-40"
                  >
                    Save Notes
                  </button>
                </div>

                <button
                  onClick={() => onDelete(inc.id)}
                  className="text-xs font-mono text-red-400/60 hover:text-red-400 transition-colors"
                >
                  Delete incident
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Create incident modal ────────────────────────────────────────
function CreateModal({ onClose, onCreate }) {
  const [form, setForm] = useState({
    title: "", description: "", severity: "MEDIUM",
    attack_type: "Unknown Threat", source_ip: "0.0.0.0",
  });
  const [loading, setLoading] = useState(false);
  const set = (k, v) => setForm(p => ({ ...p, [k]: v }));

  const submit = async () => {
    if (!form.title.trim()) return;
    setLoading(true);
    try {
      await onCreate(form);
      onClose();
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
        className="w-full max-w-lg glass border border-cyber-border rounded-2xl p-6 space-y-4"
        onClick={e => e.stopPropagation()}
      >
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <Plus className="w-4 h-4 text-cyber-accent" /> Create Incident
        </h2>

        {[
          ["Title",       "title",       "text",   "Incident title…"],
          ["Source IP",   "source_ip",   "text",   "0.0.0.0"],
        ].map(([label, key, type, ph]) => (
          <div key={key}>
            <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">{label}</label>
            <input type={type} value={form[key]} onChange={e => set(key, e.target.value)}
              placeholder={ph}
              className="w-full mt-1 bg-transparent border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-cyber-muted focus:outline-none focus:border-cyber-accent/50"
            />
          </div>
        ))}

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">Severity</label>
            <select value={form.severity} onChange={e => set("severity", e.target.value)}
              className="w-full mt-1 bg-cyber-card border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-accent/50">
              {["LOW","MEDIUM","HIGH","CRITICAL"].map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">Attack Type</label>
            <select value={form.attack_type} onChange={e => set("attack_type", e.target.value)}
              className="w-full mt-1 bg-cyber-card border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-accent/50">
              {["DDoS","Port Scan","Brute Force","Web Attack","Infiltration","Unknown Threat"].map(a => <option key={a}>{a}</option>)}
            </select>
          </div>
        </div>

        <div>
          <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">Description</label>
          <textarea value={form.description} onChange={e => set("description", e.target.value)} rows={3}
            placeholder="Describe the incident…"
            className="w-full mt-1 bg-transparent border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-cyber-muted focus:outline-none focus:border-cyber-accent/50 resize-none"
          />
        </div>

        <div className="flex gap-3 justify-end">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-cyber-border text-cyber-muted text-sm hover:text-white transition-colors">
            Cancel
          </button>
          <button onClick={submit} disabled={loading || !form.title.trim()}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent text-sm font-semibold hover:bg-cyber-accent/20 disabled:opacity-40 transition-colors">
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            Create
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ── Main page ────────────────────────────────────────────────────
export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [stats,     setStats]     = useState({});
  const [loading,   setLoading]   = useState(true);
  const [showCreate,setShowCreate]= useState(false);
  const [filter,    setFilter]    = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [inc, st] = await Promise.all([fetchIncidents({ per_page: 50 }), fetchIncidentStats()]);
      setIncidents(inc.data.incidents || []);
      setStats(st.data || {});
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (body) => { await createIncident(body); load(); };
  const handleUpdate = async (id, body) => {
    await updateIncident(id, body);
    setIncidents(prev => prev.map(i => i.id === id ? { ...i, ...body } : i));
  };
  const handleDelete = async (id) => {
    await deleteIncident(id); setIncidents(prev => prev.filter(i => i.id !== id));
  };

  const filtered = filter
    ? incidents.filter(i => i.status === filter)
    : incidents;

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
            <AlertOctagon className="w-5 h-5 text-red-400" /> Incident Management
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {stats.open || 0} open · {stats.investigating || 0} investigating · {stats.resolved || 0} resolved
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 text-cyber-accent text-sm font-semibold hover:bg-cyber-accent/20 transition-colors">
            <Plus className="w-4 h-4" /> New Incident
          </button>
          <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        <StatBox label="Total"       value={stats.total}    color="text-white" />
        <StatBox label="Open"        value={stats.open}     color="text-red-400" />
        <StatBox label="Investigating" value={stats.investigating} color="text-orange-400" />
        <StatBox label="Resolved"    value={stats.resolved} color="text-green-400" />
        <StatBox label="Critical"    value={stats.critical} color="text-red-500" />
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2">
        {["", "OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"].map(s => (
          <button key={s} onClick={() => setFilter(s)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono border transition-colors ${
              filter === s
                ? "bg-cyber-accent/10 border-cyber-accent/30 text-cyber-accent"
                : "border-cyber-border text-cyber-muted hover:text-white"
            }`}>
            {s || "All"}
          </button>
        ))}
      </div>

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-cyber-muted font-mono text-sm">
          <Loader className="w-5 h-5 animate-spin mr-2" /> Loading incidents…
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 space-y-2 text-cyber-muted">
          <Shield className="w-10 h-10 opacity-30" />
          <p className="text-sm font-mono">No incidents found</p>
          <p className="text-xs font-mono opacity-60">Create one manually or run the simulation to generate threats</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(inc => (
            <IncidentRow key={inc.id} inc={inc} onUpdate={handleUpdate} onDelete={handleDelete} />
          ))}
        </div>
      )}

      {/* Create modal */}
      <AnimatePresence>
        {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreate={handleCreate} />}
      </AnimatePresence>
    </div>
  );
}
