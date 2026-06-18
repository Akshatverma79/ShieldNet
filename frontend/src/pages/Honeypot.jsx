import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bug, Play, Trash2, RefreshCw, AlertTriangle,
  Server, Terminal, Loader
} from "lucide-react";
import { fetchHoneypotLogs, simulateHoneypot, clearHoneypot } from "../services/api";
import { format } from "date-fns";

function HoneypotEvent({ event }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      className="glass border border-red-500/20 bg-red-500/3 rounded-xl p-4 cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-red-500 status-dot" />
          <div>
            <p className="text-sm font-mono font-semibold text-white">
              🎣 Attacker: <span className="text-red-400">{event.attacker_ip}</span>
            </p>
            <p className="text-xs text-cyber-muted font-mono">
              {event.service} (:{event.port}) · {event.session_duration_s}s
              {event.exfil_attempted && " · ⚠ Exfil attempted"}
            </p>
          </div>
        </div>
        <div className="text-right">
          <p className="text-xs text-cyber-muted font-mono">
            {event.timestamp ? format(new Date(event.timestamp), "MMM d HH:mm:ss") : "—"}
          </p>
          <p className="text-[10px] text-cyber-muted">{event.commands.length} command(s)</p>
        </div>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden mt-3 pt-3 border-t border-red-500/20"
          >
            <p className="text-xs text-cyber-muted font-mono mb-2 uppercase tracking-wider">Commands executed:</p>
            <div className="bg-black/40 rounded-lg p-3 font-mono text-xs space-y-1">
              {event.commands.map((cmd, i) => (
                <p key={i} className="text-green-400">
                  <span className="text-cyber-muted mr-2">{String(i + 1).padStart(2, "0")} $</span>
                  {cmd}
                </p>
              ))}
            </div>
            <div className="mt-2 grid grid-cols-3 gap-2 text-[10px] font-mono">
              <div><span className="text-cyber-muted">Banner:</span> <span className="text-white">{event.banner_sent}</span></div>
              <div><span className="text-cyber-muted">Bytes:</span> <span className="text-white">{event.bytes_transferred}</span></div>
              <div><span className="text-cyber-muted">Exfil:</span> <span className={event.exfil_attempted ? "text-red-400" : "text-green-400"}>{event.exfil_attempted ? "YES" : "NO"}</span></div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default function Honeypot() {
  const [logs,       setLogs]       = useState([]);
  const [services,   setServices]   = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [simulating, setSimulating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchHoneypotLogs(50);
      setLogs(res.data.logs || []);
      setServices(res.data.services || []);
    } catch { } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const runSim = async () => {
    setSimulating(true);
    try {
      const res = await simulateHoneypot();
      setLogs(prev => [res.data, ...prev]);
    } catch { } finally { setSimulating(false); }
  };

  const clear = async () => {
    await clearHoneypot().catch(() => {});
    setLogs([]);
  };

  return (
    <div className="p-6 space-y-5 min-h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Bug className="w-5 h-5 text-yellow-400" /> Honeypot Monitor
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            {logs.length} attacker interactions captured
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={runSim} disabled={simulating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 text-xs font-semibold hover:bg-yellow-500/20 disabled:opacity-40 transition-colors">
            {simulating ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            Simulate Trigger
          </button>
          <button onClick={clear} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-red-400 transition-colors">
            <Trash2 className="w-4 h-4" />
          </button>
          <button onClick={load} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Active services */}
      <div className="glass border border-cyber-border rounded-xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <Server className="w-4 h-4 text-cyber-accent" />
          <p className="text-xs font-semibold text-white uppercase tracking-wider">Honeypot Services (Fake)</p>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {services.map((s, i) => (
            <div key={i} className="bg-cyber-border/20 rounded-lg p-3 text-xs font-mono">
              <div className="flex items-center gap-1.5 mb-1">
                <span className="w-2 h-2 rounded-full bg-green-500 status-dot" />
                <span className="text-white font-semibold">{s.service}</span>
              </div>
              <p className="text-cyber-muted">Port {s.port}</p>
              <p className="text-cyber-muted/70 text-[10px] truncate">{s.banner}</p>
            </div>
          ))}
        </div>
        <p className="mt-3 text-[10px] text-cyber-muted/60 font-mono">
          ⚠ These are simulated services. In production, deploy actual honeypot software (e.g., Cowrie, Dionaea).
        </p>
      </div>

      {/* Info banner */}
      <div className="glass border border-yellow-500/30 bg-yellow-500/5 rounded-xl p-3 flex items-start gap-3 text-xs font-mono text-yellow-400">
        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
        <p>Honeypot captures attacker behaviour in fake vulnerable services. Real attacker IPs and commands are logged for threat intelligence purposes.</p>
      </div>

      {/* Event log */}
      {loading ? (
        <div className="flex items-center justify-center py-12 text-cyber-muted font-mono text-sm">
          <Loader className="w-5 h-5 animate-spin mr-2" /> Loading…
        </div>
      ) : logs.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 space-y-3 text-cyber-muted">
          <Terminal className="w-10 h-10 opacity-30" />
          <p className="text-sm font-mono">No honeypot triggers yet</p>
          <p className="text-xs font-mono opacity-60">Click "Simulate Trigger" to generate a demo interaction</p>
        </div>
      ) : (
        <div className="space-y-3">
          <AnimatePresence>
            {logs.map((e, i) => <HoneypotEvent key={e.id || i} event={e} />)}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}
