import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Zap, AlertTriangle, Scan, Lock,
  Play, CheckCircle, XCircle, Loader
} from "lucide-react";
import { triggerSimulation } from "../services/api";

const ATTACKS = [
  {
    id:          "ddos",
    label:       "DDoS Attack",
    description: "Simulates a Distributed Denial-of-Service flood — high packet rate, symmetric traffic pattern, multiple source IPs targeting a single endpoint.",
    icon:        Zap,
    accent:      "#ff3b5c",
    borderColor: "border-red-500/30",
    bgColor:     "bg-red-500/10",
    textColor:   "text-red-400",
    details:     ["Protocol: UDP/TCP Flood", "Packet Rate: 10,000–100,000 pps", "Source IPs: Spoofed range", "Target: Port 80/443/53"],
  },
  {
    id:          "portscan",
    label:       "Port Scan",
    description: "Simulates a TCP SYN scan across all ports — characteristic short-lived connections, low byte count per packet, high SYN/RST flag ratio.",
    icon:        Scan,
    accent:      "#ffd60a",
    borderColor: "border-yellow-500/30",
    bgColor:     "bg-yellow-500/10",
    textColor:   "text-yellow-400",
    details:     ["Protocol: TCP SYN", "Ports: 1–65535 sweep", "Packet size: 40–80 bytes", "Duration: < 100ms/port"],
  },
  {
    id:          "bruteforce",
    label:       "Brute Force",
    description: "Simulates a credential brute-force attack on SSH/FTP/RDP — sustained bi-directional flow to a single auth port with high SYN+ACK frequency.",
    icon:        Lock,
    accent:      "#9d4edd",
    borderColor: "border-purple-500/30",
    bgColor:     "bg-purple-500/10",
    textColor:   "text-purple-400",
    details:     ["Protocol: TCP", "Target: SSH/FTP/RDP ports", "Auth attempts: 100–2000", "Direction: Bidirectional"],
  },
];

function AttackCard({ attack, onRun }) {
  const Icon = attack.icon;
  const [count,   setCount]   = useState(5);
  const [loading, setLoading] = useState(false);
  const [done,    setDone]    = useState(false);
  const [error,   setError]   = useState(null);

  const run = async () => {
    setLoading(true);
    setError(null);
    setDone(false);
    try {
      await triggerSimulation(attack.id, count);
      setDone(true);
      onRun?.(attack.id, count);
    } catch (e) {
      setError(e?.response?.data?.detail || "Simulation failed. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      whileHover={{ y: -2 }}
      className={`glass border ${attack.borderColor} rounded-xl p-6 flex flex-col gap-4`}
    >
      {/* Header */}
      <div className="flex items-start gap-3">
        <div className={`p-3 rounded-xl ${attack.bgColor}`}>
          <Icon className={`w-5 h-5 ${attack.textColor}`} />
        </div>
        <div>
          <h3 className={`font-semibold text-sm ${attack.textColor}`}>{attack.label}</h3>
          <p className="text-xs text-cyber-muted mt-1 leading-relaxed">{attack.description}</p>
        </div>
      </div>

      {/* Technical details */}
      <div className="grid grid-cols-2 gap-1.5">
        {attack.details.map((d, i) => (
          <div key={i} className="flex items-center gap-1.5 text-xs font-mono text-cyber-muted">
            <span style={{ color: attack.accent }}>›</span> {d}
          </div>
        ))}
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 pt-2 border-t border-cyber-border">
        <div className="flex items-center gap-2">
          <label className="text-xs text-cyber-muted font-mono">Events:</label>
          <input
            type="number" min={1} max={50} value={count}
            onChange={(e) => setCount(Math.max(1, Math.min(50, Number(e.target.value))))}
            className="w-16 bg-transparent border border-cyber-border rounded px-2 py-1 text-xs text-white font-mono text-center focus:outline-none focus:border-cyber-accent/50"
          />
        </div>
        <button
          onClick={run}
          disabled={loading}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
            loading
              ? "bg-cyber-border text-cyber-muted cursor-wait"
              : `${attack.bgColor} ${attack.textColor} border ${attack.borderColor} hover:brightness-125`
          }`}
        >
          {loading
            ? <><Loader className="w-3.5 h-3.5 animate-spin" /> Running…</>
            : <><Play   className="w-3.5 h-3.5" /> Run Simulation</>
          }
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-2 text-xs text-red-400 font-mono bg-red-500/5 border border-red-500/20 rounded p-2">
          <XCircle className="w-3.5 h-3.5 shrink-0" />
          {error}
        </div>
      )}

      {/* Success */}
      {done && !loading && (
        <div className="text-xs text-cyber-green font-mono bg-green-500/5 border border-green-500/20 rounded p-2 flex items-center gap-2">
          <CheckCircle className="w-3.5 h-3.5 shrink-0" />
          {count} events injected — check Live Feed &amp; Threat Logs
        </div>
      )}
    </motion.div>
  );
}

export default function Simulation() {
  const [runHistory, setRunHistory] = useState([]);

  const handleRun = (type, count) => {
    setRunHistory(prev => [
      { type, count, time: new Date().toLocaleTimeString(), id: Date.now() },
      ...prev.slice(0, 9),
    ]);
  };

  return (
    <div className="p-6 space-y-6 min-h-full">

      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-white flex items-center gap-2">
          <Zap className="w-5 h-5 text-yellow-400" />
          Attack Simulation
        </h1>
        <p className="text-xs text-cyber-muted font-mono mt-1">
          Inject synthetic attack traffic into the detection pipeline — for testing and demo purposes only.
        </p>
      </div>

      {/* Warning */}
      <div className="flex items-start gap-3 p-4 rounded-xl border border-yellow-500/30 bg-yellow-500/5 text-yellow-400 text-xs font-mono">
        <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
        <p>
          Simulations generate synthetic feature vectors processed by the real ML pipeline.
          No actual network packets are sent. Results are logged to the database and broadcast via WebSocket.
        </p>
      </div>

      {/* Attack cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {ATTACKS.map(attack => (
          <AttackCard key={attack.id} attack={attack} onRun={handleRun} />
        ))}
      </div>

      {/* Run history */}
      {runHistory.length > 0 && (
        <div className="glass border border-cyber-border rounded-xl p-5">
          <h2 className="text-sm font-semibold text-white uppercase tracking-widest mb-3">
            Session Run History
          </h2>
          <div className="space-y-1.5">
            <AnimatePresence>
              {runHistory.map(r => (
                <motion.div
                  key={r.id}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-3 text-xs font-mono text-cyber-muted"
                >
                  <span className="text-cyber-accent">{r.time}</span>
                  <span className="text-white capitalize">{r.type}</span>
                  <span>×{r.count} events injected</span>
                  <CheckCircle className="w-3 h-3 text-cyber-green ml-auto" />
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      )}
    </div>
  );
}
