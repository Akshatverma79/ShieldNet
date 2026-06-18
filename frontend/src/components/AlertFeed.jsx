import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, CheckCircle } from "lucide-react";
import { wsService } from "../services/websocket";
import { format } from "date-fns";

const SEVERITY_STYLES = {
  CRITICAL: { bar: "bg-red-500",    badge: "bg-red-500/20 text-red-400 border-red-500/30" },
  HIGH:     { bar: "bg-orange-500", badge: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  MEDIUM:   { bar: "bg-yellow-500", badge: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  LOW:      { bar: "bg-green-500",  badge: "bg-green-500/20 text-green-400 border-green-500/30" },
};

function AlertRow({ alert, isNew }) {
  const isThreat = alert.status === "THREAT";
  const s = SEVERITY_STYLES[alert.severity] || SEVERITY_STYLES.LOW;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -20, height: 0 }}
      animate={{ opacity: 1, x: 0, height: "auto" }}
      exit={{ opacity: 0, x: 20, height: 0 }}
      transition={{ duration: 0.3 }}
      className={`relative flex items-start gap-3 p-3 rounded-lg border transition-all ${
        isThreat
          ? "bg-red-500/5 border-red-500/20"
          : "bg-green-500/5 border-green-500/10"
      } ${isNew ? "ring-1 ring-cyber-accent/40" : ""}`}
    >
      {/* Left severity bar */}
      <div className={`absolute left-0 top-0 bottom-0 w-0.5 rounded-l-lg ${s.bar}`} />

      {/* Icon */}
      <div className="mt-0.5 ml-1">
        {isThreat
          ? <AlertTriangle className="w-4 h-4 text-cyber-red" />
          : <CheckCircle className="w-4 h-4 text-cyber-green" />
        }
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-xs font-semibold font-mono ${isThreat ? "text-cyber-red" : "text-cyber-green"}`}>
            {isThreat ? "⚠ THREAT" : "✓ NORMAL"}
          </span>
          {isThreat && (
            <span className={`text-xs px-1.5 py-0.5 rounded border font-mono ${s.badge}`}>
              {alert.attack_type}
            </span>
          )}
          <span className={`text-xs px-1.5 py-0.5 rounded border font-mono ${s.badge}`}>
            {alert.severity}
          </span>
        </div>
        <div className="flex gap-3 mt-1 text-xs text-cyber-muted font-mono">
          <span>{alert.source_ip} → {alert.destination_ip}</span>
          <span className="text-cyber-accent">Risk: {alert.risk_score}%</span>
        </div>
        {isThreat && alert.reason && (
          <p className="text-xs text-cyber-muted mt-0.5 truncate">
            {Array.isArray(alert.reason) ? alert.reason[0] : alert.reason}
          </p>
        )}
      </div>

      {/* Timestamp */}
      <div className="text-xs text-cyber-muted font-mono shrink-0">
        {format(new Date(alert.timestamp || Date.now()), "HH:mm:ss")}
      </div>
    </motion.div>
  );
}

export default function AlertFeed({ maxItems = 30 }) {
  const [alerts, setAlerts] = useState([]);
  const [newId, setNewId]   = useState(null);

  useEffect(() => {
    const handle = (data) => {
      if (!data) return;
      const alert = { ...data, _uid: Date.now() + Math.random() };
      setAlerts((prev) => [alert, ...prev].slice(0, maxItems));
      setNewId(alert._uid);
      setTimeout(() => setNewId(null), 2000);
    };

    const u1 = wsService.on("prediction", handle);
    const u2 = wsService.on("simulation", handle);
    return () => { u1(); u2(); };
  }, [maxItems]);

  return (
    <div className="space-y-1.5 overflow-y-auto max-h-96 pr-1">
      {alerts.length === 0 ? (
        <div className="text-center text-cyber-muted text-sm py-8 font-mono">
          Waiting for live events…
        </div>
      ) : (
        <AnimatePresence mode="popLayout">
          {alerts.map((a) => (
            <AlertRow key={a._uid} alert={a} isNew={a._uid === newId} />
          ))}
        </AnimatePresence>
      )}
    </div>
  );
}
