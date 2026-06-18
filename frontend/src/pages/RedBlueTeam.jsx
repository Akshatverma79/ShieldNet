import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Swords, Shield, Play, Square, Zap, Lock, Scan,
  CheckCircle, AlertTriangle, Loader, RefreshCw
} from "lucide-react";
import {
  fetchRedBlueState, startRedBlue, redAttack,
  blueDefend, stopRedBlue
} from "../services/api";

const TEAM_COLOR = {
  RED:  "text-red-400  bg-red-500/10  border-red-500/30",
  BLUE: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

function ScoreBoard({ score, mode }) {
  return (
    <div className="glass border border-cyber-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider">Scoreboard</h2>
        <span className={`text-xs px-2 py-1 rounded border font-mono ${
          mode === "stopped" ? "text-cyber-muted border-cyber-border" : "text-green-400 border-green-400/40 bg-green-500/10"
        }`}>{mode === "stopped" ? "IDLE" : "ACTIVE"}</span>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="text-center">
          <p className="text-xs text-red-400 font-mono uppercase tracking-wider">Red Team</p>
          <p className="text-4xl font-bold font-mono text-red-400 mt-1">{score?.red ?? 0}</p>
          <p className="text-xs text-cyber-muted font-mono">points</p>
        </div>
        <div className="text-center">
          <p className="text-xs text-blue-400 font-mono uppercase tracking-wider">Blue Team</p>
          <p className="text-4xl font-bold font-mono text-blue-400 mt-1">{score?.blue ?? 0}</p>
          <p className="text-xs text-cyber-muted font-mono">points</p>
        </div>
      </div>
    </div>
  );
}

function EventLog({ events }) {
  return (
    <div className="glass border border-cyber-border rounded-xl p-5">
      <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-3">Event Log</h2>
      <div className="space-y-2 overflow-y-auto max-h-64">
        {events.length === 0 ? (
          <p className="text-xs text-cyber-muted font-mono text-center py-4">Start an exercise to see events</p>
        ) : (
          <AnimatePresence>
            {[...events].reverse().map((e, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className={`flex items-start gap-2 p-2 rounded-lg text-xs font-mono border ${
                  e.team === "RED"
                    ? "bg-red-500/5 border-red-500/20"
                    : "bg-blue-500/5 border-blue-500/20"
                }`}
              >
                {e.team === "RED"
                  ? <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                  : <Shield className="w-3 h-3 text-blue-400 shrink-0 mt-0.5" />
                }
                <div className="flex-1">
                  <span className={e.team === "RED" ? "text-red-400" : "text-blue-400"}>[{e.team}]</span>
                  {" "}<span className="text-white">{e.action}</span>
                  {e.team === "RED" && (
                    <span className={e.detected ? " ✓ DETECTED" : " ✗ EVADED"}>
                      <span className={e.detected ? " text-green-400" : " text-red-400"}>
                        {e.detected ? " — Detected!" : " — Evaded!"}
                      </span>
                    </span>
                  )}
                </div>
                <div className="text-right">
                  <span className={e.team === "RED" ? "text-red-400" : "text-blue-400"}>
                    +{e.points?.[e.team === "RED" ? "red" : "blue"] ?? 0}pts
                  </span>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}

export default function RedBlueTeam() {
  const [state,   setState]   = useState({ mode: "stopped", score: { red: 0, blue: 0 }, round: 0, events: [] });
  const [busy,    setBusy]    = useState(false);

  const refresh = useCallback(async () => {
    try {
      const res = await fetchRedBlueState();
      setState(res.data);
    } catch { }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const doStart = async (mode) => {
    setBusy(true);
    try { const res = await startRedBlue(mode); await refresh(); } finally { setBusy(false); }
  };

  const doRedAttack = async (type) => {
    setBusy(true);
    try { await redAttack(type); await refresh(); } finally { setBusy(false); }
  };

  const doBlueDefend = async (action) => {
    setBusy(true);
    try { await blueDefend(action); await refresh(); } finally { setBusy(false); }
  };

  const doStop = async () => {
    setBusy(true);
    try { await stopRedBlue(); await refresh(); } finally { setBusy(false); }
  };

  const isActive = state.mode !== "stopped";

  return (
    <div className="p-6 space-y-5 min-h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <Swords className="w-5 h-5 text-purple-400" /> Red Team vs Blue Team
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            Adversarial exercise — Round {state.round}
          </p>
        </div>
        <button onClick={refresh} className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors">
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Exercise controls */}
      <div className="glass border border-cyber-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider mb-3">Exercise Control</h2>
        <div className="flex flex-wrap gap-3">
          {!isActive ? (
            <>
              {["battle", "red_active", "blue_active"].map(mode => (
                <button key={mode} onClick={() => doStart(mode)} disabled={busy}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 text-xs font-semibold hover:bg-green-500/20 disabled:opacity-40 transition-colors">
                  <Play className="w-3.5 h-3.5" />
                  Start {mode.replace("_", " ").replace(/\b\w/g, c => c.toUpperCase())}
                </button>
              ))}
            </>
          ) : (
            <button onClick={doStop} disabled={busy}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-semibold hover:bg-red-500/20 disabled:opacity-40 transition-colors">
              {busy ? <Loader className="w-3.5 h-3.5 animate-spin" /> : <Square className="w-3.5 h-3.5" />}
              Stop Exercise
            </button>
          )}
        </div>
        {!isActive && <p className="mt-2 text-xs text-cyber-muted font-mono">
          Battle = both teams active. red_active/blue_active = solo practice.
        </p>}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

        {/* Red Team actions */}
        <div className="glass border border-red-500/20 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Red Team — Attack
          </h2>
          <div className="space-y-2">
            {[
              { type: "ddos",       label: "Launch DDoS",   icon: Zap,  desc: "+10 pts · forces blue response" },
              { type: "portscan",   label: "Port Scan",     icon: Scan, desc: "+10 pts · reconnaissance phase" },
              { type: "bruteforce", label: "Brute Force",   icon: Lock, desc: "+10 pts · target auth service"  },
            ].map(a => (
              <button key={a.type} onClick={() => doRedAttack(a.type)} disabled={!isActive || busy}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border border-red-500/20 bg-red-500/5 text-left hover:bg-red-500/10 disabled:opacity-40 transition-colors">
                <a.icon className="w-4 h-4 text-red-400 shrink-0" />
                <div>
                  <p className="text-xs font-semibold text-red-400">{a.label}</p>
                  <p className="text-[10px] text-cyber-muted font-mono">{a.desc}</p>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Scoreboard */}
        <ScoreBoard score={state.score} mode={state.mode} />

        {/* Blue Team actions */}
        <div className="glass border border-blue-500/20 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-blue-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <Shield className="w-4 h-4" /> Blue Team — Defend
          </h2>
          <div className="space-y-2">
            {[
              { action: "block_ip", label: "Block IP Range",    desc: "+20 pts · perimeter defence"    },
              { action: "add_rule", label: "Add IDS Rule",       desc: "+15 pts · improve detection"   },
              { action: "scan",     label: "Vulnerability Scan", desc: "+10 pts · proactive hardening" },
            ].map(a => (
              <button key={a.action} onClick={() => doBlueDefend(a.action)} disabled={!isActive || busy}
                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg border border-blue-500/20 bg-blue-500/5 text-left hover:bg-blue-500/10 disabled:opacity-40 transition-colors">
                <CheckCircle className="w-4 h-4 text-blue-400 shrink-0" />
                <div>
                  <p className="text-xs font-semibold text-blue-400">{a.label}</p>
                  <p className="text-[10px] text-cyber-muted font-mono">{a.desc}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Event log */}
      <EventLog events={state.events || []} />
    </div>
  );
}
