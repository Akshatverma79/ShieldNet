import { useEffect, useState } from "react";
import { Outlet, NavLink, useLocation } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, LayoutDashboard, History, Zap, Globe,
  Wifi, WifiOff, Bot, AlertOctagon, ShieldAlert,
  FileText, Settings, ChevronRight, Radio, TrendingUp,
  Users, Bug, CheckSquare, Brain, Swords, Database
} from "lucide-react";
import { wsService } from "../services/websocket";

const NAV_SECTIONS = [
  {
    label: "Operations",
    items: [
      { to: "/dashboard",    label: "Dashboard",        icon: LayoutDashboard },
      { to: "/incidents",    label: "Incidents",        icon: AlertOctagon    },
      { to: "/history",      label: "Threat Logs",      icon: History         },
    ],
  },
  {
    label: "AI Intelligence",
    items: [
      { to: "/copilot",      label: "AI Copilot",       icon: Bot             },
      { to: "/xai",          label: "XAI Dashboard",    icon: Brain           },
      { to: "/intel",        label: "Threat Intel",     icon: Globe           },
    ],
  },
  {
    label: "Security",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert  },
      { to: "/user-risk",    label: "User Risk",        icon: Users           },
      { to: "/honeypot",     label: "Honeypot",         icon: Bug             },
      { to: "/compliance",   label: "Compliance",       icon: CheckSquare     },
    ],
  },
  {
    label: "Lab & Learning",
    items: [
      { to: "/simulation",   label: "Simulation Lab",   icon: Zap             },
      { to: "/redblue",      label: "Red vs Blue",      icon: Swords          },
      { to: "/learning",     label: "ML Pipeline",      icon: Database        },
    ],
  },
  {
    label: "Reports & Config",
    items: [
      { to: "/reports",      label: "Reports",          icon: FileText        },
      { to: "/settings",     label: "Settings",         icon: Settings        },
    ],
  },
];

export default function Layout() {
  const [wsConnected, setWsConnected] = useState(false);
  const [liveCount,   setLiveCount]   = useState(0);
  const [threatCount, setThreatCount] = useState(0);
  const location = useLocation();

  useEffect(() => {
    wsService.connect();
    const u1 = wsService.on("connected",    () => setWsConnected(true));
    const u2 = wsService.on("disconnected", () => setWsConnected(false));
    const u3 = wsService.on("prediction",   (d) => {
      setLiveCount(n => n + 1);
      if (d?.status === "THREAT") setThreatCount(n => n + 1);
    });
    const u4 = wsService.on("simulation",   (d) => {
      setLiveCount(n => n + 1);
      if (d?.status === "THREAT") setThreatCount(n => n + 1);
    });
    return () => { u1(); u2(); u3(); u4(); wsService.disconnect(); };
  }, []);

  return (
    <div className="flex h-screen overflow-hidden bg-cyber-bg font-sans">

      {/* ── Sidebar ─────────────────────────────────────────── */}
      <aside className="w-60 flex-shrink-0 flex flex-col bg-cyber-card border-r border-cyber-border z-10">

        {/* Logo */}
        <div className="px-4 py-3 border-b border-cyber-border">
          <div className="flex items-center gap-2.5">
            <div className="relative">
              <div className="w-8 h-8 rounded-lg bg-cyber-accent/10 border border-cyber-accent/30 flex items-center justify-center">
                <Shield className="w-4 h-4 text-cyber-accent" />
              </div>
              <span className={`absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full border-2 border-cyber-card ${wsConnected ? "bg-cyber-green" : "bg-red-500"}`} />
            </div>
            <div>
              <h1 className="text-sm font-bold text-white tracking-wide">ShieldNet</h1>
              <p className="text-[9px] text-cyber-muted font-mono">Enterprise SOC v3.0</p>
            </div>
          </div>

          {/* Live mini bar */}
          <div className="mt-2 flex items-center justify-between text-[9px] font-mono">
            <span className={`flex items-center gap-1 ${wsConnected ? "text-cyber-green" : "text-red-400"}`}>
              {wsConnected ? <Radio className="w-2 h-2 animate-pulse" /> : <WifiOff className="w-2 h-2" />}
              {wsConnected ? "LIVE" : "OFFLINE"}
            </span>
            <span className="text-cyber-muted">{liveCount.toLocaleString()} events</span>
            {threatCount > 0 && <span className="text-cyber-red font-bold">{threatCount} threats</span>}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-2 py-2 space-y-3">
          {NAV_SECTIONS.map((section) => (
            <div key={section.label}>
              <p className="text-[9px] font-semibold text-cyber-muted/50 uppercase tracking-widest px-2 mb-0.5">
                {section.label}
              </p>
              <div className="space-y-0.5">
                {section.items.map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to}>
                    {({ isActive }) => (
                      <motion.div
                        whileHover={{ x: 2 }}
                        transition={{ type: "spring", stiffness: 400 }}
                        className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg cursor-pointer transition-colors ${
                          isActive
                            ? "bg-cyber-accent/10 text-cyber-accent border border-cyber-accent/20"
                            : "text-cyber-muted hover:text-white hover:bg-white/5"
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5 shrink-0" />
                        <span className="text-xs font-medium flex-1">{label}</span>
                        {isActive && <ChevronRight className="w-3 h-3 text-cyber-accent/50" />}
                      </motion.div>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* WS footer */}
        <div className="px-3 py-2.5 border-t border-cyber-border">
          <div className="flex items-center gap-1.5 text-[10px] font-mono">
            <Wifi className={`w-2.5 h-2.5 ${wsConnected ? "text-cyber-green" : "text-red-400"}`} />
            <span className={wsConnected ? "text-cyber-green" : "text-red-400"}>
              {wsConnected ? "WebSocket Connected" : "Reconnecting…"}
            </span>
          </div>
          <div className="flex items-center gap-1.5 text-[10px] text-cyber-muted font-mono mt-0.5">
            <TrendingUp className="w-2.5 h-2.5" />
            <span>{liveCount.toLocaleString()} processed</span>
          </div>
        </div>
      </aside>

      {/* ── Main ─────────────────────────────────────────────── */}
      <main className="flex-1 overflow-y-auto bg-cyber-bg">
        <AnimatePresence mode="wait">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -5 }}
            transition={{ duration: 0.18 }}
            className="min-h-full"
          >
            <Outlet />
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}
