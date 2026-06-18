import { motion } from "framer-motion";

/**
 * Glassmorphism stat card used across the dashboard.
 * Props: title, value, subtitle, icon (ReactNode), color ("cyan"|"red"|"green"|"yellow"|"purple")
 */
const COLOR_MAP = {
  cyan:   { text: "text-cyber-accent",  bg: "bg-cyber-accent/10",  border: "border-cyber-accent/20",  glow: "shadow-glow"       },
  red:    { text: "text-cyber-red",     bg: "bg-cyber-red/10",     border: "border-cyber-red/20",     glow: "shadow-glow-red"   },
  green:  { text: "text-cyber-green",   bg: "bg-cyber-green/10",   border: "border-cyber-green/20",   glow: "shadow-glow-green" },
  yellow: { text: "text-cyber-yellow",  bg: "bg-cyber-yellow/10",  border: "border-cyber-yellow/20",  glow: ""                  },
  purple: { text: "text-cyber-purple",  bg: "bg-cyber-purple/10",  border: "border-cyber-purple/20",  glow: ""                  },
};

export default function StatCard({ title, value, subtitle, icon, color = "cyan", trend }) {
  const c = COLOR_MAP[color] || COLOR_MAP.cyan;

  return (
    <motion.div
      whileHover={{ y: -2, scale: 1.01 }}
      transition={{ type: "spring", stiffness: 300 }}
      className={`glass rounded-xl p-5 border ${c.border} ${c.glow} relative overflow-hidden`}
    >
      {/* Background decoration */}
      <div className={`absolute -top-4 -right-4 w-20 h-20 rounded-full ${c.bg} blur-2xl`} />

      <div className="relative z-10">
        {/* Header row */}
        <div className="flex items-start justify-between">
          <p className="text-cyber-muted text-xs font-medium uppercase tracking-widest">{title}</p>
          {icon && (
            <div className={`p-2 rounded-lg ${c.bg}`}>
              <span className={c.text}>{icon}</span>
            </div>
          )}
        </div>

        {/* Value */}
        <p className={`text-3xl font-bold mt-3 font-mono ${c.text}`}>
          {value ?? "—"}
        </p>

        {/* Subtitle / trend */}
        {subtitle && (
          <p className="text-cyber-muted text-xs mt-1">{subtitle}</p>
        )}
        {trend != null && (
          <p className={`text-xs mt-1 font-mono ${trend >= 0 ? "text-cyber-red" : "text-cyber-green"}`}>
            {trend >= 0 ? "▲" : "▼"} {Math.abs(trend)}% vs last hour
          </p>
        )}
      </div>
    </motion.div>
  );
}
