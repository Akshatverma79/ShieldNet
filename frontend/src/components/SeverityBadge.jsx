const MAP = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  LOW:      "bg-green-500/20 text-green-400 border-green-500/30",
  THREAT:   "bg-red-500/20 text-red-400 border-red-500/30",
  NORMAL:   "bg-green-500/20 text-green-400 border-green-500/30",
};

export default function SeverityBadge({ label }) {
  const cls = MAP[label?.toUpperCase()] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold border ${cls}`}>
      {label}
    </span>
  );
}
