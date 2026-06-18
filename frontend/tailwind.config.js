/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg:       "#060b16",
          card:     "#0d1526",
          border:   "#1a2744",
          accent:   "#00e5ff",
          green:    "#00ff99",
          red:      "#ff3b5c",
          yellow:   "#ffd60a",
          purple:   "#9d4edd",
          muted:    "#8aa4c8",
        },
      },
      fontFamily: {
        mono: ["'JetBrains Mono'", "monospace"],
        sans: ["'Inter'", "sans-serif"],
      },
      boxShadow: {
        glow:        "0 0 20px rgba(0,229,255,0.15)",
        "glow-red":  "0 0 20px rgba(255,59,92,0.2)",
        "glow-green":"0 0 20px rgba(0,255,153,0.15)",
      },
      animation: {
        pulse_slow: "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        ping_slow:  "ping 2s cubic-bezier(0, 0, 0.2, 1) infinite",
      },
    },
  },
  plugins: [],
};
