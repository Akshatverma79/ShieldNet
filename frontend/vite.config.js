import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      // WebSocket MUST come before the generic /api rule or Vite matches /api first
      "/api/ws": {
        target:       "ws://localhost:8000",
        ws:           true,
        changeOrigin: true,
      },
      // All other REST calls
      "/api": {
        target:       "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
