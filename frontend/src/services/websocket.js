/**
 * ShieldNet WebSocket Service
 * Singleton native-WebSocket connection with exponential back-off reconnect.
 *
 * In development (Vite proxy) the WS path is relative so the browser
 * connects to the Vite dev server, which proxies to FastAPI on port 8000.
 * In production set VITE_WS_URL to the full backend address.
 */

function buildWsUrl() {
  // If an explicit override is set (production), use it
  const override = import.meta.env.VITE_WS_URL;
  if (override) return override + "/api/ws";

  // Otherwise use the current page origin with protocol swap (http→ws)
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api/ws`;
}

const WS_URL = buildWsUrl();

class ShieldNetWS {
  constructor() {
    this._ws           = null;
    this._listeners    = new Map();   // event → Set<callback>
    this._reconnectMs  = 2000;
    this._maxReconnect = 30_000;
    this._shouldRun    = false;
  }

  /** Start the connection. Safe to call multiple times. */
  connect() {
    if (this._shouldRun) return;
    this._shouldRun   = true;
    this._reconnectMs = 2000;
    this._open();
  }

  /** Permanently close the connection. */
  disconnect() {
    this._shouldRun = false;
    if (this._ws) {
      this._ws.onclose = null;   // prevent auto-reconnect
      this._ws.close();
      this._ws = null;
    }
    this._emit("disconnected", {});
  }
  /**
   * Subscribe to an event.
   * @returns  unsubscribe function
   */
  on(event, cb) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set());
    this._listeners.get(event).add(cb);
    return () => this.off(event, cb);
  }

  off(event, cb) {
    this._listeners.get(event)?.delete(cb);
  }

  // ── Private ──────────────────────────────────────────────────

  _emit(event, data) {
    this._listeners.get(event)?.forEach((cb) => {
      try { cb(data); } catch (e) { console.warn("[WS emit]", e); }
    });
  }

  _open() {
    try {
      this._ws = new WebSocket(WS_URL);

      this._ws.onopen = () => {
        this._reconnectMs = 2000;   // reset back-off on successful connect
        this._emit("connected", {});
        console.info("[ShieldNet WS] connected →", WS_URL);
      };

      this._ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          // Backend sends { event: "prediction"|"simulation", data: {...} }
          const evtName = msg.event || "message";
          const evtData = msg.data  ?? msg;
          this._emit(evtName, evtData);
        } catch {
          this._emit("message", e.data);
        }
      };

      this._ws.onerror = () => {
        // onerror always precedes onclose — just close cleanly
        this._ws?.close();
      };

      this._ws.onclose = () => {
        this._emit("disconnected", {});
        if (!this._shouldRun) return;
        console.info(`[ShieldNet WS] reconnecting in ${this._reconnectMs}ms…`);
        setTimeout(() => {
          if (this._shouldRun) this._open();
        }, this._reconnectMs);
        // Exponential back-off, cap at 30 s
        this._reconnectMs = Math.min(this._reconnectMs * 1.5, this._maxReconnect);
      };

    } catch (err) {
      console.error("[ShieldNet WS] open failed:", err);
      if (this._shouldRun) {
        setTimeout(() => this._open(), this._reconnectMs);
      }
    }
  }
}

// Module-level singleton
export const wsService = new ShieldNetWS();
