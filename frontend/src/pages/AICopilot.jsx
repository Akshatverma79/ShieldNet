import { useState, useRef, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bot, Send, User, Shield, AlertTriangle,
  Zap, RefreshCw, ChevronDown, Info, Copy, Check
} from "lucide-react";
import { copilotChat, explainLog, fetchLogs } from "../services/api";

// ── Markdown-style renderer for copilot responses ───────────────
function CopilotText({ text }) {
  const lines = text.split("\n");
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (line.startsWith("**") && line.endsWith("**")) {
          return <p key={i} className="font-bold text-white">{line.slice(2, -2)}</p>;
        }
        if (line.startsWith("- ")) {
          return <p key={i} className="flex gap-2 text-cyber-muted"><span className="text-cyber-accent mt-0.5">›</span>{line.slice(2)}</p>;
        }
        if (/^\d+\./.test(line)) {
          return <p key={i} className="text-cyber-muted">{line}</p>;
        }
        if (line.startsWith("#")) {
          return <p key={i} className="font-semibold text-cyber-accent text-sm">{line.replace(/^#+\s/, "")}</p>;
        }
        if (line === "") return <div key={i} className="h-1" />;
        // inline bold
        const parts = line.split(/\*\*(.+?)\*\*/g);
        return (
          <p key={i} className="text-cyber-muted leading-relaxed">
            {parts.map((p, j) => j % 2 === 1 ? <strong key={j} className="text-white">{p}</strong> : p)}
          </p>
        );
      })}
    </div>
  );
}

// ── Single chat bubble ───────────────────────────────────────────
function ChatBubble({ msg }) {
  const [copied, setCopied] = useState(false);
  const isUser = msg.role === "user";

  const copy = () => {
    navigator.clipboard.writeText(msg.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className={`flex gap-3 ${isUser ? "flex-row-reverse" : "flex-row"}`}
    >
      {/* Avatar */}
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
        isUser ? "bg-cyber-accent/20 border border-cyber-accent/30" : "bg-purple-500/20 border border-purple-500/30"
      }`}>
        {isUser ? <User className="w-4 h-4 text-cyber-accent" /> : <Bot className="w-4 h-4 text-purple-400" />}
      </div>

      {/* Bubble */}
      <div className={`max-w-[80%] group relative ${isUser ? "items-end" : "items-start"} flex flex-col gap-1`}>
        <div className={`rounded-xl px-4 py-3 text-xs leading-relaxed ${
          isUser
            ? "bg-cyber-accent/10 border border-cyber-accent/20 text-white"
            : "bg-cyber-card border border-cyber-border"
        }`}>
          {isUser ? (
            <p className="text-white">{msg.content}</p>
          ) : (
            <CopilotText text={msg.content} />
          )}
        </div>

        {/* Copy button */}
        {!isUser && (
          <button
            onClick={copy}
            className="absolute -right-7 top-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded text-cyber-muted hover:text-white"
          >
            {copied ? <Check className="w-3 h-3 text-cyber-green" /> : <Copy className="w-3 h-3" />}
          </button>
        )}

        <span className="text-[10px] text-cyber-muted font-mono px-1">
          {new Date(msg.ts).toLocaleTimeString()}
        </span>
      </div>
    </motion.div>
  );
}

// ── Quick-action chips ───────────────────────────────────────────
const QUICK_ACTIONS = [
  "What attacks were detected today?",
  "Explain the risk score calculation",
  "What is MITRE ATT&CK?",
  "How do I respond to a DDoS attack?",
  "Why was this IP flagged?",
  "What is brute force detection?",
];

export default function AICopilot() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "**ShieldNet AI Security Copilot**\n\nI'm your intelligent security analyst. I can:\n- 🔍 Explain why threats were detected\n- 🎯 Map attacks to MITRE ATT&CK framework\n- ✅ Recommend response actions\n- 📊 Break down risk scores\n- 🚨 Guide incident response\n\nSelect a recent alert to analyse it, or ask me anything about your security posture.",
      ts: Date.now(),
    }
  ]);
  const [input,       setInput]       = useState("");
  const [loading,     setLoading]     = useState(false);
  const [context,     setContext]     = useState(null);  // active threat context
  const [recentLogs,  setRecentLogs]  = useState([]);
  const [showLogs,    setShowLogs]    = useState(false);
  const bottomRef = useRef(null);
  const inputRef  = useRef(null);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Load recent threats for context selection
  useEffect(() => {
    fetchLogs({ per_page: 10, status: "THREAT" })
      .then(r => setRecentLogs(r.data.logs || []))
      .catch(() => {});
  }, []);

  const sendMessage = useCallback(async (text = input) => {
    const content = text.trim();
    if (!content || loading) return;

    const userMsg = { role: "user", content, ts: Date.now() };
    setMessages(prev => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const history = [...messages, userMsg].map(m => ({ role: m.role, content: m.content }));
      const res = await copilotChat(history, context);
      setMessages(prev => [...prev, {
        role:    "assistant",
        content: res.data.response,
        ts:      Date.now(),
        actions: res.data.actions || [],
      }]);
    } catch (e) {
      setMessages(prev => [...prev, {
        role:    "assistant",
        content: "⚠ Connection error. Ensure the ShieldNet backend is running on port 8000.",
        ts:      Date.now(),
      }]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  }, [input, loading, messages, context]);

  const analyseLog = async (log) => {
    setShowLogs(false);
    const ctx = {
      log_id:      log.id,
      attack_type: log.attack_type,
      risk_score:  log.risk_score,
      source_ip:   log.source_ip,
      severity:    log.severity,
      reasons:     log.reason || [],
      confidence:  log.confidence,
    };
    setContext(ctx);

    const userMsg = {
      role: "user",
      content: `Analyse threat log #${log.id}: ${log.attack_type} from ${log.source_ip} (Risk: ${log.risk_score}%)`,
      ts: Date.now(),
    };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    try {
      const res = await explainLog(log.id);
      const analysis = res.data;
      const content = [
        `**Threat Analysis — Log #${log.id}**\n`,
        `**${analysis.attack_type}** detected from \`${analysis.source_ip}\``,
        `Risk: **${analysis.risk_score}%** | Severity: **${analysis.severity}** | Confidence: **${(analysis.confidence * 100).toFixed(0)}%**\n`,
        "**Detected Behaviours:**",
        ...(analysis.reasons || []).map(r => `- ${r}`),
        `\n**MITRE ATT&CK:** ${analysis.mitre?.id} — ${analysis.mitre?.name} (${analysis.mitre?.tactic})\n`,
        "**Recommended Actions:**",
        ...(analysis.recommended_actions || []).map((a, i) => `${i + 1}. ${a}`),
      ].join("\n");

      setMessages(prev => [...prev, { role: "assistant", content, ts: Date.now() }]);
    } catch {
      // sendMessage() would be a no-op here because loading=true, so push directly
      setMessages(prev => [...prev, {
        role: "assistant",
        content: `Unable to fetch full analysis for Log #${log.id}. The backend may still be processing. Try asking me directly: "Analyse threat ${log.attack_type} from ${log.source_ip} with risk ${log.risk_score}%"`,
        ts: Date.now(),
      }]);
    } finally {
      setLoading(false);
    }
  };

  const clearChat = () => {
    setMessages([{
      role: "assistant",
      content: "Chat cleared. How can I help you with your security analysis?",
      ts: Date.now(),
    }]);
    setContext(null);
  };

  return (
    <div className="flex flex-col h-full p-4 gap-4">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-500/20 border border-purple-500/30 flex items-center justify-center">
            <Bot className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">AI Security Copilot</h1>
            <p className="text-xs text-cyber-muted font-mono">Powered by ShieldNet Intelligence Engine</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Context indicator */}
          {context && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-orange-500/10 border border-orange-500/30 text-xs font-mono text-orange-400">
              <AlertTriangle className="w-3 h-3" />
              Context: {context.attack_type}
              <button onClick={() => setContext(null)} className="text-orange-400/60 hover:text-orange-400 ml-1">×</button>
            </div>
          )}

          {/* Analyse recent threat */}
          <div className="relative">
            <button
              onClick={() => setShowLogs(!showLogs)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-cyber-border bg-cyber-card text-xs text-cyber-muted hover:text-white hover:border-cyber-accent/40 transition-colors"
            >
              <Zap className="w-3.5 h-3.5" />
              Analyse Threat
              <ChevronDown className="w-3 h-3" />
            </button>
            <AnimatePresence>
              {showLogs && (
                <motion.div
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  className="absolute right-0 top-full mt-1 w-80 bg-cyber-card border border-cyber-border rounded-xl shadow-2xl z-50 overflow-hidden"
                >
                  <div className="px-3 py-2 border-b border-cyber-border text-xs font-semibold text-cyber-muted uppercase tracking-wider">
                    Recent Threats
                  </div>
                  {recentLogs.length === 0 ? (
                    <p className="px-3 py-4 text-xs text-cyber-muted text-center font-mono">No threats recorded yet</p>
                  ) : (
                    recentLogs.map(log => (
                      <button
                        key={log.id}
                        onClick={() => analyseLog(log)}
                        className="w-full flex items-center gap-3 px-3 py-2.5 hover:bg-white/5 transition-colors text-left"
                      >
                        <div className={`w-2 h-2 rounded-full shrink-0 ${
                          log.severity === "CRITICAL" ? "bg-red-500" :
                          log.severity === "HIGH"     ? "bg-orange-500" :
                          log.severity === "MEDIUM"   ? "bg-yellow-500" : "bg-green-500"
                        }`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs text-white font-mono truncate">#{log.id} {log.attack_type}</p>
                          <p className="text-[10px] text-cyber-muted font-mono">{log.source_ip} · Risk {log.risk_score}%</p>
                        </div>
                        <span className="text-[10px] font-mono text-cyber-accent">{log.severity}</span>
                      </button>
                    ))
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          <button
            onClick={clearChat}
            className="p-2 rounded-lg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Chat area */}
      <div className="flex-1 overflow-y-auto glass border border-cyber-border rounded-xl p-4 space-y-4 min-h-0">
        {messages.map((msg, i) => <ChatBubble key={i} msg={msg} />)}

        {/* Typing indicator */}
        {loading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex gap-3"
          >
            <div className="w-8 h-8 rounded-lg bg-purple-500/20 border border-purple-500/30 flex items-center justify-center">
              <Bot className="w-4 h-4 text-purple-400" />
            </div>
            <div className="bg-cyber-card border border-cyber-border rounded-xl px-4 py-3 flex items-center gap-1">
              {[0,1,2].map(i => (
                <motion.div
                  key={i}
                  className="w-1.5 h-1.5 bg-purple-400 rounded-full"
                  animate={{ y: [0, -4, 0] }}
                  transition={{ duration: 0.6, repeat: Infinity, delay: i * 0.15 }}
                />
              ))}
            </div>
          </motion.div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick actions */}
      <div className="flex gap-2 flex-wrap">
        {QUICK_ACTIONS.map(q => (
          <button
            key={q}
            onClick={() => sendMessage(q)}
            disabled={loading}
            className="px-2.5 py-1.5 rounded-lg border border-cyber-border text-[11px] font-mono text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent/40 transition-colors disabled:opacity-40"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input bar */}
      <div className="flex gap-3 items-end">
        <div className="flex-1 relative">
          <textarea
            ref={inputRef}
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); } }}
            placeholder="Ask about threats, request analysis, or get response recommendations…"
            rows={2}
            className="w-full bg-cyber-card border border-cyber-border rounded-xl px-4 py-3 text-sm text-white placeholder-cyber-muted font-mono resize-none focus:outline-none focus:border-cyber-accent/50 transition-colors"
          />
          <div className="absolute bottom-2 right-3 text-[10px] text-cyber-muted/60 font-mono">
            Enter to send · Shift+Enter for new line
          </div>
        </div>
        <button
          onClick={() => sendMessage()}
          disabled={loading || !input.trim()}
          className="p-3 rounded-xl bg-purple-500/20 border border-purple-500/30 text-purple-400 hover:bg-purple-500/30 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
        >
          <Send className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
}
