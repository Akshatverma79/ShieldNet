import { useState } from "react";
import { Fragment } from "react";
import { motion } from "framer-motion";
import {
  Settings as SettingsIcon, Shield, Bell, Database,
  Monitor, Key, Save, RefreshCw, Check, Info,
  Wifi, Eye, EyeOff
} from "lucide-react";

function Section({ title, icon: Icon, children }) {
  return (
    <div className="glass border border-cyber-border rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2 pb-3 border-b border-cyber-border">
        <Icon className="w-4 h-4 text-cyber-accent" />
        <h2 className="text-sm font-semibold text-white uppercase tracking-wider">{title}</h2>
      </div>
      {children}
    </div>
  );
}

function Toggle({ label, description, value, onChange }) {
  return (
    <div className="flex items-center justify-between py-2">
      <div>
        <p className="text-sm text-white">{label}</p>
        {description && <p className="text-xs text-cyber-muted mt-0.5">{description}</p>}
      </div>
      <button
        onClick={() => onChange(!value)}
        className={`w-11 h-6 rounded-full border transition-all relative ${
          value
            ? "bg-cyber-accent/20 border-cyber-accent/50"
            : "bg-cyber-border border-cyber-border"
        }`}
      >
        <span className={`absolute top-0.5 w-5 h-5 rounded-full transition-all ${
          value ? "left-5 bg-cyber-accent" : "left-0.5 bg-cyber-muted"
        }`} />
      </button>
    </div>
  );
}

function TextInput({ label, value, onChange, type = "text", placeholder = "" }) {
  const [show, setShow] = useState(false);
  const isPassword = type === "password";
  return (
    <div>
      <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">{label}</label>
      <div className="relative mt-1">
        <input
          type={isPassword && !show ? "password" : "text"}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          className="w-full bg-transparent border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono placeholder-cyber-muted focus:outline-none focus:border-cyber-accent/50 pr-9"
        />
        {isPassword && (
          <button
            onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-white"
          >
            {show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>
    </div>
  );
}

function SelectInput({ label, value, onChange, options }) {
  return (
    <div>
      <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">{label}</label>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="w-full mt-1 bg-cyber-card border border-cyber-border rounded-lg px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyber-accent/50"
      >
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </div>
  );
}

export default function Settings() {
  const [saved, setSaved] = useState(false);

  // General
  const [orgName,    setOrgName]    = useState("ShieldNet SOC");
  const [timezone,   setTimezone]   = useState("UTC");
  const [logLevel,   setLogLevel]   = useState("INFO");

  // Detection
  const [threshold,  setThreshold]  = useState("75");
  const [autoIncident, setAutoIncident] = useState(true);
  const [realtime,   setRealtime]   = useState(true);
  const [shap,       setShap]       = useState(false);

  // Alerts
  const [alertEmail, setAlertEmail] = useState(true);
  const [alertWS,    setAlertWS]    = useState(true);
  const [alertCritical, setAlertCritical] = useState(true);
  const [alertHigh,  setAlertHigh]  = useState(true);
  const [alertMedium,setAlertMedium]= useState(false);

  // Network
  const [backendUrl, setBackendUrl] = useState("http://localhost:8000");
  const [wsUrl,      setWsUrl]      = useState("ws://localhost:8000");
  const [refreshInt, setRefreshInt] = useState("15");

  // API
  const [apiKey,     setApiKey]     = useState("sn-xxxxxxxxxxxxxxxxxxxxxxxx");

  const save = () => {
    // In a full implementation these would be persisted via API or localStorage
    localStorage.setItem("shieldnet_settings", JSON.stringify({
      orgName, timezone, logLevel, threshold, autoIncident,
      realtime, shap, alertEmail, alertWS, alertCritical,
      alertHigh, alertMedium, backendUrl, wsUrl, refreshInt,
    }));
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="p-6 space-y-5 min-h-full max-w-3xl">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-cyber-accent" /> Settings
          </h1>
          <p className="text-xs text-cyber-muted font-mono mt-0.5">
            Platform configuration and preferences
          </p>
        </div>
        <motion.button
          onClick={save}
          whileTap={{ scale: 0.96 }}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-semibold transition-all ${
            saved
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-cyber-accent/10 border-cyber-accent/30 text-cyber-accent hover:bg-cyber-accent/20"
          }`}
        >
          {saved ? <><Check className="w-4 h-4" /> Saved</> : <><Save className="w-4 h-4" /> Save Settings</>}
        </motion.button>
      </div>

      {/* General */}
      <Section title="General" icon={Monitor}>
        <TextInput label="Organisation Name" value={orgName} onChange={setOrgName} placeholder="Your SOC name" />
        <div className="grid grid-cols-2 gap-3">
          <SelectInput
            label="Timezone"
            value={timezone}
            onChange={setTimezone}
            options={[
              { value: "UTC",        label: "UTC" },
              { value: "US/Eastern", label: "US / Eastern" },
              { value: "US/Pacific", label: "US / Pacific" },
              { value: "Europe/London", label: "Europe / London" },
              { value: "Asia/Karachi", label: "Asia / Karachi (PKT)" },
            ]}
          />
          <SelectInput
            label="Log Level"
            value={logLevel}
            onChange={setLogLevel}
            options={[
              { value: "DEBUG", label: "DEBUG" },
              { value: "INFO",  label: "INFO" },
              { value: "WARNING", label: "WARNING" },
              { value: "ERROR", label: "ERROR" },
            ]}
          />
        </div>
      </Section>

      {/* Threat Detection */}
      <Section title="Threat Detection" icon={Shield}>
        <div>
          <label className="text-xs text-cyber-muted font-mono uppercase tracking-wider">
            Risk Score Alert Threshold ({threshold}%)
          </label>
          <input
            type="range" min={1} max={100} value={threshold}
            onChange={e => setThreshold(e.target.value)}
            className="w-full mt-2 accent-cyber-accent"
          />
          <div className="flex justify-between text-[10px] font-mono text-cyber-muted mt-1">
            <span>1% (very sensitive)</span>
            <span className="text-cyber-accent font-bold">{threshold}%</span>
            <span>100% (very strict)</span>
          </div>
        </div>
        <Toggle
          label="Auto-create incidents for HIGH+ threats"
          description="Automatically generate an incident for every threat above the risk threshold"
          value={autoIncident}
          onChange={setAutoIncident}
        />
        <Toggle
          label="Real-time WebSocket processing"
          description="Stream threat events to the dashboard immediately via WebSocket"
          value={realtime}
          onChange={setRealtime}
        />
        <Toggle
          label="SHAP explainability (slower, more detailed)"
          description="Use SHAP TreeExplainer for AI reason generation — increases detection latency"
          value={shap}
          onChange={setShap}
        />
      </Section>

      {/* Alerts */}
      <Section title="Alert Preferences" icon={Bell}>
        <Toggle label="WebSocket live alerts"        description="Push alerts to dashboard in real time"              value={alertWS}       onChange={setAlertWS} />
        <Toggle label="Email notifications"          description="Send email on new CRITICAL incidents (requires SMTP config)" value={alertEmail}    onChange={setAlertEmail} />
        <div className="mt-2 pt-2 border-t border-cyber-border">
          <p className="text-xs text-cyber-muted font-mono uppercase tracking-wider mb-2">Alert Severity Levels</p>
          <Toggle label="Critical alerts" value={alertCritical} onChange={setAlertCritical} />
          <Toggle label="High alerts"     value={alertHigh}     onChange={setAlertHigh} />
          <Toggle label="Medium alerts"   value={alertMedium}   onChange={setAlertMedium} />
        </div>
      </Section>

      {/* Network / API */}
      <Section title="Backend Connection" icon={Wifi}>
        <TextInput label="Backend API URL"    value={backendUrl} onChange={setBackendUrl} placeholder="http://localhost:8000" />
        <TextInput label="WebSocket URL"      value={wsUrl}      onChange={setWsUrl}      placeholder="ws://localhost:8000" />
        <TextInput label="Dashboard Refresh Interval (seconds)" value={refreshInt} onChange={setRefreshInt} placeholder="15" />
      </Section>

      {/* API Key */}
      <Section title="API Access" icon={Key}>
        <TextInput label="API Key" value={apiKey} onChange={setApiKey} type="password" placeholder="sn-xxxxxxxx" />
        <div className="flex items-start gap-2 text-xs text-cyber-muted bg-cyber-border/20 rounded-lg p-3">
          <Info className="w-4 h-4 text-cyber-accent shrink-0 mt-0.5" />
          <p>API keys are used to authenticate external integrations with ShieldNet. Rotate keys regularly and never commit them to version control.</p>
        </div>
      </Section>

      {/* About */}
      <Section title="About ShieldNet" icon={Shield}>
        <div className="grid grid-cols-2 gap-y-2 text-xs font-mono">
          {[
            ["Platform",      "ShieldNet Enterprise SOC"],
            ["Version",       "3.0.0"],
            ["ML Engine",     "Isolation Forest + Heuristic Classifier"],
            ["MITRE Coverage","T1046, T1110, T1190, T1498, T1071, T1059"],
            ["Database",      "SQLite (SQLAlchemy ORM)"],
            ["Backend",       "FastAPI + Python 3.11"],
            ["Frontend",      "React 18 + Tailwind CSS + Recharts"],
            ["License",       "MIT — Educational / Research Use"],
          ].map(([k, v]) => (
            <Fragment key={k}>
              <span className="text-cyber-muted">{k}</span>
              <span className="text-white">{v}</span>
            </Fragment>
          ))}
        </div>
      </Section>

    </div>
  );
}
