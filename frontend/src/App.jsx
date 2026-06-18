import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout           from "./components/Layout";
import Dashboard        from "./pages/Dashboard";
import ThreatHistory    from "./pages/ThreatHistory";
import Simulation       from "./pages/Simulation";
import ThreatIntel      from "./pages/ThreatIntel";
import AICopilot        from "./pages/AICopilot";
import Incidents        from "./pages/Incidents";
import Vulnerabilities  from "./pages/Vulnerabilities";
import Reports          from "./pages/Reports";
import Settings         from "./pages/Settings";
import UserRisk         from "./pages/UserRisk";
import Honeypot         from "./pages/Honeypot";
import Compliance       from "./pages/Compliance";
import XAIDashboard     from "./pages/XAIDashboard";
import RedBlueTeam      from "./pages/RedBlueTeam";
import LearningPipeline from "./pages/LearningPipeline";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index                   element={<Navigate to="/dashboard" replace />} />
          {/* Core */}
          <Route path="dashboard"        element={<Dashboard />} />
          <Route path="history"          element={<ThreatHistory />} />
          <Route path="intel"            element={<ThreatIntel />} />
          {/* AI & Intelligence */}
          <Route path="copilot"          element={<AICopilot />} />
          <Route path="xai"              element={<XAIDashboard />} />
          {/* Operations */}
          <Route path="incidents"        element={<Incidents />} />
          <Route path="vulnerabilities"  element={<Vulnerabilities />} />
          <Route path="user-risk"        element={<UserRisk />} />
          <Route path="honeypot"         element={<Honeypot />} />
          {/* Governance */}
          <Route path="compliance"       element={<Compliance />} />
          <Route path="reports"          element={<Reports />} />
          {/* Lab */}
          <Route path="simulation"       element={<Simulation />} />
          <Route path="redblue"          element={<RedBlueTeam />} />
          <Route path="learning"         element={<LearningPipeline />} />
          {/* Config */}
          <Route path="settings"         element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
