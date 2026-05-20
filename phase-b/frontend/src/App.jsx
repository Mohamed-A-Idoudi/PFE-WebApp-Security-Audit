import { useState, useEffect, useCallback } from "react";

const API = "";

const COLORS = {
  bg: "#0a0e1a", surface: "#111827", surfaceHover: "#1a2235",
  border: "#1e293b", borderActive: "#3b82f6", primary: "#3b82f6",
  primaryDark: "#2563eb", accent: "#06b6d4", text: "#f1f5f9",
  textMuted: "#94a3b8", textDim: "#64748b", critical: "#ef4444",
  high: "#f97316", medium: "#eab308", low: "#22c55e",
  info: "#6366f1", cardBg: "#0f172a",
};

const sevColor = (s) => ({
  Critical: COLORS.critical, High: COLORS.high,
  Medium: COLORS.medium, Low: COLORS.low,
}[s] || COLORS.textDim);

const Badge = ({ text, color }) => (
  <span style={{ background: color + "22", color, padding: "2px 10px",
    borderRadius: 4, fontSize: 12, fontWeight: 700, letterSpacing: 0.5,
    border: `1px solid ${color}44` }}>{text}</span>
);

const Card = ({ children, style = {}, onClick }) => (
  <div onClick={onClick} style={{ background: COLORS.surface,
    border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 20,
    ...style, cursor: onClick ? "pointer" : "default", transition: "border-color 0.2s" }}
    onMouseEnter={e => { if (onClick) e.currentTarget.style.borderColor = COLORS.borderActive; }}
    onMouseLeave={e => { e.currentTarget.style.borderColor = COLORS.border; }}>
    {children}
  </div>
);

const Btn = ({ children, primary, small, onClick, disabled, style = {} }) => (
  <button onClick={onClick} disabled={disabled} style={{
    background: primary ? COLORS.primary : "transparent",
    color: primary ? "#fff" : COLORS.textMuted,
    border: primary ? "none" : `1px solid ${COLORS.border}`,
    padding: small ? "6px 14px" : "10px 22px", borderRadius: 8,
    fontSize: small ? 13 : 14, fontWeight: 600,
    cursor: disabled ? "not-allowed" : "pointer",
    opacity: disabled ? 0.5 : 1, transition: "all 0.2s", ...style
  }}>{children}</button>
);

const Spinner = () => (
  <div style={{ display: "inline-block", width: 18, height: 18,
    border: `2px solid ${COLORS.border}`,
    borderTopColor: COLORS.primary, borderRadius: "50%",
    animation: "spin 0.7s linear infinite" }}>
    <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
  </div>
);

const Sidebar = ({ active, setPage, user, onLogout }) => {
  const items = [
    { id: "dash", label: "Dashboard", icon: "◉" },
    { id: "scan", label: "New Scan", icon: "▶" },
    { id: "results", label: "Results", icon: "◈" },
    { id: "report", label: "Reports", icon: "◻" },
    ...(user?.role === "admin" ? [{ id: "users", label: "Users", icon: "⊕" }] : []),
  ];
  return (
    <div style={{ width: 220, background: COLORS.cardBg,
      borderRight: `1px solid ${COLORS.border}`, display: "flex",
      flexDirection: "column", flexShrink: 0 }}>
      <div style={{ padding: "24px 20px 32px", borderBottom: `1px solid ${COLORS.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 34, height: 34, borderRadius: 8,
            background: `linear-gradient(135deg, ${COLORS.primary}, ${COLORS.accent})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, fontWeight: 900, color: "#fff" }}>S</div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700, color: COLORS.text }}>SecuriScan</div>
            <div style={{ fontSize: 11, color: COLORS.textDim }}>OWASP Assessment</div>
          </div>
        </div>
      </div>
      <div style={{ padding: "16px 12px", flex: 1 }}>
        {items.map(it => (
          <div key={it.id} onClick={() => setPage(it.id)} style={{
            padding: "10px 12px", borderRadius: 8, marginBottom: 4,
            cursor: "pointer", display: "flex", alignItems: "center", gap: 10,
            background: active === it.id ? COLORS.primary + "18" : "transparent",
            color: active === it.id ? COLORS.primary : COLORS.textMuted,
            fontWeight: active === it.id ? 600 : 400, fontSize: 14 }}>
            <span style={{ fontSize: 16, opacity: 0.7 }}>{it.icon}</span> {it.label}
          </div>
        ))}
      </div>
      <div style={{ padding: "16px 20px", borderTop: `1px solid ${COLORS.border}` }}>
        <div style={{ fontSize: 12, color: COLORS.textDim, marginBottom: 8 }}>
          {user?.email}<br />
          <Badge text={user?.role || ""} color={COLORS.accent} />
        </div>
        <Btn small onClick={onLogout} style={{ width: "100%", fontSize: 12 }}>Logout</Btn>
      </div>
    </div>
  );
};

// ── Login Page ──────────────────────────────────────────────────────────────

const LoginPage = ({ onLogin }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setLoading(true); setError("");
    try {
      const res = await fetch(`${API}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error || "Login failed"); return; }
      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch {
      setError("Cannot connect to server");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", height: "100vh", background: COLORS.bg,
      alignItems: "center", justifyContent: "center" }}>
      <div style={{ width: 400 }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <div style={{ width: 56, height: 56, borderRadius: 14, margin: "0 auto 16px",
            background: `linear-gradient(135deg, ${COLORS.primary}, ${COLORS.accent})`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 24, fontWeight: 900, color: "#fff" }}>S</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: COLORS.text }}>SecuriScan</div>
          <div style={{ fontSize: 14, color: COLORS.textDim, marginTop: 6 }}>
            OWASP Web Application Security Assessment</div>
        </div>
        <Card>
          <h3 style={{ fontSize: 16, fontWeight: 600, color: COLORS.text, margin: "0 0 20px" }}>
            Sign in to your account</h3>
          {error && (
            <div style={{ background: COLORS.critical + "18", border: `1px solid ${COLORS.critical}44`,
              borderRadius: 8, padding: "10px 14px", marginBottom: 16,
              fontSize: 13, color: COLORS.critical }}>{error}</div>
          )}
          <label style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
            textTransform: "uppercase", letterSpacing: 0.5, display: "block", marginBottom: 6 }}>
            Email</label>
          <input value={email} onChange={e => setEmail(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleLogin()}
            style={{ width: "100%", padding: "10px 14px", background: COLORS.cardBg,
              border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text,
              fontSize: 14, outline: "none", boxSizing: "border-box", marginBottom: 14 }} />
          <label style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
            textTransform: "uppercase", letterSpacing: 0.5, display: "block", marginBottom: 6 }}>
            Password</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleLogin()}
            style={{ width: "100%", padding: "10px 14px", background: COLORS.cardBg,
              border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text,
              fontSize: 14, outline: "none", boxSizing: "border-box", marginBottom: 20 }} />
          <Btn primary onClick={handleLogin} disabled={loading}
            style={{ width: "100%", padding: 12, fontSize: 15 }}>
            {loading ? "Signing in..." : "Sign in"}
          </Btn>
        </Card>
        <div style={{ textAlign: "center", marginTop: 20, fontSize: 12, color: COLORS.textDim }}>
          ADVANCIA IT SYSTEM — PFE 2026</div>
      </div>
    </div>
  );
};

// ── API Helper ──────────────────────────────────────────────────────────────

const apiFetch = async (path, options = {}, token) => {
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
};

// ── Dashboard ───────────────────────────────────────────────────────────────

const DashboardPage = ({ token, setPage, setActiveScan }) => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch("/api/scans", {}, token)
      .then(setScans).catch(console.error).finally(() => setLoading(false));
  }, [token]);

  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: COLORS.text, margin: 0 }}>Dashboard</h2>
        <p style={{ color: COLORS.textDim, fontSize: 14, margin: "6px 0 0" }}>
          OWASP Top 10 Security Assessment Overview</p>
      </div>
      <div style={{ display: "flex", gap: 16, marginBottom: 28, flexWrap: "wrap" }}>
        {[
          ["Total Scans", scans.length, COLORS.primary],
          ["Completed", scans.filter(s => s.status === "complete").length, COLORS.low],
          ["Running", scans.filter(s => s.status === "running").length, COLORS.accent],
          ["Errors", scans.filter(s => s.status === "error").length, COLORS.critical],
        ].map(([label, value, accent]) => (
          <Card key={label} style={{ flex: 1, minWidth: 140, textAlign: "center" }}>
            <div style={{ fontSize: 32, fontWeight: 800, color: accent }}>{value}</div>
            <div style={{ fontSize: 12, color: COLORS.textDim, marginTop: 4,
              textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</div>
          </Card>
        ))}
      </div>
      {loading ? (
        <Card style={{ textAlign: "center", padding: 40 }}><Spinner /></Card>
      ) : scans.length === 0 ? (
        <Card style={{ textAlign: "center", padding: 40 }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>🔍</div>
          <div style={{ color: COLORS.text, fontWeight: 600, marginBottom: 8 }}>No scans yet</div>
          <div style={{ color: COLORS.textDim, fontSize: 14, marginBottom: 20 }}>
            Launch your first security assessment</div>
          <Btn primary onClick={() => setPage("scan")}>New Scan</Btn>
        </Card>
      ) : (
        <Card>
          <h3 style={{ fontSize: 15, fontWeight: 600, color: COLORS.text, margin: "0 0 16px" }}>
            Recent Scans</h3>
          {scans.slice(0, 8).map(s => (
            <div key={s.scan_id} onClick={() => { setActiveScan(s.scan_id); setPage("results"); }}
              style={{ display: "flex", alignItems: "center", padding: "10px 0",
                borderBottom: `1px solid ${COLORS.border}22`, cursor: "pointer", gap: 12 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0,
                background: s.status === "complete" ? COLORS.low :
                  s.status === "running" ? COLORS.accent : COLORS.critical }} />
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 13, color: COLORS.text, fontWeight: 600 }}>
                  {s.target_name || s.target_url}</div>
                <div style={{ fontSize: 12, color: COLORS.textDim }}>
                  {new Date(s.created_at).toLocaleString()} — {s.finding_count} finding{s.finding_count !== 1 ? "s" : ""}
                  {s.completed_at && ` · ${Math.round((new Date(s.completed_at) - new Date(s.created_at)) / 60000)}m`}
                </div>
              </div>
              <Badge text={s.status.toUpperCase()}
                color={s.status === "complete" ? COLORS.low :
                  s.status === "running" ? COLORS.accent : COLORS.critical} />
            </div>
          ))}
        </Card>
      )}
    </div>
  );
};

// ── Scan Page ───────────────────────────────────────────────────────────────

const ScanPage = ({ token, setPage, setActiveScan }) => {
  const [target, setTarget] = useState("http://");
  const [name, setName] = useState("");
  const [scanType, setScanType] = useState("full");
  const [running, setRunning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("");
  const [error, setError] = useState("");

  const phaseLabel = (p) => {
    if (p <= 5)  return "Checking connectivity...";
    if (p <= 15) return "Analysing HTTP headers and cookies...";
    if (p <= 30) return "Running nmap port scan...";
    if (p <= 45) return "Checking directory exposure and CORS...";
    if (p <= 55) return "Testing authentication rate limiting...";
    if (p <= 70) return "Running Nikto web server scan...";
    if (p <= 85) return "Running Nuclei vulnerability templates...";
    if (p < 100) return "Running SQLmap injection detection...";
    return "Finalising results...";
  };

  useEffect(() => {
    if (!running || !scanId) return;
    const interval = setInterval(async () => {
      try {
        const data = await apiFetch(`/api/status/${scanId}`, {}, token);
        setProgress(data.progress || 0);
        setStatusMsg(data.status);
        if (data.status === "complete" || data.status === "error") {
          clearInterval(interval);
          setRunning(false);
          if (data.status === "complete") {
            setActiveScan(scanId);
            setTimeout(() => setPage("results"), 1000);
          } else {
            setError(data.error_message || "Scan failed — check target is reachable");
          }
        }
      } catch (e) {
        clearInterval(interval);
        setError(e.message);
        setRunning(false);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [running, scanId, token]);

  const launch = async () => {
    setError("");
    const urlPattern = /^https?:\/\/[a-zA-Z0-9._-]+(:\d+)?(\/.*)?$/;
    if (!target || !urlPattern.test(target)) {
      setError("Please enter a valid URL starting with http:// or https://");
      return;
    }
    try {
      const data = await apiFetch("/api/scan", {
        method: "POST",
        body: JSON.stringify({ url: target, name, scan_type: scanType }),
      }, token);
      setScanId(data.scan_id);
      setRunning(true);
      setProgress(0);
      setStatusMsg("running");
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: COLORS.text, margin: 0 }}>New Scan</h2>
        <p style={{ color: COLORS.textDim, fontSize: 14, margin: "6px 0 0" }}>
          Configure and launch an OWASP Top 10 assessment</p>
      </div>
      {error && (
        <div style={{ background: COLORS.critical + "18", border: `1px solid ${COLORS.critical}44`,
          borderRadius: 8, padding: "10px 14px", marginBottom: 16,
          fontSize: 13, color: COLORS.critical }}>{error}</div>
      )}
      {!running ? (
        <>
          <Card style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
              textTransform: "uppercase", letterSpacing: 0.5, display: "block", marginBottom: 6 }}>
              Target URL *</label>
            <input value={target} onChange={e => setTarget(e.target.value)}
              placeholder="http://target.example.com"
              style={{ width: "100%", padding: "11px 14px", background: COLORS.cardBg,
                border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text,
                fontSize: 14, outline: "none", boxSizing: "border-box",
                fontFamily: "monospace", marginBottom: 14 }} />
            <label style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
              textTransform: "uppercase", letterSpacing: 0.5, display: "block", marginBottom: 6 }}>
              Label (optional)</label>
            <input value={name} onChange={e => setName(e.target.value)}
              placeholder="e.g. Juice Shop — Local VM"
              style={{ width: "100%", padding: "11px 14px", background: COLORS.cardBg,
                border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text,
                fontSize: 14, outline: "none", boxSizing: "border-box" }} />
            <div style={{ marginTop: 20 }}>
              <label style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
                textTransform: "uppercase", letterSpacing: 0.5, display: "block", marginBottom: 10 }}>
                Scan type</label>
              <div style={{ display: "flex", gap: 12 }}>
                {[
                  ["full", "Full OWASP Top 10", "7 phases — headers, ports, dirs, auth, nikto, nuclei, sqlmap"],
                  ["quick", "Quick scan", "Phases 1–4 only — headers, nmap, dirs, auth"]
                ].map(([id, label, desc]) => (
                  <div key={id} onClick={() => setScanType(id)} style={{
                    flex: 1, padding: "14px 16px", borderRadius: 8,
                    border: `1px solid ${scanType === id ? COLORS.primary : COLORS.border}`,
                    background: scanType === id ? COLORS.primary + "12" : COLORS.cardBg,
                    cursor: "pointer", transition: "all 0.2s" }}>
                    <div style={{ fontSize: 14, fontWeight: 600,
                      color: scanType === id ? COLORS.primary : COLORS.text, marginBottom: 4 }}>
                      {label}</div>
                    <div style={{ fontSize: 12, color: COLORS.textDim }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ marginTop: 20, padding: "12px 14px", background: COLORS.cardBg,
              borderRadius: 8, border: `1px solid ${COLORS.border}` }}>
              <div style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
                textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 10 }}>
                Assessment pipeline</div>
              {[
                { phase: "P0", name: "Connectivity check", tool: "urllib" },
                { phase: "P1", name: "Header analysis", tool: "header-check · cookies" },
                { phase: "P2", name: "Port scan", tool: "nmap -sV + banner verify" },
                { phase: "P3", name: "Directory exposure", tool: "dir-check · cors-check" },
                { phase: "P4", name: "Auth testing", tool: "endpoint discovery · rate-limit" },
                { phase: "P5", name: "Web server scan", tool: "nikto 6700+ checks" },
                { phase: "P6", name: "Vulnerability templates", tool: "nuclei 9000+ CVEs" },
                { phase: "P7", name: "Injection detection", tool: "sqlmap (read-only)" },
              ].map((p, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10,
                  padding: "6px 0",
                  borderBottom: i < 7 ? `1px solid ${COLORS.border}22` : "none" }}>
                  <div style={{ width: 28, height: 28, borderRadius: 6,
                    background: COLORS.primary + "18", display: "flex",
                    alignItems: "center", justifyContent: "center", fontSize: 11,
                    fontWeight: 700, color: COLORS.primary, flexShrink: 0 }}>{p.phase}</div>
                  <div style={{ flex: 1, fontSize: 13, color: COLORS.text }}>{p.name}</div>
                  <div style={{ fontSize: 11, color: COLORS.textDim,
                    fontFamily: "monospace" }}>{p.tool}</div>
                </div>
              ))}
            </div>
          </Card>
          <Btn primary onClick={launch}
            style={{ width: "100%", padding: 14, fontSize: 16, borderRadius: 10 }}>
            Launch Assessment
          </Btn>
        </>
      ) : (
        <Card>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: 20 }}>
            <div>
              <h3 style={{ fontSize: 16, fontWeight: 600, color: COLORS.text, margin: "0 0 4px" }}>
                Scan in progress</h3>
              <div style={{ fontSize: 13, color: COLORS.textDim, fontFamily: "monospace" }}>
                {target}</div>
            </div>
            <Badge text={`${progress}%`} color={COLORS.primary} />
          </div>
          <div style={{ background: COLORS.cardBg, borderRadius: 8, height: 8,
            marginBottom: 20, overflow: "hidden" }}>
            <div style={{ height: "100%",
              background: `linear-gradient(90deg, ${COLORS.primary}, ${COLORS.accent})`,
              width: `${progress}%`, transition: "width 0.8s ease", borderRadius: 8 }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between",
            fontSize: 13, color: COLORS.textDim }}>
            <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Spinner />
              <span style={{ color: COLORS.accent }}>{phaseLabel(progress)}</span>
            </span>
            <span style={{ fontFamily: "monospace", fontSize: 11 }}>ID: {scanId}</span>
          </div>
          {statusMsg === "complete" && (
            <div style={{ marginTop: 16, padding: "10px 14px", background: COLORS.low + "18",
              borderRadius: 8, border: `1px solid ${COLORS.low}44`, fontSize: 13, color: COLORS.low }}>
              Scan complete — redirecting to results...
            </div>
          )}
        </Card>
      )}
    </div>
  );
};

// ── Results Page ────────────────────────────────────────────────────────────

const ResultsPage = ({ token, activeScan, setActiveScan, setDetail }) => {
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadScans = () =>
    apiFetch("/api/scans", {}, token).then(setScans).catch(console.error);

  useEffect(() => { loadScans(); }, [token]);

  useEffect(() => {
    if (!activeScan) return;
    setLoading(true);
    apiFetch(`/api/results/${activeScan}`, {}, token)
      .then(data => { setFindings(data.findings || []); setCurrentScan(data); })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [activeScan, token]);

  const deleteScan = async (e, scanId) => {
    e.stopPropagation();
    if (!confirm("Delete this scan and all its findings?")) return;
    try {
      await fetch(`/api/scans/${scanId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` }
      });
      setScans(prev => prev.filter(s => s.scan_id !== scanId));
      if (activeScan === scanId) { setActiveScan(null); setFindings([]); setCurrentScan(null); }
    } catch (e) { console.error(e); }
  };

  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1; return acc;
  }, {});

  return (
    <div>
      <div style={{ marginBottom: 20, display: "flex",
        justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: COLORS.text, margin: 0 }}>Results</h2>
          {currentScan && (
            <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
              {[["Critical", COLORS.critical], ["High", COLORS.high],
                ["Medium", COLORS.medium], ["Low", COLORS.low]].map(([sev, color]) =>
                sevCounts[sev] ? (
                  <Badge key={sev} text={`${sevCounts[sev]} ${sev}`} color={color} />
                ) : null
              )}
            </div>
          )}
        </div>
      </div>
      <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
        {scans.filter(s => s.status === "complete").map(s => (
          <div key={s.scan_id} style={{ display: "flex", alignItems: "center", gap: 2 }}>
            <div onClick={() => setActiveScan(s.scan_id)}
              style={{ padding: "6px 14px", borderRadius: "8px 0 0 8px", cursor: "pointer",
                background: activeScan === s.scan_id ? COLORS.primary + "18" : COLORS.cardBg,
                border: `1px solid ${activeScan === s.scan_id ? COLORS.primary : COLORS.border}`,
                borderRight: "none",
                fontSize: 13, color: activeScan === s.scan_id ? COLORS.primary : COLORS.textMuted }}>
              {s.target_name || s.target_url}
            </div>
            <div onClick={(e) => deleteScan(e, s.scan_id)}
              style={{ padding: "6px 10px", borderRadius: "0 8px 8px 0", cursor: "pointer",
                background: COLORS.cardBg,
                border: `1px solid ${activeScan === s.scan_id ? COLORS.primary : COLORS.border}`,
                color: COLORS.critical, fontSize: 14, lineHeight: 1,
                transition: "background 0.2s" }}
              onMouseEnter={e => e.currentTarget.style.background = COLORS.critical + "18"}
              onMouseLeave={e => e.currentTarget.style.background = COLORS.cardBg}>
              ×
            </div>
          </div>
        ))}
      </div>
      {loading ? (
        <Card style={{ textAlign: "center", padding: 40 }}><Spinner /></Card>
      ) : !activeScan ? (
        <Card style={{ textAlign: "center", padding: 40 }}>
          <div style={{ color: COLORS.textDim }}>Select a completed scan above</div>
        </Card>
      ) : findings.length === 0 ? (
        <Card style={{ textAlign: "center", padding: 40 }}>
          <div style={{ color: COLORS.textDim }}>No findings for this scan</div>
        </Card>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {findings.sort((a, b) => b.cvss_score - a.cvss_score).map(f => (
            <Card key={f.id} onClick={() => setDetail(f)}
              style={{ display: "flex", alignItems: "center", gap: 16 }}>
              <div style={{ width: 48, height: 48, borderRadius: 10,
                background: sevColor(f.severity) + "18", display: "flex",
                alignItems: "center", justifyContent: "center", fontSize: 16,
                fontWeight: 900, color: sevColor(f.severity), flexShrink: 0 }}>
                {(f.cvss_score || 0).toFixed(1)}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.text, marginBottom: 4 }}>
                  {f.title}</div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  <Badge text={f.severity} color={sevColor(f.severity)} />
                  {f.owasp_id && <Badge text={f.owasp_id} color={COLORS.accent} />}
                  <span style={{ fontSize: 12, color: COLORS.textDim }}>via {f.tool_used}</span>
                </div>
              </div>
              <span style={{ color: COLORS.textDim, fontSize: 18 }}>→</span>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};

// ── Detail Page ─────────────────────────────────────────────────────────────

const DetailPage = ({ finding, back }) => (
  <div>
    <div onClick={back} style={{ cursor: "pointer", color: COLORS.primary,
      fontSize: 13, marginBottom: 16 }}>← Back to results</div>
    <Card style={{ marginBottom: 20 }}>
      <div style={{ display: "flex", justifyContent: "space-between",
        alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div>
          <h2 style={{ fontSize: 20, fontWeight: 700, color: COLORS.text, margin: "0 0 8px" }}>
            {finding.title}</h2>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <Badge text={finding.severity} color={sevColor(finding.severity)} />
            {finding.owasp_id && (
              <Badge text={`${finding.owasp_id} — ${finding.owasp_label}`} color={COLORS.accent} />
            )}
          </div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={{ fontSize: 36, fontWeight: 900, color: sevColor(finding.severity) }}>
            {(finding.cvss_score || 0).toFixed(1)}</div>
          <div style={{ fontSize: 11, color: COLORS.textDim }}>CVSS v3.1</div>
        </div>
      </div>
      <div style={{ fontSize: 14, color: COLORS.textMuted, lineHeight: 1.7 }}>
        {finding.description}</div>
    </Card>
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
      <Card>
        <h4 style={{ fontSize: 12, color: COLORS.textDim, margin: "0 0 12px",
          textTransform: "uppercase", letterSpacing: 0.5 }}>Technical details</h4>
        <div style={{ fontSize: 13, color: COLORS.textMuted, lineHeight: 2 }}>
          <div>Endpoint: <code style={{ color: COLORS.text, background: COLORS.cardBg,
            padding: "1px 6px", borderRadius: 4 }}>{finding.endpoint}</code></div>
          <div>Tool: <span style={{ color: COLORS.text }}>{finding.tool_used}</span></div>
          {finding.cvss_vector && (
            <div style={{ fontSize: 11 }}>Vector: <code style={{ color: COLORS.textDim }}>
              {finding.cvss_vector}</code></div>
          )}
        </div>
      </Card>
      <Card>
        <h4 style={{ fontSize: 12, color: COLORS.textDim, margin: "0 0 12px",
          textTransform: "uppercase", letterSpacing: 0.5 }}>Remediation</h4>
        <div style={{ fontSize: 13, color: COLORS.textMuted, lineHeight: 1.7 }}>
          {finding.remediation}</div>
      </Card>
    </div>
    {finding.evidence && (
      <Card>
        <h4 style={{ fontSize: 12, color: COLORS.textDim, margin: "0 0 12px",
          textTransform: "uppercase", letterSpacing: 0.5 }}>Evidence</h4>
        <pre style={{ fontSize: 11, color: COLORS.textDim, background: COLORS.cardBg,
          padding: 12, borderRadius: 8, overflow: "auto", whiteSpace: "pre-wrap",
          wordBreak: "break-all", margin: 0 }}>{finding.evidence}</pre>
      </Card>
    )}
  </div>
);

// ── Report Page ─────────────────────────────────────────────────────────────

const ReportPage = ({ token }) => {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState("");
  const [generating, setGenerating] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [reportResult, setReportResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    apiFetch("/api/scans", {}, token)
      .then(s => setScans(s.filter(x => x.status === "complete")))
      .catch(console.error);
  }, [token]);

  const generate = async (format) => {
    if (!selectedScan) { setError("Select a completed scan first"); return; }
    setGenerating(true); setError(""); setReportResult(null);
    try {
      const data = await apiFetch(`/api/report/${selectedScan}`, {
        method: "POST",
        body: JSON.stringify({ format, language: "en" }),
      }, token);
      setReportResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setGenerating(false);
    }
  };

  const download = async () => {
    if (!reportResult) return;
    setDownloading(true);
    setError("");
    for (let i = 0; i < 10; i++) {
      try {
        const res = await fetch(`/api/report/${reportResult.report_id}/download`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (res.status === 404) {
          await new Promise(r => setTimeout(r, 3000));
          continue;
        }
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          setError(err.error || "Download failed");
          setDownloading(false);
          return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `SecuriScan_SEC-${reportResult.report_id?.toUpperCase()}.${reportResult.format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setDownloading(false);
        return;
      } catch (e) {
        setError("Download failed: " + e.message);
        setDownloading(false);
        return;
      }
    }
    setError("Report is taking longer than expected. Click download again.");
    setDownloading(false);
  };

  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: COLORS.text, margin: 0 }}>Reports</h2>
        <p style={{ color: COLORS.textDim, fontSize: 14, margin: "6px 0 0" }}>
          Generate professional security assessment reports</p>
      </div>

      {error && (
        <div style={{ background: COLORS.critical + "18", border: `1px solid ${COLORS.critical}44`,
          borderRadius: 8, padding: "10px 14px", marginBottom: 16,
          fontSize: 13, color: COLORS.critical }}>{error}</div>
      )}

      {reportResult ? (
        /* ── Download state ── */
        <Card style={{ textAlign: "center", padding: 40 }}>
          <div style={{ fontSize: 36, marginBottom: 16 }}>📄</div>
          <div style={{ color: COLORS.low, fontWeight: 700, fontSize: 18, marginBottom: 6 }}>
            Report Ready</div>
          <div style={{ color: COLORS.textDim, fontSize: 13, marginBottom: 4 }}>
            Reference: <code style={{ color: COLORS.text, background: COLORS.cardBg,
              padding: "2px 8px", borderRadius: 4 }}>
              SEC-{reportResult.report_id?.toUpperCase()}
            </code>
          </div>
          <div style={{ color: COLORS.textDim, fontSize: 12, marginBottom: 32 }}>
            Format: {reportResult.format?.toUpperCase()} · Language: English
          </div>
          <div style={{ display: "flex", gap: 12, justifyContent: "center",
            flexWrap: "wrap", marginBottom: 20 }}>
            <Btn primary onClick={download} disabled={downloading}
              style={{ minWidth: 200, padding: "12px 24px", fontSize: 14 }}>
              {downloading ? (
                <span style={{ display: "flex", alignItems: "center",
                  gap: 8, justifyContent: "center" }}>
                  <Spinner /> Preparing...
                </span>
              ) : `⬇ Download ${reportResult.format?.toUpperCase()}`}
            </Btn>
          </div>
          <div onClick={() => { setReportResult(null); setError(""); setSelectedScan(""); }}
            style={{ cursor: "pointer", color: COLORS.textDim, fontSize: 13,
              display: "inline-flex", alignItems: "center", gap: 6,
              padding: "8px 16px", borderRadius: 8,
              border: `1px solid ${COLORS.border}`, transition: "all 0.2s" }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = COLORS.primary;
              e.currentTarget.style.color = COLORS.primary;
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = COLORS.border;
              e.currentTarget.style.color = COLORS.textDim;
            }}>
            ← Generate another report
          </div>
          <div style={{ marginTop: 12, fontSize: 11, color: COLORS.textDim }}>
            The file will be ready a few seconds after clicking
          </div>
        </Card>
      ) : (
        /* ── Generation state ── */
        <>
          <Card style={{ marginBottom: 20 }}>
            <label style={{ fontSize: 12, color: COLORS.textDim, fontWeight: 600,
              textTransform: "uppercase", letterSpacing: 0.5, display: "block", marginBottom: 10 }}>
              Select scan</label>
            <select value={selectedScan} onChange={e => setSelectedScan(e.target.value)}
              style={{ width: "100%", padding: "10px 14px", background: COLORS.cardBg,
                border: `1px solid ${COLORS.border}`, borderRadius: 8, color: COLORS.text,
                fontSize: 14, outline: "none" }}>
              <option value="">-- Select a completed scan --</option>
              {scans.map(s => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.target_name || s.target_url} — {new Date(s.created_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </Card>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            {[
              ["pdf", "📄", "PDF Report", "Client-ready with ADVANCIA branding"],
              ["html", "🌐", "HTML Report", "Interactive web-based report"],
              ["json", "📋", "JSON Export", "Machine-readable format"]
            ].map(([fmt, icon, label, desc]) => (
              <Card key={fmt} style={{ flex: 1, minWidth: 160, textAlign: "center", padding: 24 }}>
                <div style={{ fontSize: 28, marginBottom: 8 }}>{icon}</div>
                <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.text, marginBottom: 4 }}>
                  {label}</div>
                <div style={{ fontSize: 12, color: COLORS.textDim, marginBottom: 16 }}>{desc}</div>
                <Btn primary={fmt === "pdf"} small onClick={() => generate(fmt)}
                  disabled={generating || !selectedScan}>
                  {generating ? "Generating..." : `Generate ${fmt.toUpperCase()}`}
                </Btn>
              </Card>
            ))}
          </div>
        </>
      )}
    </div>
  );
};

// ── Users Page (Admin) ──────────────────────────────────────────────────────

const UsersPage = ({ token }) => {
  const [users, setUsers] = useState([]);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const load = () => apiFetch("/api/users", {}, token).then(setUsers).catch(console.error);
  useEffect(() => { load(); }, [token]);

  const create = async () => {
    setError(""); setSuccess("");
    try {
      await apiFetch("/api/users", {
        method: "POST",
        body: JSON.stringify({ email, password, role }),
      }, token);
      setSuccess("User created"); setEmail(""); setPassword(""); load();
    } catch (e) { setError(e.message); }
  };

  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700, color: COLORS.text, margin: 0 }}>
          User management</h2>
      </div>
      <Card style={{ marginBottom: 20 }}>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: COLORS.text, margin: "0 0 16px" }}>
          Create user</h3>
        {error && <div style={{ color: COLORS.critical, fontSize: 13, marginBottom: 12 }}>{error}</div>}
        {success && <div style={{ color: COLORS.low, fontSize: 13, marginBottom: 12 }}>{success}</div>}
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <input value={email} onChange={e => setEmail(e.target.value)} placeholder="Email"
            style={{ flex: 2, padding: "10px 14px", background: COLORS.cardBg,
              border: `1px solid ${COLORS.border}`, borderRadius: 8,
              color: COLORS.text, fontSize: 14, outline: "none" }} />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)}
            placeholder="Password"
            style={{ flex: 1, padding: "10px 14px", background: COLORS.cardBg,
              border: `1px solid ${COLORS.border}`, borderRadius: 8,
              color: COLORS.text, fontSize: 14, outline: "none" }} />
          <select value={role} onChange={e => setRole(e.target.value)}
            style={{ padding: "10px 14px", background: COLORS.cardBg,
              border: `1px solid ${COLORS.border}`, borderRadius: 8,
              color: COLORS.text, fontSize: 14, outline: "none" }}>
            <option value="analyst">Analyst</option>
            <option value="admin">Admin</option>
          </select>
          <Btn primary onClick={create}>Create</Btn>
        </div>
      </Card>
      <Card>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: COLORS.text, margin: "0 0 16px" }}>
          Users</h3>
        {users.map(u => (
          <div key={u.id} style={{ display: "flex", alignItems: "center",
            padding: "10px 0", borderBottom: `1px solid ${COLORS.border}22`, gap: 12 }}>
            <div style={{ flex: 1, fontSize: 13, color: COLORS.text }}>{u.email}</div>
            <Badge text={u.role} color={u.role === "admin" ? COLORS.critical : COLORS.accent} />
            <Badge text={u.is_active ? "active" : "inactive"}
              color={u.is_active ? COLORS.low : COLORS.textDim} />
          </div>
        ))}
      </Card>
    </div>
  );
};

// ── Root App ────────────────────────────────────────────────────────────────

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("token") || "");
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("user") || "null"); } catch { return null; }
  });
  const [page, setPage] = useState("dash");
  const [detail, setDetail] = useState(null);
  const [activeScan, setActiveScan] = useState(null);

  const handleLogin = (userData, tokenData) => { setUser(userData); setToken(tokenData); };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setToken(""); setUser(null); setPage("dash");
  };

  if (!token || !user) return <LoginPage onLogin={handleLogin} />;

  return (
    <div style={{ display: "flex", height: "100vh", background: COLORS.bg,
      color: COLORS.text,
      fontFamily: "'Geist', 'SF Pro Display', -apple-system, system-ui, sans-serif",
      overflow: "hidden" }}>
      <Sidebar active={page} setPage={p => { setPage(p); setDetail(null); }}
        user={user} onLogout={handleLogout} />
      <div style={{ flex: 1, overflow: "auto", padding: "28px 36px" }}>
        {page === "dash" && <DashboardPage token={token} setPage={setPage} setActiveScan={setActiveScan} />}
        {page === "scan" && <ScanPage token={token} setPage={setPage} setActiveScan={setActiveScan} />}
        {page === "results" && !detail && (
          <ResultsPage token={token} activeScan={activeScan}
            setActiveScan={setActiveScan} setDetail={setDetail} />
        )}
        {page === "results" && detail && <DetailPage finding={detail} back={() => setDetail(null)} />}
        {page === "report" && <ReportPage token={token} />}
        {page === "users" && user?.role === "admin" && <UsersPage token={token} />}
      </div>
    </div>
  );
}