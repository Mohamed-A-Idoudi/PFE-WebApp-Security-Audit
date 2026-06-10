import { useState } from "react";
import { apiLogin } from "../utils/api";
import { Spinner } from "../components/Spinner";

export function LoginPage({ onLogin, navigate }) {
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const res  = await apiLogin(email, password);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Authentication failed");
      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));
      onLogin(data.user, data.token);
    } catch (err) {
      setError(err.message || "Authentication failed");
    } finally { setLoading(false); }
  }

  return (
    <div className="ss-login-wrap">
      <div className="ss-login-card">

        {/* Back link */}
        {navigate && (
          <button onClick={() => navigate("/")} style={{
            background:"none", border:"none", cursor:"pointer",
            color:"var(--fade)", fontSize:"12px", marginBottom:"20px",
            display:"flex", alignItems:"center", gap:"6px", padding:0,
          }}>
            <svg width="12" height="12" fill="none" viewBox="0 0 12 12">
              <path d="M8 2L4 6l4 4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            Back to home
          </button>
        )}

        <div className="ss-login-logo">SECURI<span>SCAN</span></div>
        <div className="ss-login-sub">Web Application Security Audit Platform</div>

        <form onSubmit={handleSubmit} className="ss-col ss-gap-4">
          <div className="ss-field">
            <label className="ss-label">Email address</label>
            <input className="ss-input" type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="analyst@securiscan.local" autoComplete="email" required />
          </div>
          <div className="ss-field">
            <label className="ss-label">Password</label>
            <input className="ss-input" type="password" value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••" autoComplete="current-password" required />
          </div>
          {error && <div className="ss-notice ss-notice-err">{error}</div>}
          <button type="submit" className="ss-btn ss-btn-primary ss-btn-lg ss-w-full" disabled={loading} style={{ marginTop:"4px", justifyContent:"center" }}>
            {loading && <Spinner size={15} color="#fff" />}
            {loading ? "Authenticating…" : "Sign In"}
          </button>
        </form>

        <div style={{ marginTop:"26px", paddingTop:"16px", borderTop:"1px solid var(--line)", display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <span style={{ fontSize:"11px", color:"var(--fade)" }}>SecuriScan © 2026</span>
          <span style={{ fontFamily:"var(--font-mono)", fontSize:"10px", color:"var(--fade)", background:"var(--raised)", border:"1px solid var(--wire)", padding:"2px 6px", borderRadius:"var(--r-xs)" }}>v1.0.0</span>
        </div>
      </div>
    </div>
  );
}
