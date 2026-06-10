import { useState, useEffect } from "react";
import { COLORS } from "./utils/colors";
import { Sidebar }      from "./components/Sidebar";
import { LoginPage }    from "./pages/LoginPage";
import { Dashboard }    from "./pages/Dashboard";
import { ScanPage }     from "./pages/ScanPage";
import { ResultsPage }  from "./pages/ResultsPage";
import { ReportPage }   from "./pages/ReportPage";
import { UsersPage }    from "./pages/UsersPage";
import { LandingPage }  from "./pages/LandingPage";
import { AboutPage }    from "./pages/AboutPage";
import { ContactPage }  from "./pages/ContactPage";
import { AdminPage }    from "./pages/AdminPage";
import { me }           from "./utils/api";

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("token") || "");
  const [user,  setUser]  = useState(() => {
    try { return JSON.parse(localStorage.getItem("user") || "null"); } catch { return null; }
  });
  const [path,       setPath]       = useState(window.location.pathname);
  const [innerPage,  setInnerPage]  = useState("dash");
  const [activeScan, setActiveScan] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);

  // Handle browser back/forward
  useEffect(() => {
    const handler = () => setPath(window.location.pathname);
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
  }, []);

  // Validate token on mount
  useEffect(() => {
    if (!token) { setAuthChecked(true); return; }
    me(token)
      .then(u => { setUser(u); setAuthChecked(true); })
      .catch(() => {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        setToken(""); setUser(null); setAuthChecked(true);
      });
  }, []);

  function navigate(to) {
    window.history.pushState({}, "", to);
    setPath(to);
  }

  function handleLogin(userData, tokenData) {
    setUser(userData);
    setToken(tokenData);
    navigate("/app");
  }

  function handleLogout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setToken(""); setUser(null);
    navigate("/");
  }

  // Loading state
  if (!authChecked) {
    return (
      <div style={{ height:"100vh", display:"flex", alignItems:"center", justifyContent:"center", background:"var(--void)" }}>
        <div style={{ textAlign:"center" }}>
          <div style={{ fontFamily:"var(--font-hd)", fontSize:"22px", fontWeight:700, letterSpacing:"2px", color:"var(--dim)" }}>
            SECURI<span style={{ color:"var(--blue)" }}>SCAN</span>
          </div>
          <div style={{ marginTop:"16px", width:"120px", height:"2px", background:"var(--line)", borderRadius:"1px", overflow:"hidden" }}>
            <div style={{ height:"100%", background:"var(--blue)", animation:"loadbar 1.2s ease-in-out infinite", borderRadius:"1px" }}/>
          </div>
          <style>{`@keyframes loadbar{0%{width:0;margin-left:0}50%{width:80%}100%{width:0;margin-left:100%}}`}</style>
        </div>
      </div>
    );
  }

  // ── Public routes (no auth needed) ────────────────────────────
  if (path === "/" || path === "")       return <LandingPage navigate={navigate} user={user} />;
  if (path === "/about")                 return <AboutPage   navigate={navigate} user={user} />;
  if (path === "/contact")               return <ContactPage navigate={navigate} user={user} />;

  // ── Login route ────────────────────────────────────────────────
  if (path === "/login") {
    if (token && user) { navigate("/app"); return null; }
    return <LoginPage onLogin={handleLogin} navigate={navigate} />;
  }

  // ── Admin route ────────────────────────────────────────────────
  if (path === "/admin") {
    if (!token || !user) { navigate("/login"); return null; }
    if (user.role !== "admin") { navigate("/app"); return null; }
    return <AdminPage token={token} user={user} onLogout={handleLogout} navigate={navigate} />;
  }

  // ── App routes (auth required) ─────────────────────────────────
  if (!token || !user) {
    navigate("/login");
    return null;
  }

  // Default anything else to /app
  return (
    <div className="ss-shell">
      <Sidebar
        active={innerPage}
        setPage={p => setInnerPage(p)}
        user={user}
        onLogout={handleLogout}
        onAdminClick={() => navigate("/admin")}
      />
      <main className="ss-main">
        {innerPage === "dash"    && <Dashboard   token={token} setPage={setInnerPage} setActiveScan={setActiveScan} />}
        {innerPage === "scan"    && <ScanPage    token={token} setPage={setInnerPage} setActiveScan={setActiveScan} />}
        {innerPage === "results" && <ResultsPage token={token} activeScan={activeScan} setActiveScan={setActiveScan} />}
        {innerPage === "report"  && <ReportPage  token={token} />}
        {innerPage === "users"   && user?.role === "admin" && <UsersPage token={token} />}
      </main>
    </div>
  );
}
