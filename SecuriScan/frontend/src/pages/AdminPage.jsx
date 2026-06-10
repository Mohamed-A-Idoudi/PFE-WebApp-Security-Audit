import { useState, useEffect } from "react";
import { getUsers, getScans, createUser, deleteUser } from "../utils/api";
import { StatusDot } from "../components/Badge";
import { Spinner } from "../components/Spinner";

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day:"2-digit", month:"short", year:"numeric", hour:"2-digit", minute:"2-digit" });
}

export function AdminPage({ token, user, onLogout, navigate }) {
  const [users,   setUsers]   = useState([]);
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab,     setTab]     = useState("overview"); // overview | users | scans
  const [error,   setError]   = useState("");
  const [success, setSuccess] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [form,    setForm]    = useState({ email:"", password:"", role:"analyst" });
  const [saving,  setSaving]  = useState(false);
  const [deleting,setDeleting]= useState("");

  useEffect(() => {
    Promise.all([
      getUsers(token).catch(() => []),
      getScans(token, true).catch(() => []),
    ]).then(([u, s]) => {
      setUsers(u);
      setScans(s);
    }).finally(() => setLoading(false));
  }, [token]);

  // Per-user activity computed from scans
  function userActivity(email) {
    const userScans = scans.filter(s => s.created_by_email === email);
    const totalFindings = userScans.reduce((acc, s) => {
      if (!s.finding_counts) return acc;
      return acc + Object.values(s.finding_counts).reduce((a,b) => a+b, 0);
    }, 0);
    const lastScan = userScans[0]; // already sorted by date desc
    return {
      scans:       userScans.length,
      findings:    totalFindings,
      lastScan:    lastScan?.created_at,
      lastTarget:  lastScan?.target_url,
      running:     userScans.filter(s => s.status === "running").length,
    };
  }

  // Platform stats
  const totalFindings = scans.reduce((acc, s) => {
    if (!s.finding_counts) return acc;
    return acc + Object.values(s.finding_counts).reduce((a,b) => a+b, 0);
  }, 0);
  const totalCrit = scans.reduce((acc, s) => acc + (s.finding_counts?.Critical || 0), 0);
  const running   = scans.filter(s => s.status === "running").length;
  const completed = scans.filter(s => s.status === "complete").length;

  async function handleAddUser(e) {
    e.preventDefault();
    setSaving(true); setError(""); setSuccess("");
    try {
      await createUser(form, token);
      setSuccess(`User ${form.email} created.`);
      setForm({ email:"", password:"", role:"analyst" });
      setShowAdd(false);
      const u = await getUsers(token);
      setUsers(u);
    } catch(err) { setError(err.message); }
    finally { setSaving(false); }
  }

  async function handleDelete(id, email) {
    if (!window.confirm(`Delete user ${email}? This cannot be undone.`)) return;
    setDeleting(id);
    try {
      await deleteUser(id, token);
      setUsers(prev => prev.filter(u => u.id !== id));
    } catch(err) { setError(err.message); }
    finally { setDeleting(""); }
  }

  const TABS = [
    { id:"overview", label:"Overview"      },
    { id:"users",    label:`Users (${users.length})` },
    { id:"scans",    label:`All Scans (${scans.length})` },
  ];

  return (
    <div style={{ background:"var(--void)", minHeight:"100vh", color:"var(--text)" }}>

      {/* Admin header */}
      <header style={{
        background:"var(--deep)", borderBottom:"1px solid var(--line)",
        padding:"0 32px", display:"flex", alignItems:"center",
        justifyContent:"space-between", height:"56px",
      }}>
        <div style={{ display:"flex", alignItems:"center", gap:"20px" }}>
          <button onClick={() => navigate("/")} style={{
            background:"none", border:"none", cursor:"pointer",
            fontFamily:"var(--font-hd)", fontSize:"17px", fontWeight:700,
            letterSpacing:"1.8px", color:"var(--text)",
          }}>
            SECURI<span style={{ color:"var(--blue)" }}>SCAN</span>
          </button>
          <div style={{
            padding:"2px 8px", borderRadius:"var(--r-xs)",
            background:"rgba(99,102,241,.1)", border:"1px solid rgba(99,102,241,.22)",
            fontSize:"10px", fontFamily:"var(--font-hd)", letterSpacing:".8px",
            textTransform:"uppercase", color:"#a5b4fc",
          }}>
            Admin Console
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:"12px" }}>
          <button onClick={() => navigate("/app")} className="ss-btn ss-btn-secondary ss-btn-sm">
            ← Open App
          </button>
          <div style={{ fontSize:"12px", color:"var(--dim)" }}>{user.email}</div>
          <button onClick={onLogout} className="ss-btn ss-btn-ghost ss-btn-sm">Sign out</button>
        </div>
      </header>

      <div style={{ padding:"28px 32px", maxWidth:"1200px", margin:"0 auto" }}>

        {/* Page title */}
        <div style={{ marginBottom:"24px" }}>
          <h1 style={{ fontFamily:"var(--font-hd)", fontSize:"22px", fontWeight:700, marginBottom:"4px" }}>Platform Administration</h1>
          <div style={{ fontSize:"12px", color:"var(--fade)" }}>Platform-wide activity and user management</div>
        </div>

        {error   && <div className="ss-notice ss-notice-err ss-mb-4">{error}</div>}
        {success && <div className="ss-notice ss-notice-ok  ss-mb-4">{success}</div>}

        {/* Tabs */}
        <div style={{ display:"flex", gap:"4px", marginBottom:"22px", borderBottom:"1px solid var(--line)", paddingBottom:"0" }}>
          {TABS.map(({ id, label }) => (
            <button key={id} onClick={() => setTab(id)} style={{
              padding:"8px 16px", background:"none", border:"none",
              borderBottom:`2px solid ${tab===id?"var(--blue)":"transparent"}`,
              color: tab===id?"var(--text)":"var(--dim)",
              fontSize:"13px", fontWeight: tab===id?500:400,
              cursor:"pointer", transition:"all .12s",
              marginBottom:"-1px",
            }}>{label}</button>
          ))}
        </div>

        {loading ? (
          <div className="ss-empty"><Spinner size={24}/><p>Loading…</p></div>
        ) : tab === "overview" ? (

          /* ── OVERVIEW ── */
          <div>
            {/* Platform stats */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:"12px", marginBottom:"22px" }}>
              {[
                { label:"Total Users",    value:users.length,   sub:"registered accounts" },
                { label:"Total Scans",    value:scans.length,   sub:`${running} running · ${completed} complete` },
                { label:"Total Findings", value:totalFindings,  sub:`${totalCrit} critical` },
                { label:"Active Now",     value:running,        sub:"scans in progress" },
              ].map(({ label, value, sub }) => (
                <div key={label} style={{
                  background:"var(--surface)", border:"1px solid var(--line)",
                  borderRadius:"var(--r-md)", padding:"16px 18px",
                }}>
                  <div style={{ fontSize:"11px", fontFamily:"var(--font-hd)", letterSpacing:".8px", textTransform:"uppercase", color:"var(--fade)", marginBottom:"6px" }}>{label}</div>
                  <div style={{ fontFamily:"var(--font-hd)", fontSize:"30px", fontWeight:700, color:"var(--text)", marginBottom:"4px" }}>{value}</div>
                  <div style={{ fontSize:"11px", color:"var(--fade)" }}>{sub}</div>
                </div>
              ))}
            </div>

            {/* User activity summary */}
            <div className="ss-card-bare">
              <div style={{ padding:"13px 18px", borderBottom:"1px solid var(--line)" }}>
                <span className="ss-h3">User Activity Summary</span>
              </div>
              <table className="ss-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Scans</th>
                    <th>Findings</th>
                    <th>Last Scan</th>
                    <th>Last Target</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => {
                    const act = userActivity(u.email);
                    return (
                      <tr key={u.id} style={{ cursor:"default" }}>
                        <td>
                          <div style={{ fontSize:"12px", fontFamily:"var(--font-mono)" }}>{u.email}</div>
                        </td>
                        <td>
                          <span style={{
                            padding:"2px 7px", borderRadius:"var(--r-xs)",
                            fontSize:"10px", fontFamily:"var(--font-hd)", letterSpacing:".5px",
                            textTransform:"uppercase", fontWeight:600,
                            background: u.role==="admin"?"rgba(99,102,241,.1)":"var(--raised)",
                            color:      u.role==="admin"?"#a5b4fc":"var(--dim)",
                            border:     u.role==="admin"?"1px solid rgba(99,102,241,.22)":"1px solid var(--wire)",
                          }}>{u.role}</span>
                        </td>
                        <td style={{ fontFamily:"var(--font-hd)", fontSize:"16px", fontWeight:600 }}>{act.scans}</td>
                        <td style={{ fontFamily:"var(--font-hd)", fontSize:"16px", fontWeight:600, color: act.findings>0?"var(--text)":"var(--fade)" }}>{act.findings}</td>
                        <td style={{ fontSize:"12px", color:"var(--dim)" }}>{fmtDate(act.lastScan)}</td>
                        <td>
                          <span style={{ fontFamily:"var(--font-mono)", fontSize:"11px", color:"var(--dim)" }}>
                            {act.lastTarget ? (act.lastTarget.length > 36 ? act.lastTarget.slice(0,36)+"…" : act.lastTarget) : "—"}
                          </span>
                        </td>
                        <td>
                          <span style={{
                            fontSize:"11px",
                            color: u.is_active ? "var(--low)" : "var(--crit)",
                          }}>
                            {u.is_active ? "Active" : "Disabled"}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

        ) : tab === "users" ? (

          /* ── USERS ── */
          <div>
            <div style={{ display:"flex", justifyContent:"flex-end", marginBottom:"14px" }}>
              <button className="ss-btn ss-btn-primary ss-btn-sm" onClick={() => setShowAdd(v=>!v)}>
                {showAdd ? "Cancel" : "+ Add User"}
              </button>
            </div>

            {showAdd && (
              <div className="ss-card ss-mb-4" style={{ maxWidth:"420px" }}>
                <div className="ss-h3" style={{ marginBottom:"14px" }}>Create User</div>
                <form onSubmit={handleAddUser} style={{ display:"flex", flexDirection:"column", gap:"12px" }}>
                  <div className="ss-field">
                    <label className="ss-label">Email</label>
                    <input className="ss-input" type="email" value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} placeholder="user@securiscan.local" required />
                  </div>
                  <div className="ss-field">
                    <label className="ss-label">Password</label>
                    <input className="ss-input" type="password" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))} placeholder="Min 8 characters" required minLength={8} />
                  </div>
                  <div className="ss-field">
                    <label className="ss-label">Role</label>
                    <select className="ss-input" value={form.role} onChange={e=>setForm(f=>({...f,role:e.target.value}))}>
                      <option value="analyst">Analyst — can run scans</option>
                      <option value="admin">Admin — full platform access</option>
                    </select>
                  </div>
                  <div className="ss-flex ss-gap-2 ss-mt-2">
                    <button type="submit" className="ss-btn ss-btn-primary" disabled={saving}>
                      {saving && <Spinner size={13} color="#fff" />}
                      {saving ? "Creating…" : "Create User"}
                    </button>
                    <button type="button" className="ss-btn ss-btn-ghost" onClick={() => setShowAdd(false)}>Cancel</button>
                  </div>
                </form>
              </div>
            )}

            <div className="ss-card-bare">
              <table className="ss-table">
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Scans</th>
                    <th>Findings</th>
                    <th>Joined</th>
                    <th>Status</th>
                    <th style={{ width:80 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => {
                    const act = userActivity(u.email);
                    const isMe = u.email === user.email;
                    return (
                      <tr key={u.id} style={{ cursor:"default" }}>
                        <td>
                          <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
                            <div style={{
                              width:26, height:26, borderRadius:"50%",
                              background:"var(--raised)", border:"1px solid var(--wire)",
                              display:"flex", alignItems:"center", justifyContent:"center",
                              fontSize:"11px", fontWeight:700, color:"var(--dim)",
                              fontFamily:"var(--font-hd)", flexShrink:0,
                            }}>
                              {u.email[0].toUpperCase()}
                            </div>
                            <span style={{ fontFamily:"var(--font-mono)", fontSize:"12px" }}>{u.email}</span>
                            {isMe && <span style={{ fontSize:"10px", color:"var(--blue)", background:"rgba(59,130,246,.1)", padding:"1px 5px", borderRadius:"2px" }}>YOU</span>}
                          </div>
                        </td>
                        <td>
                          <span style={{
                            padding:"2px 7px", borderRadius:"var(--r-xs)", fontSize:"10px",
                            fontFamily:"var(--font-hd)", letterSpacing:".5px", textTransform:"uppercase", fontWeight:600,
                            background: u.role==="admin"?"rgba(99,102,241,.1)":"var(--raised)",
                            color:      u.role==="admin"?"#a5b4fc":"var(--dim)",
                            border:     u.role==="admin"?"1px solid rgba(99,102,241,.22)":"1px solid var(--wire)",
                          }}>{u.role}</span>
                        </td>
                        <td style={{ fontFamily:"var(--font-hd)", fontSize:"15px", fontWeight:600 }}>{act.scans}</td>
                        <td style={{ fontFamily:"var(--font-hd)", fontSize:"15px", fontWeight:600 }}>{act.findings}</td>
                        <td style={{ fontSize:"12px", color:"var(--dim)" }}>
                          {u.created_at ? new Date(u.created_at).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"}) : "—"}
                        </td>
                        <td>
                          <span style={{ fontSize:"11px", color:u.is_active?"var(--low)":"var(--crit)" }}>
                            {u.is_active ? "Active" : "Disabled"}
                          </span>
                        </td>
                        <td>
                          {!isMe && (
                            <button
                              className="ss-btn ss-btn-danger ss-btn-sm"
                              onClick={() => handleDelete(u.id, u.email)}
                              disabled={deleting===u.id}
                            >
                              {deleting===u.id ? <Spinner size={11} color="var(--crit)" /> : null}
                              Delete
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

        ) : (

          /* ── ALL SCANS ── */
          <div className="ss-card-bare">
            <table className="ss-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Launched by</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Type</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id} style={{ cursor:"default" }}>
                    <td>
                      <div style={{ fontFamily:"var(--font-mono)", fontSize:"11.5px" }}>{s.target_url}</div>
                      {s.target_name && s.target_name !== s.target_url && (
                        <div style={{ fontSize:"11px", color:"var(--fade)", marginTop:"2px" }}>{s.target_name}</div>
                      )}
                    </td>
                    <td style={{ fontFamily:"var(--font-mono)", fontSize:"11px", color:"var(--dim)" }}>
                      {s.created_by_email || "—"}
                    </td>
                    <td><StatusDot status={s.status} /></td>
                    <td>
                      {s.finding_counts ? (
                        <div className="ss-flex ss-gap-2">
                          {s.finding_counts.Critical>0&&<span style={{color:"var(--crit)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.Critical}C</span>}
                          {s.finding_counts.High>0&&<span style={{color:"var(--high)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.High}H</span>}
                          {s.finding_counts.Medium>0&&<span style={{color:"var(--med)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.Medium}M</span>}
                          {s.finding_counts.Low>0&&<span style={{color:"var(--low)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.Low}L</span>}
                        </div>
                      ) : <span className="ss-mono">—</span>}
                    </td>
                    <td>
                      <span className="ss-tag">{s.scan_type}</span>
                    </td>
                    <td style={{ fontSize:"12px", color:"var(--dim)" }}>{fmtDate(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

        )}
      </div>
    </div>
  );
}
