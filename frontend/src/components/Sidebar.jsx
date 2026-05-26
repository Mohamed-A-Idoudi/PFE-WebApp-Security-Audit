export function Sidebar({ active, setPage, user, onLogout, onAdminClick }) {
  const nav = [
    { id:"dash",    label:"Dashboard", icon:<IcoDash/> },
    { id:"scan",    label:"New Scan",  icon:<IcoScan/> },
    { id:"results", label:"Results",   icon:<IcoList/> },
    { id:"report",  label:"Reports",   icon:<IcoDoc/>  },
    ...(user?.role==="admin" ? [{ id:"users", label:"Users", icon:<IcoUsers/> }] : []),
  ];

  return (
    <aside style={{ width:"var(--sidebar-w)", minWidth:"var(--sidebar-w)", background:"var(--deep)", borderRight:"1px solid var(--line)", display:"flex", flexDirection:"column", height:"100vh", overflow:"hidden" }}>
      {/* Wordmark */}
      <div style={{ padding:"20px 18px 16px", borderBottom:"1px solid var(--line)" }}>
        <div style={{ fontFamily:"var(--font-hd)", fontSize:"20px", fontWeight:700, letterSpacing:"1.8px", color:"var(--text)" }}>
          SECURI<span style={{ color:"var(--blue)" }}>SCAN</span>
        </div>
        <div style={{ fontFamily:"var(--font-hd)", fontSize:"9px", letterSpacing:"1.5px", textTransform:"uppercase", color:"var(--fade)", marginTop:"2px" }}>
          Security Audit Platform
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex:1, padding:"10px 0", overflowY:"auto" }}>
        {nav.map(({ id, label, icon }) => {
          const on = active === id;
          return (
            <button key={id} onClick={() => setPage(id)} style={{
              width:"100%", display:"flex", alignItems:"center", gap:"9px",
              padding:"8px 18px",
              background: on?"var(--raised)":"transparent",
              border:"none", borderLeft:`3px solid ${on?"var(--blue)":"transparent"}`,
              color: on?"var(--text)":"var(--dim)",
              fontSize:"13px", fontFamily:"var(--font-ui)", fontWeight:on?500:400,
              cursor:"pointer", textAlign:"left", transition:"all .1s",
            }}
            onMouseEnter={e=>{ if(!on){e.currentTarget.style.color="var(--text)";e.currentTarget.style.background="var(--surface)";} }}
            onMouseLeave={e=>{ if(!on){e.currentTarget.style.color="var(--dim)";e.currentTarget.style.background="transparent";} }}>
              <span style={{ opacity:on?1:.65, display:"flex" }}>{icon}</span>
              {label}
            </button>
          );
        })}
      </nav>

      {/* Admin panel link */}
      {user?.role === "admin" && onAdminClick && (
        <div style={{ padding:"8px 18px", borderTop:"1px solid var(--line)" }}>
          <button onClick={onAdminClick} style={{
            width:"100%", display:"flex", alignItems:"center", gap:"8px",
            padding:"7px 10px", borderRadius:"var(--r-sm)",
            background:"rgba(99,102,241,.07)", border:"1px solid rgba(99,102,241,.2)",
            color:"#a5b4fc", fontSize:"12px", cursor:"pointer",
            fontFamily:"var(--font-ui)", transition:"all .1s",
          }}
          onMouseEnter={e=>{e.currentTarget.style.background="rgba(99,102,241,.14)";}}
          onMouseLeave={e=>{e.currentTarget.style.background="rgba(99,102,241,.07)";}}>
            <IcoAdmin />
            Admin Console
            <svg width="10" height="10" fill="none" viewBox="0 0 12 12" style={{ marginLeft:"auto", opacity:.6 }}>
              <path d="M2 6h8M6 2l4 4-4 4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </div>
      )}

      {/* User footer */}
      <div style={{ borderTop:"1px solid var(--line)", padding:"13px 18px" }}>
        <div style={{ marginBottom:"9px" }}>
          <div style={{ fontSize:"12px", color:"var(--text)", fontWeight:500, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{user?.email||"—"}</div>
          <div style={{ fontFamily:"var(--font-hd)", fontSize:"9px", letterSpacing:".8px", textTransform:"uppercase", color:"var(--fade)", marginTop:"2px" }}>{user?.role||"analyst"}</div>
        </div>
        <button onClick={onLogout} style={{
          width:"100%", display:"flex", alignItems:"center", gap:"6px",
          padding:"5px 9px", background:"transparent",
          border:"1px solid var(--wire)", borderRadius:"var(--r-sm)",
          color:"var(--fade)", fontSize:"12px", cursor:"pointer",
          fontFamily:"var(--font-ui)", transition:"all .1s",
        }}
        onMouseEnter={e=>{e.currentTarget.style.color="var(--crit)";e.currentTarget.style.borderColor="rgba(239,68,68,.3)";}}
        onMouseLeave={e=>{e.currentTarget.style.color="var(--fade)";e.currentTarget.style.borderColor="var(--wire)";}}>
          <IcoLogout/> Sign out
        </button>
      </div>
    </aside>
  );
}

function IcoDash()  { return <svg width="15" height="15" fill="none" viewBox="0 0 16 16"><rect x="1" y="1" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.3"/><rect x="9" y="1" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.3"/><rect x="1" y="9" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.3"/><rect x="9" y="9" width="6" height="6" rx="1.2" stroke="currentColor" strokeWidth="1.3"/></svg>; }
function IcoScan()  { return <svg width="15" height="15" fill="none" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.3" stroke="currentColor" strokeWidth="1.3"/><path d="M8 5v3l2 1.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>; }
function IcoList()  { return <svg width="15" height="15" fill="none" viewBox="0 0 16 16"><path d="M3 4h10M3 8h10M3 12h6" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/></svg>; }
function IcoDoc()   { return <svg width="15" height="15" fill="none" viewBox="0 0 16 16"><path d="M9.5 1.5H4a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V6l-3.5-4.5Z" stroke="currentColor" strokeWidth="1.3"/><path d="M9.5 1.5V6H13M5 9h6M5 11.5h4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>; }
function IcoUsers() { return <svg width="15" height="15" fill="none" viewBox="0 0 16 16"><circle cx="6" cy="5" r="2.3" stroke="currentColor" strokeWidth="1.3"/><path d="M1.5 13.5c0-2.485 2.015-4.5 4.5-4.5s4.5 2.015 4.5 4.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><path d="M10.5 3.5a2 2 0 1 1 0 4M14.5 13.5c0-1.934-1.343-3.563-3-4.128" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>; }
function IcoLogout(){ return <svg width="13" height="13" fill="none" viewBox="0 0 16 16"><path d="M6 2H3a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3M10.5 5.5 13 8l-2.5 2.5M13 8H6" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>; }
function IcoAdmin() { return <svg width="13" height="13" fill="none" viewBox="0 0 16 16"><path d="M8 1l1.5 3.5 3.5.5-2.5 2.5.5 3.5L8 9.5 5 11l.5-3.5L3 5l3.5-.5L8 1z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round"/></svg>; }
