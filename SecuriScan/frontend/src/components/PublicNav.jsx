export function PublicNav({ navigate, user, activePath }) {
  const links = [
    { path:"/",       label:"Home"    },
    { path:"/about",  label:"About"   },
    { path:"/contact",label:"Contact" },
  ];

  return (
    <nav style={{
      position:"sticky", top:0, zIndex:100,
      background:"rgba(6,8,16,.92)",
      backdropFilter:"blur(12px)",
      borderBottom:"1px solid var(--line)",
      padding:"0 40px",
      display:"flex", alignItems:"center", justifyContent:"space-between",
      height:"56px",
    }}>
      <button onClick={() => navigate("/")} style={{
        background:"none", border:"none", cursor:"pointer", padding:0,
        fontFamily:"var(--font-hd)", fontSize:"18px", fontWeight:700,
        letterSpacing:"1.8px", color:"var(--text)",
      }}>
        SECURI<span style={{ color:"var(--blue)" }}>SCAN</span>
      </button>

      <div style={{ display:"flex", alignItems:"center", gap:"4px" }}>
        {links.map(({ path, label }) => {
          const active = activePath === path;
          return (
            <button key={path} onClick={() => navigate(path)} style={{
              border:"none", cursor:"pointer",
              padding:"6px 14px", borderRadius:"var(--r-sm)",
              fontSize:"13px", fontWeight: active ? 500 : 400,
              color:       active ? "var(--text)"   : "var(--dim)",
              background:  active ? "var(--raised)" : "transparent",
              transition:"all .12s",
            }}
            onMouseEnter={e => { if(!active) { e.currentTarget.style.color="var(--text)"; e.currentTarget.style.background="var(--raised)"; } }}
            onMouseLeave={e => { if(!active) { e.currentTarget.style.color="var(--dim)";  e.currentTarget.style.background="transparent"; } }}>
              {label}
            </button>
          );
        })}

        <div style={{ width:"1px", height:"18px", background:"var(--wire)", margin:"0 8px" }} />

        {user ? (
          <button onClick={() => navigate("/app")} className="ss-btn ss-btn-primary ss-btn-sm">
            Open App
          </button>
        ) : (
          <button onClick={() => navigate("/login")} className="ss-btn ss-btn-primary ss-btn-sm">
            Sign In
          </button>
        )}
      </div>
    </nav>
  );
}
