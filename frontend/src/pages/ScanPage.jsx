import { useState, useEffect, useRef } from "react";
import { createScan, getScan } from "../utils/api";
import { StatusDot } from "../components/Badge";
import { Spinner } from "../components/Spinner";

const PHASES = [
  {pct:4,  label:"Phase 0",  desc:"Connectivity check"},
  {pct:7,  label:"Phase 0b", desc:"Passive OSINT"},
  {pct:10, label:"Phase 0c", desc:"Technology fingerprinting"},
  {pct:13, label:"Phase 0d", desc:"URL discovery (Katana)"},
  {pct:17, label:"Phase 1",  desc:"Headers + EOL detection"},
  {pct:22, label:"Phase 1",  desc:"TLS analysis (testssl)"},
  {pct:27, label:"Phase 1b", desc:"JS library CVE scan"},
  {pct:36, label:"Phase 2",  desc:"Port scan (nmap)"},
  {pct:46, label:"Phase 3",  desc:"Directory exposure (ffuf)"},
  {pct:54, label:"Phase 3b", desc:"XSS detection (dalfox)"},
  {pct:62, label:"Phase 4",  desc:"Authentication testing"},
  {pct:73, label:"Phase 5",  desc:"Web server scan (Nikto)"},
  {pct:86, label:"Phase 6",  desc:"Template scan (Nuclei)"},
  {pct:96, label:"Phase 7",  desc:"SQL injection (SQLmap)"},
  {pct:100,label:"Complete", desc:"Scan finished"},
];
function activePhase(p) { for(let i=PHASES.length-1;i>=0;i--) if(p>=PHASES[i].pct) return PHASES[i]; return PHASES[0]; }

export function ScanPage({ token, setPage, setActiveScan }) {
  const [url,      setUrl]      = useState("");
  const [name,     setName]     = useState("");
  const [scanType] = useState("full");
  const [speed,    setSpeed]    = useState("normal");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [scan,     setScan]     = useState(null);
  const [scanId,   setScanId]   = useState(null);
  const timer = useRef(null);

  // Auto-fill name from URL
  function handleUrlChange(val) {
    setUrl(val);
    if (!name) {
      try { setName(new URL(val).hostname); } catch(_) {}
    }
  }

  useEffect(() => {
    if (!scanId) return;
    timer.current = setInterval(async () => {
      try {
        const s = await getScan(scanId, token);
        setScan(s);
        if (s.status==="complete"||s.status==="error") {
          clearInterval(timer.current);
          if (s.status==="complete") { setActiveScan(scanId); setTimeout(()=>setPage("results"),1000); }
        }
      } catch(_) {}
    }, 1500);
    return () => clearInterval(timer.current);
  }, [scanId]);

  async function handleLaunch(e) {
    e.preventDefault();
    setLoading(true); setError("");
    try {
      const data = await createScan({
        target_url: url.trim(),
        name:       name.trim() || url.trim(),
        scan_type:  scanType,
        scan_speed: speed,
      }, token);
      setScanId(data.scan_id);
      setScan({ status:"running", progress:0, target_url:url.trim(), target_name:name.trim()||url.trim() });
    } catch(err) { setError(err.message); }
    finally { setLoading(false); }
  }

  // ── Active scan view ───────────────────────────────────────────
  if (scan && scanId) {
    const pct=scan.progress||0, phase=activePhase(pct);
    return (
      <div>
        <div className="ss-page-header">
          <div><div className="ss-breadcrumb">Scan · Active</div><div className="ss-h1">Scan in Progress</div></div>
        </div>
        <div style={{maxWidth:"640px",display:"flex",flexDirection:"column",gap:"14px"}}>
          <div className="ss-card" style={{display:"flex",justifyContent:"space-between"}}>
            <div>
              <div className="ss-label ss-mb-2">Target</div>
              {scan.target_name && scan.target_name !== scan.target_url && (
                <div style={{fontSize:"13px",fontWeight:500,color:"var(--text)",marginBottom:"2px"}}>{scan.target_name}</div>
              )}
              <div className="ss-mono">{scan.target_url}</div>
            </div>
            <div style={{textAlign:"right"}}>
              <div className="ss-label ss-mb-2">Mode</div>
              <div style={{fontSize:"12px",color:"var(--dim)"}}>{speed}</div>
            </div>
          </div>
          <div className="ss-card">
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"12px"}}>
              <StatusDot status={scan.status==="complete"?"complete":scan.status==="error"?"error":"running"}/>
              <span style={{fontFamily:"var(--font-hd)",fontSize:"22px",fontWeight:700}}>{pct}%</span>
            </div>
            <div className="ss-progress-track" style={{height:"5px",marginBottom:"16px"}}>
              <div className={`ss-progress-fill ${scan.status==="complete"?"done":scan.status==="error"?"error":""}`} style={{width:`${pct}%`}}/>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:"4px"}}>
              {PHASES.map((p,i) => {
                const done=pct>p.pct, cur=phase?.pct===p.pct&&scan.status==="running", future=pct<p.pct&&!cur;
                return (
                  <div key={i} className={`ss-phase-row ${cur?"active":""}`} style={{opacity:future?.3:1}}>
                    <span className="ss-phase-indicator" style={{border:done?"none":cur?"2px solid var(--blue)":"1px solid var(--wire)",background:done?"var(--low)":cur?"var(--blue)":"transparent"}}>
                      {done&&<svg width="9" height="9" fill="none" viewBox="0 0 9 9"><path d="M1.5 4.5l2 2L7.5 2" stroke="#fff" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>}
                      {cur&&<Spinner size={9} color="#fff"/>}
                    </span>
                    <span style={{fontFamily:"var(--font-hd)",fontSize:"10px",color:"var(--fade)",minWidth:"62px"}}>{p.label}</span>
                    <span style={{fontSize:"12px",color:cur?"var(--text)":"var(--dim)"}}>{p.desc}</span>
                  </div>
                );
              })}
            </div>
          </div>
          {scan.status==="error"&&<div className="ss-notice ss-notice-err">Scan failed. Check scanner container logs.</div>}
        </div>
      </div>
    );
  }

  // ── Launch form ────────────────────────────────────────────────
  return (
    <div>
      <div className="ss-page-header">
        <div><div className="ss-breadcrumb">Scan · Configure</div><div className="ss-h1">New Security Scan</div></div>
      </div>
      <div style={{maxWidth:"540px"}}>
        <form onSubmit={handleLaunch} style={{display:"flex",flexDirection:"column",gap:"16px"}}>
          <div className="ss-card">
            <div className="ss-h3" style={{marginBottom:"14px"}}>Target</div>
            <div style={{display:"flex",flexDirection:"column",gap:"12px"}}>
              <div className="ss-field">
                <label className="ss-label">Target URL <span style={{color:"var(--crit)"}}>*</span></label>
                <input className="ss-input ss-input-mono" type="url" value={url}
                  onChange={e=>handleUrlChange(e.target.value)}
                  placeholder="https://target.example.com" required/>
              </div>
              <div className="ss-field">
                <label className="ss-label">Scan Name <span style={{color:"var(--fade)",fontWeight:400,textTransform:"none",letterSpacing:0}}>— optional label for this scan</span></label>
                <input className="ss-input" type="text" value={name} onChange={e=>setName(e.target.value)}
                  placeholder="e.g. ADVANCIA Production, Juice Shop v15"/>
              </div>
            </div>
          </div>

          <div className="ss-card">
            <div className="ss-h3" style={{marginBottom:"14px"}}>Configuration</div>
            <div>
              <div className="ss-field">
                <label className="ss-label">Scan Speed</label>
                <select className="ss-input" value={speed} onChange={e=>setSpeed(e.target.value)}>
                  <option value="normal">Normal — Direct</option>
                  <option value="stealth">Stealth — Tor + slow</option>
                </select>
                <div style={{fontSize:"11px",color:"var(--fade)",marginTop:"2px"}}>{speed==="stealth"?"Tor routing · lower detection":"Faster · direct connection"}</div>
              </div>
            </div>
          </div>

          {error&&<div className="ss-notice ss-notice-err">{error}</div>}

          <button type="submit" className="ss-btn ss-btn-primary ss-btn-lg" disabled={loading||!url.trim()} style={{justifyContent:"center"}}>
            {loading?<Spinner size={15} color="#fff"/>:<svg width="14" height="14" fill="none" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.3" stroke="currentColor" strokeWidth="1.5"/><path d="M8 5v3l2 1.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>}
            {loading?"Launching…":"Launch Scan"}
          </button>
        </form>
      </div>
    </div>
  );
}