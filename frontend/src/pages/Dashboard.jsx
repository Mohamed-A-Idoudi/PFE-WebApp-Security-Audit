import { useState, useEffect } from "react";
import { getScans, deleteScan } from "../utils/api";
import { StatusDot } from "../components/Badge";
import { Spinner } from "../components/Spinner";

function fmtDate(iso) { if(!iso)return"—"; return new Date(iso).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit"}); }
function fmtDur(a,b)  { if(!a||!b)return"—"; const ms=new Date(b)-new Date(a),m=Math.floor(ms/60000),s=Math.floor((ms%60000)/1000); return m>0?`${m}m ${s}s`:`${s}s`; }

export function Dashboard({ token, setPage, setActiveScan }) {
  const [scans,   setScans]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState("");
  const [sortBy,  setSortBy]  = useState("url"); // "url" | "date" | "status"
  const [deleting,setDeleting]= useState("");

  useEffect(() => {
    getScans(token).then(setScans).catch(e=>setError(e.message)).finally(()=>setLoading(false));
  }, [token]);

  async function handleDelete(e, id) {
    e.stopPropagation(); // don't navigate to results
    if (!window.confirm("Delete this scan and all its findings?")) return;
    setDeleting(id);
    try {
      await deleteScan(id, token);
      setScans(prev => prev.filter(s => s.id !== id));
    } catch (err) { setError(err.message); }
    finally { setDeleting(""); }
  }

  function openScan(id) { setActiveScan(id); setPage("results"); }

  const sorted = [...scans].sort((a, b) => {
    if (sortBy === "url")    return (a.target_url||"").localeCompare(b.target_url||"");
    if (sortBy === "status") return (a.status||"").localeCompare(b.status||"");
    return new Date(b.created_at) - new Date(a.created_at); // date desc
  });

  const totals = { Critical:0, High:0, Medium:0, Low:0 };
  scans.forEach(s => { if(s.finding_counts) Object.keys(totals).forEach(k=>{ totals[k]+=s.finding_counts[k]||0; }); });
  const total = Object.values(totals).reduce((a,b)=>a+b,0);

  const SortBtn = ({ field, label }) => (
    <button onClick={() => setSortBy(field)} style={{
      padding:"3px 8px", borderRadius:"var(--r-sm)", fontSize:"11px", cursor:"pointer",
      background: sortBy===field?"rgba(59,130,246,.15)":"transparent",
      color: sortBy===field?"var(--blue)":"var(--fade)",
      border: `1px solid ${sortBy===field?"var(--blue)":"var(--wire)"}`,
      fontFamily:"var(--font-hd)", letterSpacing:".4px",
    }}>{label}</button>
  );

  return (
    <div>
      <div className="ss-page-header">
        <div><div className="ss-breadcrumb">Overview</div><div className="ss-h1">Dashboard</div></div>
        <button className="ss-btn ss-btn-primary" onClick={()=>setPage("scan")}>
          <svg width="13" height="13" fill="none" viewBox="0 0 16 16"><path d="M8 2v12M2 8h12" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/></svg>
          New Scan
        </button>
      </div>

      {error && <div className="ss-notice ss-notice-err ss-mb-4">{error}</div>}

      <div className="ss-stats">
        {[["Critical","crit"],["High","high"],["Medium","med"],["Low","low"]].map(([l,c])=>(
          <div key={l} className={`ss-stat ${c}`}>
            <div className="ss-stat-num">{loading?"—":totals[l]}</div>
            <div className="ss-stat-lbl">{l}</div>
          </div>
        ))}
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 264px", gap:"14px" }}>

        {/* Scan table */}
        <div className="ss-card-bare">
          <div style={{ padding:"11px 16px", borderBottom:"1px solid var(--line)", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
            <div className="ss-flex ss-center ss-gap-2">
              <span className="ss-h3">Scan History</span>
              <span style={{fontSize:"11px",color:"var(--fade)"}}>{scans.length}</span>
            </div>
            <div className="ss-flex ss-gap-2">
              <span style={{fontSize:"11px",color:"var(--fade)",alignSelf:"center"}}>Sort:</span>
              <SortBtn field="url"    label="URL"    />
              <SortBtn field="date"   label="Date"   />
              <SortBtn field="status" label="Status" />
            </div>
          </div>

          {loading ? (
            <div className="ss-empty"><Spinner size={22}/><p>Loading…</p></div>
          ) : sorted.length===0 ? (
            <div className="ss-empty">
              <p>No scans yet.</p>
              <button className="ss-btn ss-btn-primary ss-btn-sm ss-mt-2" onClick={()=>setPage("scan")}>Run first scan</button>
            </div>
          ) : (
            <table className="ss-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Duration</th>
                  <th>Started</th>
                  <th style={{width:64}}></th>
                </tr>
              </thead>
              <tbody>
                {sorted.map(s => (
                  <tr key={s.id} onClick={()=>openScan(s.id)}>
                    <td>
                      {s.target_name && s.target_name !== s.target_url && (
                        <div style={{fontSize:"13px",fontWeight:500,color:"var(--text)",marginBottom:"2px"}}>{s.target_name}</div>
                      )}
                      <div style={{fontFamily:"var(--font-mono)",fontSize:"11.5px",color:s.target_name&&s.target_name!==s.target_url?"var(--dim)":"var(--text)"}}>{s.target_url}</div>
                      <div style={{fontSize:"11px",color:"var(--fade)",marginTop:"2px"}}>{s.scan_type} · {s.scan_speed}</div>
                    </td>
                    <td><StatusDot status={s.status}/></td>
                    <td>
                      {s.finding_counts ? (
                        <div className="ss-flex ss-gap-2">
                          {s.finding_counts.Critical>0&&<span style={{color:"var(--crit)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.Critical}C</span>}
                          {s.finding_counts.High>0&&<span style={{color:"var(--high)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.High}H</span>}
                          {s.finding_counts.Medium>0&&<span style={{color:"var(--med)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.Medium}M</span>}
                          {s.finding_counts.Low>0&&<span style={{color:"var(--low)",fontFamily:"var(--font-hd)",fontWeight:700,fontSize:"12px"}}>{s.finding_counts.Low}L</span>}
                        </div>
                      ) : s.finding_count > 0 ? (
                        <span style={{fontFamily:"var(--font-hd)",fontWeight:600,fontSize:"12px",color:"var(--text)"}}>{s.finding_count}</span>
                      ) : <span className="ss-mono">—</span>}
                    </td>
                    <td><span className="ss-mono">{fmtDur(s.created_at,s.completed_at)}</span></td>
                    <td><span style={{fontSize:"12px",color:"var(--dim)"}}>{fmtDate(s.created_at)}</span></td>
                    <td onClick={e=>e.stopPropagation()}>
                      <button
                        className="ss-btn ss-btn-danger ss-btn-sm"
                        onClick={e=>handleDelete(e,s.id)}
                        disabled={deleting===s.id}
                        style={{opacity: deleting===s.id?.5:1}}
                      >
                        {deleting===s.id ? <Spinner size={11} color="var(--crit)"/> : (
                          <svg width="11" height="11" fill="none" viewBox="0 0 14 14"><path d="M2 3h10M5 3V2h4v1M6 6v4M8 6v4M3 3l1 9h6l1-9" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                        )}
                        Del
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Right panel */}
        <div style={{display:"flex",flexDirection:"column",gap:"12px"}}>
          <div className="ss-card">
            <div className="ss-h3 ss-mb-3">Platform</div>
            {[["Total Scans",scans.length],["Completed",scans.filter(s=>s.status==="complete").length],["Running",scans.filter(s=>s.status==="running").length],["Total Findings",total]].map(([l,v])=>(
              <div key={l} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"7px 0",borderBottom:"1px solid var(--line)"}}>
                <span style={{fontSize:"12px",color:"var(--dim)"}}>{l}</span>
                <span style={{fontFamily:"var(--font-hd)",fontSize:"17px",fontWeight:700,color:"var(--text)"}}>{loading?"—":v}</span>
              </div>
            ))}
          </div>
          {total>0&&(
            <div className="ss-card">
              <div className="ss-h3 ss-mb-3">Risk Distribution</div>
              <div style={{height:"8px",background:"var(--line)",borderRadius:"4px",overflow:"hidden",display:"flex",marginBottom:"10px"}}>
                {[["Critical","var(--crit)"],["High","var(--high)"],["Medium","var(--med)"],["Low","var(--low)"]].map(([k,c])=>
                  totals[k]>0?<div key={k} style={{width:`${(totals[k]/total)*100}%`,background:c}}/>:null
                )}
              </div>
              {[["Crit","Critical"],["High","High"],["Med","Medium"],["Low","Low"]].map(([l,k],i)=>(
                <div key={k} style={{display:"flex",alignItems:"center",gap:"6px",fontSize:"11px",marginBottom:"3px"}}>
                  <span style={{width:"8px",height:"8px",background:["var(--crit)","var(--high)","var(--med)","var(--low)"][i],borderRadius:"2px",display:"inline-block",flexShrink:0}}/>
                  <span style={{color:"var(--dim)",flex:1}}>{l}</span>
                  <span style={{fontWeight:700,color:"var(--text)"}}>{totals[k]}</span>
                </div>
              ))}
            </div>
          )}
          <div className="ss-card">
            <div className="ss-h3 ss-mb-3">Quick Actions</div>
            <div className="ss-col ss-gap-2">
              <button className="ss-btn ss-btn-secondary ss-w-full" onClick={()=>setPage("scan")}>Launch Scan</button>
              <button className="ss-btn ss-btn-secondary ss-w-full" onClick={()=>setPage("results")}>Browse Results</button>
              <button className="ss-btn ss-btn-secondary ss-w-full" onClick={()=>setPage("report")}>Generate Report</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}