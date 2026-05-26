import { useState, useEffect, useRef } from "react";
import { getScans, getFindings, getScan, toggleFalsePositive } from "../utils/api";
import { Badge, CvssChip, OwaspTag, StatusDot, Tag } from "../components/Badge";
import { Spinner } from "../components/Spinner";

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", {
    day:"2-digit", month:"short", year:"numeric"
  });
}

export function ResultsPage({ token, activeScan, setActiveScan }) {
  const [scans,      setScans]      = useState([]);
  const [scanId,     setScanId]     = useState(activeScan || "");
  const [findings,   setFindings]   = useState([]);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");
  const [sevFilter,  setSevFilter]  = useState("All");
  const [showFp,     setShowFp]     = useState(false);  // show false positives
  const [search,     setSearch]     = useState("");
  const [selected,   setSelected]   = useState(null);
  const [liveStatus, setLiveStatus] = useState(null);   // progress when running
  const pollRef = useRef(null);

  // Load scan list
  useEffect(() => {
    getScans(token).then(s => {
      const sorted = [...s].sort((a,b) =>
        (a.target_url||"").localeCompare(b.target_url||"")
      );
      setScans(sorted);
      if (!scanId) {
        const first = sorted.find(x => x.status === "complete") || sorted[0];
        if (first) setScanId(first.id);
      }
    }).catch(() => {});
  }, [token]);

  // Load findings when scan changes
  useEffect(() => {
    if (!scanId) return;
    setLoading(true); setFindings([]); setSelected(null); setError("");
    getFindings(scanId, token)
      .then(setFindings)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [scanId, token]);

  // Poll progress if scan is running
  useEffect(() => {
    const current = scans.find(s => s.id === scanId);
    if (!current || current.status !== "running") {
      setLiveStatus(null);
      clearInterval(pollRef.current);
      return;
    }
    setLiveStatus({ progress: current.progress || 0, status: "running" });
    pollRef.current = setInterval(async () => {
      try {
        const s = await getScan(scanId, token);
        setLiveStatus({ progress: s.progress || 0, status: s.status });
        if (s.status === "complete") {
          clearInterval(pollRef.current);
          // Reload findings once complete
          getFindings(scanId, token).then(setFindings).catch(() => {});
          // Update scan in list
          setScans(prev => prev.map(x =>
            x.id === scanId ? { ...x, status: "complete", progress: 100 } : x
          ));
        }
        if (s.status === "error") {
          clearInterval(pollRef.current);
        }
      } catch(_) {}
    }, 3000);
    return () => clearInterval(pollRef.current);
  }, [scanId, scans, token]);

  function changeScan(id) { setScanId(id); setActiveScan(id); }

  async function handleToggleFp(f) {
    const newVal = !f.is_false_positive;
    try {
      await toggleFalsePositive(f.id, newVal, token);
      setFindings(prev => prev.map(x =>
        x.id === f.id ? { ...x, is_false_positive: newVal } : x
      ));
      if (selected?.id === f.id) setSelected(s => ({ ...s, is_false_positive: newVal }));
    } catch (err) {
      setError(err.message);
    }
  }

  const currentScan = scans.find(s => s.id === scanId);
  const counts = { Critical:0, High:0, Medium:0, Low:0 };
  findings.filter(f => !f.is_false_positive).forEach(f => {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  });
  const fpCount = findings.filter(f => f.is_false_positive).length;

  const filtered = findings.filter(f => {
    if (!showFp && f.is_false_positive) return false;
    if (sevFilter !== "All" && f.severity !== sevFilter) return false;
    if (search && !f.title.toLowerCase().includes(search.toLowerCase()) &&
        !(f.endpoint||"").toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="ss-page-header">
        <div>
          <div className="ss-breadcrumb">Scan · Findings</div>
          <div className="ss-h1">Results</div>
        </div>
        {!loading && findings.length > 0 && (
          <span style={{ fontSize:"12px", color:"var(--dim)" }}>
            {findings.filter(f => !f.is_false_positive).length} confirmed
            {fpCount > 0 && ` · ${fpCount} false positive`}
          </span>
        )}
      </div>

      {/* Scan selector */}
      <div className="ss-card ss-mb-4" style={{ padding:"11px 16px" }}>
        <div className="ss-flex ss-center ss-gap-3">
          <span className="ss-label" style={{ whiteSpace:"nowrap" }}>Scan</span>
          <select
            className="ss-input"
            style={{ flex:1, maxWidth:"520px" }}
            value={scanId}
            onChange={e => changeScan(e.target.value)}
          >
            {scans.map(s => (
              <option key={s.id} value={s.id}>
                {s.target_name && s.target_name !== s.target_url
                  ? `[${s.target_name}]  ` : ""}
                {s.target_url}  —  {fmtDate(s.created_at)}  [{s.status}]
              </option>
            ))}
          </select>
          {currentScan && <StatusDot status={liveStatus?.status || currentScan.status} />}
        </div>

        {/* Live progress bar for running scans */}
        {liveStatus && liveStatus.status === "running" && (
          <div style={{ marginTop:"10px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:"5px" }}>
              <span style={{ fontSize:"11px", color:"var(--cyan)" }}>
                Scan in progress — findings will appear as phases complete
              </span>
              <span style={{ fontFamily:"var(--font-hd)", fontSize:"13px", fontWeight:700, color:"var(--text)" }}>
                {liveStatus.progress}%
              </span>
            </div>
            <div className="ss-progress-track" style={{ height:"4px" }}>
              <div className="ss-progress-fill" style={{ width:`${liveStatus.progress}%` }} />
            </div>
          </div>
        )}

        {currentScan?.status === "error" && (
          <div className="ss-notice ss-notice-warn" style={{ marginTop:"10px" }}>
            Scan ended with error — may have partial findings. Select a completed scan for full results.
          </div>
        )}
      </div>

      {/* Filter bar */}
      {findings.length > 0 && (
        <div className="ss-flex ss-center ss-gap-2 ss-mb-4" style={{ flexWrap:"wrap" }}>
          {["All","Critical","High","Medium","Low"].map(s => {
            const cnt = s === "All"
              ? findings.filter(f => !f.is_false_positive).length
              : counts[s];
            const on = sevFilter === s;
            return (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding:"4px 11px", borderRadius:"var(--r-sm)",
                border:`1px solid ${on?"var(--blue)":"var(--wire)"}`,
                background: on?"rgba(59,130,246,.11)":"var(--surface)",
                color: on?"var(--blue)":"var(--dim)",
                fontSize:"12px", cursor:"pointer", fontFamily:"var(--font-hd)",
                display:"flex", alignItems:"center", gap:"5px",
              }}>
                <span>{s}</span>
                <span style={{
                  background: on?"rgba(59,130,246,.2)":"var(--raised)",
                  padding:"1px 5px", borderRadius:"9px", fontSize:"11px", fontWeight:700,
                }}>{cnt}</span>
              </button>
            );
          })}
          {fpCount > 0 && (
            <button onClick={() => setShowFp(v => !v)} style={{
              padding:"4px 11px", borderRadius:"var(--r-sm)",
              border:`1px solid ${showFp?"var(--med)":"var(--wire)"}`,
              background: showFp?"rgba(245,158,11,.1)":"var(--surface)",
              color: showFp?"var(--med)":"var(--fade)",
              fontSize:"12px", cursor:"pointer", fontFamily:"var(--font-hd)",
            }}>
              {showFp ? "Hide" : "Show"} false positives ({fpCount})
            </button>
          )}
          <input
            className="ss-input"
            style={{ marginLeft:"auto", width:"200px" }}
            placeholder="Search…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      )}

      {error && <div className="ss-notice ss-notice-err ss-mb-4">{error}</div>}

      {/* Findings table + detail panel */}
      <div style={{
        display:"grid",
        gridTemplateColumns: selected ? "1fr 400px" : "1fr",
        gap:"14px", alignItems:"start",
      }}>
        <div className="ss-card-bare">
          {loading ? (
            <div className="ss-empty"><Spinner size={22}/><p>Loading findings…</p></div>
          ) : filtered.length === 0 ? (
            <div className="ss-empty">
              <div style={{ fontSize:"28px", opacity:.3 }}>◎</div>
              {findings.length === 0 ? (
                <>
                  <p>No findings for this scan.</p>
                  <p style={{ fontSize:"11px" }}>
                    {currentScan?.status === "error"
                      ? "Scan ended with error — try a completed scan."
                      : currentScan?.status === "running"
                      ? "Scan still running — findings will appear here as phases complete."
                      : "Scanner found nothing reportable."}
                  </p>
                </>
              ) : (
                <p>No findings match the current filter.</p>
              )}
            </div>
          ) : (
            <table className="ss-table">
              <thead>
                <tr>
                  <th style={{ width:42 }}>CVSS</th>
                  <th>Title</th>
                  <th>OWASP</th>
                  <th>Endpoint</th>
                  <th>Tool</th>
                  <th style={{ width:36 }} title="False positive">FP</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(f => (
                  <tr
                    key={f.id}
                    className={selected?.id === f.id ? "ss-row-active" : ""}
                    onClick={() => setSelected(selected?.id === f.id ? null : f)}
                    style={{ opacity: f.is_false_positive ? .45 : 1 }}
                  >
                    <td><CvssChip score={f.cvss_score} /></td>
                    <td>
                      <div className="ss-flex ss-center ss-gap-2">
                        <Badge severity={f.severity} />
                        <span style={{
                          fontSize:"13px",
                          textDecoration: f.is_false_positive ? "line-through" : "none",
                          color: f.is_false_positive ? "var(--fade)" : "var(--text)",
                        }}>
                          {f.title}
                        </span>
                      </div>
                    </td>
                    <td><OwaspTag id={f.owasp_id} label={f.owasp_label} /></td>
                    <td>
                      <span className="ss-mono" style={{ fontSize:"11px" }}>
                        {f.endpoint
                          ? (f.endpoint.length > 42
                            ? f.endpoint.slice(0,42)+"…"
                            : f.endpoint)
                          : "—"}
                      </span>
                    </td>
                    <td><Tag>{f.tool_used || "—"}</Tag></td>
                    <td onClick={e => e.stopPropagation()}>
                      <button
                        title={f.is_false_positive ? "Mark as real finding" : "Mark as false positive"}
                        onClick={() => handleToggleFp(f)}
                        style={{
                          width:"24px", height:"24px",
                          borderRadius:"var(--r-sm)",
                          border:`1px solid ${f.is_false_positive ? "var(--med)" : "var(--wire)"}`,
                          background: f.is_false_positive ? "rgba(245,158,11,.12)" : "transparent",
                          color: f.is_false_positive ? "var(--med)" : "var(--fade)",
                          cursor:"pointer", fontSize:"13px",
                          display:"flex", alignItems:"center", justifyContent:"center",
                        }}
                      >
                        {f.is_false_positive ? "✓" : "?"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Detail panel */}
        {selected && (
          <div className="ss-card" style={{ position:"sticky", top:"24px" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:"14px" }}>
              <div className="ss-flex ss-gap-2 ss-center">
                <Badge severity={selected.severity} />
                {selected.is_false_positive && (
                  <span style={{
                    fontSize:"10px", fontFamily:"var(--font-hd)", letterSpacing:".4px",
                    textTransform:"uppercase", color:"var(--med)",
                    background:"rgba(245,158,11,.1)", border:"1px solid rgba(245,158,11,.22)",
                    padding:"1px 6px", borderRadius:"var(--r-xs)",
                  }}>
                    False Positive
                  </span>
                )}
              </div>
              <button
                onClick={() => setSelected(null)}
                style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"20px", lineHeight:1 }}
              >×</button>
            </div>

            <div style={{ fontFamily:"var(--font-hd)", fontSize:"15px", fontWeight:600, marginBottom:"14px", lineHeight:1.3 }}>
              {selected.title}
            </div>

            {/* Meta grid */}
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px", marginBottom:"14px" }}>
              {[
                { l:"CVSS",       v:<CvssChip score={selected.cvss_score}/> },
                { l:"OWASP",      v:<OwaspTag id={selected.owasp_id} label={selected.owasp_label}/> },
                { l:"Tool",       v:<Tag>{selected.tool_used||"—"}</Tag> },
                { l:"Confidence", v:<span style={{ fontSize:"12px", color:selected.confidence==="confirmed"?"var(--low)":"var(--dim)" }}>{selected.confidence||"—"}</span> },
              ].map(({l,v}) => (
                <div key={l} style={{ background:"var(--raised)", padding:"7px 9px", borderRadius:"var(--r-sm)" }}>
                  <div className="ss-label" style={{ marginBottom:"3px" }}>{l}</div>{v}
                </div>
              ))}
            </div>

            {selected.cvss_vector && (
              <div style={{ marginBottom:"12px" }}>
                <div className="ss-label" style={{ marginBottom:"4px" }}>CVSS Vector</div>
                <div className="ss-code" style={{ padding:"7px 9px", fontSize:"10.5px" }}>{selected.cvss_vector}</div>
              </div>
            )}
            {selected.endpoint && (
              <div style={{ marginBottom:"12px" }}>
                <div className="ss-label" style={{ marginBottom:"4px" }}>Endpoint</div>
                <div className="ss-code" style={{ padding:"7px 9px", fontSize:"11px" }}>{selected.endpoint}</div>
              </div>
            )}
            <div style={{ marginBottom:"12px" }}>
              <div className="ss-label" style={{ marginBottom:"4px" }}>Description</div>
              <div style={{ fontSize:"12px", color:"var(--dim)", lineHeight:1.6 }}>{selected.description}</div>
            </div>
            {selected.evidence && (
              <div style={{ marginBottom:"12px" }}>
                <div className="ss-label" style={{ marginBottom:"4px" }}>Evidence</div>
                <div className="ss-code">{selected.evidence}</div>
              </div>
            )}
            {selected.remediation && (
              <div style={{ marginBottom:"12px" }}>
                <div className="ss-label" style={{ marginBottom:"4px" }}>Remediation</div>
                <div style={{
                  fontSize:"12px", color:"var(--dim)", lineHeight:1.6,
                  background:"var(--low-bg)", border:"1px solid rgba(34,197,94,.15)",
                  borderRadius:"var(--r-sm)", padding:"9px 11px",
                }}>
                  {selected.remediation}
                </div>
              </div>
            )}

            {/* FP toggle in detail panel */}
            <button
              onClick={() => handleToggleFp(selected)}
              className={selected.is_false_positive ? "ss-btn ss-btn-secondary ss-btn-sm" : "ss-btn ss-btn-ghost ss-btn-sm"}
              style={{ width:"100%", justifyContent:"center", marginTop:"4px" }}
            >
              {selected.is_false_positive
                ? "✓ Marked as False Positive — click to restore"
                : "Mark as False Positive"}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
