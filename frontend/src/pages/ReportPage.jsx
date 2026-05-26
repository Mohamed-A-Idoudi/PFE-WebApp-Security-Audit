import { useState, useEffect } from "react";
import { getScans, generateReport, getReportDownloadUrl } from "../utils/api";
import { Spinner } from "../components/Spinner";

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", {
    day:"2-digit", month:"short", year:"numeric",
    hour:"2-digit", minute:"2-digit"
  });
}

export function ReportPage({ token }) {
  const [scans,      setScans]      = useState([]);
  const [scanId,     setScanId]     = useState("");
  const [loading,    setLoading]    = useState(false);
  const [downloading,setDownloading]= useState(false);
  const [reportId,   setReportId]   = useState(null);
  const [error,      setError]      = useState("");

  useEffect(() => {
    getScans(token).then(s => {
      const done = [...s.filter(x => x.status === "complete")]
        .sort((a, b) => (a.target_url || "").localeCompare(b.target_url || ""));
      setScans(done);
      if (done.length > 0) setScanId(done[0].id);
    }).catch(() => {});
  }, [token]);

  async function handleGenerate() {
    if (!scanId) return;
    setLoading(true); setError(""); setReportId(null);
    try {
      const data = await generateReport(scanId, token);
      if (!data.report_id) throw new Error("No report_id in response");
      setReportId(data.report_id);
    } catch (err) {
      setError(err.message || "Report generation failed");
    } finally {
      setLoading(false);
    }
  }

  // ── Download using fetch + blob (Authorization header, not query param) ───
  async function handleDownload() {
    if (!reportId) return;
    setDownloading(true); setError("");
    try {
      // Wait up to 15s for WeasyPrint to finish rendering
      let res;
      for (let attempt = 0; attempt < 5; attempt++) {
        res = await fetch(getReportDownloadUrl(reportId), {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) break;
        if (res.status === 404) {
          // Still rendering — wait 3s and retry
          await new Promise(r => setTimeout(r, 3000));
          continue;
        }
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${res.status}`);
      }
      if (!res.ok) throw new Error("Report not ready — try again in a few seconds");

      const blob     = await res.blob();
      const url      = URL.createObjectURL(blob);
      const a        = document.createElement("a");
      a.href         = url;
      a.download     = `SecuriScan_Report_${reportId}_${scanId}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message || "Download failed");
    } finally {
      setDownloading(false);
    }
  }

  const currentScan = scans.find(s => s.id === scanId);

  return (
    <div>
      <div className="ss-page-header">
        <div>
          <div className="ss-breadcrumb">Reports · Generate</div>
          <div className="ss-h1">Audit Reports</div>
        </div>
      </div>

      <div style={{ maxWidth:"560px", display:"flex", flexDirection:"column", gap:"14px" }}>

        {/* Scan selector */}
        <div className="ss-card">
          <div className="ss-h3" style={{ marginBottom:"14px" }}>Select Completed Scan</div>
          {scans.length === 0 ? (
            <div className="ss-notice ss-notice-info">
              No completed scans available. Run a full scan first.
            </div>
          ) : (
            <>
              <div className="ss-field">
                <label className="ss-label">Scan</label>
                <select
                  className="ss-input"
                  value={scanId}
                  onChange={e => { setScanId(e.target.value); setReportId(null); setError(""); }}
                >
                  {scans.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.target_name && s.target_name !== s.target_url
                        ? `[${s.target_name}]  ` : ""}
                      {s.target_url}  —  {fmtDate(s.created_at)}
                    </option>
                  ))}
                </select>
              </div>
              {currentScan && (
                <div style={{ marginTop:"10px", fontSize:"12px", color:"var(--dim)", display:"flex", gap:"16px" }}>
                  <span>ID: <span className="ss-mono">{currentScan.id}</span></span>
                  <span>Type: {currentScan.scan_type}</span>
                  <span>Speed: {currentScan.scan_speed}</span>
                </div>
              )}
            </>
          )}
        </div>

        {/* Contents */}
        <div className="ss-card">
          <div className="ss-h3" style={{ marginBottom:"12px" }}>Report Contents</div>
          {[
            "Executive summary with risk overview",
            "Severity distribution matrix",
            "Full findings list with CVSS v3.1 scores",
            "Evidence and proof-of-concept per finding",
            "Remediation recommendations",
            "OWASP Top 10:2025 coverage mapping",
            "Branded cover page with scan metadata",
          ].map((item, i) => (
            <div key={i} style={{ display:"flex", alignItems:"flex-start", gap:"8px", fontSize:"12px", color:"var(--dim)", marginBottom:"6px" }}>
              <svg width="13" height="13" fill="none" viewBox="0 0 14 14" style={{ flexShrink:0, marginTop:"1px" }}>
                <circle cx="7" cy="7" r="5.8" stroke="var(--low)" strokeWidth="1"/>
                <path d="M4.5 7l1.7 1.7L9.5 5" stroke="var(--low)" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
              {item}
            </div>
          ))}
        </div>

        {error && <div className="ss-notice ss-notice-err">{error}</div>}

        {reportId && (
          <div className="ss-notice ss-notice-ok">
            Report ready — ID: <span className="ss-mono">{reportId}</span>
          </div>
        )}

        {/* Actions */}
        <div style={{ display:"flex", gap:"10px" }}>
          <button
            className="ss-btn ss-btn-primary ss-btn-lg"
            onClick={handleGenerate}
            disabled={!scanId || loading}
            style={{ flex:1, justifyContent:"center" }}
          >
            {loading && <Spinner size={15} color="#fff" />}
            {loading ? "Generating…" : "Generate PDF Report"}
          </button>

          {reportId && (
            <button
              className="ss-btn ss-btn-secondary ss-btn-lg"
              onClick={handleDownload}
              disabled={downloading}
            >
              {downloading
                ? <><Spinner size={15} />&nbsp;Downloading…</>
                : <>
                    <svg width="13" height="13" fill="none" viewBox="0 0 16 16">
                      <path d="M8 2v8m0 0-3-3m3 3 3-3M3 13h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                    Download PDF
                  </>
              }
            </button>
          )}
        </div>

      </div>
    </div>
  );
}