import { PublicNav } from "../components/PublicNav";

const CAPABILITIES = [
  {
    category: "Reconnaissance",
    items: ["Passive OSINT (theHarvester)", "Technology fingerprinting (WhatWeb)", "Full URL crawl (Katana)", "JavaScript library CVE detection"],
  },
  {
    category: "Infrastructure",
    items: ["Port and service enumeration (nmap)", "TLS/SSL configuration audit (testssl.sh)", "HTTP security header analysis", "End-of-life software detection"],
  },
  {
    category: "Application",
    items: ["Directory and file exposure (ffuf + SecLists)", "XSS detection (dalfox, 13k+ payloads)", "SQL injection testing (SQLmap)", "Authentication brute force (Hydra)"],
  },
  {
    category: "CVE & Templates",
    items: ["13,000+ Nuclei vulnerability templates", "OSV API for real-time CVE lookup", "Three-pass scan strategy (Critical → Medium → Exposure)", "OWASP CWE mapping from MITRE"],
  },
];

const STANDARDS = [
  { code:"NIST SP 800-115", name:"Technical Guide to Information Security Testing and Assessment" },
  { code:"OWASP WSTG v4.2", name:"Web Security Testing Guide, version 4.2" },
  { code:"OWASP Top 10:2025", name:"Most Critical Web Application Security Risks" },
  { code:"CVSS v3.1",        name:"Common Vulnerability Scoring System — FIRST" },
  { code:"ASVS v4.0",        name:"Application Security Verification Standard" },
  { code:"MITRE CWE",        name:"Common Weakness Enumeration — NVD" },
];

export function AboutPage({ navigate, user }) {
  return (
    <div style={{ background:"var(--void)", minHeight:"100vh", color:"var(--text)" }}>
      <PublicNav navigate={navigate} user={user} activePath="/about" />

      {/* Hero */}
      <section style={{ padding:"80px 40px 60px", maxWidth:"760px", margin:"0 auto", textAlign:"center" }}>
        <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--blue)", marginBottom:"16px" }}>
          About the Platform
        </div>
        <h1 style={{ fontFamily:"var(--font-hd)", fontSize:"42px", fontWeight:700, marginBottom:"20px", lineHeight:1.1 }}>
          What is SecuriScan?
        </h1>
        <p style={{ fontSize:"16px", color:"var(--dim)", lineHeight:1.7, marginBottom:"16px" }}>
          SecuriScan is an automated web application security assessment platform
          that consolidates 12 industry-standard penetration testing tools into a
          single, structured pipeline. It replaces hours of manual tool execution
          with a repeatable, documented, and audit-ready process.
        </p>
        <p style={{ fontSize:"15px", color:"var(--dim)", lineHeight:1.7 }}>
          Every finding is scored with CVSS v3.1, mapped to the OWASP Top 10:2025,
          and linked to its CWE identifier. The result is a professional audit report
          that communicates risk in terms that both technical teams and management
          can act on.
        </p>
      </section>

      {/* Mission */}
      <section style={{
        background:"var(--deep)", borderTop:"1px solid var(--line)", borderBottom:"1px solid var(--line)",
        padding:"60px 40px",
      }}>
        <div style={{ maxWidth:"800px", margin:"0 auto" }}>
          <div style={{
            borderLeft:"3px solid var(--blue)", paddingLeft:"24px",
          }}>
            <p style={{ fontFamily:"var(--font-hd)", fontSize:"22px", fontWeight:500, lineHeight:1.5, color:"var(--text)" }}>
              "Security testing should be systematic, reproducible, and accessible —
              not dependent on the knowledge of a single individual or the cost of
              an enterprise license."
            </p>
            <div style={{ marginTop:"16px", fontSize:"12px", color:"var(--fade)", fontFamily:"var(--font-mono)" }}>
              SecuriScan Design Philosophy
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities */}
      <section style={{ padding:"72px 40px", maxWidth:"1100px", margin:"0 auto" }}>
        <div style={{ marginBottom:"44px" }}>
          <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--fade)", marginBottom:"10px" }}>Technical Coverage</div>
          <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"30px", fontWeight:700 }}>Platform capabilities</h2>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(2,1fr)", gap:"16px" }}>
          {CAPABILITIES.map(({ category, items }) => (
            <div key={category} style={{
              background:"var(--surface)", border:"1px solid var(--line)",
              borderRadius:"var(--r-md)", padding:"22px",
            }}>
              <div style={{ fontFamily:"var(--font-hd)", fontSize:"13px", fontWeight:600, letterSpacing:".5px", textTransform:"uppercase", color:"var(--blue)", marginBottom:"14px" }}>
                {category}
              </div>
              {items.map(item => (
                <div key={item} style={{ display:"flex", gap:"8px", fontSize:"13px", color:"var(--dim)", marginBottom:"8px", lineHeight:1.4 }}>
                  <span style={{ color:"var(--blue)", flexShrink:0, marginTop:"1px" }}>›</span>
                  {item}
                </div>
              ))}
            </div>
          ))}
        </div>
      </section>

      {/* Pipeline overview */}
      <section style={{
        background:"var(--deep)", borderTop:"1px solid var(--line)", borderBottom:"1px solid var(--line)",
        padding:"60px 40px",
      }}>
        <div style={{ maxWidth:"1000px", margin:"0 auto" }}>
          <div style={{ marginBottom:"36px" }}>
            <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--fade)", marginBottom:"10px" }}>Scan Pipeline</div>
            <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"28px", fontWeight:700 }}>15 phases, fully automated</h2>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:"8px" }}>
            {[
              ["Phase 0",  "Connectivity check"],
              ["Phase 0b", "Passive OSINT"],
              ["Phase 0c", "Technology fingerprinting"],
              ["Phase 0d", "URL discovery"],
              ["Phase 1",  "HTTP headers + EOL"],
              ["Phase 1",  "TLS/SSL analysis"],
              ["Phase 1b", "JS library CVEs"],
              ["Phase 2",  "Port scanning"],
              ["Phase 3",  "Directory exposure"],
              ["Phase 3b", "XSS detection"],
              ["Phase 4",  "Auth testing"],
              ["Phase 5",  "Web server audit"],
              ["Phase 6",  "CVE templates"],
              ["Phase 7",  "SQL injection"],
              ["Complete", "Report generation"],
            ].map(([phase, desc]) => (
              <div key={desc} style={{
                display:"flex", alignItems:"center", gap:"10px",
                padding:"8px 12px", background:"var(--surface)",
                border:"1px solid var(--line)", borderRadius:"var(--r-sm)",
              }}>
                <span style={{ fontFamily:"var(--font-hd)", fontSize:"10px", color:"var(--blue)", minWidth:"60px", letterSpacing:".3px" }}>{phase}</span>
                <span style={{ fontSize:"12px", color:"var(--dim)" }}>{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Standards */}
      <section style={{ padding:"72px 40px", maxWidth:"900px", margin:"0 auto" }}>
        <div style={{ marginBottom:"36px" }}>
          <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--fade)", marginBottom:"10px" }}>Compliance & Methodology</div>
          <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"28px", fontWeight:700 }}>Built on industry standards</h2>
        </div>
        {STANDARDS.map(({ code, name }) => (
          <div key={code} style={{
            display:"flex", alignItems:"center", gap:"20px",
            padding:"14px 0", borderBottom:"1px solid var(--line)",
          }}>
            <span style={{
              fontFamily:"var(--font-mono)", fontSize:"12px", fontWeight:600,
              color:"var(--blue)", minWidth:"160px",
            }}>{code}</span>
            <span style={{ fontSize:"13px", color:"var(--dim)" }}>{name}</span>
          </div>
        ))}
      </section>

      {/* CTA */}
      <section style={{
        padding:"60px 40px", textAlign:"center",
        borderTop:"1px solid var(--line)",
      }}>
        <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"28px", fontWeight:700, marginBottom:"24px" }}>
          Ready to run your first scan?
        </h2>
        <button
          onClick={() => navigate(user ? "/app" : "/login")}
          className="ss-btn ss-btn-primary ss-btn-lg"
          style={{ fontSize:"15px", padding:"12px 32px" }}
        >
          {user ? "Open Platform" : "Sign In"}
        </button>
      </section>

      {/* Footer */}
      <footer style={{ borderTop:"1px solid var(--line)", padding:"24px 40px", display:"flex", justifyContent:"space-between", alignItems:"center", fontSize:"12px", color:"var(--fade)" }}>
        <div style={{ fontFamily:"var(--font-hd)", fontWeight:600, letterSpacing:"1px" }}>SECURI<span style={{color:"var(--blue)"}}>SCAN</span></div>
        <div style={{ display:"flex", gap:"20px" }}>
          <button onClick={() => navigate("/")}       style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>Home</button>
          <button onClick={() => navigate("/contact")}style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>Contact</button>
        </div>
        <div>SecuriScan © 2026</div>
      </footer>
    </div>
  );
}
