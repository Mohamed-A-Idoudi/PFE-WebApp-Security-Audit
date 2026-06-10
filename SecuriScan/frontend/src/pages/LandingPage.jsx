import { PublicNav } from "../components/PublicNav";

const FEATURES = [
  {
    icon: "⬡",
    title: "15-Phase Pipeline",
    desc: "From passive OSINT through active exploitation testing — every phase automated and documented.",
  },
  {
    icon: "⬡",
    title: "12 Integrated Tools",
    desc: "nmap, Nikto, SQLmap, Nuclei, dalfox, ffuf, testssl.sh, Katana, WhatWeb, theHarvester, Hydra, OSV API.",
  },
  {
    icon: "⬡",
    title: "OWASP Top 10:2025",
    desc: "Every finding mapped to the OWASP Top 10:2025 taxonomy with MITRE CWE resolution.",
  },
  {
    icon: "⬡",
    title: "CVSS v3.1 Scoring",
    desc: "Accurate severity scoring using the industry standard CVSS v3.1 from the official RedHat library.",
  },
  {
    icon: "⬡",
    title: "Professional PDF Reports",
    desc: "Executive summary, risk matrix, evidence, and remediation — ready to deliver to stakeholders.",
  },
  {
    icon: "⬡",
    title: "Stealth Mode",
    desc: "All scanner traffic routed through Tor with randomized timing, headers, and low request rates.",
  },
];

const METHODOLOGY = [
  "NIST SP 800-115", "OWASP WSTG v4.2",
  "OWASP Top 10:2025", "CVSS v3.1",
  "ASVS v4.0", "MITRE CWE",
];

const TOOLS = [
  ["nmap",       "Port scanning"],
  ["Nikto",      "Web server analysis"],
  ["SQLmap",     "SQL injection"],
  ["Nuclei",     "CVE templates"],
  ["dalfox",     "XSS detection"],
  ["ffuf",       "Directory fuzzing"],
  ["testssl.sh", "TLS analysis"],
  ["Katana",     "URL crawling"],
  ["WhatWeb",    "Fingerprinting"],
  ["Hydra",      "Auth testing"],
  ["theHarvester","OSINT"],
  ["OSV API",    "CVE lookup"],
];

export function LandingPage({ navigate, user }) {
  return (
    <div style={{ background:"var(--void)", minHeight:"100vh", color:"var(--text)" }}>
      <PublicNav navigate={navigate} user={user} activePath="/" />

      {/* Hero */}
      <section style={{
        position:"relative", overflow:"hidden",
        padding:"100px 40px 80px",
        textAlign:"center",
      }}>
        {/* Background glow */}
        <div style={{
          position:"absolute", inset:0, pointerEvents:"none",
          background:"radial-gradient(ellipse 800px 500px at 50% 0%, rgba(59,130,246,.08) 0%, transparent 65%)",
        }}/>
        {/* Grid */}
        <div style={{
          position:"absolute", inset:0, pointerEvents:"none",
          backgroundImage:"repeating-linear-gradient(0deg, transparent, transparent 39px, rgba(255,255,255,.015) 40px), repeating-linear-gradient(90deg, transparent, transparent 39px, rgba(255,255,255,.015) 40px)",
        }}/>

        <div style={{ position:"relative", maxWidth:"800px", margin:"0 auto" }}>
          <div style={{
            display:"inline-flex", alignItems:"center", gap:"8px",
            padding:"4px 14px", borderRadius:"20px",
            background:"rgba(59,130,246,.08)", border:"1px solid rgba(59,130,246,.2)",
            fontSize:"11px", fontFamily:"var(--font-hd)", letterSpacing:"1px",
            textTransform:"uppercase", color:"var(--blue)",
            marginBottom:"28px",
          }}>
            <span style={{ width:"6px", height:"6px", borderRadius:"50%", background:"var(--blue)", animation:"ss-pulse 1.4s ease infinite", display:"inline-block" }}/>
            Web Application Security Platform
          </div>

          <h1 style={{
            fontFamily:"var(--font-hd)", fontSize:"clamp(48px,8vw,80px)",
            fontWeight:700, lineHeight:1.05, letterSpacing:"-1px",
            marginBottom:"20px",
          }}>
            SECURI<span style={{ color:"var(--blue)" }}>SCAN</span>
          </h1>

          <p style={{
            fontSize:"18px", color:"var(--dim)", lineHeight:1.6,
            maxWidth:"560px", margin:"0 auto 40px",
          }}>
            Automated web application penetration testing. Professional findings,
            CVSS-scored, OWASP-mapped, report-ready.
          </p>

          <div style={{ display:"flex", gap:"12px", justifyContent:"center", flexWrap:"wrap" }}>
            <button
              onClick={() => navigate(user ? "/app" : "/login")}
              className="ss-btn ss-btn-primary ss-btn-lg"
              style={{ fontSize:"15px", padding:"12px 32px" }}
            >
              {user ? "Open Platform" : "Get Started"}
              <svg width="14" height="14" fill="none" viewBox="0 0 16 16">
                <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
            <button
              onClick={() => navigate("/about")}
              className="ss-btn ss-btn-secondary ss-btn-lg"
              style={{ fontSize:"15px", padding:"12px 32px" }}
            >
              Learn More
            </button>
          </div>

          {/* Methodology badges */}
          <div style={{ display:"flex", gap:"8px", justifyContent:"center", flexWrap:"wrap", marginTop:"48px" }}>
            {METHODOLOGY.map(m => (
              <span key={m} style={{
                padding:"3px 10px", borderRadius:"var(--r-sm)",
                background:"var(--raised)", border:"1px solid var(--wire)",
                fontSize:"11px", fontFamily:"var(--font-mono)", color:"var(--dim)",
              }}>
                {m}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Stats bar */}
      <section style={{
        borderTop:"1px solid var(--line)", borderBottom:"1px solid var(--line)",
        padding:"28px 40px",
        display:"grid", gridTemplateColumns:"repeat(4, 1fr)",
        maxWidth:"900px", margin:"0 auto",
      }}>
        {[
          ["15", "Detection Phases"],
          ["12", "Security Tools"],
          ["100+", "OWASP CVE Templates"],
          ["6", "Report Sections"],
        ].map(([num, lbl]) => (
          <div key={lbl} style={{ textAlign:"center" }}>
            <div style={{ fontFamily:"var(--font-hd)", fontSize:"36px", fontWeight:700, color:"var(--blue)" }}>{num}</div>
            <div style={{ fontSize:"12px", color:"var(--dim)", marginTop:"4px" }}>{lbl}</div>
          </div>
        ))}
      </section>

      {/* Features grid */}
      <section style={{ padding:"80px 40px", maxWidth:"1100px", margin:"0 auto" }}>
        <div style={{ textAlign:"center", marginBottom:"48px" }}>
          <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--blue)", marginBottom:"12px" }}>Platform Capabilities</div>
          <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"36px", fontWeight:700 }}>
            Everything a penetration test needs
          </h2>
        </div>

        <div style={{ display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:"16px" }}>
          {FEATURES.map(({ title, desc }) => (
            <div key={title} style={{
              background:"var(--surface)", border:"1px solid var(--line)",
              borderRadius:"var(--r-md)", padding:"24px",
              transition:"border-color .15s",
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor="var(--wire)"}
            onMouseLeave={e => e.currentTarget.style.borderColor="var(--line)"}>
              <div style={{
                width:"32px", height:"32px", borderRadius:"var(--r-sm)",
                background:"rgba(59,130,246,.1)", border:"1px solid rgba(59,130,246,.2)",
                display:"flex", alignItems:"center", justifyContent:"center",
                marginBottom:"14px", color:"var(--blue)", fontSize:"16px",
              }}>
                <svg width="14" height="14" fill="none" viewBox="0 0 16 16">
                  <path d="M8 2l1.8 4.2L14 7l-3.1 3 .9 4.3L8 12.3 4.2 14.3l.9-4.3L2 7l4.2-.8L8 2z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/>
                </svg>
              </div>
              <div style={{ fontFamily:"var(--font-hd)", fontSize:"15px", fontWeight:600, marginBottom:"8px" }}>{title}</div>
              <div style={{ fontSize:"12px", color:"var(--dim)", lineHeight:1.6 }}>{desc}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Tools grid */}
      <section style={{ padding:"60px 40px", background:"var(--deep)", borderTop:"1px solid var(--line)", borderBottom:"1px solid var(--line)" }}>
        <div style={{ maxWidth:"1100px", margin:"0 auto" }}>
          <div style={{ textAlign:"center", marginBottom:"36px" }}>
            <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--fade)", marginBottom:"10px" }}>Integrated Toolchain</div>
            <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"28px", fontWeight:700 }}>12 professional-grade tools</h2>
          </div>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(6, 1fr)", gap:"10px" }}>
            {TOOLS.map(([name, role]) => (
              <div key={name} style={{
                background:"var(--surface)", border:"1px solid var(--line)",
                borderRadius:"var(--r-sm)", padding:"14px 12px", textAlign:"center",
              }}>
                <div style={{ fontFamily:"var(--font-mono)", fontSize:"12px", fontWeight:500, color:"var(--text)", marginBottom:"4px" }}>{name}</div>
                <div style={{ fontSize:"10px", color:"var(--fade)" }}>{role}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section style={{ padding:"80px 40px", maxWidth:"900px", margin:"0 auto" }}>
        <div style={{ textAlign:"center", marginBottom:"48px" }}>
          <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--blue)", marginBottom:"12px" }}>Workflow</div>
          <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"32px", fontWeight:700 }}>Three steps to a full audit</h2>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:"24px" }}>
          {[
            { n:"01", title:"Configure", desc:"Enter target URL, select scan type (Quick/Full), and choose speed (Normal/Stealth). Launch." },
            { n:"02", title:"Scan",      desc:"15 automated phases run sequentially. Monitor real-time progress as findings accumulate." },
            { n:"03", title:"Report",    desc:"Review findings by severity, mark false positives, and generate a branded PDF audit report." },
          ].map(({ n, title, desc }) => (
            <div key={n} style={{ position:"relative", paddingTop:"8px" }}>
              <div style={{
                fontFamily:"var(--font-hd)", fontSize:"48px", fontWeight:700,
                color:"var(--line)", marginBottom:"12px", lineHeight:1,
              }}>{n}</div>
              <div style={{ fontFamily:"var(--font-hd)", fontSize:"18px", fontWeight:600, marginBottom:"8px" }}>{title}</div>
              <div style={{ fontSize:"13px", color:"var(--dim)", lineHeight:1.6 }}>{desc}</div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section style={{
        padding:"80px 40px", textAlign:"center",
        borderTop:"1px solid var(--line)",
        background:"linear-gradient(to bottom, var(--void), var(--deep))",
      }}>
        <h2 style={{ fontFamily:"var(--font-hd)", fontSize:"32px", fontWeight:700, marginBottom:"16px" }}>
          Start your security audit
        </h2>
        <p style={{ fontSize:"14px", color:"var(--dim)", marginBottom:"32px", maxWidth:"440px", margin:"0 auto 32px" }}>
          Sign in to access the full platform. Run your first scan in under a minute.
        </p>
        <button
          onClick={() => navigate(user ? "/app" : "/login")}
          className="ss-btn ss-btn-primary ss-btn-lg"
          style={{ fontSize:"15px", padding:"12px 36px" }}
        >
          {user ? "Open Platform" : "Sign In to SecuriScan"}
        </button>
      </section>

      {/* Footer */}
      <footer style={{
        borderTop:"1px solid var(--line)", padding:"24px 40px",
        display:"flex", justifyContent:"space-between", alignItems:"center",
        fontSize:"12px", color:"var(--fade)",
      }}>
        <div style={{ fontFamily:"var(--font-hd)", fontWeight:600, letterSpacing:"1px" }}>
          SECURI<span style={{ color:"var(--blue)" }}>SCAN</span>
        </div>
        <div style={{ display:"flex", gap:"20px" }}>
          <button onClick={() => navigate("/about")}   style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>About</button>
          <button onClick={() => navigate("/contact")} style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>Contact</button>
          <button onClick={() => navigate("/login")}   style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>Sign In</button>
        </div>
        <div>SecuriScan © 2026</div>
      </footer>
    </div>
  );
}
