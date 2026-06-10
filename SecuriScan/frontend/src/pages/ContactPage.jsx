import { useState } from "react";
import { PublicNav } from "../components/PublicNav";

export function ContactPage({ navigate, user }) {
  const [form,    setForm]    = useState({ name:"", email:"", subject:"", message:"" });
  const [sent,    setSent]    = useState(false);

  function handleSubmit(e) {
    e.preventDefault();
    // Static form — show confirmation (no backend)
    setSent(true);
  }

  return (
    <div style={{ background:"var(--void)", minHeight:"100vh", color:"var(--text)" }}>
      <PublicNav navigate={navigate} user={user} activePath="/contact" />

      <section style={{ padding:"72px 40px 40px", maxWidth:"700px", margin:"0 auto" }}>
        <div style={{ fontFamily:"var(--font-hd)", fontSize:"11px", letterSpacing:"2px", textTransform:"uppercase", color:"var(--blue)", marginBottom:"14px" }}>
          Get in Touch
        </div>
        <h1 style={{ fontFamily:"var(--font-hd)", fontSize:"38px", fontWeight:700, marginBottom:"14px" }}>
          Contact SecuriScan
        </h1>
        <p style={{ fontSize:"14px", color:"var(--dim)", lineHeight:1.6, marginBottom:"40px" }}>
          For access requests, technical questions, or enterprise licensing inquiries.
          Our security team responds within one business day.
        </p>

        {/* Contact info */}
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"14px", marginBottom:"40px" }}>
          {[
            { label:"Email",    value:"contact@securiscan.io",      icon:"✉" },
            { label:"Platform", value:"securiscan.io",              icon:"⬡" },
            { label:"Support",  value:"24h response time",          icon:"◎" },
            { label:"Security", value:"Responsible disclosure accepted", icon:"⬡" },
          ].map(({ label, value, icon }) => (
            <div key={label} style={{
              background:"var(--surface)", border:"1px solid var(--line)",
              borderRadius:"var(--r-md)", padding:"16px 18px",
              display:"flex", gap:"12px", alignItems:"flex-start",
            }}>
              <span style={{ color:"var(--blue)", fontSize:"16px", flexShrink:0, marginTop:"1px" }}>{icon}</span>
              <div>
                <div style={{ fontFamily:"var(--font-hd)", fontSize:"10px", letterSpacing:"1px", textTransform:"uppercase", color:"var(--fade)", marginBottom:"3px" }}>{label}</div>
                <div style={{ fontSize:"13px", color:"var(--text)" }}>{value}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Contact form */}
        {sent ? (
          <div style={{
            background:"var(--low-bg)", border:"1px solid rgba(34,197,94,.2)",
            borderRadius:"var(--r-md)", padding:"28px", textAlign:"center",
          }}>
            <div style={{ fontSize:"28px", marginBottom:"12px" }}>✓</div>
            <div style={{ fontFamily:"var(--font-hd)", fontSize:"16px", fontWeight:600, color:"var(--low)", marginBottom:"8px" }}>
              Message Sent
            </div>
            <div style={{ fontSize:"13px", color:"var(--dim)" }}>
              We'll respond to {form.email} within one business day.
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display:"flex", flexDirection:"column", gap:"14px" }}>
            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"14px" }}>
              <div className="ss-field">
                <label className="ss-label">Full Name</label>
                <input className="ss-input" value={form.name} onChange={e => setForm(f=>({...f,name:e.target.value}))} placeholder="Your full name" required />
              </div>
              <div className="ss-field">
                <label className="ss-label">Email Address</label>
                <input className="ss-input" type="email" value={form.email} onChange={e => setForm(f=>({...f,email:e.target.value}))} placeholder="you@organization.com" required />
              </div>
            </div>
            <div className="ss-field">
              <label className="ss-label">Subject</label>
              <select className="ss-input" value={form.subject} onChange={e => setForm(f=>({...f,subject:e.target.value}))} required>
                <option value="">Select a subject…</option>
                <option value="access">Platform Access Request</option>
                <option value="technical">Technical Question</option>
                <option value="enterprise">Enterprise Licensing</option>
                <option value="security">Security / Responsible Disclosure</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div className="ss-field">
              <label className="ss-label">Message</label>
              <textarea
                className="ss-input"
                value={form.message}
                onChange={e => setForm(f=>({...f,message:e.target.value}))}
                placeholder="Describe your request or question…"
                rows={5}
                style={{ resize:"vertical", minHeight:"120px" }}
                required
              />
            </div>
            <button type="submit" className="ss-btn ss-btn-primary ss-btn-lg" style={{ justifyContent:"center" }}>
              Send Message
            </button>
          </form>
        )}
      </section>

      {/* Footer */}
      <footer style={{ borderTop:"1px solid var(--line)", padding:"24px 40px", marginTop:"60px", display:"flex", justifyContent:"space-between", alignItems:"center", fontSize:"12px", color:"var(--fade)" }}>
        <div style={{ fontFamily:"var(--font-hd)", fontWeight:600, letterSpacing:"1px" }}>SECURI<span style={{color:"var(--blue)"}}>SCAN</span></div>
        <div style={{ display:"flex", gap:"20px" }}>
          <button onClick={() => navigate("/")}     style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>Home</button>
          <button onClick={() => navigate("/about")}style={{ background:"none", border:"none", color:"var(--fade)", cursor:"pointer", fontSize:"12px" }}>About</button>
        </div>
        <div>SecuriScan © 2026</div>
      </footer>
    </div>
  );
}
