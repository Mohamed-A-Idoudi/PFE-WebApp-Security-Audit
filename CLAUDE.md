# PFE — Web Application Security Audit

## Project
Final Year Engineering Project (PFE) — ITBS / ADVANCIA IT SYSTEM.
Auditor: Mohamed Amine IDOUDI (PFE Intern).
Professional supervisor: Ramzi Ben Slimene (Technical Director, ADVANCIA).
Academic supervisor: Montassar Turki (Expert Professor, ITBS).

## Current status
Week 10 (16 April 2026). Recovery week after a productivity loss period (weeks 8–9).
Scope revised in Master Execution Plan v5.0.

## Three-part scope (revised)
- Part A — OWASP Top 10 pentest on Juice Shop. Deadline 29/05/2026.
- Part B — Enterprise Defence Bypass STUDY (research-only, no lab build). Deadline 12/06/2026.
- Part C — Containerised Security Assessment Tool (orchestrator of open-source
  scanners, web UI, findings report generator). Deadline 31/07/2026.

## Target (Part A)
OWASP Juice Shop (Node.js / Angular / SQLite) via Docker at http://192.168.56.20:3000.
Attacker host (Kali): 192.168.56.10.
Lab: isolated host-only network (VMnet1, 192.168.56.0/24).

## Project folder structure
~/Penetration-testing/
├── CLAUDE.md                      (this file)
├── pre-engagement/                (RoE, CdC, MEP — kept on Windows host for editing)
├── WebApp Pentesting/
│   ├── Information-Gathering/     (recon evidence + findings)
│   ├── Vulnerability-Assessment/
│   ├── Exploitation/
│   ├── Lateral-Movement/          (unused — Part B is research-only)
│   └── Post-Exploitation/         (unused — Part B is research-only)
├── Reporting/
├── Results/
└── pfe-public/                    (future GitHub public repo content)

## Methodology
Hybrid: NIST SP 800-115 + OWASP WSTG v4.2 + Top 10:2025 + ASVS v4.0 + CVSS v3.1.
Traceability chain per finding:
  Risk (Top 10) → Test (WSTG) → Evidence (req/resp + screenshot) → Control (ASVS) → Severity (CVSS).

## Evidence rules
- Raw tool output: preserved in Information-Gathering/recon/<tool>/
- AI-assisted summaries kept separate in Information-Gathering/recon/ai-assisted-summaries/
- Confirmed findings: Information-Gathering/findings/FINDING-NNN/
  Each finding contains:
    - finding.md (writeup in audit format)
    - command.txt (exact command run)
    - evidence-output.txt (raw tool output extract)
    - screenshot.png (if applicable)
- Git commit after every finding addition.

## Language rules
- French: deliverables to ADVANCIA (weekly reports, findings reports, pentest reports).
- English: deliverables to ITBS (PFE report, chapters, sprint reports).

## Tool policy
Tool choice is made per task, with tradeoffs presented. No default tool is assumed.
Current candidates include: Maltego (OSINT), nmap, whatweb, nikto, ffuf, Burp Suite
Community, OWASP ZAP, sqlmap (validation mode), curl, httpie, Apache Bench, slowhttptest,
nuclei. Part B research-only — no active exploitation tools needed.
Metasploit not in scope for the revised Part B.

## Tone and output preferences
- Be direct. Push back when I'm wrong. No yes-man.
- Explain WHY before HOW for technical decisions.
- One task at a time.
- Concise by default.
- No emojis unless I use them first.

## What Claude Code should NOT do
- Do NOT run recon or testing autonomously. I drive tool selection and execution.
- Do NOT generate finding content without raw tool output that I observed.
- Do NOT consult the /api/challenges endpoint of Juice Shop as a testing guide.
  WSTG walkthrough must be systematic, not answer-key guided.
- Do NOT execute code or automate tests for exploitation phase.

## What Claude Code SHOULD do
- Help Format raw tool output I captured into finding.md writeups.
- Help design and scaffold the Part C tool code (W19–W23).
- Help write CVSS vectors after I described the attack.
- Help Draft report sections from real evidence I supply.
