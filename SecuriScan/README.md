# PFE — Web Application Security Audit Framework
**ADVANCIA IT SYSTEM | Mohamed Amine IDOUDI | 2026**
**Supervisor:** Ramzi Ben Slimene

---

## Project Overview
Two-phase PFE combining manual penetration testing with an automated
containerized vulnerability scanning framework.

---

## Phase A — Manual Penetration Test ✅ COMPLETE

**Target:** OWASP Juice Shop v19.2.1 (http://192.168.56.20:3000)
**Duration:** February → May 2026
**Location:** `/WebApp_Pentesting/`

### Results
- 12 confirmed findings across 9/10 OWASP Top 10:2025 categories
- Full attack chain demonstrated (reconnaissance → admin compromise)
- Critical SQLi (CVSS 9.8) with complete user database extraction
- Professional French audit report delivered

### Standards Applied
- NIST SP 800-115
- OWASP WSTG v4.2
- OWASP Top 10:2025
- OWASP ASVS v4.0
- CVSS v3.1

---

## Phase B — SecuriScan Framework 🔄 IN PROGRESS

**Duration:** May → June 2026
**Location:** `/phase-b/`
**Target submission:** June 15-20, 2026

### Description
Containerized vulnerability scanner with React frontend,
Python Flask backend, and automated PDF report generation.

### Tech Stack
| Layer | Technology | Purpose |
|-------|-----------|---------|
| Frontend | React 19 + Vite | User interface |
| Backend | Python Flask | REST API |
| Scanner | nmap + nikto | Vulnerability detection |
| Mapping | Custom Python | OWASP Top 10 classification |
| Database | SQLite + SQLAlchemy | Scan history |
| Reports | WeasyPrint | PDF generation |
| Deploy | Docker Compose | Containerization |

---

## Lab Environment
| Role | System | IP |
|------|--------|----|
| Attacker | Kali Linux 2024 | 192.168.56.10 |
| Target | Ubuntu + Docker + Juice Shop | 192.168.56.20:3000 |
| Network | VMware VMnet1 (isolated) | 192.168.56.0/24 |
