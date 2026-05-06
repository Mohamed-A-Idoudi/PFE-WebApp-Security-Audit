# CLAUDE.md — Project Context for AI Assistant

## Project
PFE Web Application Security Audit Framework
Student: Mohamed Amine IDOUDI
Organization: ADVANCIA IT SYSTEM, Tunis
Supervisor: Ramzi Ben Slimene
Period: February — August 2026

## Phase A — COMPLETE
Manual pentest against OWASP Juice Shop.
12 findings documented. Report delivered May 2026.
All exploitation evidence in: /WebApp_Pentesting/Exploitation/
Report: rapport-pentest-ADVANCIA-v2.docx

## Phase B — IN PROGRESS
Building SecuriScan: containerized vulnerability scanner.
Stack: React 19 + Python Flask + SQLite + Docker Compose.
Location: /phase-b/

## Development Environment
- Kali Linux 192.168.56.10 (attacker + development)
- Ubuntu Server 192.168.56.20 (Juice Shop target)
- Windows host: VS Code + Docker Desktop
- GitHub: https://github.com/Mohamed-A-Idoudi/PFE-WebApp-Security-Audit.git

## Key Decisions Made
- Frontend already built: React 19 + Vite in C:\Users\IDOUDI\Documents\SecuriScan
- No Tailwind yet — all inline CSS currently
- Backend not started yet
- Docker not configured yet
- Target submission: June 15-20 2026 (first session)

## Phase B File Structure
phase-b/
├── frontend/     React app
├── backend/      Flask API (app.py, models.py, requirements.txt)
├── scanner/      engine.py (nmap + nikto wrappers)
├── docs/         Architecture diagrams (.drawio + .png)
└── docker-compose.yml

## Commands Reference
# Start Juice Shop
ssh adminjs@192.168.56.20 then docker start juiceshop

# Kali internet (if lost after reboot)
sudo nmcli device connect eth0

# Frontend dev server
cd C:\Users\IDOUDI\Documents\SecuriScan && npm run dev

# Backend (once built)
cd phase-b/backend && python app.py
