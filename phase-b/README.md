# SecuriScan — Automated Vulnerability Scanner
**Phase B — PFE ADVANCIA IT SYSTEM 2026**

## Overview
SecuriScan is a containerized web application vulnerability scanner
that automates OWASP Top 10:2025 detection and generates professional
audit reports.

## Architecture
- Frontend: React 19 + Vite (port 5173 dev / 80 prod)
- Backend: Python Flask REST API (port 5000)
- Scanner: nmap + nikto + custom header checks
- Database: SQLite via SQLAlchemy
- Reports: WeasyPrint PDF generation
- Deploy: Docker Compose

## Quick Start
```bash
docker compose up --build
# Open http://localhost:3000
```

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/scan | Start a new scan |
| GET | /api/status/:id | Poll scan progress |
| GET | /api/results/:id | Get findings |
| GET | /api/report/:id | Download PDF report |

## Project Structure
phase-b/
├── frontend/          # React application
├── backend/           # Flask REST API
├── scanner/           # Scanning engine
├── docs/              # Architecture diagrams
└── docker-compose.yml
