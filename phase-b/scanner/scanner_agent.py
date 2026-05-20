from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os
import re
import socket
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from sqlalchemy import create_engine, text

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://securiscan:password@db:5432/securiscan"
)
engine = create_engine(DATABASE_URL)

def now():
    return datetime.now(timezone.utc)

def update_scan_status(scan_id, status, progress):
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE scans SET status=:status, progress=:progress WHERE id=:scan_id"),
            {"status": status, "progress": progress, "scan_id": scan_id}
        )
        conn.commit()

def save_finding(scan_id, title, owasp_id, owasp_label,
                 severity, cvss_score, cvss_vector,
                 description, endpoint, evidence, remediation, tool_used):
    # Deduplicate — skip if same title+endpoint already exists for this scan
    with engine.connect() as conn:
        existing = conn.execute(
            text("SELECT id FROM findings WHERE scan_id=:sid AND title=:t AND endpoint=:e"),
            {"sid": scan_id, "t": title, "e": endpoint}
        ).fetchone()
        if existing:
            print(f"[SCANNER] Duplicate skipped: {title[:60]}")
            return
        conn.execute(
            text("""
                INSERT INTO findings
                (scan_id, title, owasp_id, owasp_label, severity,
                 cvss_score, cvss_vector, description, endpoint,
                 evidence, remediation, tool_used, created_at)
                VALUES
                (:scan_id, :title, :owasp_id, :owasp_label, :severity,
                 :cvss_score, :cvss_vector, :description, :endpoint,
                 :evidence, :remediation, :tool_used, :created_at)
            """),
            {
                "scan_id": scan_id, "title": title,
                "owasp_id": owasp_id, "owasp_label": owasp_label,
                "severity": severity, "cvss_score": cvss_score,
                "cvss_vector": cvss_vector, "description": description,
                "endpoint": endpoint, "evidence": evidence,
                "remediation": remediation, "tool_used": tool_used,
                "created_at": now()
            }
        )
        conn.commit()

def extract_host(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

def extract_host_port(url):
    part = url.replace("https://", "").replace("http://", "").split("/")[0]
    if ":" in part:
        host, port = part.rsplit(":", 1)
        return host, port
    return part, "80" if url.startswith("http://") else "443"

# ── Phase 0 — Connectivity check ─────────────────────────────────────────────

def check_connectivity(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=10)
        return True, response.status, None
    except urllib.error.HTTPError as e:
        return True, e.code, None
    except urllib.error.URLError as e:
        return False, 0, str(e.reason)
    except Exception as e:
        return False, 0, str(e)

# ── Phase 1 — Header analysis ─────────────────────────────────────────────────

def run_header_checks(scan_id, url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=15)
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Missing security headers
        required = {
            "content-security-policy": "prevents XSS and code injection attacks",
            "strict-transport-security": "enforces HTTPS connections",
            "x-frame-options": "prevents clickjacking attacks",
            "x-content-type-options": "prevents MIME-type sniffing",
            "referrer-policy": "controls referrer information leakage",
            "permissions-policy": "controls browser feature access"
        }
        missing = [f"{h} ({p})" for h, p in required.items() if h not in headers]
        if missing:
            save_finding(
                scan_id=scan_id,
                title="Missing HTTP Security Headers",
                owasp_id="A05", owasp_label="Security Misconfiguration",
                severity="Medium", cvss_score=4.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
                description=f"{len(missing)} required security headers are absent. Missing: {', '.join(missing)}.",
                endpoint=url,
                evidence=f"Response headers received:\n{json.dumps(dict(headers), indent=2)[:800]}",
                remediation="Add all missing security headers to your web server configuration.",
                tool_used="header-check"
            )

        # Unencrypted HTTP
        if url.startswith("http://"):
            save_finding(
                scan_id=scan_id,
                title="Application Served Over Unencrypted HTTP",
                owasp_id="A02", owasp_label="Cryptographic Failures",
                severity="High", cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description="Application is accessible over HTTP. All data including credentials transmitted in plaintext.",
                endpoint=url,
                evidence="URL scheme is http:// — TLS/SSL encryption is not in use.",
                remediation="Obtain a TLS certificate and redirect all HTTP to HTTPS. Configure HSTS.",
                tool_used="header-check"
            )

        # Insecure cookies
        cookie_header = headers.get("set-cookie", "")
        if cookie_header:
            issues = []
            if "secure" not in cookie_header.lower():
                issues.append("missing Secure flag")
            if "httponly" not in cookie_header.lower():
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_header.lower():
                issues.append("missing SameSite attribute")
            if issues:
                save_finding(
                    scan_id=scan_id,
                    title="Insecure Cookie Configuration",
                    owasp_id="A05", owasp_label="Security Misconfiguration",
                    severity="Medium", cvss_score=4.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                    description=f"Session cookies missing security attributes: {', '.join(issues)}.",
                    endpoint=url,
                    evidence=f"Set-Cookie: {cookie_header[:300]}",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                    tool_used="header-check"
                )

        # Server version disclosure — only if version number actually present
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server and any(c.isdigit() for c in server):
            save_finding(
                scan_id=scan_id,
                title="Server Version Disclosure",
                owasp_id="A05", owasp_label="Security Misconfiguration",
                severity="Low", cvss_score=3.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                description="Server discloses software version in response headers.",
                endpoint=url,
                evidence=f"Server: {server}" + (f"\nX-Powered-By: {x_powered}" if x_powered else ""),
                remediation="Suppress version info. For nginx: server_tokens off; Apache: ServerTokens Prod.",
                tool_used="header-check"
            )

        print("[SCANNER] Phase 1 complete — headers analysed")

    except Exception as e:
        print(f"[SCANNER] Phase 1 error: {e}")

# ── Phase 2 — nmap port scan ──────────────────────────────────────────────────

def verify_port_banner(host, port_num):
    """Actively grab banner to confirm service is real, not firewalled."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, int(port_num)))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        return banner if banner else "connected — no banner"
    except Exception:
        return None

def run_nmap(scan_id, url):
    host = extract_host(url)
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-p",
             "21,22,23,25,80,443,3000,3306,5432,6379,8080,8443,27017",
             host],
            capture_output=True, text=True, timeout=180
        )
        output = result.stdout
        print(f"[SCANNER] nmap output:\n{output[:600]}")

        # Build port → service line map
        port_services = {}
        for line in output.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_services[parts[0]] = line.lower()

        port_checks = [
            ("21/tcp",    "FTP Service Exposed", "A05", "Security Misconfiguration",
             "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "FTP transmits credentials and data in plaintext.",
             "Disable FTP. Use SFTP or SCP instead."),
            ("22/tcp",    "SSH Service Exposed on Web Server", "A05", "Security Misconfiguration",
             "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "SSH exposed on the same host as the web application.",
             "Restrict SSH to management VPN only."),
            ("23/tcp",    "Telnet Service Exposed", "A02", "Cryptographic Failures",
             "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
             "Telnet transmits all data including credentials in plaintext.",
             "Disable Telnet immediately. Use SSH."),
            ("3306/tcp",  "MySQL Database Port Exposed", "A05", "Security Misconfiguration",
             "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "MySQL port directly accessible from the internet.",
             "Bind MySQL to 127.0.0.1. Block port 3306 at firewall."),
            ("5432/tcp",  "PostgreSQL Database Port Exposed", "A05", "Security Misconfiguration",
             "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "PostgreSQL port exposed enabling direct database attacks.",
             "Bind PostgreSQL to localhost. Block with firewall."),
            ("6379/tcp",  "Redis Exposed Without Authentication", "A05", "Security Misconfiguration",
             "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "Redis exposed. Default Redis has no authentication.",
             "Bind Redis to 127.0.0.1. Enable requirepass."),
            ("27017/tcp", "MongoDB Exposed Without Authentication", "A05", "Security Misconfiguration",
             "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "MongoDB port exposed. Default MongoDB has no authentication.",
             "Enable MongoDB auth. Block port 27017 at firewall."),
        ]

        for port, title, owasp_id, owasp_label, severity, cvss, vector, desc, remediation in port_checks:
            if port not in port_services:
                continue
            service_line = port_services[port]

            # Gate 1 — skip tcpwrapped (firewalled, not a real service)
            if "tcpwrapped" in service_line:
                print(f"[SCANNER] {port} tcpwrapped — skipping (firewall protected)")
                continue

            # Gate 2 — actively verify the port responds
            port_num = port.split("/")[0]
            banner = verify_port_banner(host, port_num)
            if banner is None:
                print(f"[SCANNER] {port} not responding to probe — skipping")
                continue

            # Gate 3 — for DB ports require service name confirmed by nmap
            db_ports = {
                "3306/tcp": "mysql",
                "5432/tcp": "postgres",
                "6379/tcp": "redis",
                "27017/tcp": "mongo"
            }
            if port in db_ports:
                if db_ports[port] not in service_line:
                    print(f"[SCANNER] {port} service not confirmed as {db_ports[port]} — skipping")
                    continue

            save_finding(
                scan_id=scan_id, title=title,
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=severity, cvss_score=cvss, cvss_vector=vector,
                description=desc,
                endpoint=f"{host}:{port_num}",
                evidence=f"nmap detection: {service_line}\nBanner probe: {banner[:200]}",
                remediation=remediation,
                tool_used="nmap"
            )
            print(f"[SCANNER] nmap confirmed: {title}")

        print("[SCANNER] Phase 2 complete — nmap done")

    except subprocess.TimeoutExpired:
        print("[SCANNER] nmap timeout")
    except Exception as e:
        print(f"[SCANNER] nmap error: {e}")

# ── Phase 3 — Directory & path exposure ──────────────────────────────────────

def verify_exposed_path(path_url, status_code, path):
    """Read response body to confirm it's genuinely exposed, not a soft 404."""
    try:
        req = urllib.request.Request(
            path_url, headers={"User-Agent": "SecuriScan/1.0"}
        )
        response = urllib.request.urlopen(req, timeout=8)
        content = response.read(3000).decode("utf-8", errors="ignore")
        content_lower = content.lower()

        # Soft 404 — page says not found but returns 200
        soft_404 = ["page not found", "404", "not found", "does not exist",
                    "introuvable", "n'existe pas", "error 404"]
        if any(s in content_lower for s in soft_404):
            print(f"[SCANNER] {path} is a soft 404 — skipping")
            return False, ""

        # For admin paths — require admin-like content
        if "/admin" in path.lower():
            admin_keywords = ["admin", "dashboard", "login", "password",
                             "username", "sign in", "connexion", "panel"]
            if not any(k in content_lower for k in admin_keywords):
                print(f"[SCANNER] {path} returned 200 but no admin content — skipping")
                return False, ""

        # For .env — require it actually contains env-like content
        if "/.env" in path:
            env_keywords = ["key=", "secret=", "password=", "db_", "api_", "token="]
            if not any(k in content_lower for k in env_keywords):
                print(f"[SCANNER] /.env returned 200 but no secrets content — skipping")
                return False, ""

        return True, content[:300]

    except Exception:
        return False, ""

def run_directory_checks(scan_id, url):
    base = url.rstrip("/")

    sensitive_paths = [
        ("/ftp/", "Publicly Accessible FTP Directory", "A01", "Broken Access Control",
         "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         "The /ftp/ directory is publicly accessible without authentication.",
         "Restrict directory access. Require authentication."),
        ("/admin", "Admin Panel Exposed Without Authentication", "A01", "Broken Access Control",
         "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "Administrative interface accessible without authentication.",
         "Restrict admin to authenticated users only. Use IP allowlisting."),
        ("/api/users", "User Enumeration via Exposed API", "A01", "Broken Access Control",
         "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         "The /api/users endpoint returns user data without authentication.",
         "Require authentication on all API endpoints."),
        ("/.env", "Environment File Exposed", "A02", "Cryptographic Failures",
         "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "The .env file containing secrets is publicly accessible.",
         "Never serve .env files. Add to web server deny rules."),
        ("/server-status", "Apache Server Status Exposed", "A05", "Security Misconfiguration",
         "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "Apache server-status page exposes internal server metrics.",
         "Restrict /server-status to localhost only."),
        ("/swagger", "API Documentation Publicly Exposed", "A05", "Security Misconfiguration",
         "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "Swagger/OpenAPI documentation publicly accessible.",
         "Restrict API docs to authenticated users."),
        ("/api-docs", "API Documentation Publicly Exposed", "A05", "Security Misconfiguration",
         "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "API documentation endpoint publicly accessible.",
         "Require authentication to access API documentation."),
        ("/.git/HEAD", "Git Repository Exposed", "A05", "Security Misconfiguration",
         "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
         "The .git directory is publicly accessible, exposing source code.",
         "Block access to .git directory in web server config."),
        ("/backup", "Backup Directory Exposed", "A05", "Security Misconfiguration",
         "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
         "A backup directory is publicly accessible.",
         "Remove backup files from web root. Store outside document root."),
        ("/phpinfo.php", "PHP Info Page Exposed", "A05", "Security Misconfiguration",
         "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
         "phpinfo() page exposes PHP configuration and server environment.",
         "Remove phpinfo.php from production servers."),
    ]

    for path, title, owasp_id, owasp_label, severity, cvss, vector, desc, remediation in sensitive_paths:
        target_url = f"{base}{path}"
        try:
            req = urllib.request.Request(
                target_url, headers={"User-Agent": "SecuriScan/1.0"}
            )
            response = urllib.request.urlopen(req, timeout=8)
            if response.status in [200, 201]:
                # Gate — verify content confirms exposure
                genuine, content_snippet = verify_exposed_path(target_url, response.status, path)
                if not genuine:
                    continue
                save_finding(
                    scan_id=scan_id, title=title,
                    owasp_id=owasp_id, owasp_label=owasp_label,
                    severity=severity, cvss_score=cvss, cvss_vector=vector,
                    description=desc, endpoint=target_url,
                    evidence=f"HTTP {response.status} confirmed for {target_url}\nContent preview: {content_snippet[:200]}",
                    remediation=remediation, tool_used="dir-check"
                )
                print(f"[SCANNER] Confirmed exposed path: {path}")
        except urllib.error.HTTPError as e:
            if e.code not in [401, 403, 404]:
                print(f"[SCANNER] Unexpected HTTP {e.code} for {path}")
        except Exception:
            pass

    # CORS check
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "SecuriScan/1.0",
                         "Origin": "https://evil-attacker.com"}
        )
        response = urllib.request.urlopen(req, timeout=10)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        cors = resp_headers.get("access-control-allow-origin", "")
        if cors == "*":
            save_finding(
                scan_id=scan_id,
                title="Wildcard CORS Policy",
                owasp_id="A05", owasp_label="Security Misconfiguration",
                severity="Medium", cvss_score=5.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                description="Access-Control-Allow-Origin: * allows any website to read API responses.",
                endpoint=url,
                evidence=f"Request Origin: https://evil-attacker.com\nResponse: Access-Control-Allow-Origin: {cors}",
                remediation="Replace wildcard with explicit trusted origins list.",
                tool_used="cors-check"
            )
    except Exception as e:
        print(f"[SCANNER] CORS check error: {e}")

    print("[SCANNER] Phase 3 complete — directory checks done")

# ── Phase 4 — Auth checks ─────────────────────────────────────────────────────

def run_auth_checks(scan_id, url):
    base = url.rstrip("/")

    # Step 1 — discover real login endpoints (don't test 404s)
    candidate_paths = [
        "/login", "/signin", "/api/login", "/api/auth/login",
        "/api/v1/login", "/wp-login.php", "/admin/login",
        "/user/login", "/account/login", "/auth/login",
        "/rest/user/login",  # Juice Shop specific
    ]

    confirmed_endpoints = []
    for path in candidate_paths:
        test_url = f"{base}{path}"
        try:
            req = urllib.request.Request(
                test_url,
                data=b"{}",
                headers={"Content-Type": "application/json",
                        "User-Agent": "SecuriScan/1.0"},
                method="POST"
            )
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                if resp.status in [200, 400, 401, 422]:
                    confirmed_endpoints.append(test_url)
                    print(f"[SCANNER] Confirmed login endpoint: {test_url} ({resp.status})")
            except urllib.error.HTTPError as e:
                if e.code in [200, 400, 401, 422]:
                    confirmed_endpoints.append(test_url)
                    print(f"[SCANNER] Confirmed login endpoint: {test_url} ({e.code})")
                # 404 = not found, skip
                # 405 = wrong method, skip
        except Exception:
            pass

    if not confirmed_endpoints:
        print("[SCANNER] No login endpoints found — skipping auth check")
        return

    # Step 2 — test rate limiting only on confirmed endpoints
    for login_url in confirmed_endpoints[:3]:  # max 3 endpoints
        responses = []
        for i in range(10):
            try:
                req = urllib.request.Request(
                    login_url,
                    data=json.dumps({
                        "email": f"securiscan_test_{i}@test-probe.com",
                        "password": "WrongPassword_SecuriScan_Probe_123!"
                    }).encode(),
                    headers={"Content-Type": "application/json",
                            "User-Agent": "SecuriScan/1.0"},
                    method="POST"
                )
                try:
                    resp = urllib.request.urlopen(req, timeout=5)
                    responses.append(resp.status)
                except urllib.error.HTTPError as e:
                    responses.append(e.code)
                    if e.code == 429:
                        print(f"[SCANNER] Rate limiting confirmed on {login_url}")
                        break
            except Exception as e:
                print(f"[SCANNER] Auth probe error: {e}")
                break

        # Only report if no 429 was returned across all attempts
        if 429 not in responses and len(responses) >= 8:
            save_finding(
                scan_id=scan_id,
                title="No Rate Limiting on Authentication Endpoint",
                owasp_id="A07",
                owasp_label="Identification and Authentication Failures",
                severity="High",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description=f"The endpoint {login_url} accepted {len(responses)} consecutive failed login attempts without rate limiting. An attacker can brute-force credentials without restriction.",
                endpoint=login_url,
                evidence=f"Sent {len(responses)} POST requests with unique credentials.\nHTTP responses received: {responses}\nNo HTTP 429 (Too Many Requests) was returned.",
                remediation="Implement rate limiting: max 5 attempts/minute/IP. Add account lockout. Use CAPTCHA.",
                tool_used="auth-check"
            )
            print(f"[SCANNER] No rate limiting confirmed on {login_url}")

    print("[SCANNER] Phase 4 complete — auth checks done")

# ── Phase 5 — Nikto ───────────────────────────────────────────────────────────

NIKTO_SKIP = [
    "target ip", "target hostname", "target port",
    "start time", "end time", "host(s) tested",
    "no cgi", "cgi tests", "retrieved x-powered",
    "retrieved access-control", "error:", "nikto v",
    "platform:", "ssl info", "1 host(s)",
    "scan terminated", "multiple ips found",
    "server:", "host summary", "0 error",
    "items reported", "remote host",
    "ovhcloud", "ovh", "apacheovh",
    "multiple ips", "ipv6", "ipv4",
    "robotstxt", "robots.txt",
]

def is_real_nikto_finding(line):
    """Only accept lines with a real nikto finding ID like [013587]"""
    if not re.search(r'\[\d{5,6}\]', line):
        return False
    if len(line) < 30:
        return False
    line_lower = line.lower()
    if any(skip in line_lower for skip in NIKTO_SKIP):
        return False
    return True

def run_nikto(scan_id, url):
    host, port = extract_host_port(url)
    ssl_flag = url.startswith("https://")
    try:
        cmd = ["nikto", "-h", host, "-p", port,
               "-timeout", "10", "-maxtime", "180s", "-nointeractive"]
        if ssl_flag:
            cmd.append("-ssl")

        print(f"[SCANNER] Running nikto against {host}:{port}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=220)
        output = result.stdout
        print(f"[SCANNER] Nikto raw output ({len(output)} chars)")

        if not output.strip():
            print("[SCANNER] Nikto produced no output")
            return

        seen = set()
        count = 0

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue

            # Gate — must have a real nikto finding ID
            if not is_real_nikto_finding(line):
                continue

            msg = line.lstrip("+ ").strip()
            if len(msg) < 20 or msg in seen:
                continue
            seen.add(msg)

            line_lower = line.lower()

            # Map to OWASP category based on content
            if any(k in line_lower for k in ["sql", "inject"]):
                owasp_id, owasp_label = "A03", "Injection"
                severity, cvss = "Critical", 9.8
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                remediation = "Use parameterized queries. Validate all user input."
            elif any(k in line_lower for k in ["xss", "cross-site", "<script"]):
                owasp_id, owasp_label = "A03", "Injection"
                severity, cvss = "High", 7.2
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"
                remediation = "Encode output. Implement strict Content-Security-Policy."
            elif any(k in line_lower for k in ["cve-"]):
                owasp_id, owasp_label = "A06", "Vulnerable and Outdated Components"
                severity, cvss = "High", 7.5
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                remediation = "Update the affected component to the latest stable version."
            elif any(k in line_lower for k in ["outdated", "obsolete", "deprecated"]):
                owasp_id, owasp_label = "A06", "Vulnerable and Outdated Components"
                severity, cvss = "High", 7.5
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                remediation = "Update all components to latest stable versions."
            elif any(k in line_lower for k in ["directory index", "listing", "index of"]):
                owasp_id, owasp_label = "A01", "Broken Access Control"
                severity, cvss = "Medium", 5.3
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                remediation = "Disable directory listing in web server configuration."
            elif any(k in line_lower for k in ["password", "default login", "default password"]):
                owasp_id, owasp_label = "A07", "Identification and Authentication Failures"
                severity, cvss = "High", 7.5
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                remediation = "Change all default credentials. Enforce strong password policy."
            elif any(k in line_lower for k in ["cookie", "httponly", "secure flag"]):
                owasp_id, owasp_label = "A07", "Identification and Authentication Failures"
                severity, cvss = "Medium", 4.3
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"
                remediation = "Set HttpOnly and Secure flags on all session cookies."
            elif any(k in line_lower for k in ["backup", ".bak", ".old", ".conf"]):
                owasp_id, owasp_label = "A05", "Security Misconfiguration"
                severity, cvss = "High", 7.5
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                remediation = "Remove backup and config files from web root."
            elif any(k in line_lower for k in ["missing", "header", "permissions-policy",
                                                "strict-transport", "content-security",
                                                "referrer-policy", "x-content-type", "x-frame"]):
                owasp_id, owasp_label = "A05", "Security Misconfiguration"
                severity, cvss = "Medium", 4.7
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N"
                remediation = "Add the missing security header to your web server configuration."
            elif any(k in line_lower for k in ["uncommon header", "tcn", "disclosure",
                                                "breach", "deflate"]):
                owasp_id, owasp_label = "A05", "Security Misconfiguration"
                severity, cvss = "Low", 3.1
                cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
                remediation = "Remove or restrict headers that disclose internal information."
            else:
                owasp_id, owasp_label = "A05", "Security Misconfiguration"
                severity, cvss = "Low", 3.1
                cvss_vector = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
                remediation = "Review the identified issue and apply appropriate hardening."

            save_finding(
                scan_id=scan_id,
                title=f"Nikto: {msg[:120]}",
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=severity, cvss_score=cvss, cvss_vector=cvss_vector,
                description=msg, endpoint=url,
                evidence=f"Nikto finding ID confirmed:\n{line}",
                remediation=remediation,
                tool_used="nikto"
            )
            count += 1

        print(f"[SCANNER] Phase 5 complete — {count} nikto findings saved")

    except subprocess.TimeoutExpired:
        print("[SCANNER] Nikto timeout after 220s")
    except FileNotFoundError:
        print("[SCANNER] Nikto not installed")
    except Exception as e:
        print(f"[SCANNER] Nikto error: {e}")

# ── Phase 6 — Nuclei ──────────────────────────────────────────────────────────

def run_nuclei(scan_id, url):
    output_file = f"/tmp/nuclei_{scan_id}.json"
    try:
        cmd = [
            "nuclei", "-u", url,
            "-json-export", output_file,
            "-severity", "medium,high,critical",
            "-timeout", "5",
            "-bulk-size", "5",
            "-concurrency", "5",
            "-rate-limit", "30",
            "-no-interactsh",
            "-silent",
            "-duc",
        ]
        print(f"[SCANNER] Running nuclei against {url}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)

        if not os.path.exists(output_file):
            print("[SCANNER] Nuclei produced no output")
            return

        severity_map = {
            "critical": ("Critical", 9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "high":     ("High",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
            "medium":   ("Medium",   5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
        }
        owasp_tag_map = {
            "cve":           ("A06", "Vulnerable and Outdated Components"),
            "misconfig":     ("A05", "Security Misconfiguration"),
            "exposure":      ("A01", "Broken Access Control"),
            "default-login": ("A07", "Identification and Authentication Failures"),
            "token":         ("A02", "Cryptographic Failures"),
            "injection":     ("A03", "Injection"),
            "xss":           ("A03", "Injection"),
        }

        seen = set()
        count = 0
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue

                template_id = finding.get("template-id", "")
                name = finding.get("info", {}).get("name", template_id)
                sev = finding.get("info", {}).get("severity", "medium").lower()
                matched_url = finding.get("matched-at", url)
                tags = finding.get("info", {}).get("tags", [])
                description = finding.get("info", {}).get("description", name)

                key = f"{template_id}:{matched_url}"
                if key in seen:
                    continue
                seen.add(key)

                severity_label, cvss, vector = severity_map.get(
                    sev, ("Medium", 5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
                )
                owasp_id, owasp_label = "A05", "Security Misconfiguration"
                for tag in (tags if isinstance(tags, list) else [tags]):
                    tag_lower = str(tag).lower()
                    for keyword, (oid, olabel) in owasp_tag_map.items():
                        if keyword in tag_lower:
                            owasp_id, owasp_label = oid, olabel
                            break

                remediation = finding.get("info", {}).get("remediation",
                    "Review the nuclei template for remediation guidance.")

                save_finding(
                    scan_id=scan_id,
                    title=f"Nuclei: {name[:80]}",
                    owasp_id=owasp_id, owasp_label=owasp_label,
                    severity=severity_label, cvss_score=cvss, cvss_vector=vector,
                    description=str(description)[:500],
                    endpoint=matched_url,
                    evidence=f"Template: {template_id}\nTags: {tags}\nMatched: {matched_url}",
                    remediation=str(remediation)[:400],
                    tool_used="nuclei"
                )
                count += 1

        print(f"[SCANNER] Phase 6 complete — {count} nuclei findings saved")

    except subprocess.TimeoutExpired:
        print("[SCANNER] Nuclei timeout after 90s")
    except FileNotFoundError:
        print("[SCANNER] Nuclei not installed")
    except Exception as e:
        print(f"[SCANNER] Nuclei error: {e}")

# ── Phase 7 — SQLmap helpers ──────────────────────────────────────────────────

def _sqlmap_found_injection(output):
    """
    Returns True ONLY if sqlmap explicitly confirmed injection.
    Returns False if WAF detected or parameters tested negative.
    """
    output_lower = output.lower()

    # Explicit false positive indicators — if any present, not injectable
    false_positive_indicators = [
        "does not seem to be injectable",
        "does not appear to be dynamic",
        "all tested parameters do not appear",
        "protected by some kind of waf",
        "heuristics detected that the target is protected",
        "might not be injectable",
    ]
    if any(fp in output_lower for fp in false_positive_indicators):
        return False

    # Only confirm on strong explicit statements
    strong_confirmed = [
        "is vulnerable",
        "sqlmap identified the following injection point",
        "the back-end dbms is",
    ]
    return any(ind in output_lower for ind in strong_confirmed)

def _extract_param(output):
    match = re.search(r"parameter '([^']+)'", output, re.IGNORECASE)
    if match:
        return match.group(1)
    match = re.search(r"Parameter:\s*(\S+)", output)
    if match:
        return match.group(1)
    return "unknown"

# ── Phase 7 — SQLmap ──────────────────────────────────────────────────────────

def run_sqlmap(scan_id, url):
    base = url.rstrip("/")
    output_dir = f"/tmp/sqlmap_{scan_id}"
    os.makedirs(output_dir, exist_ok=True)

    targets_to_test = set()

    # Step 1 — crawl homepage for parameterized URLs
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (SecuriScan Scanner)"}
        )
        response = urllib.request.urlopen(req, timeout=15)
        html = response.read().decode("utf-8", errors="ignore")

        all_links = re.findall(r'(?:href|action|src)=["\']([^"\']+)["\']', html)
        for link in all_links:
            if "?" in link and "=" in link:
                if link.startswith("http"):
                    targets_to_test.add(link)
                elif link.startswith("/"):
                    targets_to_test.add(f"{base}{link}")

        js_urls = re.findall(r'["\']([/\w\-\.]+\?[\w\-]+=[\w\-]*)["\']', html)
        for link in js_urls:
            if link.startswith("/"):
                targets_to_test.add(f"{base}{link}")

        print(f"[SCANNER] SQLmap discovered {len(targets_to_test)} parameterized endpoints")

    except Exception as e:
        print(f"[SCANNER] SQLmap homepage crawl error: {e}")

    targets_to_test.add(url)

    # Step 2 — sqlmap built-in crawler
    crawl_targets = []
    try:
        crawl_cmd = [
            "sqlmap", "-u", url,
            "--batch", "--level=2", "--risk=1",
            "--crawl=3", "--forms",
            "--technique=BEU", "--time-sec=5",
            "--output-dir", output_dir,
            "--no-cast", "--fresh-queries",
            "--disable-coloring", "--random-agent",
            "--threads=3",
        ]
        print(f"[SCANNER] SQLmap crawling {url}")
        crawl_result = subprocess.run(
            crawl_cmd, capture_output=True, text=True, timeout=120
        )
        crawl_output = crawl_result.stdout + crawl_result.stderr

        discovered = re.findall(r'testing URL:\s*(https?://\S+)', crawl_output)
        for d in discovered:
            crawl_targets.append(d.strip())

        if _sqlmap_found_injection(crawl_output):
            injected_param = _extract_param(crawl_output)
            save_finding(
                scan_id=scan_id,
                title="SQL Injection Vulnerability Detected",
                owasp_id="A03", owasp_label="Injection",
                severity="Critical", cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                description=f"SQLmap confirmed SQL injection on {url}. Injectable parameter: {injected_param}.",
                endpoint=url,
                evidence=crawl_output[:1000],
                remediation="Use parameterized queries. Never concatenate user input into SQL strings.",
                tool_used="sqlmap"
            )
            print(f"[SCANNER] SQLi confirmed at {url}")
            print("[SCANNER] Phase 7 complete — sqlmap done")
            return

    except subprocess.TimeoutExpired:
        print("[SCANNER] SQLmap crawl timeout — continuing with discovered URLs")
    except FileNotFoundError:
        print("[SCANNER] SQLmap not installed")
        return
    except Exception as e:
        print(f"[SCANNER] SQLmap crawl error: {e}")

    # Step 3 — test individual discovered endpoints
    all_targets = list(targets_to_test) + crawl_targets
    tested = set()
    found = False

    for endpoint in all_targets[:10]:
        endpoint = endpoint.strip()
        if endpoint in tested or not endpoint.startswith("http"):
            continue
        tested.add(endpoint)

        try:
            cmd = [
                "sqlmap", "-u", endpoint,
                "--batch", "--level=2", "--risk=1",
                "--technique=BEU", "--time-sec=5",
                "--output-dir", output_dir,
                "--forms", "--no-cast", "--fresh-queries",
                "--disable-coloring", "--random-agent",
                "--threads=3",
            ]
            print(f"[SCANNER] SQLmap testing {endpoint}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            output = result.stdout + result.stderr

            if _sqlmap_found_injection(output):
                injected_param = _extract_param(output)
                save_finding(
                    scan_id=scan_id,
                    title="SQL Injection Vulnerability Detected",
                    owasp_id="A03", owasp_label="Injection",
                    severity="Critical", cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=f"SQLmap confirmed SQL injection at {endpoint}. Injectable parameter: {injected_param}.",
                    endpoint=endpoint,
                    evidence=output[:1000],
                    remediation="Use parameterized queries. Never concatenate user input into SQL strings.",
                    tool_used="sqlmap"
                )
                print(f"[SCANNER] SQLi confirmed at {endpoint}")
                found = True
                break

        except subprocess.TimeoutExpired:
            print(f"[SCANNER] SQLmap timeout on {endpoint}")
        except Exception as e:
            print(f"[SCANNER] SQLmap error on {endpoint}: {e}")

    if not found:
        print("[SCANNER] SQLmap — no injection confirmed on tested endpoints")

    print("[SCANNER] Phase 7 complete — sqlmap done")

def query_osv_api(package_name, version, ecosystem="npm"):
    """
    Query Google OSV API for known vulnerabilities.
    Returns list of {id, summary, severity, cvss} or empty list.
    Free, no API key required.
    """
    import json
    import urllib.request
    
    try:
        payload = json.dumps({
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }).encode()
        
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        
        vulns = []
        for v in data.get("vulns", [])[:5]:  # cap at 5 per library
            # Extract CVSS score if available
            cvss = 5.0  # default medium
            severity = "Medium"
            for sev in v.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        # Parse CVSS vector score
                        cvss = float(score_str.split("/")[0]) if "/" not in score_str else 5.0
                        # Try to get from database_specific
                    except:
                        pass
            
            # Get score from database_specific.severity if available
            for affected in v.get("affected", []):
                for db_sev in affected.get("database_specific", {}).get("severity", [""]):
                    pass
                    
            # Determine severity from CVE score ranges
            if cvss >= 9.0: severity = "Critical"
            elif cvss >= 7.0: severity = "High"
            elif cvss >= 4.0: severity = "Medium"
            else: severity = "Low"
            
            vulns.append({
                "id": v.get("id", ""),
                "summary": v.get("summary", v.get("details", "")[:200]),
                "cvss": cvss,
                "severity": severity,
                "aliases": v.get("aliases", [])
            })
        
        return vulns
    except Exception as e:
        print(f"[SCANNER] OSV API error for {package_name} {version}: {e}")
        return []


# Map common JS library names found in source to their npm package names
JS_LIBRARY_SIGNATURES = [
    # (display_name, npm_package_name, regex_to_find_version_in_source)
    ("jQuery",             "jquery",             r'[Jj][Qq]uery\s+[Jj][Ss].*?v?(\d+\.\d+\.\d+)'),
    ("jQuery",             "jquery",             r'[Jj][Qq]uery\s+v(\d+\.\d+\.\d+)'),
    ("jQuery",             "jquery",             r'jquery[/-](\d+\.\d+\.\d+)'),
    ("jquery-validation",  "jquery-validation",  r'jQuery Validation Plugin.*?v?(\d+\.\d+\.\d+)'),
    ("jquery-validation",  "jquery-validation",  r'jquery[.-]validation.*?v?(\d+\.\d+\.\d+)'),
    ("Bootstrap",          "bootstrap",          r'[Bb]ootstrap\s+v(\d+\.\d+\.\d+)'),
    ("Bootstrap",          "bootstrap",          r'bootstrap[/-](\d+\.\d+\.\d+)'),
    ("AngularJS",          "angular",            r'[Aa]ngular(?:JS)?\s+v(\d+\.\d+\.\d+)'),
    ("React",              "react",              r'[Rr]eact\s+v(\d+\.\d+\.\d+)'),
    ("Vue.js",             "vue",                r'[Vv]ue\.js\s+v(\d+\.\d+\.\d+)'),
    ("Lodash",             "lodash",             r'[Ll]odash\s+(\d+\.\d+\.\d+)'),
    ("Moment.js",          "moment",             r'[Mm]oment\.js\s+v?(\d+\.\d+\.\d+)'),
    ("Underscore.js",      "underscore",         r'[Uu]nderscore\.js\s+(\d+\.\d+\.\d+)'),
    ("Handlebars",         "handlebars",         r'[Hh]andlebars\.js\s+v(\d+\.\d+\.\d+)'),
    ("D3.js",              "d3",                 r'[Dd]3\s+[Vv](\d+\.\d+\.\d+)'),
    ("Axios",              "axios",              r'axios[/\s]+v?(\d+\.\d+\.\d+)'),
]


def run_js_library_check(scan_id, url):
    """
    Dynamic JS library vulnerability detection:
    1. Fetch homepage, extract all script URLs
    2. Download each JS file, search for known library version strings
    3. Query OSV API dynamically for each found version
    4. Save findings for any confirmed CVEs
    """
    base = url.rstrip("/")
    found_scripts = set()

    # Step 1 — fetch homepage and extract script URLs
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=15)
        html = response.read().decode("utf-8", errors="ignore")

        script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in script_urls:
            if src.startswith("http"):
                found_scripts.add(src)
            elif src.startswith("//"):
                found_scripts.add(f"https:{src}")
            elif src.startswith("/"):
                found_scripts.add(f"{base}{src}")

        print(f"[SCANNER] JS check: found {len(found_scripts)} script files to analyse")

    except Exception as e:
        print(f"[SCANNER] JS check homepage error: {e}")
        return

    # Step 2 — download and analyse each JS file
    checked = 0
    already_found = set()  # avoid duplicate library findings

    for script_url in list(found_scripts)[:25]:
        try:
            req = urllib.request.Request(
                script_url,
                headers={"User-Agent": "SecuriScan/1.0"}
            )
            resp = urllib.request.urlopen(req, timeout=10)
            # Only read first 100KB — version strings are always at the top
            js_content = resp.read(102400).decode("utf-8", errors="ignore")
            checked += 1

            # Step 3 — search for known library signatures
            for display_name, npm_name, version_pattern in JS_LIBRARY_SIGNATURES:
                match = re.search(version_pattern, js_content, re.IGNORECASE)
                if not match:
                    continue

                version = match.group(1)
                dedup_key = f"{npm_name}:{version}"
                if dedup_key in already_found:
                    continue
                already_found.add(dedup_key)

                print(f"[SCANNER] Found {display_name} v{version} at {script_url} — querying OSV...")

                # Step 4 — query OSV API for this exact version
                vulns = query_osv_api(npm_name, version, "npm")

                if not vulns:
                    print(f"[SCANNER] {display_name} v{version} — no known CVEs")
                    continue

                # Build evidence
                cve_ids = []
                for v in vulns:
                    cve_ids.extend([a for a in v.get("aliases", []) if a.startswith("CVE-")])
                cve_list = ", ".join(cve_ids[:6]) or "See OSV database"

                # Use highest CVSS from all vulns
                max_cvss = max(v["cvss"] for v in vulns)
                if max_cvss >= 9.0:   severity = "Critical"
                elif max_cvss >= 7.0: severity = "High"
                elif max_cvss >= 4.0: severity = "Medium"
                else:                 severity = "Low"

                summaries = " | ".join([
                    f"{v['id']}: {v['summary'][:100]}"
                    for v in vulns
                ])

                save_finding(
                    scan_id=scan_id,
                    title=f"Vulnerable JS Library: {display_name} v{version}",
                    owasp_id="A06",
                    owasp_label="Vulnerable and Outdated Components",
                    severity=severity,
                    cvss_score=max_cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    description=(
                        f"{display_name} version {version} loaded from {script_url} "
                        f"has {len(vulns)} known CVE(s): {cve_list}. "
                        f"This version is outdated and should be updated immediately."
                    ),
                    endpoint=script_url,
                    evidence=(
                        f"Version string found in source:\n{match.group(0)}\n\n"
                        f"CVEs confirmed by OSV API:\n{summaries}\n\n"
                        f"File URL: {script_url}"
                    ),
                    remediation=(
                        f"Update {display_name} to the latest stable version. "
                        f"Replace the file at {script_url} with the latest release. "
                        f"Check https://www.npmjs.com/package/{npm_name} for the current version."
                    ),
                    tool_used="js-check"
                )
                print(f"[SCANNER] CONFIRMED: {display_name} v{version} has {len(vulns)} CVEs — saved as {severity}")

        except Exception as e:
            pass

    print(f"[SCANNER] Phase 1b complete — checked {checked} JS files, found {len(already_found)} libraries")
# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "scanner"})

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    scan_id = data.get("scan_id")
    url = data.get("url")

    if not scan_id or not url:
        return jsonify({"error": "scan_id and url required"}), 400

    print(f"[SCANNER] Starting scan {scan_id} against {url}")

    try:
        # Phase 0
        print("[SCANNER] Phase 0: Connectivity check")
        update_scan_status(scan_id, "running", 2)
        reachable, status_code, error_msg = check_connectivity(url)
        if not reachable:
            with engine.connect() as conn:
                conn.execute(
                    text("UPDATE scans SET status='error', progress=0 WHERE id=:id"),
                    {"id": scan_id}
                )
                conn.commit()
            return jsonify({"error": f"Target unreachable: {error_msg}"}), 400
        print(f"[SCANNER] Target reachable — HTTP {status_code}")
        update_scan_status(scan_id, "running", 5)

        # Phase 1
        print("[SCANNER] Phase 1: Header analysis")
        try:
            run_header_checks(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 1 error: {e}")
        update_scan_status(scan_id, "running", 15)

        # Phase 2
        print("[SCANNER] Phase 2: nmap port scan")
        try:
            run_nmap(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 2 error: {e}")
        update_scan_status(scan_id, "running", 30)

        # Phase 3
        print("[SCANNER] Phase 3: Directory exposure checks")
        try:
            run_directory_checks(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 3 error: {e}")
        update_scan_status(scan_id, "running", 45)

        # Phase 4
        print("[SCANNER] Phase 4: Authentication checks")
        try:
            run_auth_checks(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 4 error: {e}")
        update_scan_status(scan_id, "running", 55)

        # Phase 5
        print("[SCANNER] Phase 5: Nikto web server scan")
        try:
            run_nikto(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 5 error: {e}")
        update_scan_status(scan_id, "running", 70)

        # Phase 6
        print("[SCANNER] Phase 6: Nuclei vulnerability scan")
        try:
            run_nuclei(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 6 error: {e}")
        update_scan_status(scan_id, "running", 85)

        # Phase 7
        print("[SCANNER] Phase 7: SQLmap injection detection")
        try:
            run_sqlmap(scan_id, url)
        except Exception as e:
            print(f"[SCANNER] Phase 7 error: {e}")
        update_scan_status(scan_id, "running", 95)

        # Complete
        with engine.connect() as conn:
            conn.execute(
                text("UPDATE scans SET status='complete', progress=100, completed_at=:t WHERE id=:id"),
                {"t": now(), "id": scan_id}
            )
            conn.commit()

        print(f"[SCANNER] Scan {scan_id} complete")
        return jsonify({"status": "complete", "scan_id": scan_id})

    except Exception as e:
        print(f"[SCANNER] Fatal error: {e}")
        update_scan_status(scan_id, "error", 0)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)