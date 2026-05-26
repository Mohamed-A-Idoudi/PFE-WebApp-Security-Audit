"""
Phase 2 — Network port scan
nmap -sV with banner verification and tcpwrapped filter.
Saves confirmed open services only.
"""
import socket
import subprocess
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep, extract_host


def verify_port_banner(host: str, port_num: str) -> str | None:
    """Active banner grab to confirm service is real, not firewalled."""
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


PORT_CHECKS = [
    ("21/tcp",    "FTP Service Exposed", "A05", "Security Misconfiguration",
     "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "FTP transmits credentials and data in plaintext. Port 21 is open.",
     "Disable FTP. Use SFTP or SCP for file transfers."),
    ("22/tcp",    "SSH Service Exposed on Web Server", "A05", "Security Misconfiguration",
     "Low", 3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "SSH is exposed on the same host as the web application, increasing attack surface.",
     "Restrict SSH access to a management VPN or bastion host. Disable password authentication."),
    ("23/tcp",    "Telnet Service Exposed", "A02", "Cryptographic Failures",
     "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "Telnet transmits all data including credentials in plaintext.",
     "Disable Telnet immediately. Replace with SSH."),
    ("3306/tcp",  "MySQL Database Port Exposed", "A05", "Security Misconfiguration",
     "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "MySQL database port directly accessible from the internet.",
     "Bind MySQL to 127.0.0.1. Block port 3306 at firewall."),
    ("5432/tcp",  "PostgreSQL Database Port Exposed", "A05", "Security Misconfiguration",
     "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "PostgreSQL port exposed, enabling direct database attacks.",
     "Bind PostgreSQL to localhost. Block port 5432 at firewall."),
    ("6379/tcp",  "Redis Exposed Without Authentication", "A05", "Security Misconfiguration",
     "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Redis is exposed. Default Redis configuration has no authentication.",
     "Bind Redis to 127.0.0.1. Enable requirepass directive."),
    ("27017/tcp", "MongoDB Exposed Without Authentication", "A05", "Security Misconfiguration",
     "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "MongoDB port exposed. Default MongoDB has no authentication.",
     "Enable MongoDB authentication. Block port 27017 at firewall."),
]

DB_PORT_SERVICES = {
    "3306/tcp":  "mysql",
    "5432/tcp":  "postgres",
    "6379/tcp":  "redis",
    "27017/tcp": "mongo",
}


def run_nmap(scan_id: str, url: str):
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

        # Build port → full service line map
        port_services = {}
        for line in output.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_services[parts[0]] = line.lower()

        for (port, title, owasp_id, owasp_label,
             severity, cvss, vector, desc, remediation) in PORT_CHECKS:

            if port not in port_services:
                continue

            service_line = port_services[port]

            # Gate 1 — skip tcpwrapped (port is firewalled, not a real service)
            if "tcpwrapped" in service_line:
                print(f"[SCANNER] {port} tcpwrapped — skipping (firewall protected)")
                continue

            # Gate 2 — actively probe the port to confirm it responds
            port_num = port.split("/")[0]
            banner   = verify_port_banner(host, port_num)
            if banner is None:
                print(f"[SCANNER] {port} not responding to probe — skipping")
                continue

            # Gate 3 — for database ports require service name confirmed by nmap
            if port in DB_PORT_SERVICES:
                if DB_PORT_SERVICES[port] not in service_line:
                    print(f"[SCANNER] {port} service not confirmed as {DB_PORT_SERVICES[port]} — skipping")
                    continue

            save_finding(
                scan_id=scan_id, title=title,
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=severity, cvss_score=cvss, cvss_vector=vector,
                description=desc,
                endpoint=f"{host}:{port_num}",
                evidence=f"nmap: {service_line}\nBanner: {banner[:200]}",
                remediation=remediation,
                tool_used="nmap",
                confidence="confirmed",
            )
            print(f"[SCANNER] nmap confirmed: {title}")

        print("[SCANNER] Phase 2 complete")

    except subprocess.TimeoutExpired:
        print("[SCANNER] nmap timeout")
    except Exception as e:
        print(f"[SCANNER] nmap error: {e}")
