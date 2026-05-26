"""
Phase 5 — Nikto web server scan
Only accepts confirmed finding IDs. Skips categories already
covered by phases 1 and 3 to avoid duplicate findings.
"""
import re
import subprocess
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep, extract_host_port


# Skip these — already covered by Phase 1 (headers) or Phase 3 (directories)
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
    "suggested security header",
    "x-content-type-options",
    "strict-transport-security",
    "permissions-policy",
    "content-security-policy",
    "referrer-policy",
    "x-frame-options",
    "httponly",
    "samesite",
    "psql_history", "mysql_history", 
    "sqlite_history", "bash_history",
    "sh_history", "might be interesting",
]

OWASP_RULES = [
    (["sql", "inject", "sql inject", "sql injection", "sqli", "' or 1=1"],
     "A03","Injection","Critical",9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Use parameterized queries. Validate all user input."),
    (["xss", "cross-site", "<script"],
     "A03","Injection","High",7.2,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
     "Encode output. Implement strict Content-Security-Policy."),
    (["cve-"],
     "A06","Vulnerable and Outdated Components","High",7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Update the affected component to the latest stable version."),
    (["outdated", "obsolete", "deprecated", "end-of-life"],
     "A06","Vulnerable and Outdated Components","High",7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Update all components to latest stable versions."),
    (["directory index", "listing", "index of"],
     "A01","Broken Access Control","Medium",5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Disable directory listing in web server configuration."),
    (["password", "default login", "default password", "default credential"],
     "A07","Identification and Authentication Failures","High",7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Change all default credentials. Enforce strong password policy."),
    (["backup", ".bak", ".old", ".orig", "config file"],
     "A05","Security Misconfiguration","High",7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Remove backup and config files from web root."),
    (["phpinfo", "php info"],
     "A05","Security Misconfiguration","High",7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Remove phpinfo() pages from production servers."),
    (["uncommon header", "disclosure", "breach", "deflate", "compression"],
     "A05","Security Misconfiguration","Low",3.1,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Remove or restrict headers that disclose internal information."),
]

DEFAULT_OWASP = (
    "A05","Security Misconfiguration","Low",3.1,
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "Review the identified issue and apply appropriate hardening."
)


def is_real_nikto_finding(line: str) -> bool:
    if not re.search(r'\[\d{5,6}\]', line):
        return False
    if len(line) < 30:
        return False
    ll = line.lower()
    return not any(skip in ll for skip in NIKTO_SKIP)


def _map_owasp(line_lower: str):
    for (kws, oid, olabel, sev, cvss, vec, rem) in OWASP_RULES:
        if any(k in line_lower for k in kws):
            return oid, olabel, sev, cvss, vec, rem
    oid, olabel, sev, cvss, vec, rem = DEFAULT_OWASP
    return oid, olabel, sev, cvss, vec, rem


def run_nikto(scan_id: str, url: str, use_tor: bool = False):
    host, port = extract_host_port(url)
    ssl_flag   = url.startswith("https://")
    try:
        cmd = ["nikto", "-h", host, "-p", port,
               "-timeout", "10", "-maxtime", "180s", "-nointeractive"]
        if ssl_flag:
            cmd.append("-ssl")
        if use_tor:
            cmd += ["-useproxy", "socks5://127.0.0.1:9050"]

        print(f"[SCANNER] Nikto → {host}:{port}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=220)
        output = result.stdout

        if not output.strip():
            print("[SCANNER] Nikto no output")
            return

        seen  = set()
        count = 0

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue
            if not is_real_nikto_finding(line):
                continue

            msg = line.lstrip("+ ").strip()
            if len(msg) < 20 or msg in seen:
                continue
            seen.add(msg)

            owasp_id, owasp_label, severity, cvss, vector, remediation = _map_owasp(line.lower())

            save_finding(
                scan_id=scan_id,
                title=f"Nikto: {msg[:120]}",
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=severity, cvss_score=cvss, cvss_vector=vector,
                description=msg, endpoint=url,
                evidence=f"Nikto finding ID confirmed:\n{line}",
                remediation=remediation,
                tool_used="nikto",
                confidence="probable",
            )
            count += 1

        print(f"[SCANNER] Phase 5 complete — {count} findings saved")

    except subprocess.TimeoutExpired:
        print("[SCANNER] Nikto timeout after 220s")
    except FileNotFoundError:
        print("[SCANNER] Nikto not installed")
    except Exception as e:
        print(f"[SCANNER] Nikto error: {e}")
