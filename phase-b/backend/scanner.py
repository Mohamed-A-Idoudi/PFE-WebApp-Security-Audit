import subprocess
import json
import re
from datetime import datetime
from models import db, Scan, Finding


def update_progress(scan_id, progress, status=None):
    scan = Scan.query.get(scan_id)
    if scan:
        scan.progress = progress
        if status:
            scan.status = status
        db.session.commit()


def extract_host(url):
    url = url.replace("http://", "").replace("https://", "")
    host = url.split("/")[0].split(":")[0]
    return host


def extract_port(url):
    if ":" in url.replace("http://", "").replace("https://", ""):
        part = url.replace("http://", "").replace("https://", "").split("/")[0]
        if ":" in part:
            return part.split(":")[1]
    return "80"

def save_finding(scan_id, title, owasp, severity, cvss, vector,
                 description, endpoint, evidence, remediation, tool):
    finding = Finding(
        scan_id=scan_id,
        title=title,
        owasp_category=owasp,
        severity=severity,
        cvss_score=cvss,
        cvss_vector=vector,
        description=description,
        endpoint=endpoint,
        evidence=evidence,
        remediation=remediation,
        tool_used=tool
    )
    db.session.add(finding)
    db.session.commit()


def run_nmap(host, port, scan_id):
    findings = []
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-p", port, "--open", host],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout

        # Check SSH exposed
        if "22/tcp" in output and "open" in output:
            save_finding(
                scan_id=scan_id,
                title="Unnecessary SSH Service Exposed",
                owasp="A05 - Security Misconfiguration",
                severity="Low",
                cvss=3.7,
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                description="SSH service is exposed on the same host as the web application, increasing the attack surface unnecessarily.",
                endpoint="Port 22/tcp",
                evidence=output[:500],
                remediation="Disable SSH if not required. If needed, restrict to management network only.",
                tool="nmap"
            )

        # Check version disclosure
        version_match = re.search(r"(\d+\.\d+\.\d+)", output)
        if version_match:
            save_finding(
                scan_id=scan_id,
                title="Service Version Disclosure",
                owasp="A05 - Security Misconfiguration",
                severity="Medium",
                cvss=5.3,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                description=f"Service version information is disclosed: {version_match.group(0)}",
                endpoint=f"Port {port}/tcp",
                evidence=output[:300],
                remediation="Suppress version banners in service configuration.",
                tool="nmap"
            )

        return output
    except subprocess.TimeoutExpired:
        return "nmap timeout"
    except FileNotFoundError:
        return "nmap not found - install nmap"
    except Exception as e:
        return str(e)


def run_header_checks(url, scan_id):
    import urllib.request
    import urllib.error

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=10)
        headers = dict(response.headers)
        header_names = {k.lower() for k in headers.keys()}

        # Check missing security headers
        missing = []
        required_headers = {
            "content-security-policy": "Prevents XSS attacks",
            "strict-transport-security": "Enforces HTTPS",
            "x-frame-options": "Prevents clickjacking",
            "x-content-type-options": "Prevents MIME sniffing",
            "referrer-policy": "Controls referrer information",
            "permissions-policy": "Controls browser features"
        }

        for header, purpose in required_headers.items():
            if header not in header_names:
                missing.append(f"{header} ({purpose})")

        if missing:
            save_finding(
                scan_id=scan_id,
                title="Missing Security Headers",
                owasp="A05 - Security Misconfiguration",
                severity="Medium",
                cvss=4.7,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
                description=f"The following security headers are absent: {', '.join(missing)}",
                endpoint=url,
                evidence=f"Response headers: {json.dumps(dict(headers), indent=2)[:400]}",
                remediation="Add all missing security headers to the web server configuration.",
                tool="header-check"
            )

        # Check CORS wildcard
        cors = headers.get("Access-Control-Allow-Origin", "")
        if cors == "*":
            save_finding(
                scan_id=scan_id,
                title="Wildcard CORS Policy",
                owasp="A05 - Security Misconfiguration",
                severity="Medium",
                cvss=5.4,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                description="Access-Control-Allow-Origin is set to wildcard (*), allowing any origin to read API responses.",
                endpoint=url,
                evidence=f"Access-Control-Allow-Origin: {cors}",
                remediation="Replace wildcard with explicit list of trusted origins.",
                tool="header-check"
            )

        # Check HTTP (no TLS)
        if url.startswith("http://"):
            save_finding(
                scan_id=scan_id,
                title="Application Served Over Unencrypted HTTP",
                owasp="A02 - Cryptographic Failures",
                severity="High",
                cvss=5.9,
                vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description="The application transmits all data including credentials over unencrypted HTTP.",
                endpoint=url,
                evidence=f"URL scheme is http:// — no TLS negotiation occurs",
                remediation="Enable HTTPS with a valid TLS certificate. Redirect all HTTP to HTTPS.",
                tool="header-check"
            )

        return headers

    except urllib.error.URLError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def run_ftp_check(url, scan_id):
    ftp_url = url.rstrip("/") + "/ftp/"
    try:
        import urllib.request
        req = urllib.request.Request(ftp_url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=10)
        content = response.read().decode("utf-8", errors="ignore")

        if response.status == 200 and ("Index of" in content or ".md" in content or ".bak" in content):
            save_finding(
                scan_id=scan_id,
                title="Publicly Accessible FTP/Files Directory",
                owasp="A01 - Broken Access Control",
                severity="High",
                cvss=7.5,
                vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description="A directory containing sensitive files is publicly accessible without authentication.",
                endpoint=ftp_url,
                evidence=f"HTTP {response.status} returned for {ftp_url} — directory listing visible",
                remediation="Remove sensitive directories from the web root. Implement access controls.",
                tool="ftp-check"
            )
    except Exception:
        pass


def run_full_scan(scan_id, target_url, app):
    with app.app_context():
        try:
            update_progress(scan_id, 5)

            host = extract_host(target_url)
            port = extract_port(target_url)

            # Phase 1 - nmap
            update_progress(scan_id, 20)
            run_nmap(host, port, scan_id)

            # Phase 2 - Headers
            update_progress(scan_id, 50)
            run_header_checks(target_url, scan_id)

            # Phase 3 - FTP check
            update_progress(scan_id, 75)
            run_ftp_check(target_url, scan_id)

            # Complete
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = "complete"
                scan.progress = 100
                scan.completed_at = datetime.utcnow()
                db.session.commit()

        except Exception as e:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.status = "error"
                scan.error_message = str(e)
                db.session.commit()