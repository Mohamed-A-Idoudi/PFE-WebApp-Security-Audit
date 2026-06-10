"""
Phase 1 — HTTP header analysis + outdated software detection.
Checks: missing security headers, unencrypted HTTP, insecure cookies,
server disclosure, and End-of-Life software versions.
"""
import json
import re
import urllib.request
import urllib.error
from .db import save_finding
from .utils import random_ua


EOL_SOFTWARE = [
    (r"PHP/([0-9]+\.[0-9]+)", "PHP", {
        "5.": ("Critical", 9.8, "PHP 5.x reached End of Life in December 2018. Hundreds of unpatched CVEs exist."),
        "7.0": ("Critical", 9.8, "PHP 7.0 reached End of Life in December 2019."),
        "7.1": ("Critical", 9.8, "PHP 7.1 reached End of Life in December 2019."),
        "7.2": ("High", 8.5, "PHP 7.2 reached End of Life in November 2020."),
        "7.3": ("High", 8.5, "PHP 7.3 reached End of Life in December 2021."),
        "7.4": ("High", 7.5, "PHP 7.4 reached End of Life in November 2022."),
    }),
    (r"Apache/([0-9]+\.[0-9]+)", "Apache HTTP Server", {
        "2.2": ("Critical", 9.8, "Apache 2.2 reached End of Life in 2017. Multiple critical CVEs unpatched."),
    }),
    (r"OpenSSL/([0-9]+\.[0-9]+)", "OpenSSL", {
        "1.0": ("Critical", 9.8, "OpenSSL 1.0.x is End of Life. Vulnerable to multiple critical CVEs."),
        "1.1": ("High", 7.5, "OpenSSL 1.1.x reached End of Life in September 2023."),
    }),
    (r"IIS/([0-9]+\.[0-9]+)", "Microsoft IIS", {
        "6.": ("Critical", 9.8, "IIS 6.0 is End of Life since 2015. CVE-2017-7269 is a remotely exploitable RCE."),
        "7.": ("High", 8.0, "IIS 7.x is End of Life since 2015."),
    }),
]


def _check_outdated_software(scan_id, url, headers):
    server    = headers.get("server", "")
    x_powered = headers.get("x-powered-by", "")
    combined  = f"{server} {x_powered}"

    for pattern, software_name, eol_versions in EOL_SOFTWARE:
        match = re.search(pattern, combined, re.IGNORECASE)
        if not match:
            continue
        version = match.group(1)
        for prefix, (severity, cvss, detail) in eol_versions.items():
            if version.startswith(prefix):
                save_finding(
                    scan_id=scan_id,
                    title=f"End-of-Life Software: {software_name} {version}",
                    owasp_id="A06", owasp_label="Vulnerable and Outdated Components",
                    severity=severity, cvss_score=cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=(
                        f"{software_name} version {version} is running on this server. "
                        f"{detail} This version no longer receives security patches."
                    ),
                    endpoint=url,
                    evidence=(
                        f"Server: {server}\n"
                        f"X-Powered-By: {x_powered}\n"
                        f"Version string: {match.group(0)}"
                    ),
                    remediation=(
                        f"Upgrade {software_name} to the latest stable version immediately. "
                        f"Suppress version disclosure after upgrading."
                    ),
                    tool_used="header-check",
                    confidence="confirmed",
                )
                print(f"[SCANNER] EOL SOFTWARE FOUND: {software_name} {version}")
                break


def run_header_checks(scan_id: str, url: str):
    try:
        req      = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        response = urllib.request.urlopen(req, timeout=15)
        headers  = {k.lower(): v for k, v in response.headers.items()}

        # Missing security headers
        required = {
            "content-security-policy":   "prevents XSS and code injection attacks",
            "strict-transport-security": "enforces HTTPS connections",
            "x-frame-options":           "prevents clickjacking attacks",
            "x-content-type-options":    "prevents MIME-type sniffing",
            "referrer-policy":           "controls referrer information leakage",
            "permissions-policy":        "controls browser feature access",
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
                evidence=f"Response headers:\n{json.dumps(dict(headers), indent=2)[:800]}",
                remediation="Add all missing security headers to your web server configuration.",
                tool_used="header-check",
                confidence="confirmed",
            )

        # Unencrypted HTTP
        if url.startswith("http://"):
            save_finding(
                scan_id=scan_id,
                title="Application Served Over Unencrypted HTTP",
                owasp_id="A02", owasp_label="Cryptographic Failures",
                severity="High", cvss_score=5.9,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description="Application accessible over HTTP. Credentials and data transmitted in plaintext.",
                endpoint=url,
                evidence="URL scheme is http:// — TLS/SSL is not in use.",
                remediation="Obtain a TLS certificate. Redirect all HTTP to HTTPS. Configure HSTS.",
                tool_used="header-check",
                confidence="confirmed",
            )

        # Insecure cookies
        cookie_header = headers.get("set-cookie", "")
        if cookie_header:
            issues = []
            if "secure"   not in cookie_header.lower(): issues.append("missing Secure flag")
            if "httponly" not in cookie_header.lower(): issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_header.lower(): issues.append("missing SameSite attribute")
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
                    tool_used="header-check",
                    confidence="confirmed",
                )

        # EOL software
        _check_outdated_software(scan_id, url, headers)

        # Server version disclosure
        server    = headers.get("server", "")
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
                remediation="Suppress version info. nginx: server_tokens off; Apache: ServerTokens Prod.",
                tool_used="header-check",
                confidence="confirmed",
            )

        print("[SCANNER] Phase 1 complete — headers analysed")

    except Exception as e:
        print(f"[SCANNER] Phase 1 error: {e}")
