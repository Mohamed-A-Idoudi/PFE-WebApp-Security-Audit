"""
Phase 3 — Directory & path exposure using ffuf + SecLists
Replaces hardcoded 35-path list with ffuf fuzzing against SecLists wordlists.
Falls back to hardcoded list if ffuf/SecLists not available.
ffuf: https://github.com/ffuf/ffuf — already in Kali
SecLists: /usr/share/seclists/ — already in Kali
"""
import os
import json
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep


# SecLists wordlists available in Kali — ordered by preference
WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

# Severity mapping by path pattern — used to classify ffuf hits
SEVERITY_MAP = [
    # Critical
    (["/.git", "/.env", "/encryptionkeys", "/actuator/env",
      "/db.sql", "/database.sql", "/dump.sql", "/.aws"],
     "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "A01", "Broken Access Control"),
    # High
    (["/admin", "/administration", "/backup", "/phpinfo.php",
      "/info.php", "/wp-admin", "/actuator"],
     "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "A05", "Security Misconfiguration"),
    # Medium
    (["/swagger", "/api-docs", "/server-status", "/server-info",
      "/wp-login", "/xmlrpc"],
     "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "A05", "Security Misconfiguration"),
]

# Content verification patterns per path type
CONTENT_PATTERNS = {
    "backup":       [".sql", ".tar", ".gz", ".zip", ".bak", "index of", "directory"],
    "admin":        ["admin", "dashboard", "login", "panel", "management"],
    ".env":         ["key=", "secret=", "password=", "db_", "token=", "app_key"],
    ".git":         ["repositoryformatversion", "[core]", "ref:", "HEAD"],
    "phpinfo":      ["php version", "phpinfo()"],
    "swagger":      ["swagger", "openapi", "api documentation"],
    "actuator":     ["health", "metrics", "env", "beans", "mappings"],
    "ftp":          ["href=", ".md", ".bak", "index of", "file"],
}

SPA_MARKERS = [
    "data-beasties-container", "mat-app-background", "ng-version",
    "<app-root", "__webpack_require__", "routes/angular",
    "polyfills.js",
]


def _get_wordlist() -> str:
    for path in WORDLISTS:
        if os.path.exists(path):
            return path
    return ""


def _classify_path(path: str):
    """Return (severity, cvss, vector, owasp_id, owasp_label) for a path."""
    pl = path.lower()
    for patterns, severity, cvss, vector, oid, olabel in SEVERITY_MAP:
        if any(p in pl for p in patterns):
            return severity, cvss, vector, oid, olabel
    return "Low", 3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05", "Security Misconfiguration"


def _verify_content(url: str, path: str) -> tuple:
    """Returns (genuine: bool, snippet: str)"""
    try:
        req      = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        response = urllib.request.urlopen(req, timeout=8)
        content  = response.read(50000).decode("utf-8", errors="ignore")
        cl       = content.lower()

        # SPA shell check
        if any(m in cl for m in SPA_MARKERS):
            api_paths = ["/.git", "/.env", "/ftp", "/encryptionkeys", "/api/", "/rest/"]
            if not any(p in path for p in api_paths):
                return False, ""

        # Soft 404
        if any(s in cl for s in ["page not found", "404", "introuvable"]):
            return False, ""

        # Per-path content verification
        pl = path.lower()
        for pattern_key, keywords in CONTENT_PATTERNS.items():
            if pattern_key in pl:
                if not any(k in cl for k in keywords):
                    print(f"[SCANNER] {path} returned 200 but content doesn't match — skipping")
                    return False, ""
                break

        return True, content[:400]
    except Exception:
        return False, ""


# High-value sensitive paths — probed directly on every target
TARGETED_PATHS = [
    "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config", "/.gitignore",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin", "/admin/", "/administration", "/administrator",
    "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
    "/server-status", "/server-info",
    "/swagger.json", "/swagger-ui.html", "/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/openapi.yaml", "/graphql", "/graphiql",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/actuator/beans", "/actuator/dump",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/ftp/", "/encryptionkeys/",
    "/config.php", "/config.js", "/config.json", "/settings.php",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.htpasswd",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/console", "/h2-console", "/adminer.php", "/phpmyadmin/",
    "/.DS_Store", "/Thumbs.db",
    "/api/v1/users", "/api/users", "/api/admin",
    "/rest/user/whoami", "/rest/admin/application-configuration",
]


def _probe_sensitive_paths(url: str, scan_id: str, is_spa: bool = False) -> int:
    """Directly probe high-value sensitive paths — fast, no timeout risk."""
    base      = url.rstrip("/")
    confirmed = 0
    spa_size  = 0

    for path in TARGETED_PATHS:
        target_url = f"{base}{path}"
        try:
            req  = urllib.request.Request(
                target_url,
                headers={"User-Agent": random_ua()}
            )
            resp   = urllib.request.urlopen(req, timeout=8)
            status = resp.status

            if status not in (200, 201, 301, 302, 403):
                continue

            content = resp.read(50000).decode("utf-8", errors="ignore")

            # Skip SPA shell responses when SPA is confirmed
            if is_spa and spa_size > 0 and abs(len(content) - spa_size) < 50:
                continue

            genuine, snippet = _verify_content(target_url, path)
            if not genuine and status == 200:
                continue

            # 403 on admin paths is itself a finding — path exists
            if status == 403 and any(p in path for p in ["/admin", "/wp-admin", "/actuator"]):
                genuine = True
                snippet = "HTTP 403 — path exists but access denied"

            if not genuine:
                continue

            severity, cvss, vector, owasp_id, owasp_label = _classify_path(path)

            title = f"Exposed Path: {path}"
            if ".env" in path:
                title = "Environment File Exposed (.env)"
            elif ".git" in path:
                title = "Git Repository Exposed"
            elif "backup" in path or ".sql" in path:
                title = "Backup File Exposed"
            elif "phpinfo" in path:
                title = "PHP Info Page Exposed"
            elif "swagger" in path or "openapi" in path or "api-docs" in path:
                title = "API Documentation Publicly Exposed"
            elif "actuator" in path:
                title = "Spring Boot Actuator Exposed"
            elif "admin" in path:
                title = "Admin Panel Exposed"
            elif ".aws" in path or ".ssh" in path:
                title = "Cloud/SSH Credentials File Exposed"
                severity, cvss = "Critical", 9.8

            save_finding(
                scan_id=scan_id, title=title,
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=severity, cvss_score=cvss, cvss_vector=vector,
                description=f"{path} is accessible without authentication (HTTP {status}).",
                endpoint=target_url,
                evidence=f"HTTP {status}\nContent preview:\n{snippet[:300]}",
                remediation=(
                    "Restrict access via web server configuration. "
                    "Remove sensitive files from web root. "
                    "Require authentication for admin paths."
                ),
                tool_used="dir-probe",
                confidence="confirmed",
            )
            confirmed += 1
            print(f"[SCANNER] ✓ Sensitive path confirmed: {path} (HTTP {status})")

        except urllib.error.HTTPError as e:
            # 403 on admin paths = path exists
            if e.code == 403 and any(p in path for p in ["/admin", "/wp-admin", "/actuator", "/phpmyadmin"]):
                severity, cvss, vector, oid, olabel = _classify_path(path)
                save_finding(
                    scan_id=scan_id,
                    title=f"Admin Path Exists — Access Restricted: {path}",
                    owasp_id=oid, owasp_label=olabel,
                    severity="Medium", cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    description=f"{path} returned HTTP 403 — the path exists but is currently restricted.",
                    endpoint=target_url,
                    evidence="HTTP 403 response to unauthenticated request",
                    remediation="Verify access controls are correctly enforced. Monitor for bypass attempts.",
                    tool_used="dir-probe",
                    confidence="probable",
                )
                confirmed += 1
                print(f"[SCANNER] ✓ Admin path exists (403): {path}")
        except Exception:
            pass

    return confirmed


def _run_ffuf(url: str, wordlist: str, scan_id: str, request_delay: float = 0) -> list:
    base = url.rstrip("/")

    # Get the SPA index.html size to use as filter
    try:
        req      = urllib.request.Request(
            f"{base}/this_path_does_not_exist_securiscan",
            headers={"User-Agent": random_ua()}
        )
        response = urllib.request.urlopen(req, timeout=5)
        spa_size = len(response.read())
        print(f"[SCANNER] ffuf: SPA baseline size = {spa_size} bytes")
    except Exception:
        spa_size = 0

    output_file = f"/tmp/ffuf_{scan_id}.json"
    target      = f"{base}/FUZZ"

    cmd = [
        "ffuf", "-u", target, "-w", wordlist,
        "-o", output_file, "-of", "json",
        "-mc", "all",
        "-fc", "404",
        "-t", "20",
        "-rate", "10" if request_delay > 0 else "50",
        "-timeout", "8",
        "-H", f"User-Agent: {random_ua()}",
        "-s", "-p", "0.1-1.0",
        "-recursion-depth", "0",
    ]
    if spa_size > 0:
        cmd += ["-fs", str(spa_size)]

    print(f"[SCANNER] ffuf → {base} [{wordlist.split('/')[-1]}]")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("[SCANNER] ffuf timeout after 180s")
    except FileNotFoundError:
        print("[SCANNER] ffuf not installed")
        return []
    except Exception as e:
        print(f"[SCANNER] ffuf error: {e}")
        return []

    if request_delay > 0:
        random_sleep(request_delay * 0.5, request_delay * 2.0)
    if not os.path.exists(output_file):
        return []

    hits = []
    try:
        with open(output_file) as f:
            data = json.load(f)
        for result in data.get("results", []):
            path   = "/" + result.get("input", {}).get("FUZZ", "")
            status = result.get("status", 0)
            hits.append({"path": path, "status": status, "url": f"{base}{path}"})
        print(f"[SCANNER] ffuf: {len(hits)} hits before content verification")
    except Exception as e:
        print(f"[SCANNER] ffuf parse error: {e}")
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)

    return hits


def run_directory_checks(scan_id: str, url: str, request_delay: float = 0, fingerprint: dict = None):
    import time

    wordlist = _get_wordlist()

    # ── Determine is_spa FIRST before any function calls that use it ──
    is_spa = (fingerprint or {}).get("is_spa", False)
    if is_spa:
        print("[SCANNER] Phase 3: SPA confirmed by Phase 0c — targeted probe only")

    # Determine is_local for ffuf decision
    parsed   = urllib.parse.urlparse(url)
    is_local = (
        parsed.port in (3000, 8080, 8000) or
        (parsed.hostname or "").replace(".", "").isdigit() or
        (parsed.hostname or "") in ("localhost", "juiceshop")
    )

    # Always run targeted sensitive path probing first — fast and reliable
    print("[SCANNER] Phase 3: Probing sensitive paths")
    confirmed = _probe_sensitive_paths(url, scan_id, is_spa)
    print(f"[SCANNER] Phase 3 (targeted): {confirmed} confirmed findings")

    # Run ffuf wordlist only for local/lab targets — external targets timeout
    if wordlist and is_local:
        hits       = _run_ffuf(url, wordlist, scan_id, request_delay)
        confirmed2 = 0

        for hit in hits:
            path       = hit["path"]
            target_url = hit["url"]
            status     = hit["status"]

            genuine, snippet = _verify_content(target_url, path)
            if not genuine:
                continue

            severity, cvss, vector, owasp_id, owasp_label = _classify_path(path)

            save_finding(
                scan_id=scan_id, title=f"Exposed Path: {path}",
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=severity, cvss_score=cvss, cvss_vector=vector,
                description=f"{path} accessible without authentication (HTTP {status}).",
                endpoint=target_url,
                evidence=f"HTTP {status}\nContent:\n{snippet[:300]}",
                remediation="Restrict access. Require authentication. Remove if not needed.",
                tool_used="ffuf",
                confidence="confirmed",
            )
            confirmed2 += 1
            print(f"[SCANNER] ✓ ffuf confirmed: {path}")

        print(f"[SCANNER] Phase 3 (ffuf): {confirmed2} additional findings")

    # CORS check always runs regardless
    _check_cors(scan_id, url)
    print("[SCANNER] Phase 3 complete")


def _check_cors(scan_id: str, url: str):
    try:
        req      = urllib.request.Request(
            url,
            headers={
                "User-Agent": random_ua(),
                "Origin": "https://evil-attacker.com",
            }
        )
        response  = urllib.request.urlopen(req, timeout=10)
        resp_hdrs = {k.lower(): v for k, v in response.headers.items()}
        cors      = resp_hdrs.get("access-control-allow-origin", "")
        if cors == "*":
            save_finding(
                scan_id=scan_id, title="Wildcard CORS Policy",
                owasp_id="A05", owasp_label="Security Misconfiguration",
                severity="Medium", cvss_score=5.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
                description="Access-Control-Allow-Origin: * allows any website to read API responses.",
                endpoint=url,
                evidence=f"Origin: https://evil-attacker.com → ACAO: {cors}",
                remediation="Replace wildcard with explicit trusted origins.",
                tool_used="cors-check",
                confidence="confirmed",
            )
    except Exception:
        pass


# Minimal fallback if ffuf/SecLists unavailable
FALLBACK_PATHS = [
    "/.env", "/.git/HEAD", "/admin", "/administration", "/phpinfo.php",
    "/info.php", "/backup", "/server-status", "/swagger", "/api-docs",
    "/actuator", "/actuator/env", "/ftp/", "/encryptionkeys/",
    "/wp-admin/", "/wp-login.php", "/xmlrpc.php",
]


def _run_fallback(scan_id: str, url: str, request_delay: float):
    import time
    base = url.rstrip("/")
    for path in FALLBACK_PATHS:
        target_url = f"{base}{path}"
        try:
            req      = urllib.request.Request(target_url, headers={"User-Agent": random_ua()})
            response = urllib.request.urlopen(req, timeout=8)
            if response.status in [200, 201]:
                genuine, snippet = _verify_content(target_url, path)
                if not genuine:
                    continue
                severity, cvss, vector, oid, olabel = _classify_path(path)
                save_finding(
                    scan_id=scan_id, title=f"Exposed Path: {path}",
                    owasp_id=oid, owasp_label=olabel,
                    severity=severity, cvss_score=cvss, cvss_vector=vector,
                    description=f"{path} accessible without authentication.",
                    endpoint=target_url,
                    evidence=f"HTTP {response.status}\n{snippet[:200]}",
                    remediation="Restrict access or remove if not needed.",
                    tool_used="dir-check",
                    confidence="confirmed",
                )
                print(f"[SCANNER] ✓ Fallback confirmed: {path}")
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass
        if request_delay > 0:
            time.sleep(request_delay)