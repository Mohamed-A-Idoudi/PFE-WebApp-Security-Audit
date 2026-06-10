"""
Phase 4 — Authentication testing
- Default credential testing: SecLists default-passwords CSV
  /usr/share/seclists/Passwords/Default-Credentials/
- Rate limit testing: Hydra HTTP brute force
- Login endpoint discovery: 4 dynamic layers (OpenAPI, JS, robots, HTML forms)
"""
import os
import re
import json
import csv
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


# SecLists credential files — ordered by relevance
SECLISTS_CRED_FILES = [
    "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv",
    "/usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt",
]

# Minimal fallback if SecLists not installed
FALLBACK_CREDENTIALS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
    ("admin", "1234"), ("admin", ""), ("administrator", "administrator"),
    ("root", "root"), ("root", "toor"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("demo", "demo"),
]

TECH_LOGIN_PATHS = {
    "wordpress": ["/wp-login.php", "/wp-admin/"],
    "drupal":    ["/user/login"],
    "joomla":    ["/administrator/index.php"],
    "generic":   ["/login", "/signin", "/api/login", "/api/auth/login",
                  "/rest/user/login", "/api/v1/auth/login", "/auth/login"],
}


def _load_credentials(tech: str = "") -> list:
    """
    Load credentials from SecLists default-passwords CSV.
    Filters by detected technology if available.
    Falls back to minimal hardcoded list if SecLists unavailable.
    """
    for cred_file in SECLISTS_CRED_FILES:
        if not os.path.exists(cred_file):
            continue
        try:
            creds = []
            with open(cred_file, encoding="utf-8", errors="ignore") as f:
                # Try CSV first
                if cred_file.endswith(".csv"):
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) >= 2:
                            username = row[0].strip()
                            password = row[1].strip()
                            if username and len(username) < 50:
                                creds.append((username, password))
                else:
                    # Plain text format: user:pass
                    for line in f:
                        line = line.strip()
                        if ":" in line:
                            parts = line.split(":", 1)
                            creds.append((parts[0].strip(), parts[1].strip()))

            # Filter by technology if detected
            if tech and tech not in ["generic"]:
                filtered = [(u, p) for u, p in creds
                           if tech.lower() in u.lower() or tech.lower() in p.lower()]
                if filtered:
                    print(f"[SCANNER] SecLists: {len(filtered)} creds for {tech}")
                    return filtered[:50]

            print(f"[SCANNER] SecLists: {len(creds)} credentials loaded")
            return creds[:100]  # cap at 100 to avoid excessive testing

        except Exception as e:
            print(f"[SCANNER] SecLists load error: {e}")

    print("[SCANNER] SecLists not found — using fallback credentials")
    return FALLBACK_CREDENTIALS


def _fetch(url: str, timeout: int = 8) -> tuple:
    try:
        req  = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        resp = urllib.request.urlopen(req, timeout=timeout)
        ct   = resp.headers.get("Content-Type", "")
        return resp.read(500000).decode("utf-8", errors="ignore"), ct
    except Exception:
        return "", ""


def _layer1_openapi(base: str) -> list:
    endpoints = []
    for path in ["/api-docs", "/swagger.json", "/openapi.json",
                 "/api/swagger.json", "/v1/api-docs"]:
        content, ct = _fetch(f"{base}{path}")
        if not content or "application/json" not in ct:
            continue
        try:
            spec  = json.loads(content)
            paths = spec.get("paths", {})
            for ep, methods in paths.items():
                for method, details in methods.items():
                    if method.lower() != "post":
                        continue
                    info = (details.get("operationId", "") +
                            details.get("summary", "") +
                            str(details.get("tags", []))).lower()
                    if any(k in info for k in ["login", "auth", "signin", "token"]):
                        endpoints.append(f"{base}{ep}")
                        print(f"[SCANNER] OpenAPI auth endpoint: {base}{ep}")
        except Exception:
            pass
    return endpoints


def _layer2_javascript(base: str, html: str) -> list:
    endpoints = []
    script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
    js_sources  = [html]
    for src in script_urls[:5]:
        if src.startswith("//"): src = f"https:{src}"
        elif src.startswith("/"): src = f"{base}{src}"
        elif not src.startswith("http"): continue
        content, _ = _fetch(src)
        if content: js_sources.append(content)

    seen = set()
    for js in js_sources:
        for pattern in [
            r'["\'](/(?:api|rest|auth)/[^"\']*(?:login|auth|token)[^"\']*)["\']',
            r'(?:url|endpoint)\s*[:=]\s*["\']([^"\']*(?:login|auth)[^"\']*)["\']',
        ]:
            for match in re.findall(pattern, js, re.I):
                if match.startswith("/") and match not in seen and len(match) < 100:
                    seen.add(match)
                    endpoints.append(f"{base}{match}")
    return endpoints[:10]


def _layer3_robots(base: str) -> list:
    endpoints = []
    for path in ["/robots.txt", "/sitemap.xml"]:
        content, _ = _fetch(f"{base}{path}")
        if not content: continue
        for p in re.findall(r'(?:Disallow|Allow|loc):\s*([^\s<]+)', content):
            if any(k in p.lower() for k in ["login", "auth", "admin"]):
                endpoints.append(f"{base}{p.strip()}")
    return endpoints


def _layer4_html_forms(base: str, html: str) -> list:
    endpoints = []
    if not BS4_AVAILABLE: return endpoints
    try:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            fields = {inp.get("name", ""): inp.get("type", "text").lower()
                      for inp in form.find_all("input") if inp.get("name")}
            if not any(t == "password" for t in fields.values()):
                continue
            action = form.get("action", "")
            if action.startswith("http"):   form_url = action
            elif action.startswith("/"):    form_url = f"{base}{action}"
            else:                           form_url = base
            endpoints.append(form_url)
            print(f"[SCANNER] HTML form login: {form_url}")
    except Exception:
        pass
    return endpoints


def _is_login_endpoint(url: str) -> bool:
    path_lower = url.lower()
    is_login_path = any(k in path_lower for k in ["login","signin","auth/token","rest/user"])

    for ct, data in [
        ("application/json",
         json.dumps({"email":"probe@pentest.invalid","password":"WrongProbe!"}).encode()),
        ("application/x-www-form-urlencoded",
         b"username=probe%40pentest.invalid&password=WrongProbe"),
    ]:
        try:
            req = urllib.request.Request(url, data=data,
                headers={"Content-Type": ct, "User-Agent": random_ua()}, method="POST")
            try:
                resp    = urllib.request.urlopen(req, timeout=5)
                content = resp.read(500).decode("utf-8", errors="ignore")
                rct     = resp.headers.get("Content-Type", "")
                if "application/json" in rct or content.strip().startswith("{"):
                    return True
                if "<html" in content.lower() or "<!doctype" in content.lower():
                    return False
                return True
            except urllib.error.HTTPError as e:
                body = ""
                try: body = e.read(500).decode("utf-8", errors="ignore")
                except: pass
                if e.code in [400, 422]: return True
                if e.code == 401:
                    ct2 = ""
                    try: ct2 = e.headers.get("Content-Type", "")
                    except: pass
                    if body.strip().startswith("{") or "application/json" in ct2: return True
                    if is_login_path: return True
                if e.code == 500:
                    if any(k in body.lower() for k in ["syntaxerror","json","unexpected token"]):
                        return True
        except Exception:
            pass
    return False


def _test_default_credentials(scan_id: str, login_url: str, tech: str):
    """Test credentials from SecLists against a confirmed login endpoint."""
    credentials = _load_credentials(tech)
    print(f"[SCANNER] Testing {len(credentials)} credentials on {login_url}")

    for username, password in credentials:
        for ct, data in [
            ("application/json",
             json.dumps({"email": username, "password": password}).encode()),
            ("application/x-www-form-urlencoded",
             urllib.parse.urlencode({"username": username, "password": password}).encode()),
        ]:
            try:
                req = urllib.request.Request(login_url, data=data,
                    headers={"Content-Type": ct, "User-Agent": random_ua()}, method="POST")
                try:
                    resp    = urllib.request.urlopen(req, timeout=5)
                    content = resp.read(1000).decode("utf-8", errors="ignore").lower()
                    if resp.status == 200:
                        if any(k in content for k in ["token","jwt","dashboard",
                                                       "welcome","logout","profile"]):
                            save_finding(
                                scan_id=scan_id,
                                title=f"Default Credentials Accepted: {username}/{password or '(empty)'}",
                                owasp_id="A07",
                                owasp_label="Identification and Authentication Failures",
                                severity="Critical", cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                description=f"Application accepted default credentials '{username}'/'{password}'.",
                                endpoint=login_url,
                                evidence=f"POST {login_url}\nCredentials: {username}/{password}\nHTTP 200 with auth success indicators",
                                remediation="Change all default credentials. Enforce strong password policy.",
                                tool_used="auth-check", confidence="confirmed",
                                attack_type="default_credentials",
                            )
                            print(f"[SCANNER] DEFAULT CREDENTIALS: {username}/{password}")
                            return True
                except urllib.error.HTTPError:
                    pass
            except Exception:
                pass
    return False


def _test_rate_limiting_hydra(scan_id: str, login_url: str) -> bool:
    """
    Test rate limiting using Hydra HTTP POST brute force.
    15 attempts — covers thresholds up to 10, spans 30s for WAF detection.
    """
    parsed   = urllib.parse.urlparse(login_url)
    host     = parsed.netloc
    path     = parsed.path or "/"
    use_ssl  = parsed.scheme == "https"

    # Create temporary wordlists for Hydra
    user_file = f"/tmp/hydra_users_{scan_id}.txt"
    pass_file = f"/tmp/hydra_pass_{scan_id}.txt"

    with open(user_file, "w") as f:
        for i in range(15):
            f.write(f"probe_{i}@pentest.invalid\n")

    with open(pass_file, "w") as f:
        for i in range(15):
            f.write(f"WrongPassword_{i}_SecuriScan!\n")

    try:
        cmd = [
            "hydra",
            "-L", user_file,
            "-P", pass_file,
            "-s", str(parsed.port or (443 if use_ssl else 80)),
            "-t", "1",           # 1 thread — sequential, not parallel
            "-w", "2",           # 2s wait between attempts
            "-f",                # stop on first success (not expected here)
            "-o", f"/tmp/hydra_out_{scan_id}.txt",
        ]
        if use_ssl:
            cmd.append("-S")

        # Use https-post-form or http-post-form
        proto   = "https-post-form" if use_ssl else "http-post-form"
        form_str = f"{path}:email=^USER^&password=^PASS^:Invalid credentials"
        cmd += [f"{host}", proto, form_str]

        print(f"[SCANNER] Hydra rate limit test → {login_url}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + result.stderr

        # If hydra completed 15 attempts without mentioning rate limiting → no protection
        if "too many" in output.lower() or "429" in output or "rate" in output.lower():
            print(f"[SCANNER] Rate limiting confirmed (Hydra)")
            return True  # Protected

        # No rate limiting response observed
        save_finding(
            scan_id=scan_id,
            title="No Rate Limiting on Authentication Endpoint",
            owasp_id="A07", owasp_label="Identification and Authentication Failures",
            severity="High", cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=(
                f"Hydra completed 15 consecutive login attempts against {login_url} "
                f"without triggering rate limiting or account lockout."
            ),
            endpoint=login_url,
            evidence=(
                f"Tool: Hydra HTTP POST brute force\n"
                f"Attempts: 15 sequential requests\n"
                f"No HTTP 429 or rate-limit response detected.\n"
                f"Output: {output[:300]}"
            ),
            remediation=(
                "Implement rate limiting: max 5 failed attempts/IP/minute. "
                "Add CAPTCHA after 3 failures. "
                "Account lockout after 10 failures."
            ),
            tool_used="hydra", confidence="confirmed",
            attack_type="no_rate_limiting",
        )
        print(f"[SCANNER] No rate limiting confirmed (Hydra)")
        return False

    except subprocess.TimeoutExpired:
        print("[SCANNER] Hydra timeout")
    except FileNotFoundError:
        print("[SCANNER] Hydra not installed — falling back to urllib test")
        return _test_rate_limiting_fallback(scan_id, login_url)
    except Exception as e:
        print(f"[SCANNER] Hydra error: {e}")
    finally:
        for f in [user_file, pass_file, f"/tmp/hydra_out_{scan_id}.txt"]:
            if os.path.exists(f): os.remove(f)

    return False


def _test_rate_limiting_fallback(scan_id: str, login_url: str) -> bool:
    """urllib fallback when Hydra unavailable."""
    responses = []
    for i in range(15):
        try:
            data = json.dumps({
                "email":    f"securiscan_probe_{i}@pentest.invalid",
                "password": f"WrongPassword_{i}_SecuriScan!",
            }).encode()
            req  = urllib.request.Request(login_url, data=data,
                headers={"Content-Type": "application/json",
                         "User-Agent": random_ua()}, method="POST")
            try:
                resp = urllib.request.urlopen(req, timeout=5)
                responses.append(resp.status)
            except urllib.error.HTTPError as e:
                responses.append(e.code)
                if e.code == 429: return True
        except Exception:
            break

    if 429 not in responses and len(responses) >= 13:
        save_finding(
            scan_id=scan_id,
            title="No Rate Limiting on Authentication Endpoint",
            owasp_id="A07", owasp_label="Identification and Authentication Failures",
            severity="High", cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            description=f"Endpoint {login_url} accepted {len(responses)} failed login attempts without rate limiting.",
            endpoint=login_url,
            evidence=f"Sent 15 POST requests. Responses: {responses}. No HTTP 429 returned.",
            remediation="Implement rate limiting. Add CAPTCHA. Account lockout after 10 failures.",
            tool_used="auth-check", confidence="confirmed",
            attack_type="no_rate_limiting",
        )
        return False
    return True


def run_auth_checks(scan_id: str, url: str):
    base = url.rstrip("/")
    print(f"[SCANNER] Auth discovery → {url}")

    html, _ = _fetch(url)

    # Detect technology
    tech = "generic"
    hl   = html.lower()
    if "wp-content" in hl: tech = "wordpress"
    elif "drupal" in hl:    tech = "drupal"
    elif "joomla" in hl:    tech = "joomla"

    # 4-layer dynamic discovery
    candidates = set()
    candidates.update(_layer1_openapi(base))
    candidates.update(_layer2_javascript(base, html))
    candidates.update(_layer3_robots(base))
    candidates.update(_layer4_html_forms(base, html))

    print(f"[SCANNER] Dynamic discovery: {len(candidates)} candidates")

    # Fallback to technology-aware paths
    if not candidates:
        print(f"[SCANNER] Using {tech} fallback paths")
        for path in TECH_LOGIN_PATHS.get(tech, TECH_LOGIN_PATHS["generic"]):
            candidates.add(f"{base}{path}")

    # Confirm each candidate
    confirmed = []
    for candidate in list(candidates)[:15]:
        if _is_login_endpoint(candidate):
            confirmed.append(candidate)
            print(f"[SCANNER] Login confirmed: {candidate}")

    if not confirmed:
        print("[SCANNER] No login endpoints confirmed")
        return

    # Test each confirmed endpoint
    for login_url in confirmed[:3]:
        _test_default_credentials(scan_id, login_url, tech)
        _test_rate_limiting_hydra(scan_id, login_url)

    print("[SCANNER] Phase 4 complete")
