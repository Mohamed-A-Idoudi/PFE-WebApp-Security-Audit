"""
Phase 7 — SQL injection detection (detection-only, no exploitation)
Universal: works on any web target — REST APIs, WordPress, PHP, Node.js.
Pipeline: Katana feeds → live validation → DBMS detection → UNION+Error testing.
"""
import os
import re
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep


# ── Skip lists ────────────────────────────────────────────────────────────────
SKIP_EXTENSIONS = {
    '.css', '.js', '.min.js', '.min.css', '.png', '.jpg', '.jpeg',
    '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
    '.map', '.xml', '.txt', '.pdf', '.zip', '.gz', '.tar',
}

SKIP_PATH_FRAGMENTS = [
    '/wp-content/themes/', '/wp-content/plugins/', '/wp-includes/',
    '/assets/', '/static/', '/dist/', '/build/', '/vendor/',
    'fonts.googleapis', 'fonts.gstatic', 'cdn.', 'i0.wp.com',
]

# Params that are URL/format-type — structurally not SQL injectable
SQLI_PARAM_BLACKLIST = {
    'url', 'callback', 'redirect', 'format', 'feed', 'to',
    'next', 'return', 'redir', 'dest', 'destination',
    'action', 'uri', 'link', 'href', 'src', 'source',
}

# Params statistically most likely to be injectable — tested first
SQLI_PARAM_PRIORITY = [
    'id', 'p', 'page_id', 'cat', 'post', 'product_id',
    'item', 'user_id', 'order_id', 'news_id', 'article_id',
    'q', 'search', 's', 'query', 'keyword', 'name',
]

# DB error fingerprints — used for real DBMS detection
DBMS_ERROR_SIGNATURES = {
    "sqlite":     [
        "sqlite", "no such table", "unrecognized token",
        "syntax error", "sqlite3.operationalerror",
    ],
    "mysql":      [
        "you have an error in your sql syntax",
        "mysql_fetch", "mysql_num_rows", "warning: mysql",
        "supplied argument is not a valid mysql",
        "mysql server version for the right syntax",
    ],
    "postgresql": [
        "pg_query", "pg_exec", "postgresql", "psql",
        "unterminated quoted identifier", "syntax error at or near",
        "pg_escape_string",
    ],
    "mssql":      [
        "microsoft sql server", "odbc sql server",
        "ole db provider for sql server", "unclosed quotation mark",
        "incorrect syntax near",
    ],
    "oracle":     [
        "ora-", "oracle error", "quoted string not properly terminated",
        "sql command not properly ended",
    ],
}

# Universal REST/param patterns — probed on every target
COMMON_REST_PATTERNS = [
    # Generic search
    "/api/search?q=test",
    "/api/v1/search?q=test",
    "/api/v2/search?q=test",
    "/search?q=test",
    "/search?query=test",
    "/search?keyword=test",
    # Generic ID params
    "/api/users?id=1",
    "/api/v1/users?id=1",
    "/api/products?id=1",
    "/api/items?id=1",
    "/api/posts?id=1",
    "/api/articles?id=1",
    "/api/news?id=1",
    "/api/categories?id=1",
    # Generic name/search
    "/api/products?search=test",
    "/api/products?name=test",
    "/api/products?q=test",
    # WordPress
    "/?p=1",
    "/?page_id=1",
    "/?cat=1",
    "/?tag=1",
    # Classic PHP
    "/index.php?id=1",
    "/news.php?id=1",
    "/article.php?id=1",
    "/product.php?id=1",
    "/page.php?id=1",
    "/view.php?id=1",
    "/detail.php?id=1",
    "/rest/products/search?q=test",
    "/rest/search?q=test",
    "/rest/items/search?q=test",
    "/rest/articles/search?q=test",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_injectable_endpoint(url: str, base_domain: str) -> bool:
    """Return True only for same-domain parameterized non-asset URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc and parsed.netloc != base_domain:
            return False
        if not parsed.query or "=" not in parsed.query:
            return False
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return False
        if any(frag in url.lower() for frag in SKIP_PATH_FRAGMENTS):
            return False
        params = {k.lower() for k in urllib.parse.parse_qs(parsed.query)}
        if params and params.issubset(SQLI_PARAM_BLACKLIST):
            return False
        return True
    except Exception:
        return False


def _is_live_endpoint(url: str) -> bool:
    """
    Return True if the URL returns a non-trivial response.
    Eliminates 404s and empty API stubs before sending to SQLmap.
    """
    try:
        req  = urllib.request.Request(url, headers=evasion_headers())
        resp = urllib.request.urlopen(req, timeout=6)
        if resp.status not in (200, 201):
            return False
        content = resp.read(2000)
        # Skip empty JSON responses — endpoint exists but returns no data
        if content.strip() in (b'', b'[]', b'{}', b'null', b'""'):
            return False
        return True
    except Exception:
        return False


def _is_local_target(url: str) -> bool:
    """True for lab/internal targets — gets stronger SQLmap settings."""
    parsed = urllib.parse.urlparse(url)
    host   = (parsed.hostname or "").lower()
    port   = parsed.port or 0
    return (
        port in (3000, 8080, 8000, 8443, 5000, 8888) or
        host in ("localhost", "127.0.0.1") or
        host.endswith(".local") or
        bool(re.match(r"^192\.168\.", host)) or
        bool(re.match(r"^10\.", host)) or
        bool(re.match(r"^172\.(1[6-9]|2\d|3[01])\.", host))
    )


def _detect_dbms(url: str) -> str | None:
    """
    Real DBMS detection: inject a syntax-breaking quote and read the error.
    Falls back to path/host heuristics for WordPress targets.
    Returns a --dbms string or None (let sqlmap auto-detect).
    """
    parsed = urllib.parse.urlparse(url)

    # Build probe URLs — one clean, one with a broken quote
    probes = [url]
    if parsed.query:
        probes.insert(0, url.rstrip("'") + "'")

    for probe in probes:
        for method in ("GET", "POST"):
            try:
                req = urllib.request.Request(
                    probe,
                    headers=evasion_headers(),
                    method=method,
                )
                try:
                    resp = urllib.request.urlopen(req, timeout=8)
                    body = resp.read(4000).decode("utf-8", errors="ignore").lower()
                except urllib.error.HTTPError as e:
                    body = (e.read(4000) or b"").decode("utf-8", errors="ignore").lower()

                for dbms, sigs in DBMS_ERROR_SIGNATURES.items():
                    if any(s in body for s in sigs):
                        print(f"[SCANNER] SQLmap: DBMS fingerprinted → {dbms}")
                        return dbms
            except Exception:
                pass

    # Structural fallback for well-known stacks
    path = parsed.path.lower()
    host = (parsed.hostname or "").lower()
    if any(wp in path for wp in ["/wp-content/", "/wp-json/", "/wp-admin/"]):
        return "mysql"
    if any(wp in host for wp in ["wordpress", "wp."]):
        return "mysql"

    print("[SCANNER] SQLmap: DBMS not fingerprinted — letting sqlmap auto-detect")
    return None


def _get_sqlmap_flags(dbms_flags: list, use_tor: bool, is_local: bool) -> tuple:
    """
    Build sqlmap flag list and per-URL timeout.

    Technique choice:
      U = UNION-based    — instant (1-3 requests), requires visible output
      E = Error-based    — instant (1 request), requires visible DB errors
      B = Boolean-blind  — slow (200+ requests), works on hardened apps
                           NOT included — too slow for automated scanning

    Local targets get slightly higher level/risk since they're controlled lab environments.
    External targets get conservative settings to avoid blocking.
    """
    common = [
        "--batch",
        "--random-agent",
        "--no-cast",
        "--disable-coloring",
        "--retries=1",
        "--timeout=20",
        f"--headers=X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1",
    ] + dbms_flags

    if use_tor:
        common += ["--proxy=socks5://127.0.0.1:9050", "--tor-type=SOCKS5"]

    if is_local:
        flags = common + [
            "--level=3",
            "--risk=2",
            "--technique=UE",   # UNION + Error — fast and sufficient for lab targets
            "--time-sec=5",
            "--threads=1",
            "--delay=0",
        ]
        timeout_per_url = 90   # 90s is more than enough for UE on a local target
    else:
        flags = common + [
            "--level=2",
            "--risk=1",
            "--technique=UE",   # UNION + Error — safe for production targets
            "--time-sec=3",
            "--threads=1",
            "--delay=1",
            "--tamper=space2comment,between",   # basic WAF evasion on every request
        ]
        timeout_per_url = 60

    return flags, timeout_per_url


def _prioritize_targets(targets) -> list:
    """Sort by param priority. Blacklisted-only param URLs bubble to back."""
    def _score(url):
        try:
            params = {
                k.lower()
                for k in urllib.parse.parse_qs(
                    urllib.parse.urlparse(url).query
                )
            }
            if params and params.issubset(SQLI_PARAM_BLACKLIST):
                return 999
            for i, p in enumerate(SQLI_PARAM_PRIORITY):
                if p in params:
                    return i
            return len(SQLI_PARAM_PRIORITY)
        except Exception:
            return len(SQLI_PARAM_PRIORITY)

    return sorted(targets, key=_score)


def _dedup_by_signature(urls) -> list:
    """Remove duplicate URLs that differ only in param value, not param name."""
    seen   = set()
    result = []
    for u in urls:
        try:
            parsed = urllib.parse.urlparse(u)
            params = frozenset(urllib.parse.parse_qs(parsed.query).keys())
            sig    = (parsed.netloc, parsed.path, params)
            if sig not in seen:
                seen.add(sig)
                result.append(u)
        except Exception:
            result.append(u)
    return result


def _save_sqli(scan_id, endpoint, param, evidence):
    save_finding(
        scan_id=scan_id,
        title="SQL Injection Vulnerability Confirmed",
        owasp_id="A03", owasp_label="Injection",
        severity="Critical", cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description=(
            f"SQLmap confirmed SQL injection at {endpoint}. "
            f"Injectable parameter: '{param}'. "
            f"An attacker can read, modify, or delete the entire database "
            f"without authentication."
        ),
        endpoint=endpoint,
        evidence=evidence[:1000],
        remediation=(
            "1. Replace all SQL string concatenation with parameterised queries or ORM.\n"
            "2. Apply input validation — reject unexpected characters in parameters.\n"
            "3. Use a least-privilege database account.\n"
            "4. Enable SQL query logging and alert on anomalous patterns."
        ),
        tool_used="sqlmap",
        confidence="confirmed",
        attack_type="sql_injection",
    )

def _discover_rest_targets(base: str, base_domain: str, is_spa: bool = False) -> set:
    targets  = set()
    
    # Get SPA baseline size first
    spa_size = 0
    if is_spa:
        print("[SCANNER] SQLmap: SPA confirmed by Phase 0c — strict endpoint validation active")

    for path in COMMON_REST_PATTERNS:
        test_url = f"{base}{path}"
        if not _is_injectable_endpoint(test_url, base_domain):
            continue
        try:
            req  = urllib.request.Request(test_url, headers=evasion_headers())
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                content = resp.read()
                # Skip SPA shells — same size as baseline means path doesn't exist
                if spa_size > 0 and abs(len(content) - spa_size) < 200:
                    continue
                if content.strip() not in (b'', b'[]', b'{}', b'null'):
                    targets.add(test_url)
                    print(f"[SCANNER] SQLmap: live REST endpoint → {test_url}")
        except urllib.error.HTTPError as e:
            if e.code not in (404, 405, 403):
                targets.add(test_url)
        except Exception:
            pass
    return targets

def _run_sqlmap(cmd: list, timeout: int) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "timeout"
    except FileNotFoundError:
        return "not_installed"
    except Exception as e:
        return str(e)


def _sqlmap_found_injection(output: str) -> bool:
    ol = output.lower()
    if any(fp in ol for fp in [
        "does not seem to be injectable",
        "does not appear to be dynamic",
        "all tested parameters do not appear",
        "might not be injectable",
    ]):
        return False
    return any(c in ol for c in [
        "is vulnerable",
        "sqlmap identified the following injection point",
        "the back-end dbms is",
        "parameter appears to be",
    ])


def _waf_detected(output: str) -> bool:
    return any(w in output.lower() for w in [
        "protected by some kind of waf",
        "heuristics detected that the target is protected",
        "target appears to be protected",
    ])


def _extract_param(output: str) -> str:
    m = re.search(r"parameter '([^']+)'", output, re.IGNORECASE)
    if m: return m.group(1)
    m = re.search(r"Parameter:\s*(\S+)", output)
    if m: return m.group(1)
    return "unknown"


# ── Main entry-point ──────────────────────────────────────────────────────────

def run_sqlmap(scan_id: str, url: str, crawl_results: dict = None, fingerprint: dict = None, use_tor: bool = False):
    """
    Phase 7 — SQL Injection Detection.
    Universal pipeline:
      1. Discover targets from Katana + REST probing
      2. Live-validate each URL
      3. Dedup by param signature
      4. Fingerprint DBMS from error response
      5. Run sqlmap with UNION+Error technique (fast, non-destructive)
      6. WAF retry with tampers on detection
    """
    base        = url.rstrip("/")
    base_domain = urllib.parse.urlparse(url).netloc
    is_local    = _is_local_target(url)

    print(f"[SCANNER] SQLmap: target type → {'local/lab' if is_local else 'external'}")

    # ── Step 1: collect candidates ────────────────────────────────────────────
    targets: set = set()

    is_spa = (fingerprint or {}).get("is_spa", False)
    rest_targets = _discover_rest_targets(base, base_domain, is_spa)
    targets.update(rest_targets)

    # Katana feed — parameterized URLs + API endpoints
    if crawl_results:
        katana_count = 0
        for key in ("parameterized_urls", "api_endpoints", "urls"):
            for u in crawl_results.get(key, []):
                if _is_injectable_endpoint(u, base_domain):
                    targets.add(u)
                    katana_count += 1
        print(f"[SCANNER] SQLmap: {katana_count} injectable URLs from Katana")

    print(f"[SCANNER] SQLmap: {len(targets)} candidates before validation")

    # ── Step 2: live-validate ─────────────────────────────────────────────────
    live = {u for u in targets if _is_live_endpoint(u)}
    print(f"[SCANNER] SQLmap: {len(live)} live endpoints after validation")

    if not live:
        print("[SCANNER] SQLmap: no live injectable endpoints found — phase skipped")
        print("[SCANNER] Phase 7 complete")
        return

    # ── Step 3: dedup + prioritize ────────────────────────────────────────────
    deduped = _dedup_by_signature(list(live))
    ordered = _prioritize_targets(deduped)
    print(f"[SCANNER] SQLmap: test order → {[t[:70] for t in ordered[:5]]}")

    # ── Step 4: DBMS fingerprint (probe first live URL) ───────────────────────
    dbms = _detect_dbms(f"{base}/rest/products/search?q=test'")
    if not dbms:
        dbms = _detect_dbms(url)
    dbms_flags = ["--dbms", dbms] if dbms else []

    # ── Step 5: build flags ───────────────────────────────────────────────────
    base_flags, timeout_per_url = _get_sqlmap_flags(dbms_flags, use_tor, is_local)

    # ── Step 6: test each endpoint ────────────────────────────────────────────
    tested = set()

    for endpoint in ordered[:15]:
        if endpoint in tested:
            continue
        tested.add(endpoint)

        print(f"[SCANNER] SQLmap testing: {endpoint[:80]}")
        random_sleep(0.3, 1.0)

        cmd    = ["sqlmap", "-u", endpoint] + base_flags
        output = _run_sqlmap(cmd, timeout=timeout_per_url)

        if output == "not_installed":
            print("[SCANNER] SQLmap not installed — phase skipped")
            break

        if output == "timeout":
            print(f"[SCANNER] SQLmap timeout on {endpoint[:60]}")
            continue

        if _sqlmap_found_injection(output):
            _save_sqli(scan_id, endpoint, _extract_param(output), output)
            print(f"[SCANNER] ✓ SQLi CONFIRMED at {endpoint}")
            print("[SCANNER] Phase 7 complete")
            return

        if _waf_detected(output):
            print(f"[SCANNER] WAF detected on {endpoint[:60]} — retrying with tampers")
            tamper_cmd = ["sqlmap", "-u", endpoint] + base_flags + [
                "--tamper=space2comment,between,randomcase,charencode",
                "--headers=X-Forwarded-For: 192.168.1.1",
            ]
            output2 = _run_sqlmap(tamper_cmd, timeout=timeout_per_url)

            if _sqlmap_found_injection(output2):
                _save_sqli(scan_id, endpoint, _extract_param(output2), output2)
                print(f"[SCANNER] ✓ SQLi CONFIRMED (WAF bypass) at {endpoint}")
                print("[SCANNER] Phase 7 complete")
                return
            else:
                save_finding(
                    scan_id=scan_id,
                    title="Potential SQL Injection — WAF Protected",
                    owasp_id="A03", owasp_label="Injection",
                    severity="High", cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=(
                        f"A Web Application Firewall (WAF) is protecting {endpoint} "
                        f"from automated SQL injection probes. The endpoint may be "
                        f"vulnerable but the WAF is blocking confirmation. Manual "
                        f"testing with custom tamper scripts is required."
                    ),
                    endpoint=endpoint,
                    evidence=(
                        f"WAF detected on {endpoint}\n"
                        f"Tampers attempted: space2comment, between, randomcase, charencode\n"
                        f"All payloads blocked — manual verification required."
                    ),
                    remediation=(
                        "WAF is a compensating control, not a fix. "
                        "Implement parameterised queries regardless of WAF presence."
                    ),
                    tool_used="sqlmap",
                    confidence="probable",
                    attack_type="sql_injection",
                )
                print(f"[SCANNER] WAF-protected endpoint noted: {endpoint[:60]}")

    print("[SCANNER] Phase 7 complete")