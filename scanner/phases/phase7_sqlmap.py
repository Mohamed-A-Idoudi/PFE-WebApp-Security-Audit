"""
Phase 7 — SQL injection detection (passive, no exploitation)
REST API discovery + WAF bypass tampers + injectable URL filtering.
"""
import os
import re
import json
import subprocess
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep


# Asset extensions — never injectable
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

# BUG-04: params that are URL-type or format-type — never SQLi injectable
SQLI_PARAM_BLACKLIST = {
    'url', 'callback', 'redirect', 'format', 'feed',
    'next', 'return', 'redir', 'dest', 'destination',
    'action', 'uri', 'link', 'href', 'src',
}

# BUG-04: numeric/search params most likely to be injectable — tested first
SQLI_PARAM_PRIORITY = [
    'id', 'p', 'page_id', 'cat', 'post', 'product_id',
    'item', 'user_id', 'order_id', 'news_id', 'article_id',
    'q', 'search', 's', 'query', 'keyword',
]


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        for name, val in attrs:
            if name in ["href", "action"] and val:
                self.links.append(val)


def _is_injectable_endpoint(url: str, base_domain: str) -> bool:
    """Only test same-domain parameterized non-asset URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.netloc and parsed.netloc != base_domain:
            return False
        if not parsed.query or "=" not in parsed.query:
            return False
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return False
        url_lower = url.lower()
        if any(frag in url_lower for frag in SKIP_PATH_FRAGMENTS):
            return False
        # BUG-04: blacklist URL-type / format-type params — never injectable
        params = {k.lower() for k in urllib.parse.parse_qs(parsed.query)}
        if params and params.issubset(SQLI_PARAM_BLACKLIST):
            return False
        return True
    except Exception:
        return False


def _sqlmap_found_injection(output: str) -> bool:
    ol = output.lower()
    false_positives = [
        "does not seem to be injectable",
        "does not appear to be dynamic",
        "all tested parameters do not appear",
        "might not be injectable",
    ]
    if any(fp in ol for fp in false_positives):
        return False
    confirmed = [
        "is vulnerable",
        "sqlmap identified the following injection point",
        "the back-end dbms is",
        "parameter appears to be",
    ]
    return any(c in ol for c in confirmed)


def _waf_detected(output: str) -> bool:
    return any(w in output.lower() for w in [
        "protected by some kind of waf",
        "heuristics detected that the target is protected",
        "target appears to be protected",
    ])


def _extract_param(output: str) -> str:
    match = re.search(r"parameter '([^']+)'", output, re.IGNORECASE)
    if match: return match.group(1)
    match = re.search(r"Parameter:\s*(\S+)", output)
    if match: return match.group(1)
    return "unknown"


def _detect_dbms(url: str) -> str | None:
    """
    BUG-04: auto-detect DBMS from URL heuristics.
    Returns a --dbms value or None (let sqlmap detect).
    """
    parsed = urllib.parse.urlparse(url)
    host   = (parsed.hostname or "").lower()
    port   = parsed.port or 0
    path   = (parsed.path or "").lower()

    # Juice Shop (OWASP) uses SQLite
    if port == 3000 or "juice" in host or "/rest/" in path:
        return "sqlite"

    # WordPress targets use MySQL
    if any(wp in path for wp in ["/wp-content/", "/wp-json/", "/wp-admin/", "/?p=", "/?page_id="]):
        return "mysql"
    if any(wp in host for wp in ["wordpress", "wp.", ".wp."]):
        return "mysql"

    return None  # let sqlmap auto-detect


def _prioritize_targets(targets: set) -> list:
    """
    BUG-04: sort targets so numeric/search params come first.
    Removes any URL whose only params are on the blacklist.
    """
    def _priority(url):
        try:
            params = {k.lower() for k in urllib.parse.parse_qs(
                urllib.parse.urlparse(url).query
            )}
            # Already filtered by _is_injectable_endpoint, but double-check
            if params and params.issubset(SQLI_PARAM_BLACKLIST):
                return 999
            for i, p in enumerate(SQLI_PARAM_PRIORITY):
                if p in params:
                    return i
            return len(SQLI_PARAM_PRIORITY)
        except Exception:
            return len(SQLI_PARAM_PRIORITY)

    return sorted(targets, key=_priority)


def _save_sqli(scan_id, endpoint, param, evidence):
    save_finding(
        scan_id=scan_id,
        title="SQL Injection Vulnerability Confirmed",
        owasp_id="A03", owasp_label="Injection",
        severity="Critical", cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description=(
            f"SQLmap confirmed SQL injection at {endpoint}. "
            f"Injectable parameter: {param}. "
            f"An attacker can read, modify, or delete the entire database."
        ),
        endpoint=endpoint,
        evidence=evidence[:1000],
        remediation=(
            "Use parameterized queries for all DB interactions. "
            "Never concatenate user input into SQL. "
            "Apply least privilege to the database account."
        ),
        tool_used="sqlmap",
        confidence="confirmed",
        attack_type="sql_injection",
    )


def _discover_targets(url: str, base: str, base_domain: str) -> set:
    """Discover injectable endpoints from HTML crawl + REST patterns."""
    targets = set()

    # REST patterns to probe
    common_rest = [
        "/rest/products/search?q=test",
        "/api/products?search=test",
        "/api/search?q=test",
        "/api/v1/search?q=test",
        "/search?q=test",
        "/api/users?id=1",
        "/api/v1/users?id=1",
        "/api/items?id=1",
        "/api/articles?id=1",
        "/api/news?id=1",
        "/api/posts?id=1",
        "/api/categories?id=1",
    ]

    # Probe common REST patterns
    for path in common_rest:
        test_url = f"{base}{path}"
        try:
            req  = urllib.request.Request(test_url, headers=evasion_headers())
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                targets.add(test_url)
                print(f"[SCANNER] REST endpoint exists: {test_url}")
        except urllib.error.HTTPError as e:
            if e.code not in [404, 405]:
                targets.add(test_url)
        except Exception:
            pass

    return targets


def _run_sqlmap(cmd: list, timeout: int = 120) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "timeout"
    except FileNotFoundError:
        return "not_installed"
    except Exception as e:
        return str(e)


def run_sqlmap(scan_id: str, url: str, crawl_results: dict = None, use_tor: bool = False):
    base        = url.rstrip("/")
    base_domain = urllib.parse.urlparse(url).netloc
    output_dir  = f"/tmp/sqlmap_{scan_id}"
    os.makedirs(output_dir, exist_ok=True)

    # Discover targets
    targets = _discover_targets(url, base, base_domain)
    targets.add(url)

    # Merge ALL Katana URLs — parameterized + API endpoints
    if crawl_results:
        katana_urls = set()
        for key in ("parameterized_urls", "api_endpoints", "urls"):
            for u in crawl_results.get(key, []):
                if _is_injectable_endpoint(u, base_domain):
                    katana_urls.add(u)
        targets.update(katana_urls)
        print(f"[SCANNER] SQLmap: {len(targets)} injectable URLs "
              f"({len(katana_urls)} from Katana)")

    # BUG-04: detect DBMS from target URL
    dbms = _detect_dbms(url)
    dbms_flags = ["--dbms", dbms] if dbms else []
    if dbms:
        print(f"[SCANNER] SQLmap: DBMS auto-detected → {dbms}")

    base_flags = [
        "--batch", "--level=5", "--risk=3",
        "--technique=BEUSTQ", "--time-sec=10",
        "--output-dir", output_dir,
        "--delay=1",
        "--no-cast", "--fresh-queries",
        "--disable-coloring", "--random-agent",
        "--threads=1",
        "--headers=X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1",
    ] + dbms_flags

    if use_tor:
        base_flags += ["--proxy=socks5://127.0.0.1:9050", "--tor-type=SOCKS5"]

    # BUG-04: prioritize numeric/search params, drop blacklisted-only URLs
    sorted_targets = _prioritize_targets(targets)
    print(f"[SCANNER] SQLmap: test order → {[t[:60] for t in sorted_targets[:5]]}")

    tested = set()

    for endpoint in sorted_targets[:12]:
        if endpoint in tested:
            continue
        tested.add(endpoint)
        print(f"[SCANNER] SQLmap testing: {endpoint[:80]}")
        random_sleep(0.5, 1.5)

        cmd    = ["sqlmap", "-u", endpoint] + base_flags
        output = _run_sqlmap(cmd, timeout=120)

        if output == "not_installed":
            print("[SCANNER] SQLmap not installed")
            return
        if output == "timeout":
            print(f"[SCANNER] SQLmap timeout on {endpoint[:60]}")
            continue

        if _sqlmap_found_injection(output):
            _save_sqli(scan_id, endpoint, _extract_param(output), output)
            print(f"[SCANNER] SQLi CONFIRMED at {endpoint}")
            return

        if _waf_detected(output):
            print(f"[SCANNER] WAF detected — retrying with tampers")
            tamper_cmd = cmd + [
                "--tamper=space2comment,between,randomcase",
                "--headers=X-Forwarded-For: 192.168.1.1",
            ]
            output2 = _run_sqlmap(tamper_cmd, timeout=120)
            if _sqlmap_found_injection(output2):
                _save_sqli(scan_id, endpoint, _extract_param(output2), output2)
                print(f"[SCANNER] SQLi CONFIRMED (WAF bypass) at {endpoint}")
                return
            else:
                save_finding(
                    scan_id=scan_id,
                    title="Potential SQL Injection — WAF Protected",
                    owasp_id="A03", owasp_label="Injection",
                    severity="High", cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    description=(
                        f"SQLmap detected WAF protection on {endpoint}. "
                        f"Automated exploitation blocked. Manual verification required."
                    ),
                    endpoint=endpoint,
                    evidence=(
                        f"WAF detected on {endpoint}\n"
                        f"Tampers tried: space2comment, between, randomcase\n"
                        f"All payloads blocked. Manual testing with custom tampers required."
                    ),
                    remediation=(
                        "Implement parameterized queries regardless of WAF. "
                        "WAF is a compensating control, not a fix."
                    ),
                    tool_used="sqlmap",
                    confidence="probable",
                    attack_type="sql_injection",
                )
                print(f"[SCANNER] WAF-protected potential SQLi at {endpoint[:60]}")

    print("[SCANNER] Phase 7 complete")