"""
Phase 3b — XSS detection using dalfox
dalfox: https://github.com/hahwul/dalfox — installed via Dockerfile
Falls back to manual payload testing if dalfox unavailable.
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


# Asset file extensions — not injectable, skip them
SKIP_EXTENSIONS = {
    '.css', '.js', '.min.js', '.min.css', '.png', '.jpg', '.jpeg',
    '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
    '.map', '.xml', '.txt', '.pdf', '.zip', '.gz', '.tar',
}

# Path fragments that indicate static assets — skip regardless of extension
SKIP_PATH_FRAGMENTS = [
    '/wp-content/themes/', '/wp-content/plugins/', '/wp-includes/',
    '/assets/', '/static/', '/dist/', '/build/', '/vendor/',
    'fonts.googleapis', 'fonts.gstatic', 'cdn.', 'i0.wp.com',
    '.min.', 'style.css', 'style/css', 'icons.css',
]

# BUG-03: params that accept URLs or format strings — never XSS injectable
XSS_PARAM_BLACKLIST = {
    'url', 'redirect', 'callback', 'format', 'feed',
    'next', 'return', 'redir', 'dest', 'destination',
    'action', 'uri', 'link', 'href', 'src', 'source','to',
}

# BUG-03: params most likely to reflect user input — test these first
XSS_PARAM_PRIORITY = [
    'q', 'search', 'id', 'name', 's', 'query',
    'keyword', 'term', 'text', 'input', 'message',
    'comment', 'content', 'title', 'value', 'data',
]


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
    def handle_starttag(self, tag, attrs):
        for name, val in attrs:
            if name in ["href", "action", "src"] and val:
                self.links.append(val)


def _is_injectable_url(url: str, target_domain: str) -> bool:
    """Only test actual page endpoints, not static assets or external URLs."""
    try:
        parsed = urllib.parse.urlparse(url)
        # Must be same domain or relative
        if parsed.netloc and parsed.netloc != target_domain:
            return False
        # Must have query parameters
        if not parsed.query or "=" not in parsed.query:
            return False
        path = parsed.path.lower()
        # Skip asset file extensions
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS):
            return False
        # Skip known asset path patterns
        url_lower = url.lower()
        if any(frag in url_lower for frag in SKIP_PATH_FRAGMENTS):
            return False
        # BUG-03: skip URLs whose params are all URL-type or format-type
        params = {k.lower() for k in urllib.parse.parse_qs(parsed.query)}
        if params and params.issubset(XSS_PARAM_BLACKLIST):
            return False
        return True
    except Exception:
        return False


def _prioritize_urls(urls: set) -> list:
    """
    BUG-03: sort injectable URLs so high-value params come first.
    URLs with q/search/id/name/s params are tested before generic ones.
    """
    def _priority(url):
        try:
            params = {k.lower() for k in urllib.parse.parse_qs(
                urllib.parse.urlparse(url).query
            )}
            for i, p in enumerate(XSS_PARAM_PRIORITY):
                if p in params:
                    return i
            return len(XSS_PARAM_PRIORITY)
        except Exception:
            return len(XSS_PARAM_PRIORITY)

    return sorted(urls, key=_priority)


def _get_same_domain_urls(base_url: str) -> set:
    """Crawl homepage, return parameterized URLs on the same domain only."""
    candidates    = set()
    base          = base_url.rstrip("/")
    target_domain = urllib.parse.urlparse(base_url).netloc

    try:
        req      = urllib.request.Request(base_url, headers=evasion_headers())
        response = urllib.request.urlopen(req, timeout=15)
        html     = response.read().decode("utf-8", errors="ignore")

        extractor = LinkExtractor()
        extractor.feed(html)

        for link in extractor.links:
            if not link or link.startswith("#") or link.startswith("javascript:"):
                continue
            if "?" in link and "=" in link:
                if link.startswith("http"):
                    if urllib.parse.urlparse(link).netloc == target_domain:
                        candidates.add(link)
                elif link.startswith("/"):
                    candidates.add(f"{base}{link}")

        js_urls = re.findall(r'["\']([^\s"\']+\?[^\s"\']+)["\']', html)
        for link in js_urls:
            if "=" in link:
                if link.startswith("http"):
                    if urllib.parse.urlparse(link).netloc == target_domain:
                        candidates.add(link)
                elif link.startswith("/"):
                    candidates.add(f"{base}{link}")

    except Exception as e:
        print(f"[SCANNER] XSS crawl error: {e}")

    return candidates


def _run_dalfox(url: str, scan_id: str) -> list:
    """Run dalfox against a single URL. Returns list of confirmed XSS findings."""
    output_file = f"/tmp/dalfox_{scan_id}_{abs(hash(url)) % 99999}.json"
    findings    = []

    cmd = [
        "dalfox", "url", url,
        "--silence",
        "--no-spinner",
        "--format", "json",
        "-o", output_file,
        "--timeout", "10",
        "--delay",   "200",
        "--user-agent", random_ua(),
        "--skip-bav",
        "--only-poc", "reflected",
        "--header", f"X-Forwarded-For: {_random_xff()}",
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        print(f"[SCANNER] dalfox timeout on {url[:70]}")
        return findings
    except FileNotFoundError:
        return None  # Signal: dalfox not installed
    except Exception as e:
        print(f"[SCANNER] dalfox error: {e}")
        return findings

    if not os.path.exists(output_file):
        return findings

    try:
        with open(output_file) as f:
            content = f.read().strip()
        if not content:
            return findings

        if content.startswith("["):
            results = json.loads(content)
        else:
            results = [json.loads(line) for line in content.splitlines() if line.strip()]

        for result in results:
            if result.get("type") in ["reflected", "stored", "dom"]:
                findings.append({
                    "param":   result.get("param", "unknown"),
                    "payload": result.get("poc", result.get("payload", "")),
                    "type":    result.get("type", "reflected"),
                    "url":     result.get("poc_url", url),
                })
                print(f"[SCANNER] dalfox XSS CONFIRMED: {result.get('type')} "
                      f"param='{result.get('param')}' at {url[:70]}")

    except Exception as e:
        print(f"[SCANNER] dalfox parse error: {e}")
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)

    return findings


def _random_xff() -> str:
    import random
    return f"{random.randint(10,200)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


# Fallback payloads when dalfox unavailable
FALLBACK_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
]
FALLBACK_CONFIRM = [
    '<script>alert("xss")</script>', '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
    'onerror=alert(1)', 'onload=alert(1)',
]


def _fallback_xss_test(url: str, param: str) -> tuple:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for payload in FALLBACK_PAYLOADS:
        params[param] = [payload]
        test_url = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode(params, doseq=True))
        )
        try:
            req      = urllib.request.Request(test_url, headers=evasion_headers())
            response = urllib.request.urlopen(req, timeout=10)
            content  = response.read(50000).decode("utf-8", errors="ignore")
            if any(c.lower() in content.lower() for c in FALLBACK_CONFIRM):
                return True, payload, test_url
        except Exception:
            pass
        random_sleep(0.2, 0.8)
    return False, "", ""


def run_xss_checks(scan_id: str, url: str, crawl_results: dict = None):
    target_domain    = urllib.parse.urlparse(url).netloc
    confirmed_keys   = set()
    dalfox_available = True
    total            = 0

    if crawl_results:
        raw_candidates = set()
        for key in ("parameterized_urls", "api_endpoints", "urls"):
            raw_candidates.update(crawl_results.get(key, []))
        print(f"[SCANNER] XSS: {len(raw_candidates)} Katana URLs received")
    else:
        raw_candidates = _get_same_domain_urls(url)

    # Filter to injectable endpoints only — removes CSS, JS, images, external
    candidates = {u for u in raw_candidates if _is_injectable_url(u, target_domain)}
    print(f"[SCANNER] XSS: {len(candidates)} injectable URLs after filtering")

    if not candidates:
        print("[SCANNER] XSS: no injectable parameterized URLs found")
        return

    # BUG-03: sort by param priority, cap at 50
    sorted_candidates = _prioritize_urls(candidates)
    print(f"[SCANNER] XSS: testing up to 50 URLs (priority order)")

    for target_url in sorted_candidates[:50]:
        result = _run_dalfox(target_url, scan_id)

        if result is None:
            dalfox_available = False
            params = urllib.parse.parse_qs(
                urllib.parse.urlparse(target_url).query, keep_blank_values=True
            )
            for param in list(params.keys())[:3]:
                key = f"{param}:{target_url}"
                if key in confirmed_keys:
                    continue
                confirmed, payload, test_url = _fallback_xss_test(target_url, param)
                if confirmed:
                    confirmed_keys.add(key)
                    _save_xss(scan_id, param, payload, test_url, "reflected", "xss-check")
                    total += 1
            continue

        for finding in result:
            key = f"{finding['param']}:{target_url}"
            if key in confirmed_keys:
                continue
            confirmed_keys.add(key)
            _save_xss(scan_id, finding["param"], finding["payload"],
                      finding["url"], finding.get("type", "reflected"), "dalfox")
            total += 1

        random_sleep(0.1, 0.5)

    tool = "dalfox" if dalfox_available else "xss-check"
    print(f"[SCANNER] Phase 3b complete — {total} XSS confirmed (via {tool})")


def _save_xss(scan_id, param, payload, url, xss_type, tool):
    severity_map = {
        "reflected": ("High",   7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
        "stored":    ("High",   8.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"),
        "dom":       ("Medium", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    }
    severity, cvss, vector = severity_map.get(xss_type, severity_map["reflected"])
    save_finding(
        scan_id=scan_id,
        title=f"{xss_type.capitalize()} XSS in Parameter: {param}",
        owasp_id="A03", owasp_label="Injection",
        severity=severity, cvss_score=cvss, cvss_vector=vector,
        description=(
            f"{xss_type.capitalize()} Cross-Site Scripting confirmed in parameter '{param}'. "
            f"Unsanitized input is reflected unencoded in the HTTP response."
        ),
        endpoint=url,
        evidence=f"Tool: {tool}\nParameter: {param}\nPayload: {payload[:200]}\nURL: {url}",
        remediation=(
            "Encode all user-supplied output. "
            "Implement Content-Security-Policy header. "
            "Use framework auto-escaping."
        ),
        tool_used=tool,
        confidence="confirmed",
        attack_type="xss",
    )