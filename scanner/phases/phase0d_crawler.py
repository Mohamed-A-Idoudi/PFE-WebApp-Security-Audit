"""
Phase 0d — URL discovery using Katana
Extracts all URLs from the target including SPA routes.
Output feeds Phase 3b (dalfox XSS) and Phase 7 (sqlmap).

Katana by ProjectDiscovery: https://github.com/projectdiscovery/katana
Two modes:
- Standard: parses HTML + JS source statically (fast, no browser needed)
- Headless: runs real Chrome (thorough, finds all dynamic routes)

Falls back to standard crawl if headless Chrome unavailable.
"""
import os
import subprocess
import urllib.request
import urllib.parse
import re
from .utils import random_ua, evasion_headers, random_sleep, extract_host

def run_crawler(scan_id: str, url: str) -> dict:
    """
    Discover all URLs on the target using Katana.
    Returns a crawl_results dict consumed by Phase 3b and Phase 7:
    {
        "all_urls":          [...],  # all discovered URLs
        "parameterized_urls":[...],  # URLs with query parameters
        "forms":             [...],  # form action URLs
        "api_endpoints":     [...],  # /api/, /rest/ endpoints
        "domain":            "..."
    }
    """
    domain = urllib.parse.urlparse(url).netloc
    output = f"/tmp/katana_{scan_id}.txt"

    crawl_results = {
        "all_urls":           [],
        "parameterized_urls": [],
        "forms":              [],
        "api_endpoints":      [],
        "domain":             domain,
    }

    katana_available = _run_katana(url, output, scan_id)

    if not katana_available:
        print("[SCANNER] Katana not installed — using fallback crawler")
        return _fallback_crawler(url, crawl_results)

    if not os.path.exists(output):
        print("[SCANNER] Katana produced no output")
        return _fallback_crawler(url, crawl_results)

    with open(output) as f:
        urls = [line.strip() for line in f if line.strip()]

    os.remove(output)

    print(f"[SCANNER] Katana discovered {len(urls)} URLs")

    # Categorize URLs
    for u in urls:
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc and parsed.netloc != domain:
            continue  # skip external URLs

        crawl_results["all_urls"].append(u)

        if parsed.query and "=" in parsed.query:
            crawl_results["parameterized_urls"].append(u)

        path = parsed.path.lower()
        if any(p in path for p in ["/api/", "/rest/", "/v1/", "/v2/"]):
            crawl_results["api_endpoints"].append(u)

    print(f"[SCANNER] Phase 0d: {len(crawl_results['all_urls'])} URLs, "
          f"{len(crawl_results['parameterized_urls'])} parameterized, "
          f"{len(crawl_results['api_endpoints'])} API endpoints")

    return crawl_results


def _run_katana(url: str, output: str, scan_id: str) -> bool:
    """
    Try katana in JS-crawl mode first, fall back to standard if Chrome unavailable.
    Returns True if katana is installed (even if output is empty).
    """
    # Standard mode — parses HTML + JS source statically
    # Finds Angular routes embedded in compiled JS bundles
    cmd = [
        "katana",
        "-u",        url,
        "-jc",               # JavaScript crawling — parses JS source for URLs
        "-d",        "3",    # depth 3 — enough for most SPAs
        "-o",        output,
        "-silent",
        "-timeout",  "30",
        "-rl",       "50",   # rate limit 50 req/s
        "-H",        f"User-Agent: {random_ua()}",
        "-aff",              # also extract from form fields
        "-ef",       "png,jpg,gif,css,woff,woff2,ico,svg",  # skip binary files
    ]

    try:
        print(f"[SCANNER] Katana (JS crawl) → {url}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0 or os.path.exists(output):
            return True
        return True  # katana was found even if no output
    except FileNotFoundError:
        return False  # katana not installed
    except subprocess.TimeoutExpired:
        print("[SCANNER] Katana timeout after 300s")
        return True
    except Exception as e:
        print(f"[SCANNER] Katana error: {e}")
        return True


def _fallback_crawler(url: str, crawl_results: dict) -> dict:
    """
    Pure Python fallback when Katana unavailable.
    Parses HTML + JS bundles for URLs and routes.
    """
    base   = url.rstrip("/")
    domain = urllib.parse.urlparse(url).netloc
    seen   = set()

    def add_url(u):
        if u in seen or len(seen) > 500:
            return
        seen.add(u)
        parsed = urllib.parse.urlparse(u)
        if parsed.netloc and parsed.netloc != domain:
            return
        crawl_results["all_urls"].append(u)
        if parsed.query and "=" in parsed.query:
            crawl_results["parameterized_urls"].append(u)
        path = parsed.path.lower()
        if any(p in path for p in ["/api/", "/rest/", "/v1/", "/v2/"]):
            crawl_results["api_endpoints"].append(u)

    try:
        # Fetch homepage
        req      = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        response = urllib.request.urlopen(req, timeout=15)
        html     = response.read().decode("utf-8", errors="ignore")

        # Extract all links
        for match in re.findall(r'(?:href|action|src)=["\']([^"\']+)["\']', html):
            if match.startswith("http"):
                add_url(match)
            elif match.startswith("/"):
                add_url(f"{base}{match}")

        # Extract URLs from JS
        for match in re.findall(r'["\']([^\s"\']+\?[^\s"\']+)["\']', html):
            if "=" in match:
                if match.startswith("http"):
                    add_url(match)
                elif match.startswith("/"):
                    add_url(f"{base}{match}")

        # Fetch JS bundles and extract routes
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
        for src in script_srcs[:5]:
            if src.startswith("/"):  src = f"{base}{src}"
            elif src.startswith("//"): src = f"https:{src}"
            elif not src.startswith("http"): continue
            try:
                req2      = urllib.request.Request(src, headers={"User-Agent": random_ua()})
                resp2     = urllib.request.urlopen(req2, timeout=10)
                js_content = resp2.read(500000).decode("utf-8", errors="ignore")

                # Angular routes pattern
                for r in re.findall(r'path:["\s]*["\']([a-zA-Z0-9/\-_:]+)["\']', js_content):
                    if r and not r.startswith("http"):
                        add_url(f"{base}/{r.lstrip('/')}")

                # API endpoint patterns
                for r in re.findall(r'["\']/(api|rest)/[^\s"\'?]{1,100}["\']', js_content):
                    add_url(f"{base}/{r.lstrip('/')}")

                # Parameterized URLs in JS
                for r in re.findall(r'["\']([^"\']+\?[^"\']+)["\']', js_content):
                    if "=" in r and len(r) < 200:
                        if r.startswith("/"):
                            add_url(f"{base}{r}")
                        elif r.startswith("http") and domain in r:
                            add_url(r)
            except Exception:
                pass

        print(f"[SCANNER] Fallback crawler: {len(crawl_results['all_urls'])} URLs found")

    except Exception as e:
        print(f"[SCANNER] Fallback crawler error: {e}")

    return crawl_results
