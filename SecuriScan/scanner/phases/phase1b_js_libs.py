"""
Phase 1b — JavaScript library vulnerability detection.
Fetches homepage, extracts all script URLs, downloads each file,
extracts version strings, queries OSV API dynamically for CVEs.
"""
import re
import json
import urllib.request
from .db import save_finding
from .utils import random_ua


JS_LIBRARY_SIGNATURES = [
    ("jQuery",            "jquery",            r'[Jj][Qq]uery\s+[Jj][Ss].*?v?(\d+\.\d+\.\d+)'),
    ("jQuery",            "jquery",            r'[Jj][Qq]uery\s+v(\d+\.\d+\.\d+)'),
    ("jQuery",            "jquery",            r'jquery[/-](\d+\.\d+\.\d+)'),
    ("jquery-validation", "jquery-validation", r'jQuery Validation Plugin.*?v?(\d+\.\d+\.\d+)'),
    ("jquery-validation", "jquery-validation", r'jquery[.-]validation.*?v?(\d+\.\d+\.\d+)'),
    ("Bootstrap",         "bootstrap",         r'[Bb]ootstrap\s+v(\d+\.\d+\.\d+)'),
    ("Bootstrap",         "bootstrap",         r'bootstrap[/-](\d+\.\d+\.\d+)'),
    ("AngularJS",         "angular",           r'[Aa]ngular(?:JS)?\s+v(\d+\.\d+\.\d+)'),
    ("React",             "react",             r'[Rr]eact\s+v(\d+\.\d+\.\d+)'),
    ("Vue.js",            "vue",               r'[Vv]ue\.js\s+v(\d+\.\d+\.\d+)'),
    ("Lodash",            "lodash",            r'[Ll]odash\s+(\d+\.\d+\.\d+)'),
    ("Moment.js",         "moment",            r'[Mm]oment\.js\s+v?(\d+\.\d+\.\d+)'),
    ("Underscore.js",     "underscore",        r'[Uu]nderscore\.js\s+(\d+\.\d+\.\d+)'),
    ("Handlebars",        "handlebars",        r'[Hh]andlebars\.js\s+v(\d+\.\d+\.\d+)'),
    ("Axios",             "axios",             r'axios[/\s]+v?(\d+\.\d+\.\d+)'),
]


def query_osv_api(package_name: str, version: str, ecosystem: str = "npm") -> list:
    """Query Google OSV API. Free, no API key. Returns list of vuln dicts."""
    try:
        payload = json.dumps({
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem}
        }).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())

        vulns = []
        for v in data.get("vulns", [])[:5]:
            cvss = 5.0
            for sev in v.get("severity", []):
                if sev.get("type") == "CVSS_V3":
                    score_str = sev.get("score", "")
                    try:
                        cvss = float(score_str) if "/" not in score_str else 5.0
                    except Exception:
                        pass

            if   cvss >= 9.0: severity = "Critical"
            elif cvss >= 7.0: severity = "High"
            elif cvss >= 4.0: severity = "Medium"
            else:             severity = "Low"

            vulns.append({
                "id":       v.get("id", ""),
                "summary":  v.get("summary", v.get("details", ""))[:200],
                "cvss":     cvss,
                "severity": severity,
                "aliases":  v.get("aliases", []),
            })
        return vulns

    except Exception as e:
        print(f"[SCANNER] OSV API error for {package_name} {version}: {e}")
        return []


def run_js_library_check(scan_id: str, url: str):
    base = url.rstrip("/")
    found_scripts = set()

    try:
        req      = urllib.request.Request(url, headers={"User-Agent": random_ua()})
        response = urllib.request.urlopen(req, timeout=15)
        html     = response.read().decode("utf-8", errors="ignore")
        script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for src in script_urls:
            if src.startswith("http"):  found_scripts.add(src)
            elif src.startswith("//"): found_scripts.add(f"https:{src}")
            elif src.startswith("/"):  found_scripts.add(f"{base}{src}")
        print(f"[SCANNER] JS check: {len(found_scripts)} script files to analyse")
    except Exception as e:
        print(f"[SCANNER] JS check homepage error: {e}")
        return

    checked       = 0
    already_found = set()

    for script_url in list(found_scripts)[:25]:
        try:
            req = urllib.request.Request(script_url, headers={"User-Agent": "SecuriScan/1.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            js_content = resp.read(102400).decode("utf-8", errors="ignore")
            checked += 1

            for display_name, npm_name, version_pattern in JS_LIBRARY_SIGNATURES:
                match = re.search(version_pattern, js_content, re.IGNORECASE)
                if not match:
                    continue
                version   = match.group(1)
                dedup_key = f"{npm_name}:{version}"
                if dedup_key in already_found:
                    continue
                already_found.add(dedup_key)

                print(f"[SCANNER] Found {display_name} v{version} — querying OSV...")
                vulns = query_osv_api(npm_name, version, "npm")
                if not vulns:
                    print(f"[SCANNER] {display_name} v{version} — no known CVEs")
                    continue

                cve_ids  = [a for v in vulns for a in v.get("aliases", []) if a.startswith("CVE-")]
                cve_list = ", ".join(cve_ids[:6]) or "See OSV database"
                max_cvss = max(v["cvss"] for v in vulns)
                if   max_cvss >= 9.0: severity = "Critical"
                elif max_cvss >= 7.0: severity = "High"
                elif max_cvss >= 4.0: severity = "Medium"
                else:                 severity = "Low"

                summaries = " | ".join(f"{v['id']}: {v['summary'][:100]}" for v in vulns)

                save_finding(
                    scan_id=scan_id,
                    title=f"Vulnerable JS Library: {display_name} v{version}",
                    owasp_id="A06", owasp_label="Vulnerable and Outdated Components",
                    severity=severity, cvss_score=max_cvss,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                    description=(
                        f"{display_name} v{version} loaded from {script_url} "
                        f"has {len(vulns)} confirmed CVE(s): {cve_list}."
                    ),
                    endpoint=script_url,
                    evidence=(
                        f"Version string in source:\n{match.group(0)}\n\n"
                        f"CVEs (OSV API):\n{summaries}\n\nFile: {script_url}"
                    ),
                    remediation=(
                        f"Update {display_name} to the latest stable version. "
                        f"See https://www.npmjs.com/package/{npm_name}"
                    ),
                    tool_used="js-check",
                    confidence="confirmed",
                )
                print(f"[SCANNER] CONFIRMED: {display_name} v{version} — {len(vulns)} CVEs — {severity}")

        except Exception:
            pass

    print(f"[SCANNER] Phase 1b complete — {checked} JS files checked, {len(already_found)} libraries found")
