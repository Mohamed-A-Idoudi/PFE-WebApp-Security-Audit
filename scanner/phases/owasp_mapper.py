"""
OWASPMapper — Authoritative OWASP Top 10:2025 mapping.

Chain: Finding → CVE ID → OSV API → CWE ID → CWE→OWASP mapping → category

Data sources:
- CWE→OWASP mapping: from MITRE official CWE→OWASP Top 10:2021 mapping
  https://cwe.mitre.org/data/definitions/1344.html
- OSV API: https://api.osv.dev (same API used in phase1b for JS libraries)
  Free, no API key, returns CWE IDs for any CVE

For findings without CVE IDs (nmap, nikto, dir-check, auth-check):
- Tool + attack_type → canonical CWE → OWASP category
- Based on OWASP definitions, not keyword guessing
"""
import json
import urllib.request


# ── Official CWE → OWASP Top 10:2025 mapping ─────────────────────────────────
# Source: MITRE CWE View-1425 (OWASP Top Ten 2021) extended to 2025 categories
# https://cwe.mitre.org/data/definitions/1344.html
CWE_TO_OWASP = {
    # A01 — Broken Access Control
    22: "A01", 23: "A01", 35: "A01", 59: "A01", 200: "A01", 201: "A01",
    219: "A01", 264: "A01", 275: "A01", 276: "A01", 284: "A01", 285: "A01",
    352: "A01", 359: "A01", 377: "A01", 402: "A01", 425: "A01", 441: "A01",
    497: "A01", 538: "A01", 540: "A01", 548: "A01", 552: "A01", 566: "A01",
    601: "A01", 639: "A01", 651: "A01", 668: "A01", 706: "A01", 862: "A01",
    863: "A01", 913: "A01", 922: "A01", 1275: "A01",

    # A02 — Cryptographic Failures
    261: "A02", 296: "A02", 310: "A02", 319: "A02", 321: "A02", 322: "A02",
    323: "A02", 324: "A02", 325: "A02", 326: "A02", 327: "A02", 328: "A02",
    329: "A02", 330: "A02", 331: "A02", 335: "A02", 336: "A02", 337: "A02",
    338: "A02", 340: "A02", 347: "A02", 523: "A02", 720: "A02", 757: "A02",
    759: "A02", 760: "A02", 780: "A02", 818: "A02", 916: "A02",

    # A03 — Injection
    20: "A03", 74: "A03", 75: "A03", 77: "A03", 78: "A03", 79: "A03",
    80: "A03", 83: "A03", 87: "A03", 88: "A03", 89: "A03", 90: "A03",
    91: "A03", 93: "A03", 94: "A03", 95: "A03", 96: "A03", 97: "A03",
    98: "A03", 99: "A03", 113: "A03", 116: "A03", 138: "A03", 184: "A03",
    470: "A03", 471: "A03", 564: "A03", 610: "A03", 643: "A03", 644: "A03",
    652: "A03", 917: "A03",

    # A04 — Insecure Design
    73: "A04", 183: "A04", 209: "A04", 213: "A04", 256: "A04", 257: "A04",
    266: "A04", 269: "A04", 280: "A04", 311: "A04", 312: "A04", 313: "A04",
    316: "A04", 419: "A04", 430: "A04", 434: "A04", 444: "A04", 451: "A04",
    472: "A04", 501: "A04", 522: "A04", 525: "A04", 539: "A04", 579: "A04",
    598: "A04", 602: "A04", 620: "A04", 636: "A04", 642: "A04", 656: "A04",

    # A05 — Security Misconfiguration
    2: "A05", 11: "A05", 13: "A05", 15: "A05", 16: "A05", 260: "A05",
    315: "A05", 520: "A05", 526: "A05", 537: "A05", 541: "A05", 547: "A05",
    611: "A05", 614: "A05", 756: "A05", 776: "A05", 942: "A05", 1021: "A05",
    1173: "A05",

    # A06 — Vulnerable and Outdated Components
    1104: "A06",

    # A07 — Identification and Authentication Failures
    255: "A07", 259: "A07", 287: "A07", 288: "A07", 290: "A07", 294: "A07",
    295: "A07", 297: "A07", 300: "A07", 302: "A07", 304: "A07", 306: "A07",
    307: "A07", 346: "A07", 384: "A07", 521: "A07", 613: "A07", 640: "A07",
    798: "A07", 940: "A07", 1216: "A07",

    # A08 — Software and Data Integrity Failures
    345: "A08", 353: "A08", 426: "A08", 494: "A08", 502: "A08", 565: "A08",
    784: "A08", 829: "A08", 830: "A08",

    # A09 — Security Logging and Monitoring Failures
    117: "A09", 223: "A09", 532: "A09", 778: "A09",

    # A10 — Server-Side Request Forgery
    918: "A10",
}

OWASP_LABELS = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# Tool + attack_type → canonical CWE ID (from MITRE definitions)
# This replaces keyword guessing with authoritative CWE anchors
TOOL_TO_CWE = {
    # Injection tools
    "sqlmap":     89,    # CWE-89: SQL Injection
    "xss-check":  79,    # CWE-79: Cross-site Scripting
    "dalfox":     79,    # CWE-79: Cross-site Scripting
    # Network tools
    "nmap":       16,    # CWE-16: Configuration (exposed services)
    # Web scanning
    "nikto":      16,    # CWE-16: Configuration
    "dir-check":  548,   # CWE-548: Exposure of Information Through Directory Listing
    "cors-check": 942,   # CWE-942: Overly Permissive CORS Policy
    "header-check": 16,  # CWE-16: Configuration
    # Auth tools
    "auth-check": 307,   # CWE-307: Improper Restriction of Excessive Auth Attempts
    "hydra":      307,   # CWE-307
    # TLS
    "testssl":    326,   # CWE-326: Inadequate Encryption Strength
    # Component analysis
    "js-check":   1104,  # CWE-1104: Use of Unmaintained Third Party Components
    "nuclei":     16,    # CWE-16: default, overridden by CVE lookup
}

# Attack type → canonical CWE
ATTACK_TO_CWE = {
    "sql_injection":       89,
    "xss":                 79,
    "command_injection":   78,
    "path_traversal":      22,
    "ssrf":               918,
    "xxe":                611,
    "lfi":                 22,
    "no_rate_limiting":   307,
    "default_credentials": 798,
    "weak_cipher":        326,
    "no_tls":             319,
    "expired_cert":       295,
    "tls_vulnerability":  326,
    "missing_header":      16,
    "cors_wildcard":      942,
    "directory_listing":  548,
    "admin_exposure":     284,
    "eol_software":      1104,
    "vulnerable_library": 1104,
}


def _query_osv_for_cwe(cve_id: str) -> list:
    """
    Query OSV API (same as phase1b) for a CVE to get its CWE IDs.
    OSV is free, no API key, fast.
    Returns list of integer CWE IDs.
    """
    try:
        # OSV accepts CVE IDs directly via the vulns endpoint
        url  = f"https://api.osv.dev/v1/vulns/{cve_id}"
        req  = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        data = json.loads(resp.read().decode())

        cwe_ids = []
        # OSV returns CWE IDs in the `database_specific` or `affected` sections
        for ref in data.get("references", []):
            if "cwe" in ref.get("url", "").lower():
                import re
                matches = re.findall(r'CWE-(\d+)', ref.get("url", ""), re.IGNORECASE)
                cwe_ids.extend(int(m) for m in matches)

        # Also check aliases and details text
        details = data.get("details", "") + data.get("summary", "")
        import re
        matches = re.findall(r'CWE-(\d+)', details, re.IGNORECASE)
        cwe_ids.extend(int(m) for m in matches)

        # Check database_specific fields
        db_spec = data.get("database_specific", {})
        if "cwe_ids" in db_spec:
            for cwe in db_spec["cwe_ids"]:
                match = re.search(r'\d+', str(cwe))
                if match:
                    cwe_ids.append(int(match.group()))

        return list(set(cwe_ids))

    except Exception:
        return []


class OWASPMapper:
    """
    Authoritative OWASP Top 10:2025 mapping using:
    1. CWE→OWASP mapping from MITRE official data
    2. OSV API (same as phase1b) for CVE→CWE resolution
    3. Tool/attack_type→CWE anchors as fallback
    """

    def map(self, tool="", title="", attack_type="",
            cve_id="", **kwargs) -> dict:
        """
        Map a finding to OWASP Top 10:2025.
        Priority: CVE→OSV→CWE→OWASP > attack_type→CWE > tool→CWE > fallback
        """

        # Priority 1 — CVE ID provided → query OSV for CWE → map to OWASP
        if cve_id:
            cwe_ids = _query_osv_for_cwe(cve_id)
            for cwe in cwe_ids:
                if cwe in CWE_TO_OWASP:
                    oid = CWE_TO_OWASP[cwe]
                    return {"id": oid, "label": OWASP_LABELS[oid],
                            "confidence": "high", "cwe": cwe}

        # Priority 2 — CVE ID in title → extract and query OSV
        if not cve_id:
            import re
            match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
            if match:
                cwe_ids = _query_osv_for_cwe(match.group(0).upper())
                for cwe in cwe_ids:
                    if cwe in CWE_TO_OWASP:
                        oid = CWE_TO_OWASP[cwe]
                        return {"id": oid, "label": OWASP_LABELS[oid],
                                "confidence": "high", "cwe": cwe}

        # Priority 3 — attack_type → canonical CWE → OWASP
        if attack_type:
            cwe = ATTACK_TO_CWE.get(attack_type.lower())
            if cwe and cwe in CWE_TO_OWASP:
                oid = CWE_TO_OWASP[cwe]
                return {"id": oid, "label": OWASP_LABELS[oid],
                        "confidence": "medium", "cwe": cwe}

        # Priority 4 — tool → canonical CWE → OWASP
        tool_lower = tool.lower()
        for tool_key, cwe in TOOL_TO_CWE.items():
            if tool_key in tool_lower:
                oid = CWE_TO_OWASP.get(cwe, "A05")
                return {"id": oid, "label": OWASP_LABELS[oid],
                        "confidence": "medium", "cwe": cwe}

        # Priority 5 — title pattern → likely CWE
        title_lower = title.lower()
        title_cwe_hints = [
            (["sql inject"],                    89),
            (["cross-site script", "xss"],      79),
            (["command inject"],                78),
            (["path traversal", "directory traversal"], 22),
            (["ssrf", "server-side request"],  918),
            (["rate limit", "brute force"],    307),
            (["default cred", "default pass"], 798),
            (["tls", "ssl", "cipher"],         326),
            (["certificate"],                  295),
            (["exposed", "disclosure"],        548),
            (["admin", "unauthorized access"], 284),
            (["end-of-life", "outdated"],     1104),
            (["vulnerable", "library", "cve"], 1104),
            (["missing header", "security header"], 16),
            (["cors"],                         942),
        ]
        for patterns, cwe in title_cwe_hints:
            if any(p in title_lower for p in patterns):
                oid = CWE_TO_OWASP.get(cwe, "A05")
                return {"id": oid, "label": OWASP_LABELS[oid],
                        "confidence": "low", "cwe": cwe}

        return {"id": "A05", "label": OWASP_LABELS["A05"],
                "confidence": "low", "cwe": None}

    def map_from_nuclei_tags(self, tags) -> dict:
        """For Nuclei findings — map from template tags using CWE anchors."""
        tag_str  = " ".join(tags).lower() if isinstance(tags, list) else str(tags).lower()
        tag_cwe  = [
            ("sqli",          89),  ("xss",          79),  ("injection",    78),
            ("lfi",           22),  ("rfi",           98),  ("idor",        639),
            ("ssrf",         918),  ("rce",           94),  ("xxe",         611),
            ("default-login", 798), ("auth-bypass",  288),
            ("misconfig",     16),  ("takeover",      16),  ("exposure",    548),
            ("cve",         1104),  ("wordpress",   1104),
            ("token",        330),  ("ssl",          326),  ("tls",         326),
        ]
        for tag_keyword, cwe in tag_cwe:
            if tag_keyword in tag_str:
                oid = CWE_TO_OWASP.get(cwe, "A05")
                return {"id": oid, "label": OWASP_LABELS[oid],
                        "confidence": "high", "cwe": cwe}
        return {"id": "A05", "label": OWASP_LABELS["A05"],
                "confidence": "low", "cwe": None}


mapper = OWASPMapper()
