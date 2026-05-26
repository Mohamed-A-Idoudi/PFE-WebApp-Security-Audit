"""
Phase 6 — Nuclei vulnerability template scan
Two-pass: Critical+High then Medium.
OWASP mapping driven by template tags.
Handles missing templates gracefully.
"""
import os
import json
import subprocess
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep

SEVERITY_MAP = {
    "critical": ("Critical", 9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high":     ("High",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "medium":   ("Medium",   5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "low":      ("Low",      3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

OWASP_TAG_MAP = {
    "cve":           ("A06", "Vulnerable and Outdated Components"),
    "misconfig":     ("A05", "Security Misconfiguration"),
    "exposure":      ("A01", "Broken Access Control"),
    "default-login": ("A07", "Identification and Authentication Failures"),
    "token":         ("A02", "Cryptographic Failures"),
    "injection":     ("A03", "Injection"),
    "xss":           ("A03", "Injection"),
    "sqli":          ("A03", "Injection"),
    "lfi":           ("A01", "Broken Access Control"),
    "rce":           ("A03", "Injection"),
    "ssrf":          ("A10", "Server-Side Request Forgery"),
    "xxe":           ("A03", "Injection"),
    "idor":          ("A01", "Broken Access Control"),
    "auth-bypass":   ("A07", "Identification and Authentication Failures"),
    "takeover":      ("A05", "Security Misconfiguration"),
    "wordpress":     ("A06", "Vulnerable and Outdated Components"),
    "panel":         ("A01", "Broken Access Control"),
    "login":         ("A07", "Identification and Authentication Failures"),
}

def _map_owasp(tags) -> tuple:
    tag_list = tags if isinstance(tags, list) else str(tags).split(",")
    for tag in tag_list:
        tl = str(tag).strip().lower()
        for keyword, (oid, olabel) in OWASP_TAG_MAP.items():
            if keyword in tl:
                return oid, olabel
    return "A05", "Security Misconfiguration"


def _run_nuclei_pass(url: str, output_file: str, severity: str,
                     templates_dir: str, fingerprint: dict = None, use_tor=False) -> bool:
    """Run one nuclei pass. Returns True if output file has content."""

    cmd = [
    "nuclei", "-u", url,
    "-json-export", output_file,
    "-severity", severity,
    "-timeout", "10",
    "-bulk-size", "25",
    "-concurrency", "25",
    "-rate-limit", "100",
    "-no-interactsh",
    "-silent",
    "-duc",
    "-retries", "1",
    ]
    if use_tor:
        cmd += ["-proxy", "socks5://127.0.0.1:9050"]

    # Fingerprint-based tag selection
    tags = {"cve", "exposure", "default-login", "misconfig", "panel", "token", "sqli", "xss", "ssrf", "idor"}
    if fingerprint and any(fingerprint.values()):
        cms  = fingerprint.get("cms", "").lower()
        if "wordpress" in cms: tags.update(["wordpress", "wp-plugin"])
        if "drupal"    in cms: tags.add("drupal")
        if "joomla"    in cms: tags.add("joomla")
        if fingerprint.get("language", ""):
            lang = fingerprint["language"].lower()
            if "php"  in lang: tags.add("php")
            if "java" in lang: tags.add("java")
    cmd += ["-tags", ",".join(tags)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode not in [0, 1]:
            stderr = result.stderr[:300] if result.stderr else "no stderr"
            print(f"[SCANNER] Nuclei exit code {result.returncode}: {stderr}")
        exists = os.path.exists(output_file)
        size   = os.path.getsize(output_file) if exists else 0
        return exists and size > 0
    except subprocess.TimeoutExpired:
        print("[SCANNER] Nuclei timeout after 300s")
        return os.path.exists(output_file) and os.path.getsize(output_file) > 0
    except FileNotFoundError:
        print("[SCANNER] Nuclei binary not found")
        return False
    except Exception as e:
        print(f"[SCANNER] Nuclei error: {e}")
        return False


def _parse_output(scan_id: str, url: str, output_file: str) -> int:
    seen  = set()
    count = 0
    try:
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # BUG-01 FIX: Nuclei sometimes outputs a JSON array on one line
                items = obj if isinstance(obj, list) else [obj]
                for finding in items:

                    template_id  = finding.get("template-id", "")
                    name         = finding.get("info", {}).get("name", template_id)
                    sev          = finding.get("info", {}).get("severity", "medium").lower()
                    matched_url  = finding.get("matched-at", url)
                    tags         = finding.get("info", {}).get("tags", [])
                    description  = finding.get("info", {}).get("description", name)
                    remediation  = finding.get("info", {}).get("remediation",
                        "Review Nuclei template documentation for remediation.")

                    key = f"{template_id}:{matched_url}"
                    if key in seen:
                        continue
                    seen.add(key)

                    sev_label, cvss, vector = SEVERITY_MAP.get(
                        sev, ("Medium", 5.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")
                    )
                    owasp_id, owasp_label = _map_owasp(tags)

                    curl_cmd  = finding.get("curl-command", "")
                    extracted = finding.get("extracted-results", [])
                    evidence  = (
                        f"Template: {template_id}\n"
                        f"Tags: {tags}\n"
                        f"Matched: {matched_url}"
                    )
                    if extracted: evidence += f"\nExtracted: {extracted[:3]}"
                    if curl_cmd:  evidence += f"\nReproduction:\n{curl_cmd[:300]}"

                    save_finding(
                        scan_id=scan_id,
                        title=f"Nuclei: {name[:100]}",
                        owasp_id=owasp_id, owasp_label=owasp_label,
                        severity=sev_label, cvss_score=cvss, cvss_vector=vector,
                        description=str(description)[:500],
                        endpoint=matched_url,
                        evidence=evidence,
                        remediation=str(remediation)[:400],
                        tool_used="nuclei",
                        confidence="confirmed",
                    )
                    count += 1
                    print(f"[SCANNER] Nuclei finding: {name[:60]} — {sev_label}")

    except Exception as e:
        print(f"[SCANNER] Nuclei parse error: {e}")
    return count


def run_nuclei(scan_id: str, url: str, fingerprint: dict = None, use_tor: bool = False):
    templates_dir = "/root/.local/nuclei-templates"
    if templates_dir:
        print(f"[SCANNER] Nuclei templates: {templates_dir}")
    else:
        print("[SCANNER] Nuclei templates not found — attempting update")
        try:
            subprocess.run(["nuclei", "-update-templates", "-duc"],
                           capture_output=True, timeout=60)
            templates_dir = "/root/.local/nuclei-templates"
        except Exception:
            pass

    out_high   = f"/tmp/nuclei_{scan_id}_high.json"
    out_medium = f"/tmp/nuclei_{scan_id}_medium.json"
    total      = 0

    # Pass 1 — Critical + High
    print(f"[SCANNER] Nuclei pass 1 (critical+high) → {url}")
    if _run_nuclei_pass(url, out_high, "critical,high", templates_dir, fingerprint, use_tor):
        count = _parse_output(scan_id, url, out_high)
        total += count
        print(f"[SCANNER] Nuclei pass 1: {count} findings")
    else:
        print("[SCANNER] Nuclei pass 1: no output")

    # Pass 2 — Medium
    print(f"[SCANNER] Nuclei pass 2 (medium) → {url}")
    if _run_nuclei_pass(url, out_medium, "medium", templates_dir, fingerprint, use_tor):
        count = _parse_output(scan_id, url, out_medium)
        total += count
        print(f"[SCANNER] Nuclei pass 2: {count} findings")
    else:
        print("[SCANNER] Nuclei pass 2: no output")

    print(f"[SCANNER] Phase 6 complete — {total} Nuclei findings saved")

    for f in [out_high, out_medium]:
        if os.path.exists(f):
            os.remove(f)