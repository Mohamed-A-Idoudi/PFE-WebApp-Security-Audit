"""
Phase 1 extension — TLS/SSL analysis via testssl.sh
Covers OWASP A02 (Cryptographic Failures) properly:
expired certificates, weak ciphers, deprecated protocols,
POODLE, BEAST, CRIME, BREACH, HSTS, certificate chain issues.
Skips if target is plain HTTP on a non-443 port (no TLS to test).
"""
import json
import subprocess
import re
from urllib.parse import urlparse
from .db import save_finding
from .utils import random_ua, evasion_headers, random_sleep, extract_host

# testssl severity mapping
TESTSSL_SEVERITY = {
    "CRITICAL": ("Critical", 9.8),
    "HIGH":     ("High",     7.5),
    "MEDIUM":   ("Medium",   5.0),
    "LOW":      ("Low",      3.1),
    "WARN":     ("Low",      3.1),
}

# Findings we skip — informational only, not vulnerabilities
TESTSSL_SKIP = [
    "offered",
    "not offered",
    "ok",
    "yes",
    "no",
    "unknown",
    "yes, socket reuse",
    "master secret",
    "ticket hint",
    "stapling",
    "must staple",
    "dns caa",
    "certificate transparency",
    "pre-certificate",
    "scantime",
    "scan time",
]


def _is_interesting(severity: str, finding: str) -> bool:
    """Only save actual vulnerabilities — skip informational ok/offered lines."""
    if severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN"]:
        return False
    fl = finding.lower().strip()
    if any(skip in fl for skip in TESTSSL_SKIP):
        return False
    if len(fl) < 10:
        return False
    return True


def run_testssl(scan_id: str, url: str):
    """
    Run testssl.sh against the target.
    - HTTPS targets: uses the port from the URL (default 443).
    - HTTP targets on port 443: tests anyway (misconfigured TLS is a finding).
    - HTTP targets on any other port: skips (no TLS to test).
    """
    # BUG-02 FIX: extract real scheme and port from URL
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    port   = parsed.port or (443 if scheme == "https" else 80)

    # Skip entirely if plain HTTP on a non-443 port — there is no TLS to test
    if scheme == "http" and port != 443:
        print(f"[SCANNER] testssl.sh skipped — HTTP target on port {port} (no TLS)")
        return

    host        = extract_host(url)
    output_file = f"/tmp/testssl_{scan_id}.json"
    target      = f"https://{host}:{port}"

    try:
        cmd = [
            "testssl.sh",
            "--jsonfile", output_file,
            "--quiet",
            "--nodns", "min",
            "--fast",
            "--severity", "LOW",
            target
        ]
        print(f"[SCANNER] testssl.sh → {target}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        import os
        if not os.path.exists(output_file):
            # Try alternate command name
            cmd[0] = "testssl"
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if not os.path.exists(output_file):
            print("[SCANNER] testssl.sh produced no output")
            return

        with open(output_file) as f:
            data = json.load(f)

        # testssl JSON has a "findings" array
        findings_list = data if isinstance(data, list) else data.get("findings", [])
        if not findings_list:
            # Some versions nest differently
            for key in ["scanResult", "results"]:
                if key in data:
                    findings_list = data[key]
                    break

        seen  = set()
        count = 0

        for item in findings_list:
            # Handle both flat and nested formats
            if isinstance(item, dict):
                id_val    = item.get("id", "")
                severity  = item.get("severity", "").upper()
                finding   = item.get("finding", item.get("output", ""))
                cve       = item.get("cve", "")
            else:
                continue

            if not _is_interesting(severity, finding):
                continue

            key = f"{id_val}:{finding[:50]}"
            if key in seen:
                continue
            seen.add(key)

            sev_label, cvss = TESTSSL_SEVERITY.get(severity, ("Low", 3.1))

            # Map to OWASP category based on finding type
            id_lower = id_val.lower()
            if any(k in id_lower for k in ["cert", "chain", "expir", "trust"]):
                owasp_id, owasp_label = "A02", "Cryptographic Failures"
                description = f"Certificate issue detected: {finding}"
                remediation = "Renew certificate. Ensure full chain is served. Use trusted CA."
            elif any(k in id_lower for k in ["poodle", "beast", "crime", "breach",
                                               "lucky13", "robot", "heartbleed", "ccs"]):
                owasp_id, owasp_label = "A02", "Cryptographic Failures"
                description = f"TLS attack vulnerability confirmed: {id_val}. {finding}"
                remediation = "Update TLS configuration. Disable affected protocol/cipher. Apply server patches."
                cvss = max(cvss, 7.5)
                sev_label = "High" if cvss >= 7.0 else sev_label
            elif any(k in id_lower for k in ["ssl2", "ssl3", "tls1 ", "tls10", "tls1.0", "tls1.1"]):
                owasp_id, owasp_label = "A02", "Cryptographic Failures"
                description = f"Deprecated TLS/SSL protocol enabled: {finding}"
                remediation = "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enable TLS 1.2+ only."
            elif any(k in id_lower for k in ["cipher", "rc4", "des", "3des", "export", "null"]):
                owasp_id, owasp_label = "A02", "Cryptographic Failures"
                description = f"Weak cipher suite enabled: {finding}"
                remediation = "Disable weak ciphers. Use only AEAD cipher suites (AES-GCM, ChaCha20)."
            elif "hsts" in id_lower:
                owasp_id, owasp_label = "A05", "Security Misconfiguration"
                description = f"HSTS misconfiguration: {finding}"
                remediation = "Enable HSTS with max-age=31536000, includeSubDomains, preload."
            else:
                owasp_id, owasp_label = "A02", "Cryptographic Failures"
                description = finding
                remediation = "Review TLS configuration and apply recommended hardening."

            title = f"TLS: {id_val} — {finding[:60]}"
            evidence = f"testssl.sh finding:\nID: {id_val}\nSeverity: {severity}\nFinding: {finding}"
            if cve:
                evidence += f"\nCVE: {cve}"
                description += f" ({cve})"

            save_finding(
                scan_id=scan_id,
                title=title,
                owasp_id=owasp_id, owasp_label=owasp_label,
                severity=sev_label, cvss_score=cvss,
                cvss_vector=f"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                description=description,
                endpoint=target,
                evidence=evidence,
                remediation=remediation,
                tool_used="testssl",
                confidence="confirmed",
            )
            count += 1
            print(f"[SCANNER] TLS finding: {id_val} — {sev_label}")

        print(f"[SCANNER] Phase 1 (testssl) complete — {count} TLS findings saved")

    except subprocess.TimeoutExpired:
        print("[SCANNER] testssl.sh timeout after 120s")
    except FileNotFoundError:
        print("[SCANNER] testssl.sh not installed in container")
    except Exception as e:
        print(f"[SCANNER] testssl.sh error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        import os
        if os.path.exists(output_file):
            os.remove(output_file)