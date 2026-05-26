"""
SecuriScan — Scanner Agent v3 Final
Full pipeline with evasion, Tor stealth mode support.
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
from sqlalchemy import text
from datetime import datetime, timezone

from phases.db                  import update_scan_status, engine
from phases.utils               import phase_sleep
from phases.phase0_connectivity import check_connectivity
from phases.phase0b_osint       import run_osint
from phases.phase0c_whatweb     import run_whatweb
from phases.phase0d_crawler     import run_crawler
from phases.phase1_headers      import run_header_checks
from phases.phase1_testssl      import run_testssl
from phases.phase1b_js_libs     import run_js_library_check
from phases.phase_jwt           import run_jwt_phase
from phases.phase2_nmap         import run_nmap
from phases.phase3_directories  import run_directory_checks
from phases.phase3b_xss         import run_xss_checks
from phases.phase4_auth         import run_auth_checks
from phases.phase5_nikto        import run_nikto
from phases.phase6_nuclei       import run_nuclei
from phases.phase7_sqlmap       import run_sqlmap

app = Flask(__name__)
CORS(app)


def _now():
    return datetime.now(timezone.utc)


def _complete_scan(scan_id: str):
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE scans SET status='complete', progress=100, completed_at=:t WHERE id=:id"),
            {"t": _now(), "id": scan_id}
        )
        conn.commit()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "securiscan-scanner-v3"})


@app.route("/scan", methods=["POST"])
def scan():
    data       = request.get_json()
    scan_id    = data.get("scan_id")
    url        = data.get("url")
    scan_speed = data.get("scan_speed", "normal")
    scan_type  = data.get("scan_type", "full")

    if not scan_id or not url:
        return jsonify({"error": "scan_id and url required"}), 400

    use_tor = (scan_speed == "stealth")
    if use_tor:
        print("[SCANNER] Stealth mode: tool traffic routed through Tor")

    print(f"\n[SCANNER] ════════════════════════════════════════════")
    print(f"[SCANNER] Scan {scan_id} → {url} [{scan_speed}/{scan_type}]")
    print(f"[SCANNER] ════════════════════════════════════════════\n")

    fingerprint   = {}
    crawl_results = {}

    try:
        # Phase 0 — Connectivity
        print("[SCANNER] Phase 0: Connectivity")
        update_scan_status(scan_id, "running", 2)
        reachable, status_code, error_msg = check_connectivity(url)
        if not reachable:
            with engine.connect() as conn:
                conn.execute(text("UPDATE scans SET status='error', progress=0 WHERE id=:id"),
                             {"id": scan_id})
                conn.commit()
            return jsonify({"error": f"Target unreachable: {error_msg}"}), 400
        print(f"[SCANNER] Reachable — HTTP {status_code}")
        update_scan_status(scan_id, "running", 4)
        phase_sleep(scan_speed)

        # Phase 0b — OSINT
        print("[SCANNER] Phase 0b: Passive OSINT")
        try:    run_osint(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 0b error: {e}")
        update_scan_status(scan_id, "running", 7)
        phase_sleep(scan_speed)

        # Phase 0c — WhatWeb fingerprinting
        print("[SCANNER] Phase 0c: Technology fingerprinting")
        try:    fingerprint = run_whatweb(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 0c error: {e}")
        update_scan_status(scan_id, "running", 10)
        phase_sleep(scan_speed)

        # Phase 0d — Katana URL discovery
        print("[SCANNER] Phase 0d: URL discovery (Katana)")
        try:    crawl_results = run_crawler(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 0d error: {e}")
        update_scan_status(scan_id, "running", 13)
        phase_sleep(scan_speed)

        # Phase 1 — Headers + EOL
        print("[SCANNER] Phase 1: Headers + EOL detection")
        try:    run_header_checks(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 1 error: {e}")
        update_scan_status(scan_id, "running", 17)
        phase_sleep(scan_speed)

        # Phase 1 TLS — testssl
        print("[SCANNER] Phase 1 (TLS): testssl.sh")
        try:    run_testssl(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 1 TLS error: {e}")
        update_scan_status(scan_id, "running", 22)

        # Quick scan stops here
        if scan_type == "quick":
            print("[SCANNER] Quick scan complete")
            _complete_scan(scan_id)
            return jsonify({"status": "complete", "scan_id": scan_id})

        phase_sleep(scan_speed)

        # Phase 1b — JS library CVE check
        print("[SCANNER] Phase 1b: JS library CVE check")
        try:    run_js_library_check(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 1b error: {e}")
        update_scan_status(scan_id, "running", 27)
        phase_sleep(scan_speed)

        # Phase JWT — JWT security analysis
        print("[SCANNER] Phase JWT: JWT analysis")
        try:    run_jwt_phase(scan_id, url, scan_type=scan_type, scan_speed=scan_speed)
        except Exception as e: print(f"[SCANNER] Phase JWT error: {e}")
        update_scan_status(scan_id, "running", 31)
        phase_sleep(scan_speed)

        # Phase 2 — nmap
        print("[SCANNER] Phase 2: nmap port scan")
        try:    run_nmap(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 2 error: {e}")
        update_scan_status(scan_id, "running", 36)
        phase_sleep(scan_speed)

        # Phase 3 — Directory exposure + CORS
        REQUEST_DELAY = 1.5 if scan_speed == "stealth" else 0.0
        print("[SCANNER] Phase 3: Directory exposure + CORS")
        try:    run_directory_checks(scan_id, url, REQUEST_DELAY)
        except Exception as e: print(f"[SCANNER] Phase 3 error: {e}")
        update_scan_status(scan_id, "running", 46)
        phase_sleep(scan_speed)

        # Phase 3b — XSS
        print("[SCANNER] Phase 3b: XSS detection")
        try:    run_xss_checks(scan_id, url, crawl_results)
        except Exception as e: print(f"[SCANNER] Phase 3b error: {e}")
        update_scan_status(scan_id, "running", 54)
        phase_sleep(scan_speed)

        # Phase 4 — Authentication
        print("[SCANNER] Phase 4: Authentication testing")
        try:    run_auth_checks(scan_id, url)
        except Exception as e: print(f"[SCANNER] Phase 4 error: {e}")
        update_scan_status(scan_id, "running", 62)
        phase_sleep(scan_speed)

        # Phase 5 — Nikto
        print("[SCANNER] Phase 5: Nikto")
        try:    run_nikto(scan_id, url, use_tor=use_tor)
        except Exception as e: print(f"[SCANNER] Phase 5 error: {e}")
        update_scan_status(scan_id, "running", 73)
        phase_sleep(scan_speed)

        # Phase 6 — Nuclei
        print("[SCANNER] Phase 6: Nuclei")
        try:    run_nuclei(scan_id, url, fingerprint, use_tor=use_tor)
        except Exception as e: print(f"[SCANNER] Phase 6 error: {e}")
        update_scan_status(scan_id, "running", 86)
        phase_sleep(scan_speed)

        # Phase 7 — SQLmap
        print("[SCANNER] Phase 7: SQLmap")
        try:    run_sqlmap(scan_id, url, crawl_results, use_tor=use_tor)
        except Exception as e: print(f"[SCANNER] Phase 7 error: {e}")
        update_scan_status(scan_id, "running", 96)

        _complete_scan(scan_id)
        print(f"\n[SCANNER] ✓ Scan {scan_id} complete\n")
        return jsonify({"status": "complete", "scan_id": scan_id})

    except Exception as e:
        import traceback
        traceback.print_exc()
        update_scan_status(scan_id, "error", 0)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)