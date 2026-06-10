"""
Phase 0b — Passive OSINT via theHarvester.
Gathers emails, subdomains, and hosts from public sources.
Passive only — no active probing of the target.
"""
import os
import re
import json
import subprocess
from .utils import extract_host


def run_osint(scan_id: str, url: str) -> dict:
    host   = extract_host(url)
    parts  = host.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else host

    osint = {"emails": [], "subdomains": [], "hosts": [], "domain": domain}
    output_file = f"/tmp/harvester_{scan_id}"

    # Try multiple invocation methods — theHarvester may be a script, not a binary in PATH
    harvester_cmds = [
        ["theHarvester",          "-d", domain, "-b", "bing,yahoo,duckduckgo,certspotter,crtsh", "-l", "50", "-f", output_file],
        ["/usr/local/bin/theHarvester", "-d", domain, "-b", "bing,yahoo,duckduckgo", "-l", "50", "-f", output_file],
        ["python3", "/opt/theHarvester/theHarvester.py", "-d", domain, "-b", "bing,yahoo", "-l", "50", "-f", output_file],
    ]

    print(f"[SCANNER] theHarvester → {domain}")
    ran = False

    for cmd in harvester_cmds:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            ran    = True
            output = result.stdout + result.stderr

            # Parse JSON output if file was created
            json_file = output_file + ".json"
            if os.path.exists(json_file):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    osint["emails"]     = list(set(data.get("emails", [])))[:20]
                    osint["subdomains"] = list(set(data.get("hosts",  [])))[:30]
                    osint["hosts"]      = list(set(data.get("ips",    [])))[:20]
                    print(f"[SCANNER] OSINT: {len(osint['emails'])} emails, "
                          f"{len(osint['subdomains'])} subdomains")
                except Exception:
                    # Fallback: parse text output
                    for line in output.splitlines():
                        line = line.strip()
                        if "@" in line and "." in line and len(line) < 100:
                            m = re.search(r'[\w.\-]+@[\w.\-]+', line)
                            if m:
                                osint["emails"].append(m.group(0).lower())
            break  # successfully invoked theHarvester

        except FileNotFoundError:
            continue  # try next invocation method
        except subprocess.TimeoutExpired:
            print("[SCANNER] theHarvester timeout after 60s")
            ran = True
            break
        except Exception as e:
            print(f"[SCANNER] OSINT error: {e}")
            ran = True
            break

    if not ran:
        print("[SCANNER] theHarvester not installed — skipping OSINT phase")

    # Deduplicate
    osint["emails"]     = list(set(osint["emails"]))[:20]
    osint["subdomains"] = list(set(osint["subdomains"]))[:30]

    print(f"[SCANNER] Phase 0b: {len(osint['emails'])} emails, "
          f"{len(osint['subdomains'])} subdomains found")

    # Cleanup temp files
    for ext in ["", ".json", ".xml"]:
        path = output_file + ext
        if os.path.exists(path):
            os.remove(path)

    return osint
