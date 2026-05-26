"""
Phase 0c — Technology fingerprinting via WhatWeb
Detects CMS, server software, language, framework, and plugin versions.
Output feeds Phase 4 (auth form detection), Phase 5 (Nikto tuning),
and Phase 6 (Nuclei tag selection).
"""
import json
import subprocess
import re
from .utils import random_ua, evasion_headers, random_sleep

def run_whatweb(scan_id: str, url: str) -> dict:
    """
    Run WhatWeb with aggression level 3 (active but not intrusive).
    Returns fingerprint dict that other phases consume.

    Fingerprint structure:
    {
        "cms":        "WordPress 6.4.2",
        "server":     "Apache/2.4.54",
        "language":   "PHP/8.1",
        "framework":  "Laravel",
        "plugins":    ["WooCommerce 7.x", "Yoast SEO"],
        "raw":        {...}   ← full WhatWeb output
    }
    """
    output_file = f"/tmp/whatweb_{scan_id}.json"
    fingerprint = {
        "cms":       "",
        "server":    "",
        "language":  "",
        "framework": "",
        "plugins":   [],
        "raw":       {}
    }

    try:
        cmd = [
            "whatweb",
            "--aggression", "3",
            "--log-json", output_file,
            "--quiet",
            url
        ]
        print(f"[SCANNER] WhatWeb → {url}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if not result and result.returncode not in [0, 1]:
            print(f"[SCANNER] WhatWeb returned code {result.returncode}")

        if not __import__("os").path.exists(output_file):
            print("[SCANNER] WhatWeb produced no output — using header-based fallback")
            return _header_fingerprint(url)

        with open(output_file) as f:
            raw = json.load(f)

        # WhatWeb JSON is a list — take first result
        if isinstance(raw, list) and raw:
            result_data = raw[0]
        elif isinstance(raw, dict):
            result_data = raw
        else:
            print("[SCANNER] WhatWeb unexpected output format")
            return fingerprint

        fingerprint["raw"] = result_data
        plugins = result_data.get("plugins", {})

        # CMS detection
        for cms_name in ["WordPress", "Drupal", "Joomla", "Magento",
                         "Shopify", "Wix", "Squarespace", "TYPO3"]:
            if cms_name in plugins:
                version = _extract_version(plugins[cms_name])
                fingerprint["cms"] = f"{cms_name} {version}".strip()
                print(f"[SCANNER] WhatWeb CMS: {fingerprint['cms']}")
                break

        # Server detection
        if "Apache" in plugins:
            version = _extract_version(plugins["Apache"])
            fingerprint["server"] = f"Apache {version}".strip()
        elif "Nginx" in plugins:
            version = _extract_version(plugins["Nginx"])
            fingerprint["server"] = f"Nginx {version}".strip()
        elif "IIS" in plugins:
            version = _extract_version(plugins["IIS"])
            fingerprint["server"] = f"IIS {version}".strip()
        elif "OpenResty" in plugins:
            fingerprint["server"] = "OpenResty/Nginx"

        # Language detection
        if "PHP" in plugins:
            version = _extract_version(plugins["PHP"])
            fingerprint["language"] = f"PHP {version}".strip()
        elif "Java" in plugins or "Tomcat" in plugins:
            fingerprint["language"] = "Java"
        elif "Python" in plugins or "Django" in plugins or "Flask" in plugins:
            fingerprint["language"] = "Python"
        elif "Ruby-on-Rails" in plugins or "Ruby" in plugins:
            fingerprint["language"] = "Ruby"
        elif "ASP.NET" in plugins:
            fingerprint["language"] = "ASP.NET"

        # Framework detection
        for fw in ["Laravel", "Symfony", "CodeIgniter", "CakePHP",
                   "Django", "Flask", "Rails", "Spring", "Angular",
                   "React", "Vue.js", "Bootstrap", "jQuery"]:
            if fw in plugins:
                fingerprint["framework"] = fw
                break

        # Plugin list for WordPress sites
        if "WordPress" in fingerprint["cms"]:
            for plugin_key in plugins:
                if "Plugin" in plugin_key or "wp-" in plugin_key.lower():
                    version = _extract_version(plugins[plugin_key])
                    fingerprint["plugins"].append(f"{plugin_key} {version}".strip())

        print(f"[SCANNER] WhatWeb fingerprint: {_summarize(fingerprint)}")

    except subprocess.TimeoutExpired:
        print("[SCANNER] WhatWeb timeout — using header fallback")
        return _header_fingerprint(url)
    except FileNotFoundError:
        print("[SCANNER] WhatWeb not installed — using header fallback")
        return _header_fingerprint(url)
    except Exception as e:
        print(f"[SCANNER] WhatWeb error: {e} — using header fallback")
        return _header_fingerprint(url)
    finally:
        import os
        if os.path.exists(output_file):
            os.remove(output_file)

    return fingerprint


def _extract_version(plugin_data) -> str:
    """Extract version string from WhatWeb plugin dict."""
    if isinstance(plugin_data, dict):
        versions = plugin_data.get("version", [])
        if versions and isinstance(versions, list):
            return versions[0]
        string = plugin_data.get("string", [])
        if string and isinstance(string, list):
            match = re.search(r'\d+\.\d+[\.\d]*', str(string[0]))
            if match:
                return match.group(0)
    return ""


def _summarize(fp: dict) -> str:
    parts = []
    if fp["cms"]:      parts.append(f"CMS={fp['cms']}")
    if fp["server"]:   parts.append(f"Server={fp['server']}")
    if fp["language"]: parts.append(f"Lang={fp['language']}")
    if fp["framework"]:parts.append(f"FW={fp['framework']}")
    return " | ".join(parts) if parts else "unknown"


def _header_fingerprint(url: str) -> dict:
    """
    Fallback when WhatWeb is unavailable.
    Detect technology from HTTP headers only.
    """
    import urllib.request
    fp = {"cms": "", "server": "", "language": "", "framework": "", "plugins": [], "raw": {}}
    try:
        req      = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=10)
        headers  = {k.lower(): v for k, v in response.headers.items()}
        html     = response.read(5000).decode("utf-8", errors="ignore").lower()

        server    = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")

        if "apache" in server.lower():  fp["server"]   = server
        if "nginx"  in server.lower():  fp["server"]   = server
        if "php"    in x_powered.lower(): fp["language"] = x_powered

        if "wp-content" in html or "wordpress" in html:
            fp["cms"] = "WordPress"
        elif "drupal" in html:
            fp["cms"] = "Drupal"
        elif "joomla" in html:
            fp["cms"] = "Joomla"

        print(f"[SCANNER] Header fingerprint: {_summarize(fp)}")
    except Exception as e:
        print(f"[SCANNER] Header fingerprint error: {e}")
    return fp
