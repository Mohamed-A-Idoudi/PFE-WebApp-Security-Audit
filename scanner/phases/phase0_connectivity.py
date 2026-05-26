"""Phase 0 — Connectivity check. Fail-fast before wasting scan time."""
import urllib.request
import urllib.error


def check_connectivity(url: str):
    """Returns (reachable: bool, status_code: int, error_msg: str|None)"""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecuriScan/1.0"})
        response = urllib.request.urlopen(req, timeout=10)
        return True, response.status, None
    except urllib.error.HTTPError as e:
        return True, e.code, None   # 4xx/5xx = server is reachable
    except urllib.error.URLError as e:
        return False, 0, str(e.reason)
    except Exception as e:
        return False, 0, str(e)
