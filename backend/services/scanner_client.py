import os
import requests

def run_scan_background(scan_id: str, target_url: str, scan_speed: str = "normal", scan_type: str = "full"):
    from app import app
    from extensions import db
    from models import Scan

    scanner_url = os.getenv("SCANNER_URL", "http://scanner:5001")
    with app.app_context():
        try:
            response = requests.post(
                f"{scanner_url}/scan",
                json={"scan_id": scan_id, "url": target_url, "scan_speed": scan_speed, "scan_type": scan_type},
                timeout=10000,
            )
            if response.status_code != 200:
                raise Exception(f"Scanner returned {response.status_code}: {response.text}")
        except Exception as e:
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status        = "error"
                scan.error_message = str(e)
                db.session.commit()
            print(f"[SCANNER CLIENT] Error for scan {scan_id}: {e}")
