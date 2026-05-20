from flask import Flask, jsonify, request, g
from flask_cors import CORS
from models import db, Scan, Finding, User, Report
import uuid
import random
import threading
import os
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173", "http://localhost:80", "http://localhost"],
     supports_credentials=True)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql://securiscan:password@db:5432/securiscan"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "securiscan-dev-secret-2026")

db.init_app(app)

with app.app_context():
    db.create_all()
    # Mark any scans stuck in running as error on startup
    db.session.execute(
        db.text("UPDATE scans SET status='error' WHERE status='running'")
    )
    db.session.commit()
    # Create default users if none exist
    if not db.session.execute(
        db.select(User).filter_by(email="admin@securiscan.local")
    ).scalar_one_or_none():
        hashed = bcrypt.hashpw("admin123".encode(), bcrypt.gensalt())
        admin = User(
            email="admin@securiscan.local",
            password_hash=hashed.decode(),
            role="admin"
        )
        analyst = User(
            email="analyst@securiscan.local",
            password_hash=bcrypt.hashpw("analyst123".encode(), bcrypt.gensalt()).decode(),
            role="analyst"
        )
        db.session.add(admin)
        db.session.add(analyst)
        db.session.commit()


# ─── JWT Helpers ─────────────────────────────────────────────────────────────

def generate_token(user):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=8)
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            g.current_user_id = payload["user_id"]
            g.current_role = payload["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.current_role not in ["analyst", "admin"]:
            return jsonify({"error": "Analyst access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ─── Auth Endpoints ──────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    user = db.session.execute(
        db.select(User).filter_by(email=email, is_active=True)
    ).scalar_one_or_none()

    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(user)
    return jsonify({
        "token": token,
        "user": {"id": user.id, "email": user.email, "role": user.role}
    })


@app.route("/api/auth/me", methods=["GET"])
@token_required
def get_me():
    user = db.session.get(User, g.current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": user.id, "email": user.email, "role": user.role})


# ─── Health ───────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "SecuriScan API running"})


# ─── Scan Endpoints ───────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@analyst_required
def start_scan():
    data = request.get_json()
    target_url = data.get("url", "").strip()
    target_name = data.get("name", "").strip()
    scan_type = data.get("scan_type", "full")

    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    scan_id = str(uuid.uuid4())[:8]
    scan = Scan(
        id=scan_id,
        target_url=target_url,
        target_name=target_name or target_url,
        status="running",
        scan_type=scan_type,
        created_by=g.current_user_id
    )
    db.session.add(scan)
    db.session.commit()

    thread = threading.Thread(target=run_scan_background, args=(scan_id, target_url))
    thread.daemon = True
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "status": "running",
        "target": target_url,
        "message": "Scan started"
    })


@app.route("/api/status/<scan_id>", methods=["GET"])
@token_required
def get_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "scan_id": scan.id,
        "status": scan.status,
        "target": scan.target_url,
        "target_name": scan.target_name,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "progress": scan.progress,
        "error_message": scan.error_message
    })


@app.route("/api/results/<scan_id>", methods=["GET"])
@token_required
def get_results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = db.session.execute(
        db.select(Finding).filter_by(scan_id=scan_id)
    ).scalars().all()
    return jsonify({
        "scan_id": scan_id,
        "status": scan.status,
        "target": scan.target_url,
        "target_name": scan.target_name,
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings]
    })


@app.route("/api/scans", methods=["GET"])
@token_required
def list_scans():
    scans = db.session.execute(
        db.select(Scan).order_by(Scan.created_at.desc()).limit(20)
    ).scalars().all()
    return jsonify([{
        "scan_id": s.id,
        "target": s.target_url,
        "target_name": s.target_name,
        "status": s.status,
        "scan_type": s.scan_type,
        "created_at": s.created_at.isoformat(),
        "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        "finding_count": db.session.execute(
            db.select(db.func.count(Finding.id)).filter_by(scan_id=s.id)
        ).scalar()
    } for s in scans])


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
@analyst_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"message": "Scan deleted"})


# ─── Report Endpoints ─────────────────────────────────────────────────────────

@app.route("/api/report/<scan_id>", methods=["POST"])
@analyst_required
def generate_report(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "complete":
        return jsonify({"error": "Scan not complete yet"}), 400

    data = request.get_json()
    report_format = data.get("format", "pdf")
    language = data.get("language", "en")  # Changed: default en not fr

    report_id = str(random.randint(10000000, 99999999))
    os.makedirs("/app/reports", exist_ok=True)

    report = Report(
        id=report_id,
        scan_id=scan_id,
        generated_by=g.current_user_id,
        format=report_format,
        language=language,
        file_path=f"/app/reports/{report_id}.{report_format}"
    )
    db.session.add(report)
    db.session.commit()

    # Pass only scan_id — thread fetches everything fresh
    thread = threading.Thread(
        target=generate_report_file,
        args=(report_id, scan_id, report_format)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "report_id": report_id,
        "scan_id": scan_id,
        "format": report_format,
        "status": "generating",
        "download_url": f"/api/report/{report_id}/download"
    })


@app.route("/api/report/<report_id>/download", methods=["GET"])
@token_required
def download_report(report_id):
    from flask import send_file
    report = db.session.get(Report, report_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    if not os.path.exists(report.file_path):
        return jsonify({"error": "Report not ready yet, try again in a few seconds"}), 404
    mimetype = "application/pdf" if report.format == "pdf" else "text/html"
    filename = f"SecuriScan_SEC-{report.id}_{report.scan_id}.{report.format}"
    return send_file(
        report.file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )


# ─── User Management (Admin only) ────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
@token_required
def list_users():
    if g.current_role != "admin":
        return jsonify({"error": "Admin access required"}), 403
    users = db.session.execute(db.select(User)).scalars().all()
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.isoformat()
    } for u in users])


@app.route("/api/users", methods=["POST"])
@token_required
def create_user():
    if g.current_role != "admin":
        return jsonify({"error": "Admin access required"}), 403
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "analyst")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    existing = db.session.execute(
        db.select(User).filter_by(email=email)
    ).scalar_one_or_none()
    if existing:
        return jsonify({"error": "Email already exists"}), 409

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = User(email=email, password_hash=hashed.decode(), role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify({"id": user.id, "email": user.email, "role": user.role}), 201


# ─── Report Generation (Background Thread) ───────────────────────────────────

def generate_report_file(report_id, scan_id, fmt):
    """Runs in background thread. Fetches all data fresh to avoid DetachedInstanceError."""
    with app.app_context():
        try:
            from jinja2 import Environment, FileSystemLoader
            from datetime import datetime as dt

            scan = db.session.get(Scan, scan_id)
            if not scan:
                print(f"[REPORT] Scan {scan_id} not found in thread")
                return

            findings = db.session.execute(
                db.select(Finding)
                .filter_by(scan_id=scan_id)
                .order_by(Finding.cvss_score.desc())
            ).scalars().all()

            print(f"[REPORT] Generating {fmt} for scan {scan_id} — {len(findings)} findings")

            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for f in findings:
                if f.severity in sev_counts:
                    sev_counts[f.severity] += 1

            duration = ""
            if scan.completed_at and scan.created_at:
                mins = int((scan.completed_at - scan.created_at).total_seconds() / 60)
                duration = f"{mins} min"

            context = {
                "report_id": report_id,
                "scan": scan,
                "findings": findings,
                "sev_counts": sev_counts,
                "duration": duration,
                "generated_at": dt.utcnow().strftime("%d/%m/%Y at %H:%M UTC"),
                "total": len(findings),
            }

            template_dir = os.path.join(os.path.dirname(__file__), "templates")
            env = Environment(loader=FileSystemLoader(template_dir))
            template = env.get_template("report.html")
            html_content = template.render(**context)

            file_path = f"/app/reports/{report_id}.{fmt}"
            os.makedirs("/app/reports", exist_ok=True)

            if fmt == "pdf":
                from weasyprint import HTML
                HTML(string=html_content, base_url=template_dir).write_pdf(file_path)
            else:
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(html_content)

            report = db.session.get(Report, report_id)
            if report:
                report.file_path = file_path
                db.session.commit()

            print(f"[REPORT] {fmt.upper()} ready: {file_path}")

        except Exception as e:
            print(f"[REPORT] Generation error: {e}")
            import traceback
            traceback.print_exc()


# ─── Background Scanner ───────────────────────────────────────────────────────

def run_scan_background(scan_id, target_url):
    import requests
    scanner_url = os.getenv("SCANNER_URL", "http://scanner:5001")
    with app.app_context():
        try:
            response = requests.post(
                f"{scanner_url}/scan",
                json={"scan_id": scan_id, "url": target_url},
                timeout=1200
            )
            if response.status_code != 200:
                raise Exception(f"Scanner error: {response.text}")
        except Exception as e:
            scan = db.session.get(Scan, scan_id)
            if scan:
                scan.status = "error"
                scan.error_message = str(e)
                db.session.commit()


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)