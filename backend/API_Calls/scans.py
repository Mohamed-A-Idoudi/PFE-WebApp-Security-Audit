import uuid
import threading
from flask import Blueprint, request, jsonify, g
from extensions import db
from auth_helpers import token_required, analyst_required
from models import Scan, Finding
from services.scanner_client import run_scan_background
from models import Scan, Finding, User

scans_bp = Blueprint("scans", __name__, url_prefix="/api")


@scans_bp.route("/scan", methods=["POST"])
@analyst_required
def start_scan():
    data        = request.get_json()
    target_url  = data.get("url", "").strip()
    target_name = data.get("name", "").strip()
    scan_type   = data.get("scan_type", "full")
    scan_speed  = data.get("scan_speed", "normal")

    if not target_url:
        return jsonify({"error": "URL is required"}), 400
    if not target_url.startswith(("http://", "https://")):
        return jsonify({"error": "URL must start with http:// or https://"}), 400

    scan_id = str(uuid.uuid4())[:8]
    scan = Scan(
        id          = scan_id,
        target_url  = target_url,
        target_name = target_name or target_url,
        status      = "running",
        scan_type   = scan_type,
        scan_speed  = scan_speed,
        created_by  = g.current_user_id,
    )
    db.session.add(scan)
    db.session.commit()

    # Forward scan_type to scanner
    thread = threading.Thread(
        target=run_scan_background,
        args=(scan_id, target_url, scan_speed, scan_type)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "scan_id": scan_id,
        "status":  "running",
        "target":  target_url,
        "message": "Scan started",
    })


@scans_bp.route("/status/<scan_id>", methods=["GET"])
@token_required
def get_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "scan_id":      scan.id,
        "status":       scan.status,
        "scan_type":    scan.scan_type,
        "scan_speed":   scan.scan_speed,
        "target":       scan.target_url,
        "target_name":  scan.target_name,
        "created_at":   scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "progress":     scan.progress,
        "error_message":scan.error_message,
    })


@scans_bp.route("/results/<scan_id>", methods=["GET"])
@token_required
def get_results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    findings = db.session.execute(
        db.select(Finding)
        .filter_by(scan_id=scan_id)
        .order_by(Finding.cvss_score.desc())
    ).scalars().all()
    return jsonify({
        "scan_id":        scan_id,
        "status":         scan.status,
        "progress":       scan.progress,
        "target":         scan.target_url,
        "target_name":    scan.target_name,
        "total_findings": len(findings),
        "findings":       [f.to_dict() for f in findings],
    })


@scans_bp.route("/scans", methods=["GET"])
@token_required
def list_scans():
    user     = db.session.get(User, g.current_user_id)
    is_admin = user.role == "admin"
    show_all = request.args.get("all") == "true"

    if is_admin and show_all:
        scans = db.session.execute(
            db.select(Scan).order_by(Scan.created_at.desc()).limit(200)
        ).scalars().all()
    else:
        scans = db.session.execute(
            db.select(Scan)
            .filter_by(created_by=g.current_user_id)
            .order_by(Scan.created_at.desc())
            .limit(50)
        ).scalars().all()

    def sev_count(scan_id, severity):
        return db.session.execute(
            db.select(db.func.count(Finding.id))
            .filter_by(scan_id=scan_id, severity=severity)
        ).scalar() or 0

    result = []
    for s in scans:
        entry = {
            "scan_id":      s.id,
            "target":       s.target_url,
            "target_name":  s.target_name,
            "status":       s.status,
            "scan_type":    s.scan_type,
            "scan_speed":   s.scan_speed,
            "created_at":   s.created_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "finding_counts": {
                "Critical": sev_count(s.id, "Critical"),
                "High":     sev_count(s.id, "High"),
                "Medium":   sev_count(s.id, "Medium"),
                "Low":      sev_count(s.id, "Low"),
            },
        }
        if is_admin and show_all:
            owner = db.session.get(User, s.created_by)
            entry["created_by_email"] = owner.email if owner else "unknown"
        result.append(entry)
    return jsonify(result)


@scans_bp.route("/scans/<scan_id>", methods=["DELETE"])
@analyst_required
def delete_scan(scan_id):
    from models import Report
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    db.session.execute(db.delete(Report).where(Report.scan_id == scan_id))
    db.session.execute(db.delete(Finding).where(Finding.scan_id == scan_id))
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"message": "Scan deleted"})


# ── False positive toggle ─────────────────────────────────────────
@scans_bp.route("/findings/<int:finding_id>/false-positive", methods=["PATCH"])
@analyst_required
def toggle_false_positive(finding_id):
    data    = request.get_json()
    finding = db.session.get(Finding, finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
    finding.is_false_positive = bool(data.get("is_false_positive", False))
    db.session.commit()
    return jsonify({
        "id":               finding.id,
        "is_false_positive": finding.is_false_positive,
    })
