import os
import random
import threading
from flask import Blueprint, request, jsonify, g, send_file
from extensions import db
from auth_helpers import token_required, analyst_required
from models import Scan, Report
from services.report_service import generate_report_file

reports_bp = Blueprint("reports", __name__, url_prefix="/api")


@reports_bp.route("/report/<scan_id>", methods=["POST"])
@analyst_required
def generate_report(scan_id):
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "complete":
        return jsonify({"error": "Scan not complete yet"}), 400

    data          = request.get_json()
    report_format = data.get("format", "pdf")
    language      = data.get("language", "en")
    report_id     = str(random.randint(10000000, 99999999))

    os.makedirs("/app/reports", exist_ok=True)

    report = Report(
        id           = report_id,
        scan_id      = scan_id,
        generated_by = g.current_user_id,
        format       = report_format,
        language     = language,
        file_path    = f"/app/reports/{report_id}.{report_format}",
    )
    db.session.add(report)
    db.session.commit()

    thread = threading.Thread(
        target=generate_report_file,
        args=(report_id, scan_id, report_format)
    )
    thread.daemon = True
    thread.start()

    return jsonify({
        "report_id":    report_id,
        "scan_id":      scan_id,
        "format":       report_format,
        "status":       "generating",
        "download_url": f"/api/report/{report_id}/download",
    })


@reports_bp.route("/report/<report_id>/download", methods=["GET"])
@token_required
def download_report(report_id):
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
        download_name=filename,
    )
