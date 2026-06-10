import os
from datetime import datetime as dt


def generate_report_file(report_id: str, scan_id: str, fmt: str):
    """
    Runs in a background thread.
    Fetches all DB data fresh inside its own app context
    to avoid SQLAlchemy DetachedInstanceError.
    """
    from app import app
    from extensions import db
    from models import Scan, Finding, Report
    from jinja2 import Environment, FileSystemLoader

    with app.app_context():
        try:
            scan = db.session.get(Scan, scan_id)
            if not scan:
                print(f"[REPORT] Scan {scan_id} not found in thread")
                return

            findings = db.session.execute(
                db.select(Finding)
                .filter_by(scan_id=scan_id)
                .order_by(Finding.cvss_score.desc())
            ).scalars().all()

            print(f"[REPORT] Generating {fmt.upper()} — scan {scan_id} — {len(findings)} findings")

            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for f in findings:
                if f.severity in sev_counts:
                    sev_counts[f.severity] += 1

            duration = ""
            if scan.completed_at and scan.created_at:
                mins = int((scan.completed_at - scan.created_at).total_seconds() / 60)
                duration = f"{mins} min"

            context = {
                "report_id":    report_id,
                "scan":         scan,
                "findings":     findings,
                "sev_counts":   sev_counts,
                "duration":     duration,
                "generated_at": dt.utcnow().strftime("%d/%m/%Y at %H:%M UTC"),
                "total":        len(findings),
            }

            template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
            template_dir = os.path.abspath(template_dir)
            env          = Environment(loader=FileSystemLoader(template_dir))
            template     = env.get_template("report.html")
            html_content = template.render(**context)

            import re
            html_content = re.sub(
                r'(https?://)', lambda m: m.group().replace('://', '://\u200b'), html_content
            )

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
