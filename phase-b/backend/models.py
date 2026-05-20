from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("Scan", backref="creator", lazy=True)
    reports = db.relationship("Report", backref="generator", lazy=True)


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.String(8), primary_key=True)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    target_url = db.Column(db.String(500), nullable=False)
    target_name = db.Column(db.String(200), nullable=True)
    status = db.Column(db.String(20), default="pending")
    progress = db.Column(db.Integer, default=0)
    scan_type = db.Column(db.String(20), default="full")
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    findings = db.relationship("Finding", backref="scan", lazy=True,
                               cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="scan", lazy=True)


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.String(8), db.ForeignKey("scans.id"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    owasp_id = db.Column(db.String(5))
    owasp_label = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    cvss_vector = db.Column(db.String(200))
    description = db.Column(db.Text)
    endpoint = db.Column(db.String(500))
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    tool_used = db.Column(db.String(100))
    is_false_positive = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "owasp_id": self.owasp_id,
            "owasp_label": self.owasp_label,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "description": self.description,
            "endpoint": self.endpoint,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "tool_used": self.tool_used,
            "is_false_positive": self.is_false_positive
        }


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.String(8), primary_key=True)
    scan_id = db.Column(db.String(8), db.ForeignKey("scans.id"), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    format = db.Column(db.String(10), default="pdf")
    language = db.Column(db.String(5), default="fr")
    file_path = db.Column(db.String(500))
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "format": self.format,
            "language": self.language,
            "file_path": self.file_path,
            "generated_at": self.generated_at.isoformat()
        }