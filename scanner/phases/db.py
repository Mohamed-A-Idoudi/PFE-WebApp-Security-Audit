"""
Shared database utilities for all scanner phases.
All phases import save_finding and update_scan_status from here.
Integrates CVSSCalculator and OWASPMapper for dynamic scoring.
"""
import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from .utils import random_ua

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://securiscan:password@db:5432/securiscan"
)
engine = create_engine(DATABASE_URL)


def now():
    return datetime.now(timezone.utc)


def update_scan_status(scan_id: str, status: str, progress: int):
    with engine.connect() as conn:
        conn.execute(
            text("UPDATE scans SET status=:status, progress=:progress WHERE id=:scan_id"),
            {"status": status, "progress": progress, "scan_id": scan_id}
        )
        conn.commit()


def save_finding(scan_id, title, owasp_id=None, owasp_label=None,
                 severity=None, cvss_score=None, cvss_vector=None,
                 description="", endpoint="", evidence="", remediation="",
                 tool_used="", confidence="probable",
                 # CVSSCalculator parameters (optional — used when caller doesn't provide scores)
                 attack_vector=None, attack_complexity=None,
                 privileges_required=None, user_interaction=None,
                 scope=None, confidentiality=None, integrity=None,
                 availability=None,
                 # OWASPMapper parameters (optional)
                 attack_type=""):
    """
    Save a finding to the database.

    Two modes:
    1. Pre-scored: caller provides cvss_score, cvss_vector, owasp_id, severity
    2. Auto-scored: caller provides CVSS metric parameters and attack_type,
       CVSSCalculator and OWASPMapper compute the rest

    Always skips duplicates (same title + endpoint per scan).
    """
    from .cvss_calculator import calculator
    from .owasp_mapper import mapper

    # Auto-score if CVSS metrics provided but score not given
    if cvss_score is None and attack_vector is not None:
        result     = calculator.calculate(
            attack_vector=attack_vector,
            attack_complexity=attack_complexity or "LOW",
            privileges_required=privileges_required or "NONE",
            user_interaction=user_interaction or "NONE",
            scope=scope or "UNCHANGED",
            confidentiality=confidentiality or "NONE",
            integrity=integrity or "NONE",
            availability=availability or "NONE",
        )
        cvss_score  = result["score"]
        cvss_vector = result["vector"]
        severity    = result["severity"]

    # Auto-map OWASP if not provided
    if owasp_id is None:
        owasp_result = mapper.map(
            tool=tool_used,
            title=title,
            attack_type=attack_type,
        )
        owasp_id    = owasp_result["id"]
        owasp_label = owasp_result["label"]

    with engine.connect() as conn:
        # Deduplication check
        existing = conn.execute(
            text("SELECT id FROM findings WHERE scan_id=:sid AND title=:t AND endpoint=:e"),
            {"sid": scan_id, "t": title, "e": endpoint}
        ).fetchone()
        if existing:
            print(f"[SCANNER] Duplicate skipped: {title[:60]}")
            return

        conn.execute(
            text("""
                INSERT INTO findings
                (scan_id, title, owasp_id, owasp_label, severity,
                 cvss_score, cvss_vector, description, endpoint,
                 evidence, remediation, tool_used, confidence, created_at)
                VALUES
                (:scan_id, :title, :owasp_id, :owasp_label, :severity,
                 :cvss_score, :cvss_vector, :description, :endpoint,
                 :evidence, :remediation, :tool_used, :confidence, :created_at)
            """),
            {
                "scan_id":     scan_id,
                "title":       title,
                "owasp_id":    owasp_id    or "A05",
                "owasp_label": owasp_label or "Security Misconfiguration",
                "severity":    severity    or "Medium",
                "cvss_score":  cvss_score  or 5.0,
                "cvss_vector": cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "description": description,
                "endpoint":    endpoint,
                "evidence":    evidence,
                "remediation": remediation,
                "tool_used":   tool_used,
                "confidence":  confidence,
                "created_at":  now(),
            }
        )
        conn.commit()
