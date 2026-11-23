from flask import Blueprint, render_template
from sqlalchemy import func
from app import db
from app.models import Target, Assessment, HTTPTransaction, VulnerabilityFinding

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    total_targets = Target.query.count()
    total_assessments = Assessment.query.count()
    total_requests = HTTPTransaction.query.count()
    total_findings = VulnerabilityFinding.query.count()

    # Count vulnerabilities by severity
    severities = ["Critical", "High", "Medium", "Low", "Informational"]
    severity_counts = {sev: 0 for sev in severities}
    rows = (
        db.session.query(VulnerabilityFinding.severity, func.count(VulnerabilityFinding.id))
        .group_by(VulnerabilityFinding.severity)
        .all()
    )
    for sev, count in rows:
        if sev in severity_counts:
            severity_counts[sev] = count

    # Count vulnerabilities by category
    cat_rows = (
        db.session.query(VulnerabilityFinding.category, func.count(VulnerabilityFinding.id))
        .group_by(VulnerabilityFinding.category)
        .all()
    )
    category_labels = [r[0] for r in cat_rows] if cat_rows else [
        "Security Headers", "XSS / Reflection", "SQL Anomaly", "Access Control", "Session / Cookie"
    ]
    category_counts = [r[1] for r in cat_rows] if cat_rows else [0, 0, 0, 0, 0]

    recent_assessments = Assessment.query.order_by(Assessment.started_at.desc()).limit(5).all()
    recent_findings = (
        VulnerabilityFinding.query.order_by(VulnerabilityFinding.created_at.desc()).limit(6).all()
    )
    active_assessment = Assessment.query.filter_by(status="Active").first()

    return render_template(
        "dashboard.html",
        total_targets=total_targets,
        total_assessments=total_assessments,
        total_requests=total_requests,
        total_findings=total_findings,
        severity_counts=severity_counts,
        category_labels=category_labels,
        category_counts=category_counts,
        recent_assessments=recent_assessments,
        recent_findings=recent_findings,
        active_assessment=active_assessment,
    )
