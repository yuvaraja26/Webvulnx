from flask import Blueprint, render_template, request, redirect, url_for, flash
from app import db
from app.models import VulnerabilityFinding, HTTPTransaction
from scanner.engine import run_passive_analysis

vulnerabilities_bp = Blueprint("vulnerabilities", __name__, url_prefix="/vulnerabilities")

VALID_STATUSES = ["New", "Needs Validation", "Confirmed", "False Positive", "Fixed", "Retested"]


@vulnerabilities_bp.route("/", methods=["GET"])
def list_vulnerabilities():
    severity_filter = request.args.get("severity", "").strip()
    status_filter = request.args.get("status", "").strip()

    query = VulnerabilityFinding.query
    if severity_filter:
        query = query.filter_by(severity=severity_filter)
    if status_filter:
        query = query.filter_by(validation_status=status_filter)

    findings = query.order_by(VulnerabilityFinding.created_at.desc()).all()
    return render_template(
        "vulnerabilities.html",
        findings=findings,
        severity_filter=severity_filter,
        status_filter=status_filter,
        valid_statuses=VALID_STATUSES,
    )


@vulnerabilities_bp.route("/<int:finding_id>", methods=["GET"])
def detail(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    return render_template(
        "vulnerability_detail.html",
        finding=finding,
        valid_statuses=VALID_STATUSES,
    )


@vulnerabilities_bp.route("/<int:finding_id>/status", methods=["POST"])
def update_status(finding_id):
    finding = VulnerabilityFinding.query.get_or_404(finding_id)
    new_status = request.form.get("validation_status", "").strip()
    if new_status in VALID_STATUSES:
        finding.validation_status = new_status
        db.session.commit()
        flash(f"Finding #{finding.id} status updated to '{new_status}'.", "success")
    return redirect(url_for("vulnerabilities.detail", finding_id=finding.id))


@vulnerabilities_bp.route("/scan-all", methods=["POST"])
def scan_all_traffic():
    transactions = HTTPTransaction.query.all()
    total_new = 0
    for tx in transactions:
        total_new += run_passive_analysis(tx)
    flash(f"Passive analysis complete across {len(transactions)} transactions. {total_new} new finding(s) recorded.", "success")
    return redirect(url_for("vulnerabilities.list_vulnerabilities"))
