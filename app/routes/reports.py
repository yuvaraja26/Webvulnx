from flask import Blueprint, render_template, Response
from app.models import Assessment, Target, HTTPTransaction, VulnerabilityFinding
from reporting.pdf_generator import generate_pdf_report
from reporting.html_generator import generate_html_report

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/", methods=["GET"])
def index():
    assessments = Assessment.query.order_by(Assessment.started_at.desc()).all()
    summary_list = []
    for a in assessments:
        target = Target.query.get(a.target_id)
        tx_count = HTTPTransaction.query.filter_by(assessment_id=a.id).count()
        finding_count = VulnerabilityFinding.query.filter_by(assessment_id=a.id).count()
        summary_list.append(
            {
                "assessment": a,
                "target": target,
                "tx_count": tx_count,
                "finding_count": finding_count,
            }
        )
    return render_template("reports.html", assessments=summary_list)


@reports_bp.route("/<int:assessment_id>/pdf", methods=["GET"])
def download_pdf(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    target = Target.query.get_or_404(assessment.target_id)
    findings = VulnerabilityFinding.query.filter_by(assessment_id=assessment.id).all()
    tx_count = HTTPTransaction.query.filter_by(assessment_id=assessment.id).count()

    pdf_bytes = generate_pdf_report(assessment, target, findings, tx_count)
    filename = f"WebVulnX_Report_Assessment_{assessment.id}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@reports_bp.route("/<int:assessment_id>/html", methods=["GET"])
def download_html(assessment_id):
    assessment = Assessment.query.get_or_404(assessment_id)
    target = Target.query.get_or_404(assessment.target_id)
    findings = VulnerabilityFinding.query.filter_by(assessment_id=assessment.id).all()
    tx_count = HTTPTransaction.query.filter_by(assessment_id=assessment.id).count()

    html_content = generate_html_report(assessment, target, findings, tx_count)
    filename = f"WebVulnX_Report_Assessment_{assessment.id}.html"
    return Response(
        html_content,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
