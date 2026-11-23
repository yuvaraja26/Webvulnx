from flask import Blueprint, render_template, request
from app.models import Assessment, Target, HTTPTransaction, VulnerabilityFinding

compare_bp = Blueprint("compare", __name__, url_prefix="/compare")


def _finding_signature(finding) -> tuple[str, str]:
    return ((finding.title or "").strip(), (finding.affected_url or "").strip())


@compare_bp.route("/", methods=["GET"])
def index():
    assessments = Assessment.query.order_by(Assessment.started_at.desc()).all()
    targets_by_id = {t.id: t for t in Target.query.all()}

    if not assessments:
        return render_template(
            "compare.html",
            assessments=[],
            targets_by_id=targets_by_id,
            baseline_id=None,
            current_id=None,
            baseline_assessment=None,
            current_assessment=None,
            baseline_tx_count=0,
            current_tx_count=0,
            new_findings=[],
            resolved_findings=[],
            persisting_findings=[],
        )

    current_id = request.args.get("current_id", type=int) or assessments[0].id
    baseline_id = request.args.get("baseline_id", type=int)
    if baseline_id is None:
        baseline_id = assessments[1].id if len(assessments) > 1 else assessments[0].id

    valid_ids = {a.id for a in assessments}
    if current_id not in valid_ids:
        current_id = assessments[0].id
    if baseline_id not in valid_ids:
        baseline_id = assessments[1].id if len(assessments) > 1 else assessments[0].id

    baseline_assessment = Assessment.query.get(baseline_id)
    current_assessment = Assessment.query.get(current_id)

    baseline_tx_count = HTTPTransaction.query.filter_by(assessment_id=baseline_id).count()
    current_tx_count = HTTPTransaction.query.filter_by(assessment_id=current_id).count()

    base_findings = VulnerabilityFinding.query.filter_by(assessment_id=baseline_id).all()
    curr_findings = VulnerabilityFinding.query.filter_by(assessment_id=current_id).all()

    base_map = {_finding_signature(f): f for f in base_findings}
    curr_map = {_finding_signature(f): f for f in curr_findings}

    new_findings = [curr_map[k] for k in curr_map.keys() - base_map.keys()]
    resolved_findings = [base_map[k] for k in base_map.keys() - curr_map.keys()]
    persisting_findings = [curr_map[k] for k in curr_map.keys() & base_map.keys()]

    return render_template(
        "compare.html",
        assessments=assessments,
        targets_by_id=targets_by_id,
        baseline_id=baseline_id,
        current_id=current_id,
        baseline_assessment=baseline_assessment,
        current_assessment=current_assessment,
        baseline_tx_count=baseline_tx_count,
        current_tx_count=current_tx_count,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persisting_findings=persisting_findings,
    )
