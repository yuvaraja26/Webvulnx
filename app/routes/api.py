from functools import wraps
from flask import Blueprint, jsonify, request, current_app
from app import db
from app.models import Assessment, Target, HTTPTransaction
from app.services.scope_validator import is_url_in_authorized_scope
from app.services.traffic_processor import parse_and_sanitize_transaction
from scanner.engine import run_passive_analysis

api_bp = Blueprint("api", __name__)


def require_burp_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_key = request.headers.get("X-WebVulnX-Key", "")
        expected_key = current_app.config.get("BURP_API_KEY")
        if not provided_key or provided_key != expected_key:
            return jsonify({"status": "error", "message": "Unauthorized: Invalid API Key"}), 401
        return f(*args, **kwargs)

    return decorated


@api_bp.route("/status", methods=["GET"])
@require_burp_api_key
def api_status():
    active_assessment = Assessment.query.filter_by(status="Active").first()
    target = Target.query.get(active_assessment.target_id) if active_assessment else None

    return jsonify(
        {
            "status": "online",
            "platform": "WebVulnX Engine v1.0",
            "active_assessment_id": active_assessment.id if active_assessment else None,
            "active_assessment_title": active_assessment.title if active_assessment else None,
            "authorized_target": target.base_url if target else None,
        }
    )


@api_bp.route("/traffic", methods=["POST"])
@require_burp_api_key
def ingest_traffic():
    """Receives selected HTTP traffic from Burp Suite and runs passive vulnerability analysis."""
    payload = request.get_json(silent=True)
    if not payload or not payload.get("url"):
        return jsonify({"status": "error", "message": "Missing JSON payload or 'url' field."}), 400

    active_assessment = Assessment.query.filter_by(status="Active").first()
    if not active_assessment:
        return jsonify({"status": "error", "message": "No active assessment found."}), 400

    target = Target.query.get(active_assessment.target_id)
    in_scope, reason = is_url_in_authorized_scope(payload["url"], target.scope_prefix)
    if not in_scope:
        return jsonify({"status": "rejected", "message": f"Out of scope: {reason}"}), 403

    clean_data = parse_and_sanitize_transaction(payload)
    tx = HTTPTransaction(
        assessment_id=active_assessment.id,
        source=payload.get("source", "Burp Community Extension"),
        **clean_data,
    )
    db.session.add(tx)
    db.session.commit()

    new_findings = run_passive_analysis(tx)

    return jsonify(
        {
            "status": "ingested",
            "transaction_id": tx.id,
            "assessment_id": active_assessment.id,
            "method": tx.http_method,
            "url": tx.url,
            "new_findings": new_findings,
        }
    ), 201
