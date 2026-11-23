from flask import Blueprint, render_template, request, redirect, url_for, flash
from app import db
from app.models import Target, Assessment
from app.services.scope_validator import is_url_in_authorized_scope

targets_bp = Blueprint("targets", __name__, url_prefix="/targets")


@targets_bp.route("/", methods=["GET"])
def list_targets():
    targets = Target.query.order_by(Target.created_at.desc()).all()
    assessments = Assessment.query.order_by(Assessment.started_at.desc()).all()
    return render_template("targets.html", targets=targets, assessments=assessments)


@targets_bp.route("/add", methods=["POST"])
def add_target():
    name = request.form.get("name", "").strip()
    base_url = request.form.get("base_url", "").strip().rstrip("/")
    environment = request.form.get("environment", "Local Docker Lab").strip()
    description = request.form.get("description", "").strip()

    if not name or not base_url:
        flash("Target name and Base URL are required.", "danger")
        return redirect(url_for("targets.list_targets"))

    in_scope, reason = is_url_in_authorized_scope(base_url)
    if not in_scope:
        flash(f"Scope Violation Blocked: {reason}", "danger")
        return redirect(url_for("targets.list_targets"))

    if Target.query.filter_by(base_url=base_url).first():
        flash("Target URL is already registered.", "warning")
        return redirect(url_for("targets.list_targets"))

    new_target = Target(
        name=name,
        base_url=base_url,
        scope_prefix=base_url,
        environment=environment,
        description=description,
        is_authorized=True,
    )
    db.session.add(new_target)
    db.session.commit()
    flash(f"Authorized target '{name}' added.", "success")
    return redirect(url_for("targets.list_targets"))


@targets_bp.route("/<int:target_id>/start-assessment", methods=["POST"])
def start_assessment(target_id):
    target = Target.query.get_or_404(target_id)
    title = request.form.get("title", "").strip() or f"VAPT Assessment - {target.name}"

    Assessment.query.filter_by(status="Active").update({"status": "Paused"})

    assessment = Assessment(title=title, target_id=target.id, status="Active")
    db.session.add(assessment)
    db.session.commit()
    flash(f"Started active assessment: {title}", "success")
    return redirect(url_for("targets.list_targets"))


@targets_bp.route("/<int:target_id>/delete", methods=["POST"])
def delete_target(target_id):
    target = Target.query.get_or_404(target_id)
    db.session.delete(target)
    db.session.commit()
    flash(f"Target '{target.name}' removed.", "info")
    return redirect(url_for("targets.list_targets"))
