from datetime import datetime, timezone
from app import db

class Assessment(db.Model):
    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey("targets.id"), nullable=False)
    status = db.Column(db.String(32), default="Active")  # Active, Completed, Paused
    started_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)

    transactions = db.relationship(
        "HTTPTransaction", backref="assessment", lazy=True, cascade="all, delete-orphan"
    )
    findings = db.relationship(
        "VulnerabilityFinding", backref="assessment", lazy=True, cascade="all, delete-orphan"
    )
