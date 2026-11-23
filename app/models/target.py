from datetime import datetime, timezone
from app import db

class Target(db.Model):
    __tablename__ = "targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    base_url = db.Column(db.String(255), nullable=False, unique=True)
    scope_prefix = db.Column(db.String(255), nullable=False)
    environment = db.Column(db.String(64), default="Local Docker Lab")
    description = db.Column(db.Text, nullable=True)
    is_authorized = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    assessments = db.relationship(
        "Assessment", backref="target", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "base_url": self.base_url,
            "scope_prefix": self.scope_prefix,
            "environment": self.environment,
            "is_authorized": self.is_authorized,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M UTC"),
        }
