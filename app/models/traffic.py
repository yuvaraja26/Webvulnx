from datetime import datetime, timezone
from app import db

class HTTPTransaction(db.Model):
    __tablename__ = "http_transactions"

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey("assessments.id"), nullable=False)
    source = db.Column(db.String(50), default="Burp Community Extension")

    # Request data
    http_method = db.Column(db.String(16), nullable=False)
    url = db.Column(db.Text, nullable=False)
    host = db.Column(db.String(255), nullable=False)
    path = db.Column(db.Text, nullable=False)
    query_params = db.Column(db.Text, nullable=True)  # JSON serialized
    request_headers = db.Column(db.Text, nullable=False)  # JSON serialized (Redacted)
    request_body = db.Column(db.Text, nullable=True)
    request_content_type = db.Column(db.String(128), nullable=True)

    # Response data
    status_code = db.Column(db.Integer, nullable=True)
    response_headers = db.Column(db.Text, nullable=True)  # JSON serialized
    response_body = db.Column(db.Text, nullable=True)
    response_content_type = db.Column(db.String(128), nullable=True)
    server_header = db.Column(db.String(128), nullable=True)

    analyzed = db.Column(db.Boolean, default=False)
    captured_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
