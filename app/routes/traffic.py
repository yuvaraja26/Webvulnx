from flask import Blueprint, render_template
from app.models import HTTPTransaction

traffic_bp = Blueprint("traffic", __name__, url_prefix="/traffic")


@traffic_bp.route("/", methods=["GET"])
def list_traffic():
    transactions = HTTPTransaction.query.order_by(HTTPTransaction.captured_at.desc()).limit(100).all()
    return render_template("traffic.html", transactions=transactions)
