from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    from app import models
    from app.routes.dashboard import dashboard_bp
    from app.routes.api import api_bp
    from app.routes.targets import targets_bp
    from app.routes.traffic import traffic_bp
    from app.routes.vulnerabilities import vulnerabilities_bp
    from app.routes.reports import reports_bp
    from app.routes.compare import compare_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(targets_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(compare_bp)

    with app.app_context():
        db.create_all()
        _seed_default_juice_shop_target()

    return app


def _seed_default_juice_shop_target():
    from app.models.target import Target
    from app.models.assessment import Assessment

    existing = Target.query.filter_by(base_url="http://127.0.0.1:3000").first()
    if not existing:
        juice_shop = Target(
            name="OWASP Juice Shop (Local Docker)",
            base_url="http://127.0.0.1:3000",
            scope_prefix="http://127.0.0.1:3000",
            environment="Kali Linux Local Docker Container",
            description="Primary intentionally vulnerable target for WebVulnX VAPT analysis.",
            is_authorized=True,
        )
        db.session.add(juice_shop)
        db.session.commit()

        initial_assessment = Assessment(
            title="Juice Shop Baseline VAPT Assessment #1",
            target_id=juice_shop.id,
            status="Active",
            notes="Initial baseline assessment ready to receive Burp Suite Community traffic.",
        )
        db.session.add(initial_assessment)
        db.session.commit()
