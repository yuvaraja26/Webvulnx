from app import db
from app.models import VulnerabilityFinding
from scanner.detectors import security_headers, information_disclosure, cookie_security

PASSIVE_DETECTORS = [
    security_headers,
    information_disclosure,
    cookie_security,
]


def run_passive_analysis(tx) -> int:
    """Runs all passive detectors on a single HTTPTransaction and stores unique findings."""
    new_count = 0
    for detector in PASSIVE_DETECTORS:
        results = detector.analyze(tx)
        for item in results:
            exists = VulnerabilityFinding.query.filter_by(
                assessment_id=tx.assessment_id,
                title=item["title"],
                affected_url=item["affected_url"],
            ).first()
            if not exists:
                finding = VulnerabilityFinding(
                    assessment_id=tx.assessment_id,
                    transaction_id=tx.id,
                    **item,
                )
                db.session.add(finding)
                new_count += 1

    tx.analyzed = True
    db.session.commit()
    return new_count
