import json


def analyze(tx) -> list[dict]:
    findings = []
    try:
        headers = json.loads(tx.response_headers or "{}")
    except Exception:
        headers = {}

    set_cookie_val = None
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            set_cookie_val = str(v)
            break

    if not set_cookie_val or set_cookie_val == "[REDACTED]":
        return findings

    lower_cookie = set_cookie_val.lower()
    missing_flags = []
    if "httponly" not in lower_cookie:
        missing_flags.append("HttpOnly")
    if "samesite" not in lower_cookie:
        missing_flags.append("SameSite")
    if tx.url.startswith("https://") and "secure" not in lower_cookie:
        missing_flags.append("Secure")

    if missing_flags:
        findings.append(
            {
                "title": f"Insecure Cookie Attributes (Missing {', '.join(missing_flags)})",
                "category": "Session Security",
                "affected_url": tx.url,
                "http_method": tx.http_method,
                "parameter": "Set-Cookie",
                "severity": "Low",
                "confidence": "Confirmed",
                "validation_status": "Needs Validation",
                "description": f"A cookie set by the server is missing recommended security flags: {', '.join(missing_flags)}.",
                "detection_explanation": f"Inspected Set-Cookie attributes and found {', '.join(missing_flags)} absent.",
                "request_evidence": f"{tx.http_method} {tx.url}",
                "response_evidence": f"Set-Cookie: {set_cookie_val}",
                "impact": "Missing HttpOnly or SameSite flags weaken protection against client-side script access and CSRF.",
                "remediation": "Set HttpOnly, SameSite=Lax (or Strict), and Secure (over HTTPS) on all session cookies.",
            }
        )

    return findings
