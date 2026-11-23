import json
import re

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version"]

DEBUG_PATTERNS = [
    (r"SQLITE_ERROR", "SQLite Error Message Disclosed"),
    (r"Traceback \(most recent call last\)", "Python Stack Trace Disclosed"),
    (r"SyntaxError:|ReferenceError:|TypeError:", "JavaScript/Node.js Runtime Error Disclosed"),
    (r"SequelizeDatabaseError", "Sequelize ORM Error Disclosed"),
]


def analyze(tx) -> list[dict]:
    findings = []
    try:
        headers = json.loads(tx.response_headers or "{}")
    except Exception:
        headers = {}

    lower_headers = {k.lower(): (k, v) for k, v in headers.items()}

    for h_key in DISCLOSURE_HEADERS:
        if h_key in lower_headers:
            orig_name, val = lower_headers[h_key]
            findings.append(
                {
                    "title": f"Server Technology Disclosure ({orig_name})",
                    "category": "Information Disclosure",
                    "affected_url": tx.url,
                    "http_method": tx.http_method,
                    "parameter": orig_name,
                    "severity": "Informational",
                    "confidence": "Confirmed",
                    "validation_status": "New",
                    "description": f"The response exposes technology details via the '{orig_name}: {val}' header.",
                    "detection_explanation": f"Detected verbose banner header '{orig_name}: {val}' in HTTP response.",
                    "request_evidence": f"{tx.http_method} {tx.url}",
                    "response_evidence": f"{orig_name}: {val}",
                    "impact": "Exposing server or framework versions helps attackers identify known version-specific weaknesses.",
                    "remediation": f"Suppress or obfuscate the '{orig_name}' header in your web server or reverse proxy configuration.",
                }
            )

    body = tx.response_body or ""
    for pattern, title in DEBUG_PATTERNS:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            snippet_start = max(0, match.start() - 60)
            snippet_end = min(len(body), match.end() + 140)
            snippet = body[snippet_start:snippet_end]
            findings.append(
                {
                    "title": title,
                    "category": "Information Disclosure",
                    "affected_url": tx.url,
                    "http_method": tx.http_method,
                    "parameter": "Response Body",
                    "severity": "Medium",
                    "confidence": "Suspected",
                    "validation_status": "Needs Validation",
                    "description": "The application returned an unhandled error or debug stack trace in the HTTP response body.",
                    "detection_explanation": f"Matched error signature '{pattern}' in response body.",
                    "request_evidence": f"{tx.http_method} {tx.url}",
                    "response_evidence": snippet,
                    "impact": "Verbose error messages can reveal internal file paths, database schemas, or framework internals.",
                    "remediation": "Disable debug mode in production and return generic error pages while logging details server-side.",
                }
            )

    return findings
