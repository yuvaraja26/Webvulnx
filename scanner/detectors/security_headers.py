import json

REQUIRED_HEADERS = {
    "content-security-policy": {
        "title": "Missing Content-Security-Policy (CSP) Header",
        "severity": "Medium",
        "description": "The HTTP response does not include a Content-Security-Policy header.",
        "impact": "Without CSP, the browser has fewer restrictions on loading untrusted scripts, increasing the impact of XSS.",
        "remediation": "Define a strict Content-Security-Policy header restricting script-src, object-src, and default-src to trusted origins.",
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "Low",
        "description": "The HTTP response does not specify X-Frame-Options to prevent framing.",
        "impact": "The application may be embedded in an iframe on a third-party site, enabling clickjacking attacks.",
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use the CSP 'frame-ancestors' directive.",
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "Low",
        "description": "The response lacks 'X-Content-Type-Options: nosniff'.",
        "impact": "Browsers may MIME-sniff responses away from the declared Content-Type, potentially executing non-script content.",
        "remediation": "Add the header 'X-Content-Type-Options: nosniff' to all HTTP responses.",
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": "Informational",
        "description": "No Referrer-Policy header was detected in the response.",
        "impact": "Sensitive URL paths or query parameters may be leaked to external sites via the Referer header.",
        "remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
    },
}


def analyze(tx) -> list[dict]:
    findings = []
    try:
        headers = json.loads(tx.response_headers or "{}")
    except Exception:
        headers = {}

    if not headers:
        return findings

    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_key, meta in REQUIRED_HEADERS.items():
        if header_key not in lower_headers:
            findings.append(
                {
                    "title": meta["title"],
                    "category": "Security Misconfiguration",
                    "affected_url": tx.url,
                    "http_method": tx.http_method,
                    "parameter": header_key,
                    "severity": meta["severity"],
                    "confidence": "Confirmed",
                    "validation_status": "New",
                    "description": meta["description"],
                    "detection_explanation": f"Passive header inspection confirmed '{header_key}' is absent from the {tx.status_code} response.",
                    "request_evidence": f"{tx.http_method} {tx.url}",
                    "response_evidence": json.dumps(headers, indent=2),
                    "impact": meta["impact"],
                    "remediation": meta["remediation"],
                }
            )
    return findings
