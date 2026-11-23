import base64
import json
import re

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64url_decode_json(segment: str) -> dict | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def analyze(tx) -> list[dict]:
    """Passively inspects JWT headers and claims found in responses for weak algorithm settings."""
    findings = []
    body = tx.response_body or ""
    matches = JWT_PATTERN.findall(body)
    if not matches:
        return findings

    seen_tokens = set()
    for token in matches[:5]:
        if token in seen_tokens:
            continue
        seen_tokens.add(token)

        parts = token.split(".")
        if len(parts) != 3:
            continue

        header = _b64url_decode_json(parts[0])
        if not header:
            continue

        alg = str(header.get("alg", "")).strip()
        if alg.lower() in {"none", ""}:
            findings.append(
                {
                    "title": "JWT Token With Unsecured 'none' Algorithm",
                    "category": "Token & Session Security",
                    "affected_url": tx.url,
                    "http_method": tx.http_method,
                    "parameter": "JWT Header (alg)",
                    "severity": "High",
                    "confidence": "Confirmed",
                    "validation_status": "Needs Validation",
                    "description": "A JSON Web Token observed in the response specifies 'none' or an empty signing algorithm.",
                    "detection_explanation": f"Decoded JWT header with alg='{alg}'.",
                    "request_evidence": f"{tx.http_method} {tx.url}",
                    "response_evidence": f"JWT Header: {json.dumps(header)}",
                    "impact": "Tokens without signature verification can be forged if the verifier accepts unsigned tokens.",
                    "remediation": "Enforce strong asymmetric (e.g., RS256/ES256) or keyed HMAC (e.g., HS256) algorithms and explicitly reject 'alg': 'none'.",
                }
            )
        elif alg.upper().startswith("HS"):
            findings.append(
                {
                    "title": "Symmetric HMAC JWT Observed in Response",
                    "category": "Token & Session Security",
                    "affected_url": tx.url,
                    "http_method": tx.http_method,
                    "parameter": "JWT Header (alg)",
                    "severity": "Informational",
                    "confidence": "Confirmed",
                    "validation_status": "New",
                    "description": f"A JWT using symmetric algorithm '{alg}' was observed in the response payload.",
                    "detection_explanation": f"Decoded JWT header indicating symmetric signing algorithm '{alg}'.",
                    "request_evidence": f"{tx.http_method} {tx.url}",
                    "response_evidence": f"JWT Header: {json.dumps(header)}",
                    "impact": "Symmetric JWTs rely on shared secret strength and strict key management across services.",
                    "remediation": "Ensure HMAC signing keys have high entropy, are rotated safely, and are never exposed in client-side code.",
                }
            )

    return findings
