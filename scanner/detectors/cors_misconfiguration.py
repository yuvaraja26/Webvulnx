import json

REFLECT_ORIGIN_IN_ACAH = "access-control-allow-origin"
CREDENTIALS_HEADER = "access-control-allow-credentials"


def analyze(tx) -> list[dict]:
    """Passively flags overly permissive CORS configurations on captured responses."""
    findings = []
    try:
        res_headers = json.loads(tx.response_headers or "{}")
    except Exception:
        res_headers = {}

    try:
        req_headers = json.loads(tx.request_headers or "{}")
    except Exception:
        req_headers = {}

    if not res_headers:
        return findings

    lower_res = {k.lower(): (k, str(v)) for k, v in res_headers.items()}
    lower_req = {k.lower(): str(v) for k, v in req_headers.items()}

    if REFLECT_ORIGIN_IN_ACAH not in lower_res:
        return findings

    _, acao_val = lower_res[REFLECT_ORIGIN_IN_ACAH]
    creds_enabled = False
    if CREDENTIALS_HEADER in lower_res:
        creds_enabled = lower_res[CREDENTIALS_HEADER][1].strip().lower() == "true"

    req_origin = lower_req.get("origin", "").strip()

    if acao_val.strip() == "*" and creds_enabled:
        findings.append(
            {
                "title": "Wildcard CORS Origin With Credentials Enabled",
                "category": "CORS Misconfiguration",
                "affected_url": tx.url,
                "http_method": tx.http_method,
                "parameter": "Access-Control-Allow-Origin",
                "severity": "High",
                "confidence": "Confirmed",
                "validation_status": "Needs Validation",
                "description": "The response sets Access-Control-Allow-Origin to '*' alongside Access-Control-Allow-Credentials: true.",
                "detection_explanation": "Detected wildcard ACAO header combined with ACAO-Credentials set to true.",
                "request_evidence": f"{tx.http_method} {tx.url} (Origin: {req_origin or 'none'})",
                "response_evidence": f"Access-Control-Allow-Origin: {acao_val}\nAccess-Control-Allow-Credentials: {lower_res[CREDENTIALS_HEADER][1]}",
                "impact": "Browsers reject wildcard origins with credentialed requests under the Fetch spec, or misconfigured proxies may allow cross-origin data exposure.",
                "remediation": "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins and avoid combining wildcard origins with credentials.",
            }
        )
    elif req_origin and acao_val.strip() == req_origin:
        sev = "Medium" if creds_enabled else "Low"
        findings.append(
            {
                "title": "Reflected Origin in CORS Header",
                "category": "CORS Misconfiguration",
                "affected_url": tx.url,
                "http_method": tx.http_method,
                "parameter": "Origin / Access-Control-Allow-Origin",
                "severity": sev,
                "confidence": "Suspected",
                "validation_status": "Needs Validation",
                "description": "The server echoed the incoming request Origin header directly into Access-Control-Allow-Origin.",
                "detection_explanation": f"Request Origin '{req_origin}' matched response Access-Control-Allow-Origin '{acao_val}'.",
                "request_evidence": f"{tx.http_method} {tx.url}\nOrigin: {req_origin}",
                "response_evidence": f"Access-Control-Allow-Origin: {acao_val}\nAccess-Control-Allow-Credentials: {creds_enabled}",
                "impact": "If the origin validation logic reflects arbitrary origins without a strict allowlist, unauthorized cross-origin reads may occur.",
                "remediation": "Validate incoming Origin headers against a strict allowlist of trusted origins rather than reflecting arbitrary values.",
            }
        )

    return findings
