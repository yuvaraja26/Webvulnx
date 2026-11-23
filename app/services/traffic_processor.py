import json
from urllib.parse import urlparse, parse_qs

SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

MAX_BODY_CHARS = 50000


def redact_set_cookie(value: str) -> str:
    """Redacts the cookie value while preserving security attributes (HttpOnly, Secure, SameSite)."""
    parts = [p.strip() for p in str(value).split(";")]
    if not parts:
        return "[REDACTED]"
    name_val = parts[0].split("=", 1)
    redacted_first = f"{name_val[0]}=[REDACTED]" if len(name_val) == 2 else "[REDACTED]"
    return "; ".join([redacted_first] + parts[1:])


def redact_headers(headers: dict) -> dict:
    """Redacts sensitive authentication and session headers before persistence."""
    if not isinstance(headers, dict):
        return {}
    sanitized = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in SENSITIVE_HEADERS:
            sanitized[k] = "[REDACTED]"
        elif lk == "set-cookie":
            sanitized[k] = redact_set_cookie(v)
        else:
            sanitized[k] = str(v)
    return sanitized


def parse_and_sanitize_transaction(payload: dict) -> dict:
    """Normalizes an incoming HTTP transaction payload from Burp or local test clients."""
    url = payload.get("url", "").strip()
    parsed = urlparse(url)

    req_headers = redact_headers(payload.get("request_headers", {}))
    res_headers = redact_headers(payload.get("response_headers", {}))

    req_body = str(payload.get("request_body", "") or "")[:MAX_BODY_CHARS]
    res_body = str(payload.get("response_body", "") or "")[:MAX_BODY_CHARS]

    query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

    def get_header(h_dict, name):
        for k, v in h_dict.items():
            if k.lower() == name.lower():
                return v
        return None

    return {
        "http_method": payload.get("method", "GET").upper(),
        "url": url,
        "host": parsed.netloc,
        "path": parsed.path or "/",
        "query_params": json.dumps(query_params),
        "request_headers": json.dumps(req_headers),
        "request_body": req_body,
        "request_content_type": get_header(req_headers, "Content-Type"),
        "status_code": payload.get("status_code"),
        "response_headers": json.dumps(res_headers),
        "response_body": res_body,
        "response_content_type": get_header(res_headers, "Content-Type"),
        "server_header": get_header(res_headers, "Server"),
    }
