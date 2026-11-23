from urllib.parse import urlparse
from flask import current_app

def is_url_in_authorized_scope(url: str, registered_scope_prefix: str = None) -> tuple[bool, str]:
    """
    Validates that a target URL is strictly within the allowed local testing environment
    and matches the registered target scope prefix.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "URL scheme must be http or https."

        hostname = (parsed.hostname or "").lower()
        allowed_hosts = current_app.config.get("ALLOWED_HOSTS", {"127.0.0.1", "localhost"})

        if hostname not in allowed_hosts:
            return (
                False,
                f"Host '{hostname}' is outside the authorized local lab hosts ({', '.join(allowed_hosts)}).",
            )

        if registered_scope_prefix and not url.startswith(registered_scope_prefix):
            return (
                False,
                f"URL '{url}' does not match registered scope prefix '{registered_scope_prefix}'.",
            )

        return True, "Authorized in-scope URL."
    except Exception as exc:
        return False, f"Malformed URL: {str(exc)}"
