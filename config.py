import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Core Flask security configuration
    SECRET_KEY = os.environ.get("WEBVULNX_SECRET_KEY", "webvulnx-dev-secret-key-change-in-prod")
    
    # Local SQLite database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "WEBVULNX_DB_URI", f"sqlite:///{os.path.join(BASE_DIR, 'webvulnx.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Local API authentication token for Burp Suite Community Extension
    BURP_API_KEY = os.environ.get("WEBVULNX_API_KEY", "wv_local_burp_token_9f8a7b6c5d4e3f2a1b")

    # Strict Localhost & Authorized Lab Scope Enforcement
    ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
    DEFAULT_TARGET_URL = "http://127.0.0.1:3000"
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB max payload size from Burp proxy
