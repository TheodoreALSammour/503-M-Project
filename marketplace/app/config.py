import os


def read_secret(name, default=None):
    """Read a secret from ``<NAME>_FILE`` (Docker secret volume) or ``<NAME>``."""
    path = os.environ.get(f"{name}_FILE")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name, default)


def _database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    host = os.environ.get("DB_HOST")
    if host:
        user = os.environ.get("DB_USER", "marketplace")
        name = os.environ.get("DB_NAME", "marketplace")
        password = read_secret("DB_PASSWORD", "")
        return f"postgresql+psycopg://{user}:{password}@{host}:5432/{name}"
    return "sqlite:///marketplace.db"


class Config:
    SECRET_KEY = read_secret("MARKETPLACE_SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    MAX_CONTENT_LENGTH = 64 * 1024  # bodies are small JSON documents

    # Sessions (opaque server-side tokens, see auth.py)
    SESSION_COOKIE_NAME = "mp_session"
    CSRF_COOKIE_NAME = "mp_csrf"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
    SESSION_ABSOLUTE_TTL_SECONDS = int(os.environ.get("SESSION_ABSOLUTE_TTL_SECONDS", 8 * 3600))
    SESSION_IDLE_TTL_SECONDS = int(os.environ.get("SESSION_IDLE_TTL_SECONDS", 30 * 60))

    # Payment gateway
    GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:9000")
    GATEWAY_MERCHANT_ID = os.environ.get("GATEWAY_MERCHANT_ID", "marketplace")
    GATEWAY_REQUEST_KEY = read_secret("GATEWAY_REQUEST_KEY")
    GATEWAY_RESPONSE_KEY = read_secret("GATEWAY_RESPONSE_KEY")
    GATEWAY_RESPONSE_MAX_AGE_SECONDS = 300
    CURRENCY = "USD"

    # Rate limiting
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_ENABLED = os.environ.get("RATELIMIT_ENABLED", "true").lower() == "true"
    RATELIMIT_HEADERS_ENABLED = True
    LOGIN_RATE_LIMIT_IP = os.environ.get("LOGIN_RATE_LIMIT_IP", "10 per minute")
    LOGIN_RATE_LIMIT_ACCOUNT = os.environ.get("LOGIN_RATE_LIMIT_ACCOUNT", "5 per minute;20 per hour")
    COUPON_RATE_LIMIT = os.environ.get("COUPON_RATE_LIMIT", "10 per minute")
    CHECKOUT_RATE_LIMIT = os.environ.get("CHECKOUT_RATE_LIMIT", "10 per minute")

    # Access-control configuration (permission matrix + ABAC assignment)
    POLICY_CONFIG_PATH = os.environ.get(
        "POLICY_CONFIG_PATH", os.path.join(os.path.dirname(__file__), "policy", "policy_config.yaml"))

    LOG_DIR = os.environ.get("LOG_DIR", "logs")
