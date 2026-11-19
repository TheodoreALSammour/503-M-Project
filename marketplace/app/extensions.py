from flask import g, request
from flask_limiter import Limiter
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def client_ip():
    # The app sits directly behind Docker's port mapping; we deliberately do
    # NOT trust X-Forwarded-For (it is client controlled and would let an
    # attacker rotate their apparent IP to dodge rate limits).
    return request.remote_addr or "unknown"


def user_or_ip_key():
    user = getattr(g, "user", None)
    return f"user:{user.id}" if user is not None else f"ip:{client_ip()}"


def login_account_key():
    body = request.get_json(silent=True)
    email = body.get("email") if isinstance(body, dict) else None
    if isinstance(email, str):
        return "login-account:" + email.strip().lower()[:254]
    return f"login-account-ip:{client_ip()}"


limiter = Limiter(key_func=client_ip)
