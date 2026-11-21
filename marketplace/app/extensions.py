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
    """Per-account login limit, keyed on (email, client IP).

    Keying on the email alone let anyone lock a victim (including the admin)
    out for up to an hour just by sending a few wrong passwords for their
    email. With (email, IP) the attacker only throttles their own IP; the
    victim can still log in from theirs. Brute force from one IP is still
    capped by this limit and by the separate per-IP limit."""
    body = request.get_json(silent=True)
    email = body.get("email") if isinstance(body, dict) else None
    if isinstance(email, str):
        return f"login-account:{email.strip().lower()[:254]}|{client_ip()}"
    return f"login-account-ip:{client_ip()}"


limiter = Limiter(key_func=client_ip)
