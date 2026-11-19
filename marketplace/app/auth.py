"""Authentication: password hashing, server-side sessions, CSRF.

* Passwords are hashed with Argon2id (argon2-cffi).
* A session is an opaque 256-bit random token. Only its SHA-256 hash is stored.
* Browsers get the token in an HttpOnly, SameSite=Strict cookie; state-changing
  cookie-authenticated requests must also carry ``X-CSRF-Token`` matching the
  CSRF token bound to that session (synchronizer token pattern).
* API clients (Swagger UI / Postman, used for Admin and Finance) send the token
  as ``Authorization: Bearer``; this is not sent automatically by browsers, so
  CSRF does not apply to it.
* Every request re-loads the user from the database: a suspended account, or a
  revoked / expired / idle session, stops working immediately.
"""
import hashlib
import hmac
import secrets
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import current_app, g, request

from .audit import audit
from .extensions import db
from .models import AccountStatus, AuthSession, User, utcnow

_ph = PasswordHasher()  # Argon2id with library defaults (RFC 9106 low-memory profile)
_DUMMY_HASH = _ph.hash("dummy-password-for-timing-equalisation")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class CSRFError(Exception):
    pass


def hash_password(password):
    return _ph.hash(password)


def verify_password(user, password):
    """Constant-ish time: always run one Argon2 verification even when the
    user does not exist, so response time does not reveal valid emails."""
    target = user.password_hash if user is not None else _DUMMY_HASH
    try:
        ok = _ph.verify(target, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        ok = False
    if ok and user is not None and _ph.check_needs_rehash(user.password_hash):
        user.password_hash = _ph.hash(password)
    return ok and user is not None


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user, kind):
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    s = AuthSession(
        token_hash=_hash_token(token), csrf_token=csrf, user_id=user.id, kind=kind,
        created_at=now, last_seen_at=now,
        expires_at=now + timedelta(seconds=current_app.config["SESSION_ABSOLUTE_TTL_SECONDS"]),
    )
    db.session.add(s)
    return token, csrf, s


def revoke_all_sessions(user_id, except_session_id=None):
    q = AuthSession.query.filter(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    if except_session_id is not None:
        q = q.filter(AuthSession.id != except_session_id)
    return q.update({AuthSession.revoked_at: utcnow()}, synchronize_session=False)


def _extract_token():
    header = request.headers.get("Authorization", "")
    if header:
        parts = header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1].strip():
            return parts[1].strip(), "bearer"
        return None, "invalid"
    cookie = request.cookies.get(current_app.config["SESSION_COOKIE_NAME"])
    if cookie:
        return cookie, "cookie"
    return None, None


def load_request_user():
    """Populate ``g.user`` / ``g.auth_session`` from the request. Never trusts
    any identity or role information sent by the client."""
    g.user = None
    g.auth_session = None
    g.auth_via = None
    token, via = _extract_token()
    if not token or len(token) > 128:
        return
    s = AuthSession.query.filter_by(token_hash=_hash_token(token)).first()
    if s is None or s.revoked_at is not None or s.kind != via:
        return
    now = utcnow()
    idle = timedelta(seconds=current_app.config["SESSION_IDLE_TTL_SECONDS"])
    if s.expires_at <= now or s.last_seen_at + idle <= now:
        s.revoked_at = now
        db.session.commit()
        audit("auth.session_expired", user_id=s.user_id)
        return
    user = db.session.get(User, s.user_id)
    if user is None:
        return
    if user.status != AccountStatus.ACTIVE:
        # Suspended: kill every session of this account right now.
        revoke_all_sessions(user.id)
        db.session.commit()
        audit("auth.session_rejected_suspended", user_id=user.id)
        return

    if via == "cookie" and request.method not in SAFE_METHODS:
        sent = request.headers.get("X-CSRF-Token", "")
        if not sent or not hmac.compare_digest(sent, s.csrf_token):
            audit("auth.csrf_rejected", user_id=user.id)
            raise CSRFError()

    if (now - s.last_seen_at).total_seconds() > 30:
        s.last_seen_at = now
        db.session.commit()
    g.user = user
    g.auth_session = s
    g.auth_via = via


def set_session_cookies(response, token, csrf):
    cfg = current_app.config
    max_age = cfg["SESSION_ABSOLUTE_TTL_SECONDS"]
    response.set_cookie(cfg["SESSION_COOKIE_NAME"], token, max_age=max_age, httponly=True,
                        secure=cfg["SESSION_COOKIE_SECURE"], samesite="Strict", path="/")
    # Readable by our own JS so it can echo it in the X-CSRF-Token header.
    response.set_cookie(cfg["CSRF_COOKIE_NAME"], csrf, max_age=max_age, httponly=False,
                        secure=cfg["SESSION_COOKIE_SECURE"], samesite="Strict", path="/")


def clear_session_cookies(response):
    cfg = current_app.config
    response.delete_cookie(cfg["SESSION_COOKIE_NAME"], path="/")
    response.delete_cookie(cfg["CSRF_COOKIE_NAME"], path="/")
