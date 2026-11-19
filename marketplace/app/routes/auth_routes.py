"""Registration, login/logout, own password, seller application."""
from flask import Blueprint, current_app, g, jsonify
from sqlalchemy.exc import IntegrityError

from ..audit import audit
from ..auth import (clear_session_cookies, create_session, hash_password, revoke_all_sessions,
                    set_session_cookies, verify_password)
from ..extensions import db, limiter, login_account_key
from ..models import AccountStatus, Role, SellerProfile, SellerStatus, User
from ..policy import authorize
from ..validation import (EMAIL_RE, NAME_RE, PHONE_RE, STORE_NAME_RE, ValidationError, get_str,
                          json_body, validate_password)

bp = Blueprint("auth", __name__, url_prefix="/api")


def _login_ip_limit():
    return current_app.config["LOGIN_RATE_LIMIT_IP"]


def _login_account_limit():
    return current_app.config["LOGIN_RATE_LIMIT_ACCOUNT"]


@bp.post("/auth/register")
@limiter.limit("5 per minute")
@authorize("auth.register")
def register():
    body = json_body({"full_name", "email", "phone", "password"},
                     required=("full_name", "email", "phone", "password"))
    full_name = get_str(body, "full_name", min_len=2, max_len=120, pattern=NAME_RE)
    email = get_str(body, "email", min_len=6, max_len=254, pattern=EMAIL_RE).lower()
    phone = get_str(body, "phone", min_len=7, max_len=20, pattern=PHONE_RE)
    password = validate_password(body.get("password"), email)

    # Self-registration ALWAYS creates a Buyer. Roles are never taken from the request.
    user = User(full_name=full_name, email=email, phone=phone, password_hash=hash_password(password))
    user.add_role(Role.BUYER)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        audit("auth.register_failed", reason="email_in_use")
        return jsonify(error="conflict", message="This email cannot be used for registration."), 409
    audit("auth.register", user_id=user.id)
    return jsonify(user=user.to_public()), 201


@bp.post("/auth/login")
@limiter.limit(_login_ip_limit)
@limiter.limit(_login_account_limit, key_func=login_account_key)
@authorize("auth.login")
def login():
    body = json_body({"email", "password", "mode"}, required=("email", "password"))
    email = get_str(body, "email", min_len=1, max_len=254).lower()
    password = body.get("password")
    if not isinstance(password, str) or len(password) > 128:
        raise ValidationError("Invalid credentials format.", field="password")
    mode = body.get("mode", "bearer")
    if mode not in ("bearer", "cookie"):
        raise ValidationError("mode must be 'bearer' or 'cookie'.", field="mode")

    user = User.query.filter_by(email=email).first()
    if not verify_password(user, password):
        audit("auth.login_failed", email=email[:254], reason="bad_credentials")
        return jsonify(error="unauthorized", message="Invalid email or password."), 401
    if user.status != AccountStatus.ACTIVE:
        audit("auth.login_failed", user_id=user.id, reason="account_suspended")
        return jsonify(error="forbidden", message="This account is suspended."), 403

    token, csrf, _s = create_session(user, mode)
    db.session.commit()
    audit("auth.login_success", user_id=user.id, mode=mode, roles=sorted(user.role_names))
    payload = {"user": user.to_public(), "csrf_token": csrf}
    if mode == "bearer":
        payload["access_token"] = token
        payload["token_type"] = "Bearer"
        payload["expires_in"] = current_app.config["SESSION_ABSOLUTE_TTL_SECONDS"]
    resp = jsonify(payload)
    if mode == "cookie":
        set_session_cookies(resp, token, csrf)
    return resp


@bp.post("/auth/logout")
@authorize("auth.logout")
def logout():
    s = g.auth_session
    from ..models import utcnow
    s.revoked_at = utcnow()
    db.session.commit()
    audit("auth.logout", user_id=g.user.id)
    resp = jsonify(message="Logged out.")
    clear_session_cookies(resp)
    return resp


@bp.get("/auth/me")
@authorize("auth.me")
def me():
    return jsonify(user=g.user.to_public(), csrf_token=g.auth_session.csrf_token)


@bp.post("/account/password")
@limiter.limit("5 per minute", key_func=lambda: f"pw:{g.user.id}" if g.user else "pw:anon")
@authorize("account.update_password")
def change_password():
    body = json_body({"current_password", "new_password"}, required=("current_password", "new_password"))
    user = g.user
    current = body.get("current_password")
    if not isinstance(current, str) or not verify_password(user, current):
        audit("account.password_change_failed", user_id=user.id, reason="bad_current_password")
        return jsonify(error="unauthorized", message="Current password is incorrect."), 401
    new = validate_password(body.get("new_password"), user.email)
    if verify_password(user, new):
        raise ValidationError("New password must differ from the current one.", field="new_password")
    user.password_hash = hash_password(new)
    revoked = revoke_all_sessions(user.id, except_session_id=g.auth_session.id)
    db.session.commit()
    audit("account.password_changed", user_id=user.id, other_sessions_revoked=revoked)
    return jsonify(message="Password updated. Other sessions were signed out.")


@bp.post("/seller/apply")
@authorize("seller.apply")
def apply_seller():
    body = json_body({"store_name"}, required=("store_name",))
    store_name = get_str(body, "store_name", min_len=2, max_len=80, pattern=STORE_NAME_RE)
    user = g.user
    if user.seller_profile is not None:
        return jsonify(error="conflict", message="You already applied as a seller."), 409
    user.add_role(Role.SELLER)  # keeps Buyer role; SoD enforced inside add_role
    user.seller_profile = SellerProfile(store_name=store_name, verification_status=SellerStatus.UNVERIFIED)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="conflict", message="Store name already taken."), 409
    audit("seller.applied", user_id=user.id, store_name=store_name)
    return jsonify(user=user.to_public()), 201
