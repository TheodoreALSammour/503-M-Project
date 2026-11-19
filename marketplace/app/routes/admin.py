"""Admin (API only): change default credentials, verify sellers, suspend/reactivate."""
from flask import Blueprint, g, jsonify
from sqlalchemy.exc import IntegrityError

from ..audit import audit
from ..auth import hash_password, revoke_all_sessions, verify_password
from ..extensions import db, limiter
from ..models import AccountStatus, Role, SellerProfile, SellerStatus, User, UserRole, utcnow
from ..policy import authorize
from ..validation import EMAIL_RE, ValidationError, empty_body, get_str, json_body, validate_password
from . import arg_choice, paginate

bp = Blueprint("admin", __name__, url_prefix="/api/admin")


def _load_user(user_id):
    return db.session.get(User, user_id)


@bp.post("/change-credentials")
@limiter.limit("5 per minute", key_func=lambda: f"admincred:{g.user.id}" if g.user else "admincred:anon")
@authorize("admin.change_credentials")
def change_credentials():
    body = json_body({"current_password", "new_email", "new_password"},
                     required=("current_password", "new_email", "new_password"))
    admin = g.user
    current = body.get("current_password")
    if not isinstance(current, str) or not verify_password(admin, current):
        audit("admin.change_credentials_failed", reason="bad_current_password")
        return jsonify(error="unauthorized", message="Current password is incorrect."), 401
    new_email = get_str(body, "new_email", min_len=6, max_len=254, pattern=EMAIL_RE).lower()
    if new_email == admin.email:
        raise ValidationError("You must change the default email.", field="new_email")
    new_password = validate_password(body.get("new_password"), new_email)
    if verify_password(admin, new_password):
        raise ValidationError("You must change the default password.", field="new_password")
    old_email = admin.email
    admin.email = new_email
    admin.password_hash = hash_password(new_password)
    admin.must_change_credentials = False
    revoked = revoke_all_sessions(admin.id, except_session_id=g.auth_session.id)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="conflict", message="That email cannot be used."), 409
    audit("admin.credentials_changed", admin_id=admin.id, old_email=old_email, new_email=new_email,
          other_sessions_revoked=revoked)
    return jsonify(user=admin.to_public())


@bp.get("/sellers")
@authorize("seller.list")
def list_sellers():
    status = arg_choice("status", {SellerStatus.UNVERIFIED, SellerStatus.VERIFIED})
    q = SellerProfile.query
    if status:
        q = q.filter(SellerProfile.verification_status == status)
    rows, meta = paginate(q.order_by(SellerProfile.applied_at.desc()))
    return jsonify(sellers=[{**s.to_public(), "email": s.user.email, "full_name": s.user.full_name,
                             "account_status": s.user.status} for s in rows], **meta)


@bp.post("/sellers/<int:user_id>/verify")
@authorize("seller.verify", loader=_load_user)
def verify_seller(user_id):
    empty_body()
    target = g.resource
    profile = target.seller_profile
    if profile is None or Role.SELLER not in target.role_names:
        return jsonify(error="not_found", message="This user has not applied as a seller."), 404
    if profile.verification_status == SellerStatus.VERIFIED:
        return jsonify(error="conflict", message="Seller is already verified."), 409
    profile.verification_status = SellerStatus.VERIFIED
    profile.verified_at = utcnow()
    profile.verified_by = g.user.id
    db.session.commit()
    audit("admin.seller_verified", target_user_id=target.id, store_name=profile.store_name)
    return jsonify(user=target.to_public())


@bp.get("/users")
@authorize("account.list")
def list_users():
    status = arg_choice("status", {AccountStatus.ACTIVE, AccountStatus.SUSPENDED})
    role = arg_choice("role", set(Role.ALL))
    q = User.query
    if status:
        q = q.filter(User.status == status)
    if role:
        q = q.filter(User.roles.any(UserRole.role == role))
    rows, meta = paginate(q.order_by(User.id))
    return jsonify(users=[u.to_public() for u in rows], **meta)


@bp.post("/users/<int:user_id>/suspend")
@authorize("account.suspend", loader=_load_user)
def suspend_user(user_id):
    empty_body()
    target = g.resource
    if target.id == g.user.id:
        # Separation of duties: an admin cannot act on their own account.
        audit("authz.decision", decision="deny", action="account.suspend", policy="SOD_NOT_SELF",
              reason="admin cannot suspend own account", subject_id=g.user.id)
        return jsonify(error="forbidden", message="You cannot suspend your own account."), 403
    if target.status == AccountStatus.SUSPENDED:
        return jsonify(error="conflict", message="Account is already suspended."), 409
    target.status = AccountStatus.SUSPENDED
    revoked = revoke_all_sessions(target.id)  # existing sessions stop working immediately
    db.session.commit()
    audit("admin.account_suspended", target_user_id=target.id, sessions_revoked=revoked)
    return jsonify(user=target.to_public())


@bp.post("/users/<int:user_id>/reactivate")
@authorize("account.reactivate", loader=_load_user)
def reactivate_user(user_id):
    empty_body()
    target = g.resource
    if target.id == g.user.id:
        audit("authz.decision", decision="deny", action="account.reactivate", policy="SOD_NOT_SELF",
              reason="admin cannot act on own account", subject_id=g.user.id)
        return jsonify(error="forbidden", message="You cannot change your own account status."), 403
    if target.status == AccountStatus.ACTIVE:
        return jsonify(error="conflict", message="Account is already active."), 409
    target.status = AccountStatus.ACTIVE
    db.session.commit()
    audit("admin.account_reactivated", target_user_id=target.id)
    return jsonify(user=target.to_public())
