"""Finance Officer (API only): create coupons, view all payments."""
from datetime import datetime

from flask import Blueprint, g, jsonify
from sqlalchemy.exc import IntegrityError

from ..audit import audit
from ..coupons import CouponError, normalize_code
from ..extensions import db
from ..models import Coupon, CouponType, Payment
from ..money import MoneyError, parse_amount_to_cents, parse_percent_to_bp
from ..policy import authorize
from ..validation import ValidationError, get_int, get_str, json_body
from . import arg_choice, paginate

bp = Blueprint("finance", __name__, url_prefix="/api/finance")


def _parse_dt(body, key):
    raw = get_str(body, key, min_len=10, max_len=40)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise ValidationError(f"'{key}' must be an ISO-8601 date/time.", field=key)
    if dt.tzinfo is not None:
        from datetime import timezone
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


@bp.post("/coupons")
@authorize("coupon.create")
def create_coupon():
    body = json_body({"code", "type", "percent", "amount", "valid_from", "valid_until", "max_uses"},
                     required=("code", "type", "valid_from", "valid_until", "max_uses"))
    try:
        code = normalize_code(body.get("code"))
    except CouponError:
        code = None
    if not code:
        raise ValidationError("code must be 3-32 characters: A-Z, 0-9 or '-'.", field="code")
    kind = body.get("type")
    coupon = Coupon(code=code, kind=kind, created_by=g.user.id)
    try:
        if kind == CouponType.PERCENTAGE:
            if "amount" in body:
                raise ValidationError("percentage coupons take 'percent', not 'amount'.", field="amount")
            coupon.percent_bp = parse_percent_to_bp(body.get("percent"))
        elif kind == CouponType.FIXED:
            if "percent" in body:
                raise ValidationError("fixed coupons take 'amount', not 'percent'.", field="percent")
            coupon.amount_cents = parse_amount_to_cents(body.get("amount"), allow_zero=False)
        else:
            raise ValidationError("type must be 'percentage' or 'fixed'.", field="type")
    except MoneyError as exc:
        raise ValidationError(str(exc), field="percent" if kind == CouponType.PERCENTAGE else "amount")
    coupon.valid_from = _parse_dt(body, "valid_from")
    coupon.valid_until = _parse_dt(body, "valid_until")
    if coupon.valid_until <= coupon.valid_from:
        raise ValidationError("valid_until must be after valid_from.", field="valid_until")
    coupon.max_uses = get_int(body, "max_uses", min_value=1, max_value=1_000_000)
    coupon.used_count = 0
    db.session.add(coupon)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="conflict", message="Coupon code already exists."), 409
    audit("finance.coupon_created", coupon_id=coupon.id, code=coupon.code, type=kind,
          max_uses=coupon.max_uses)
    return jsonify(coupon=coupon.to_public()), 201


@bp.get("/coupons")
@authorize("coupon.list")
def list_coupons():
    rows, meta = paginate(Coupon.query.order_by(Coupon.id.desc()))
    return jsonify(coupons=[c.to_public() for c in rows], **meta)


@bp.get("/payments")
@authorize("payment.list_all")
def list_payments():
    outcome = arg_choice("outcome", {"approved", "declined", "rejected"})
    q = Payment.query
    if outcome:
        q = q.filter(Payment.outcome == outcome)
    rows, meta = paginate(q.order_by(Payment.id.desc()))
    audit("finance.payments_viewed", count=len(rows))
    return jsonify(payments=[p.to_public() for p in rows], **meta)
