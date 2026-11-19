"""Coupon rules (own code).

* one coupon per order (the request has a single optional ``coupon_code``)
* validity window ``valid_from <= now < valid_until``
* global ``max_uses`` across all buyers
* each buyer can use a coupon only once (also a DB unique constraint)
* percentage discount rounded half-up to the cent
* the discount never exceeds the order total
"""
from .models import Coupon, CouponRedemption, CouponType, utcnow
from .money import percentage_of
from .validation import COUPON_CODE_RE


class CouponError(Exception):
    """``reason`` is logged; clients only get a generic message so coupon
    codes cannot be enumerated (an attacker cannot tell 'expired' from
    'does not exist')."""
    PUBLIC_MESSAGE = "This coupon is not valid for this order."

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def normalize_code(code):
    if code is None:
        return None
    if not isinstance(code, str):
        raise CouponError("malformed")
    code = code.strip().upper()
    if not code:
        return None
    if not COUPON_CODE_RE.match(code):
        raise CouponError("malformed")
    return code


def find_coupon(code, *, lock=False):
    q = Coupon.query.filter_by(code=code)
    if lock:
        q = q.with_for_update(of=Coupon).execution_options(populate_existing=True)
    return q.first()


def compute_discount(coupon, subtotal_cents):
    if coupon.kind == CouponType.PERCENTAGE:
        discount = percentage_of(subtotal_cents, coupon.percent_bp)
    elif coupon.kind == CouponType.FIXED:
        discount = coupon.amount_cents
    else:
        raise CouponError("unknown coupon type")
    # A discount can never exceed the order total, nor be negative.
    return max(0, min(discount, subtotal_cents))


def evaluate(coupon, buyer_id, subtotal_cents, now=None):
    """Return the discount in cents or raise CouponError."""
    now = now or utcnow()
    if coupon is None:
        raise CouponError("unknown code")
    if now < coupon.valid_from:
        raise CouponError("not yet valid")
    if now >= coupon.valid_until:
        raise CouponError("expired")
    if coupon.used_count >= coupon.max_uses:
        raise CouponError("max uses reached")
    if CouponRedemption.query.filter_by(coupon_id=coupon.id, user_id=buyer_id).first() is not None:
        raise CouponError("already used by this buyer")
    return compute_discount(coupon, subtotal_cents)
