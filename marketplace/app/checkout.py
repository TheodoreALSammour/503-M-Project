"""Checkout and pricing (own code).

The client sends ONLY: product ids + quantities, shipping address, optional
coupon code, test card label and an idempotency key. Everything that involves
money is computed here from the database.

Atomicity / race conditions
---------------------------
The product rows (in id order, to avoid deadlocks) and the coupon row are
locked with ``SELECT ... FOR UPDATE`` for the whole checkout, including the
gateway call. Stock and coupon usage are changed in the same transaction that
records the Paid order, and only if the gateway approved and the response was
verified. A concurrent checkout for the same last item / last coupon use waits
on the lock, then re-reads the updated values and fails validation. On SQLite
(local development only) a process-wide lock provides the same serialisation.
DB CHECK constraints (stock >= 0, used_count <= max_uses) and the unique
(coupon, buyer) constraint are the last line of defence.

Double charging
---------------
1. ``(buyer, idempotency_key)`` is claimed in its own committed transaction
   before anything else - a second concurrent request with the same key gets
   409, a later one gets the original order back (no second charge).
2. The gateway receives a derived idempotency key, so even a retried call can
   only ever return the original charge.
3. ``orders.charge_id`` and ``payments.charge_id`` are UNIQUE: a charge id can
   be attached to one order only.
"""
import hashlib
import json
import threading
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import lazyload

from . import coupons, state_machine
from .audit import audit
from .extensions import db
from .gateway_client import get_client
from .models import AccountStatus, IdempotencyRecord, Order, OrderItem, Payment, Product, ProductStatus
from .validation import (CARD_LABEL_RE, IDEMPOTENCY_KEY_RE, ValidationError, as_int, get_str)

MAX_LINES = 20
MAX_QTY = 1000
MAX_EXPECTED_TOTAL_CENTS = 10**12
_sqlite_lock = threading.Lock()


class CheckoutError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class CheckoutRequest:
    items: list  # [(product_id, quantity)] sorted by product id
    shipping_address: str | None
    coupon_code: str | None
    card_label: str | None
    idempotency_key: str | None
    # Optional: the total the buyer was shown. Used ONLY to refuse the charge
    # when the server total differs (e.g. the seller changed the price after
    # the preview). It never influences what is charged.
    expected_total_cents: int | None = None

    @property
    def product_ids(self):
        return [pid for pid, _ in self.items]


def parse_items(body):
    items = body.get("items")
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_LINES:
        raise ValidationError(f"'items' must be a list of 1-{MAX_LINES} entries.", field="items")
    seen = {}
    for idx, it in enumerate(items):
        if not isinstance(it, dict) or set(it) != {"product_id", "quantity"}:
            raise ValidationError(f"items[{idx}] must contain exactly product_id and quantity.", field="items")
        pid = as_int(it["product_id"], f"items[{idx}].product_id", min_value=1, max_value=2**31 - 1)
        qty = as_int(it["quantity"], f"items[{idx}].quantity", min_value=1, max_value=MAX_QTY)
        if pid in seen:
            raise ValidationError(f"Product {pid} appears more than once.", field="items")
        seen[pid] = qty
    return sorted(seen.items())


def parse_checkout(body, *, full=True):
    items = parse_items(body)
    code = body.get("coupon_code")
    try:
        code = coupons.normalize_code(code) if code not in (None, "") else None
    except coupons.CouponError:
        raise ValidationError("Malformed coupon code.", field="coupon_code")
    if not full:
        return CheckoutRequest(items, None, code, None, None)
    expected = body.get("expected_total_cents")
    if expected is not None:
        expected = as_int(expected, "expected_total_cents", min_value=0, max_value=MAX_EXPECTED_TOTAL_CENTS)
    return CheckoutRequest(
        items=items,
        shipping_address=get_str(body, "shipping_address", min_len=5, max_len=300),
        coupon_code=code,
        card_label=get_str(body, "card_label", min_len=1, max_len=32, pattern=CARD_LABEL_RE),
        idempotency_key=get_str(body, "idempotency_key", min_len=16, max_len=64, pattern=IDEMPOTENCY_KEY_RE),
        expected_total_cents=expected,
    )


def fingerprint(req):
    canonical = json.dumps({
        "items": req.items, "shipping_address": req.shipping_address,
        "coupon_code": req.coupon_code, "card_label": req.card_label,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def load_products(ids, *, lock=False):
    q = Product.query.filter(Product.id.in_(ids)).order_by(Product.id)
    if lock:
        # Lock only the product rows (Postgres refuses FOR UPDATE on the outer
        # join used to eager-load the seller), and re-read fresh values.
        q = (q.options(lazyload(Product.seller)).with_for_update(of=Product)
             .execution_options(populate_existing=True))
    return q.all()


def seller_is_active(product):
    """A suspended seller's products cannot be bought (money must not flow to
    a suspended account that cannot even log in to ship the order)."""
    return product.seller is not None and product.seller.status == AccountStatus.ACTIVE


def _price_lines(req, products, buyer_id):
    """Validate the cart against DB state and compute the subtotal."""
    by_id = {p.id: p for p in products}
    lines, subtotal, sellers = [], 0, set()
    for pid, qty in req.items:
        p = by_id.get(pid)
        if p is None or p.status != ProductStatus.PUBLISHED or not seller_is_active(p):
            # Drafts and products of suspended sellers are invisible to buyers:
            # same message as non-existent.
            raise CheckoutError(f"Product {pid} is not available.", 404)
        sellers.add(p.seller_id)
        if qty > p.stock:
            raise CheckoutError(f"Only {p.stock} unit(s) of product {pid} in stock.", 409)
        line_total = p.price_cents * qty
        lines.append((p, qty, line_total))
        subtotal += line_total
    if len(sellers) != 1:
        raise CheckoutError("All products in an order must come from one seller.")
    seller_id = sellers.pop()
    if seller_id == buyer_id:  # P3 is enforced by the policy engine; re-checked here on locked rows
        raise CheckoutError("You cannot buy your own products.", 403)
    return lines, subtotal, seller_id


def _apply_coupon(req, buyer_id, subtotal, *, lock):
    if not req.coupon_code:
        return None, 0
    coupon = coupons.find_coupon(req.coupon_code, lock=lock)
    try:
        discount = coupons.evaluate(coupon, buyer_id, subtotal)
    except coupons.CouponError as exc:
        audit("coupon.rejected", code=req.coupon_code, reason=exc.reason, buyer_id=buyer_id)
        raise CheckoutError(coupons.CouponError.PUBLIC_MESSAGE, 422)
    return coupon, discount


def quote(buyer, req):
    """Price preview for 'check coupon' - changes nothing."""
    products = load_products(req.product_ids)
    lines, subtotal, _seller = _price_lines(req, products, buyer.id)
    coupon, discount = _apply_coupon(req, buyer.id, subtotal, lock=False)
    if coupon is not None:
        audit("coupon.validated", code=coupon.code, buyer_id=buyer.id, discount_cents=discount)
    return {
        "subtotal_cents": subtotal,
        "discount_cents": discount,
        "total_cents": subtotal - discount,
        "currency": "USD",
        "coupon_code": coupon.code if coupon else None,
        "lines": [{"product_id": p.id, "name": p.name, "unit_price_cents": p.price_cents,
                   "quantity": q, "line_total_cents": lt} for p, q, lt in lines],
    }


@contextmanager
def _critical_section():
    lock = _sqlite_lock if db.engine.dialect.name == "sqlite" else nullcontext()
    with lock:
        yield


def _replay(order, fp):
    if order.request_fingerprint != fp:
        audit("checkout.idempotency_conflict", order_id=order.id)
        raise CheckoutError("This idempotency key was already used for a different request.", 409)
    audit("checkout.idempotent_replay", order_id=order.id)
    return order, True


def perform_checkout(buyer, req):
    """Returns ``(order, replayed)``."""
    fp = fingerprint(req)
    existing = Order.query.filter_by(buyer_id=buyer.id, idempotency_key=req.idempotency_key).first()
    if existing is not None:
        return _replay(existing, fp)

    # Claim the idempotency key in its own transaction.
    claim = IdempotencyRecord(user_id=buyer.id, key=req.idempotency_key, fingerprint=fp)
    db.session.add(claim)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        rec = IdempotencyRecord.query.filter_by(user_id=buyer.id, key=req.idempotency_key).first()
        if rec is not None and rec.order_id is not None:
            return _replay(db.session.get(Order, rec.order_id), fp)
        audit("checkout.idempotency_in_progress", key=req.idempotency_key)
        raise CheckoutError("A checkout with this idempotency key is already in progress.", 409)
    claim_id = claim.id

    state = {"charged": False}
    try:
        with _critical_section():
            order = _locked_checkout(buyer, req, fp, claim_id, state)
        return order, False
    except Exception as exc:
        db.session.rollback()
        rec = db.session.get(IdempotencyRecord, claim_id)
        if not state["charged"]:
            # Nothing was charged: free the key so the buyer can fix the cart and retry.
            if rec is not None:
                db.session.delete(rec)
        elif rec is not None:
            # Something went wrong after the gateway was called: burn the key so
            # it can never trigger a second charge, and raise an alert.
            rec.state = "error"
            audit("checkout.post_charge_failure", severity="critical", key=req.idempotency_key,
                  error=type(exc).__name__)
        db.session.commit()
        raise


def _locked_checkout(buyer, req, fp, claim_id, state):
    products = load_products(req.product_ids, lock=True)
    lines, subtotal, seller_id = _price_lines(req, products, buyer.id)
    coupon, discount = _apply_coupon(req, buyer.id, subtotal, lock=True)
    total = subtotal - discount
    if total < 0 or discount < 0:  # cannot happen - defensive
        raise CheckoutError("Invalid total.")
    if req.expected_total_cents is not None and req.expected_total_cents != total:
        # Checked BEFORE charging: nothing is charged and the key is freed.
        audit("checkout.total_changed", buyer_id=buyer.id, expected_cents=req.expected_total_cents,
              actual_cents=total)
        raise CheckoutError("The total has changed since you last checked it. "
                            "Review your cart and try again.", 409)
    currency = "USD"
    gateway_key = f"mp-{buyer.id}-{req.idempotency_key}"

    audit("payment.charge_requested", buyer_id=buyer.id, amount_cents=total, currency=currency,
          gateway_idempotency_key=gateway_key)
    state["charged"] = True
    result = get_client().charge(req.card_label, total, currency, gateway_key)

    if result.outcome == "approved" and (
            Order.query.filter_by(charge_id=result.charge_id).first() is not None
            or Payment.query.filter_by(charge_id=result.charge_id).first() is not None):
        result.outcome, result.detail = "rejected", "charge id already attached to an order"

    audit("payment.result", outcome=result.outcome, charge_id=result.charge_id, verified=result.verified,
          detail=result.detail, amount_cents=total, currency=currency, buyer_id=buyer.id)
    if not result.verified:
        audit("payment.verification_failed", severity="high", detail=result.detail)

    order = Order(buyer_id=buyer.id, seller_id=seller_id, subtotal_cents=subtotal,
                  discount_cents=discount, total_cents=total, currency=currency,
                  coupon_id=coupon.id if coupon else None, shipping_address=req.shipping_address,
                  idempotency_key=req.idempotency_key, request_fingerprint=fp)
    for p, qty, line_total in lines:
        order.items.append(OrderItem(product_id=p.id, product_name=p.name, unit_price_cents=p.price_cents,
                                     quantity=qty, line_total_cents=line_total))

    approved = result.outcome == "approved"
    if approved:
        for p, qty, _ in lines:
            p.stock -= qty  # rows are locked; CHECK (stock >= 0) is the backstop
        if coupon is not None:
            coupon.used_count += 1
        order.charge_id = result.charge_id
        order.status = state_machine.OrderStatus.PAID
    else:
        order.failure_reason = (result.detail if result.outcome == "declined" else "payment_not_verified")[:64]
        order.status = state_machine.OrderStatus.FAILED
    db.session.add(order)
    db.session.flush()
    state_machine.record_checkout_outcome(order, order.status)

    if approved and coupon is not None:
        db.session.add(coupons.CouponRedemption(coupon_id=coupon.id, user_id=buyer.id, order_id=order.id))
        audit("coupon.redeemed", code=coupon.code, order_id=order.id, buyer_id=buyer.id,
              used_count=coupon.used_count, max_uses=coupon.max_uses)

    db.session.add(Payment(order_id=order.id, buyer_id=buyer.id,
                           charge_id=result.charge_id if result.outcome != "rejected" else None,
                           gateway_idempotency_key=gateway_key, amount_cents=total, currency=currency,
                           outcome=result.outcome, signature_verified=result.verified,
                           detail=result.detail[:128]))
    rec = db.session.get(IdempotencyRecord, claim_id)
    rec.state, rec.order_id = "done", order.id
    db.session.commit()
    audit("checkout.completed", order_id=order.id, status=order.status, total_cents=total)
    return order
