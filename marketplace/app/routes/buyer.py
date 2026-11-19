"""Buyer: coupon check, checkout & pay, own orders, confirm delivery."""
from flask import Blueprint, current_app, g, jsonify

from .. import checkout, state_machine
from ..extensions import db, limiter, user_or_ip_key
from ..models import Order
from ..policy import CheckoutResource, OwnerScope, authorize
from ..state_machine import OrderStatus, Trigger
from ..validation import empty_body, json_body
from . import arg_choice, paginate

bp = Blueprint("buyer", __name__, url_prefix="/api")

CHECKOUT_FIELDS = {"items", "shipping_address", "coupon_code", "card_label", "idempotency_key"}


def _load_cart_for_quote(**_kw):
    body = json_body({"items", "coupon_code"}, required=("items",))
    g.checkout_request = checkout.parse_checkout(body, full=False)
    return CheckoutResource(products=checkout.load_products(g.checkout_request.product_ids))


def _load_cart_for_checkout(**_kw):
    # Any client-sent price/total/discount/status field is rejected here.
    body = json_body(CHECKOUT_FIELDS, required=("items", "shipping_address", "card_label", "idempotency_key"))
    g.checkout_request = checkout.parse_checkout(body, full=True)
    return CheckoutResource(products=checkout.load_products(g.checkout_request.product_ids))


def _load_order(order_id):
    return db.session.get(Order, order_id)


def _coupon_limit():
    return current_app.config["COUPON_RATE_LIMIT"]


def _checkout_limit():
    return current_app.config["CHECKOUT_RATE_LIMIT"]


@bp.post("/coupons/validate")
@limiter.limit(_coupon_limit, key_func=user_or_ip_key)
@authorize("coupon.validate", loader=_load_cart_for_quote)
def validate_coupon():
    return jsonify(quote=checkout.quote(g.user, g.checkout_request))


@bp.post("/checkout")
@limiter.limit(_checkout_limit, key_func=user_or_ip_key)
@authorize("checkout.pay", loader=_load_cart_for_checkout)
def do_checkout():
    order, replayed = checkout.perform_checkout(g.user, g.checkout_request)
    status = 200 if replayed else 201
    if order.status == OrderStatus.FAILED and not replayed:
        status = 402  # Payment Required: the charge was declined / not verified
    return jsonify(order=order.to_public(), idempotent_replay=replayed), status


@bp.get("/orders")
@authorize("order.list_own", loader=lambda **_: OwnerScope(buyer_id=g.user.id) if g.user else None)
def my_orders():
    status = arg_choice("status", {OrderStatus.PAID, OrderStatus.FAILED, OrderStatus.SHIPPED,
                                   OrderStatus.DELIVERED})
    q = Order.query.filter(Order.buyer_id == g.user.id)
    if status:
        q = q.filter(Order.status == status)
    rows, meta = paginate(q.order_by(Order.id.desc()))
    return jsonify(orders=[o.to_public() for o in rows], **meta)


@bp.get("/orders/<int:order_id>")
@authorize("order.view_own", loader=_load_order)
def my_order(order_id):
    return jsonify(order=g.resource.to_public())


@bp.post("/orders/<int:order_id>/confirm-delivery")
@authorize("order.confirm_delivery", loader=_load_order)
def confirm_delivery(order_id):
    empty_body()  # no body fields accepted
    order = state_machine.transition(g.resource, OrderStatus.DELIVERED, Trigger.BUYER)
    return jsonify(order=order.to_public())
