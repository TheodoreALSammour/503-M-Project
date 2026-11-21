"""Seller: manage own products, view orders for own products, mark shipped."""
from flask import Blueprint, g, jsonify

from .. import state_machine
from ..audit import audit
from ..extensions import db
from ..models import Order, Product, ProductStatus
from ..money import MoneyError, parse_amount_to_cents
from ..policy import NewProduct, OwnerScope, authorize
from ..state_machine import OrderStatus, Trigger
from ..validation import TRACKING_RE, ValidationError, empty_body, get_int, get_str, json_body
from . import arg_choice, paginate

bp = Blueprint("seller", __name__, url_prefix="/api/seller")

MAX_STOCK = 1_000_000
PRODUCT_FIELDS = {"name", "description", "price", "stock"}


def _load_product(product_id):
    return db.session.get(Product, product_id)


def _load_order(order_id):
    return db.session.get(Order, order_id)


def _new_product_resource(**_kw):
    body = json_body(PRODUCT_FIELDS | {"status"}, required=("name", "price", "stock"))
    status = body.get("status", ProductStatus.DRAFT)
    if status not in (ProductStatus.DRAFT, ProductStatus.PUBLISHED):
        raise ValidationError("status must be 'draft' or 'published'.", field="status")
    g.product_body = body
    # The owner is ALWAYS the logged-in user - never a client supplied seller_id.
    return NewProduct(seller_id=g.user.id, target_status=status)


def _parse_price(body, required):
    if "price" not in body:
        if required:
            raise ValidationError("Field 'price' is required.", field="price")
        return None
    try:
        # A product must cost at least $0.01: $0 listings would create "Paid"
        # orders with no money involved (found by the live pentest).
        return parse_amount_to_cents(body["price"], allow_zero=False)
    except MoneyError as exc:
        raise ValidationError(str(exc), field="price")


def _apply_fields(product, body, *, creating):
    if creating or "name" in body:
        product.name = get_str(body, "name", min_len=2, max_len=120)
    if creating or "description" in body:
        product.description = get_str(body, "description", min_len=0, max_len=2000, required=False) or ""
    price = _parse_price(body, creating)
    if price is not None:
        product.price_cents = price
    if creating or "stock" in body:
        product.stock = get_int(body, "stock", min_value=0, max_value=MAX_STOCK)


@bp.get("/products")
@authorize("product.list_own", loader=lambda **_: OwnerScope(seller_id=g.user.id))
def list_products():
    status = arg_choice("status", {ProductStatus.DRAFT, ProductStatus.PUBLISHED})
    q = Product.query.filter(Product.seller_id == g.user.id)
    if status:
        q = q.filter(Product.status == status)
    rows, meta = paginate(q.order_by(Product.id.desc()))
    return jsonify(products=[p.to_public(include_private=True) for p in rows], **meta)


@bp.post("/products")
@authorize("product.create", loader=_new_product_resource)
def create_product():
    body = g.product_body
    product = Product(seller_id=g.user.id, status=g.resource.target_status)
    _apply_fields(product, body, creating=True)
    db.session.add(product)
    db.session.commit()
    audit("product.created", product_id=product.id, status=product.status)
    return jsonify(product=product.to_public(include_private=True)), 201


@bp.get("/products/<int:product_id>")
@authorize("product.view_own", loader=_load_product)
def get_product(product_id):
    return jsonify(product=g.resource.to_public(include_private=True))


@bp.patch("/products/<int:product_id>")
@authorize("product.update", loader=_load_product)
def update_product(product_id):
    # status is deliberately NOT editable here - publishing goes through
    # product.publish so that P2 (seller verification) is always evaluated.
    body = json_body(PRODUCT_FIELDS)
    if not body:
        raise ValidationError("Nothing to update.")
    product = g.resource
    _apply_fields(product, body, creating=False)
    db.session.commit()
    audit("product.updated", product_id=product.id, fields=sorted(body))
    return jsonify(product=product.to_public(include_private=True))


@bp.post("/products/<int:product_id>/publish")
@authorize("product.publish", loader=_load_product)
def publish_product(product_id):
    empty_body()
    product = g.resource
    product.status = ProductStatus.PUBLISHED
    db.session.commit()
    audit("product.published", product_id=product.id)
    return jsonify(product=product.to_public(include_private=True))


@bp.post("/products/<int:product_id>/unpublish")
@authorize("product.unpublish", loader=_load_product)
def unpublish_product(product_id):
    empty_body()
    product = g.resource
    product.status = ProductStatus.DRAFT
    db.session.commit()
    audit("product.unpublished", product_id=product.id)
    return jsonify(product=product.to_public(include_private=True))


@bp.get("/orders")
@authorize("seller_order.list", loader=lambda **_: OwnerScope(seller_id=g.user.id))
def list_orders():
    status = arg_choice("status", {OrderStatus.PAID, OrderStatus.FAILED, OrderStatus.SHIPPED,
                                   OrderStatus.DELIVERED})
    q = Order.query.filter(Order.seller_id == g.user.id)
    if status:
        q = q.filter(Order.status == status)
    rows, meta = paginate(q.order_by(Order.id.desc()))
    return jsonify(orders=[o.to_public() for o in rows], **meta)


@bp.get("/orders/<int:order_id>")
@authorize("seller_order.view", loader=_load_order)
def get_order(order_id):
    return jsonify(order=g.resource.to_public())


@bp.post("/orders/<int:order_id>/ship")
@authorize("seller_order.ship", loader=_load_order)
def ship_order(order_id):
    body = json_body({"tracking_number"}, required=("tracking_number",))
    tracking = get_str(body, "tracking_number", min_len=6, max_len=64, pattern=TRACKING_RE)
    order = state_machine.transition(g.resource, OrderStatus.SHIPPED, Trigger.SELLER,
                                     tracking_number=tracking)
    return jsonify(order=order.to_public())

