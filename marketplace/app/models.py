"""Database models.

Money is always stored as integer cents (BigInteger) - never floats.
Database CHECK and UNIQUE constraints are a last line of defence behind the
application logic (non-negative amounts/stock, one redemption per buyer per
coupon, a charge id attached to one order only, one order per idempotency key).
"""
from datetime import datetime, timezone

from sqlalchemy import event
from sqlalchemy.orm import Session

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role:
    BUYER = "buyer"
    SELLER = "seller"
    FINANCE = "finance_officer"
    ADMIN = "admin"
    ALL = (BUYER, SELLER, FINANCE, ADMIN)
    MARKET = {BUYER, SELLER}
    PRIVILEGED = {FINANCE, ADMIN}


class AccountStatus:
    ACTIVE = "active"
    SUSPENDED = "suspended"


class SellerStatus:
    UNVERIFIED = "unverified"
    VERIFIED = "verified"


class ProductStatus:
    DRAFT = "draft"
    PUBLISHED = "published"


class SeparationOfDutiesError(ValueError):
    pass


def _roles_violate_sod(roles):
    roles = set(roles)
    privileged = roles & Role.PRIVILEGED
    if not privileged:
        return False
    # Admin / Finance Officer cannot also be Buyer or Seller, nor hold both
    # privileged roles at once.
    return bool(roles & Role.MARKET) or len(privileged) > 1


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(16), nullable=False, default=AccountStatus.ACTIVE)
    must_change_credentials = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    roles = db.relationship("UserRole", cascade="all, delete-orphan", lazy="selectin")
    seller_profile = db.relationship("SellerProfile", uselist=False, back_populates="user",
                                     lazy="selectin", foreign_keys="SellerProfile.user_id")

    __table_args__ = (
        db.CheckConstraint("status IN ('active','suspended')", name="ck_user_status"),
    )

    @property
    def role_names(self):
        return {r.role for r in self.roles}

    def add_role(self, role):
        if role not in Role.ALL:
            raise ValueError(f"unknown role {role}")
        if role in self.role_names:
            return
        if _roles_violate_sod(self.role_names | {role}):
            raise SeparationOfDutiesError(
                "Separation of duties: Admin/Finance Officer accounts cannot hold other roles.")
        self.roles.append(UserRole(role=role))

    def to_public(self):
        sp = self.seller_profile
        return {
            "id": self.id,
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "roles": sorted(self.role_names),
            "status": self.status,
            "must_change_credentials": self.must_change_credentials,
            "seller": sp.to_public() if sp else None,
        }


class UserRole(db.Model):
    __tablename__ = "user_roles"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = db.Column(db.String(32), nullable=False)
    __table_args__ = (
        db.UniqueConstraint("user_id", "role", name="uq_user_role"),
        db.CheckConstraint("role IN ('buyer','seller','finance_officer','admin')", name="ck_role_name"),
    )


@event.listens_for(Session, "before_flush")
def _enforce_sod_before_flush(session, _ctx, _instances):
    """Defence in depth: refuse to persist any user whose roles break SoD,
    no matter which code path assigned them."""
    users = {o for o in list(session.new) + list(session.dirty) if isinstance(o, User)}
    for role in [o for o in list(session.new) + list(session.dirty) if isinstance(o, UserRole)]:
        if role.user_id:
            u = session.get(User, role.user_id)
            if u is not None:
                users.add(u)
    for u in users:
        if _roles_violate_sod(u.role_names):
            raise SeparationOfDutiesError(f"Separation of duties violated for user {u.id}")


class SellerProfile(db.Model):
    __tablename__ = "seller_profiles"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    store_name = db.Column(db.String(80), unique=True, nullable=False)
    verification_status = db.Column(db.String(16), nullable=False, default=SellerStatus.UNVERIFIED)
    applied_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    verified_at = db.Column(db.DateTime)
    verified_by = db.Column(db.Integer, db.ForeignKey("users.id"))

    user = db.relationship("User", back_populates="seller_profile", foreign_keys=[user_id])

    __table_args__ = (
        db.CheckConstraint("verification_status IN ('unverified','verified')", name="ck_seller_status"),
    )

    def to_public(self):
        return {
            "user_id": self.user_id,
            "store_name": self.store_name,
            "verification_status": self.verification_status,
            "applied_at": _iso(self.applied_at),
            "verified_at": _iso(self.verified_at),
        }


class AuthSession(db.Model):
    """Server-side session. The client only holds a random token; we store its
    SHA-256 hash, so a database leak does not leak usable tokens."""
    __tablename__ = "auth_sessions"
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    csrf_token = db.Column(db.String(64), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = db.Column(db.String(8), nullable=False)  # cookie | bearer
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime)


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    seller_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(2000), nullable=False, default="")
    price_cents = db.Column(db.BigInteger, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(16), nullable=False, default=ProductStatus.DRAFT)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    seller = db.relationship("User", lazy="joined")

    __table_args__ = (
        db.CheckConstraint("price_cents >= 0", name="ck_product_price_nonneg"),
        db.CheckConstraint("stock >= 0", name="ck_product_stock_nonneg"),
        db.CheckConstraint("status IN ('draft','published')", name="ck_product_status"),
    )

    def to_public(self, include_private=False):
        sp = self.seller.seller_profile if self.seller else None
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price_cents": self.price_cents,
            "price": _money(self.price_cents),
            "stock": self.stock,
            "status": self.status,
            "seller_id": self.seller_id,
            "store_name": sp.store_name if sp else None,
        }
        if include_private:
            data["created_at"] = _iso(self.created_at)
            data["updated_at"] = _iso(self.updated_at)
        return data


class CouponType:
    PERCENTAGE = "percentage"
    FIXED = "fixed"


class Coupon(db.Model):
    __tablename__ = "coupons"
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(32), unique=True, nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False)
    # percentage coupons: basis points (1250 = 12.50 %); fixed coupons: cents
    percent_bp = db.Column(db.Integer)
    amount_cents = db.Column(db.BigInteger)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    max_uses = db.Column(db.Integer, nullable=False)
    used_count = db.Column(db.Integer, nullable=False, default=0)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (
        db.CheckConstraint("kind IN ('percentage','fixed')", name="ck_coupon_kind"),
        db.CheckConstraint("max_uses >= 1", name="ck_coupon_max_uses"),
        db.CheckConstraint("used_count >= 0 AND used_count <= max_uses", name="ck_coupon_used"),
        db.CheckConstraint("percent_bp IS NULL OR (percent_bp >= 1 AND percent_bp <= 10000)",
                           name="ck_coupon_percent"),
        db.CheckConstraint("amount_cents IS NULL OR amount_cents >= 1", name="ck_coupon_amount"),
        db.CheckConstraint("valid_until > valid_from", name="ck_coupon_dates"),
    )

    def to_public(self):
        return {
            "id": self.id,
            "code": self.code,
            "type": self.kind,
            "percent": (f"{self.percent_bp // 100}.{self.percent_bp % 100:02d}"
                        if self.percent_bp is not None else None),
            "amount_cents": self.amount_cents,
            "valid_from": _iso(self.valid_from),
            "valid_until": _iso(self.valid_until),
            "max_uses": self.max_uses,
            "used_count": self.used_count,
            "created_at": _iso(self.created_at),
        }


class CouponRedemption(db.Model):
    __tablename__ = "coupon_redemptions"
    id = db.Column(db.Integer, primary_key=True)
    coupon_id = db.Column(db.Integer, db.ForeignKey("coupons.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, unique=True)
    redeemed_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (
        db.UniqueConstraint("coupon_id", "user_id", name="uq_coupon_once_per_buyer"),
    )


class Order(db.Model):
    __tablename__ = "orders"
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    seller_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False)
    subtotal_cents = db.Column(db.BigInteger, nullable=False)
    discount_cents = db.Column(db.BigInteger, nullable=False, default=0)
    total_cents = db.Column(db.BigInteger, nullable=False)
    currency = db.Column(db.String(3), nullable=False, default="USD")
    coupon_id = db.Column(db.Integer, db.ForeignKey("coupons.id"))
    shipping_address = db.Column(db.String(300), nullable=False)
    idempotency_key = db.Column(db.String(64), nullable=False)
    request_fingerprint = db.Column(db.String(64), nullable=False)
    charge_id = db.Column(db.String(40), unique=True)
    tracking_number = db.Column(db.String(64))
    failure_reason = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    items = db.relationship("OrderItem", cascade="all, delete-orphan", lazy="selectin")
    coupon = db.relationship("Coupon", lazy="joined")

    __table_args__ = (
        db.UniqueConstraint("buyer_id", "idempotency_key", name="uq_order_idempotency"),
        # There is no pending state: an order only ever exists as the outcome
        # of a completed charge attempt.
        db.CheckConstraint("status IN ('paid','failed','shipped','delivered')", name="ck_order_status"),
        db.CheckConstraint("subtotal_cents >= 0 AND discount_cents >= 0 AND total_cents >= 0",
                           name="ck_order_amounts_nonneg"),
        db.CheckConstraint("discount_cents <= subtotal_cents", name="ck_order_discount_le_subtotal"),
        db.CheckConstraint("total_cents = subtotal_cents - discount_cents", name="ck_order_total"),
        db.CheckConstraint("status = 'failed' OR charge_id IS NOT NULL", name="ck_order_paid_has_charge"),
    )

    def to_public(self):
        return {
            "id": self.id,
            "buyer_id": self.buyer_id,
            "seller_id": self.seller_id,
            "status": self.status,
            "subtotal_cents": self.subtotal_cents,
            "discount_cents": self.discount_cents,
            "total_cents": self.total_cents,
            "total": _money(self.total_cents),
            "currency": self.currency,
            "coupon_code": self.coupon.code if self.coupon else None,
            "shipping_address": self.shipping_address,
            "charge_id": self.charge_id,
            "tracking_number": self.tracking_number,
            "failure_reason": self.failure_reason,
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
            "items": [i.to_public() for i in self.items],
        }


class OrderItem(db.Model):
    __tablename__ = "order_items"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id", ondelete="CASCADE"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    product_name = db.Column(db.String(120), nullable=False)
    unit_price_cents = db.Column(db.BigInteger, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    line_total_cents = db.Column(db.BigInteger, nullable=False)
    __table_args__ = (
        db.CheckConstraint("quantity >= 1", name="ck_item_qty_pos"),
        db.CheckConstraint("unit_price_cents >= 0 AND line_total_cents >= 0", name="ck_item_amounts"),
    )

    def to_public(self):
        return {
            "product_id": self.product_id,
            "product_name": self.product_name,
            "unit_price_cents": self.unit_price_cents,
            "quantity": self.quantity,
            "line_total_cents": self.line_total_cents,
        }


class Payment(db.Model):
    __tablename__ = "payments"
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, unique=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    charge_id = db.Column(db.String(40), unique=True)
    gateway_idempotency_key = db.Column(db.String(128), nullable=False, unique=True)
    amount_cents = db.Column(db.BigInteger, nullable=False)
    currency = db.Column(db.String(3), nullable=False)
    # approved | declined | rejected (response failed verification)
    outcome = db.Column(db.String(16), nullable=False)
    signature_verified = db.Column(db.Boolean, nullable=False)
    detail = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (
        db.CheckConstraint("amount_cents >= 0", name="ck_payment_amount_nonneg"),
        db.CheckConstraint("outcome IN ('approved','declined','rejected')", name="ck_payment_outcome"),
    )

    def to_public(self):
        return {
            "id": self.id,
            "order_id": self.order_id,
            "buyer_id": self.buyer_id,
            "charge_id": self.charge_id,
            "amount_cents": self.amount_cents,
            "amount": _money(self.amount_cents),
            "currency": self.currency,
            "outcome": self.outcome,
            "signature_verified": self.signature_verified,
            "detail": self.detail,
            "created_at": _iso(self.created_at),
        }


class IdempotencyRecord(db.Model):
    """Claimed *before* charging, so two concurrent requests with the same key
    cannot both reach the gateway."""
    __tablename__ = "idempotency_records"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    key = db.Column(db.String(64), nullable=False)
    fingerprint = db.Column(db.String(64), nullable=False)
    state = db.Column(db.String(16), nullable=False, default="processing")  # processing|done|error
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    __table_args__ = (
        db.UniqueConstraint("user_id", "key", name="uq_idempotency_user_key"),
    )


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _money(cents):
    from .money import format_cents
    return format_cents(cents)
