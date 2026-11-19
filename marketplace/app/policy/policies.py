"""ABAC policies P1-P4 and the global policies.

Each policy is a pure function ``(subject, resource, params) -> Effect``.
Subject attributes come from the database (see engine.Subject.from_user);
resource attributes come from database rows or from server-built objects -
never from values in the client request.
"""
from dataclasses import dataclass, field

from ..models import AccountStatus, ProductStatus, SellerStatus
from .. import state_machine


class Effect:
    PERMIT = "permit"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class PolicyResult:
    effect: str
    reason: str = ""


# --------------------------------------------------------------------------
# Resource helper objects built by the server (never from client attributes)
# --------------------------------------------------------------------------
@dataclass
class OwnerScope:
    """Resource for list actions: the query is restricted to this owner."""
    buyer_id: int | None = None
    seller_id: int | None = None


@dataclass
class NewProduct:
    """Resource for product.create: owner is always the current user."""
    seller_id: int
    target_status: str = ProductStatus.DRAFT


@dataclass
class CheckoutResource:
    """Products being bought, loaded from the database."""
    products: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Global policies
# --------------------------------------------------------------------------
def account_active(subject, _resource, _params):
    if subject.is_anonymous:
        return PolicyResult(Effect.NOT_APPLICABLE)
    if subject.account_status != AccountStatus.ACTIVE:
        return PolicyResult(Effect.DENY, "account is suspended")
    return PolicyResult(Effect.PERMIT)


def credentials_change_required(subject, _resource, params):
    if subject.is_anonymous or not subject.must_change_credentials:
        return PolicyResult(Effect.NOT_APPLICABLE)
    if params["action"] in params["exempt"]:
        return PolicyResult(Effect.PERMIT)
    return PolicyResult(Effect.DENY, "default credentials must be changed first")


# --------------------------------------------------------------------------
# P1 Ownership
# --------------------------------------------------------------------------
def p1_ownership(subject, resource, params):
    side = params.get("as")
    if side not in ("buyer", "seller"):
        raise ValueError("P1 requires parameter as: buyer|seller")
    if resource is None:
        return PolicyResult(Effect.DENY, "no resource")
    owner = getattr(resource, f"{side}_id")
    if owner is None:
        return PolicyResult(Effect.DENY, f"resource has no {side} owner")
    if owner == subject.user_id:
        return PolicyResult(Effect.PERMIT, f"subject is the {side} of the resource")
    return PolicyResult(Effect.DENY, f"subject is not the {side} of the resource")


# --------------------------------------------------------------------------
# P2 Seller verification
# --------------------------------------------------------------------------
def p2_seller_verification(subject, resource, _params):
    target = getattr(resource, "target_status", ProductStatus.PUBLISHED)
    if target == ProductStatus.DRAFT:
        return PolicyResult(Effect.PERMIT, "any seller may create drafts")
    if target != ProductStatus.PUBLISHED:
        return PolicyResult(Effect.DENY, "unknown target status")
    if subject.seller_status == SellerStatus.VERIFIED:
        return PolicyResult(Effect.PERMIT, "seller is verified")
    return PolicyResult(Effect.DENY, "only verified sellers can publish")


# --------------------------------------------------------------------------
# P3 No self-dealing
# --------------------------------------------------------------------------
def p3_no_self_dealing(subject, resource, _params):
    if not isinstance(resource, CheckoutResource):
        return PolicyResult(Effect.DENY, "no checkout resource")
    products = resource.products
    for p in products:
        if p.seller_id == subject.user_id:
            return PolicyResult(Effect.DENY, f"subject is the seller of product {p.id}")
    return PolicyResult(Effect.PERMIT, "subject sells none of the products")


# --------------------------------------------------------------------------
# P4 Order state
# --------------------------------------------------------------------------
def p4_order_state(_subject, resource, params):
    to_status = params.get("to")
    trigger = params.get("trigger")
    if not to_status or not trigger:
        raise ValueError("P4 requires parameters to and trigger")
    current = getattr(resource, "status", None)
    if current is None:
        return PolicyResult(Effect.DENY, "resource has no state")
    if state_machine.is_allowed(current, to_status, trigger):
        return PolicyResult(Effect.PERMIT, f"{current} -> {to_status} allowed for {trigger}")
    return PolicyResult(Effect.DENY, f"{current} -> {to_status} not allowed for {trigger}")


REGISTRY = {
    "ACCOUNT_ACTIVE": account_active,
    "CREDENTIALS_CHANGE_REQUIRED": credentials_change_required,
    "P1_OWNERSHIP": p1_ownership,
    "P2_SELLER_VERIFICATION": p2_seller_verification,
    "P3_NO_SELF_DEALING": p3_no_self_dealing,
    "P4_ORDER_STATE": p4_order_state,
}
