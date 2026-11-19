"""Unit tests of the central policy module: for each policy, at least one
ALLOW and one DENY case, plus the combining rules (default deny, deny
overrides, fail closed, RBAC short-circuit)."""
import copy

import pytest
import yaml

from app.config import Config
from app.models import AccountStatus, ProductStatus, Role, SellerStatus
from app.policy import CheckoutResource, NewProduct, OwnerScope
from app.policy import policies as pol
from app.policy.engine import PolicyConfigError, PolicyEngine, Subject


@pytest.fixture(scope="module")
def config():
    with open(Config.POLICY_CONFIG_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def engine(config):
    return PolicyEngine(config)


class Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def subj(uid, *roles, seller=None, status=AccountStatus.ACTIVE, must_change=False):
    return Subject(user_id=uid, roles=frozenset(roles), seller_status=seller, account_status=status,
                   must_change_credentials=must_change)


BUYER = subj(1, Role.BUYER)
OTHER_BUYER = subj(2, Role.BUYER)
SELLER_V = subj(10, Role.BUYER, Role.SELLER, seller=SellerStatus.VERIFIED)
SELLER_U = subj(11, Role.BUYER, Role.SELLER, seller=SellerStatus.UNVERIFIED)
FINANCE = subj(20, Role.FINANCE)
ADMIN = subj(30, Role.ADMIN)
ANON = Subject.anonymous()


def order(buyer, seller, status):
    return Obj(id=99, buyer_id=buyer, seller_id=seller, status=status)


def product(seller, status=ProductStatus.PUBLISHED, pid=5):
    return Obj(id=pid, seller_id=seller, status=status)


# ---------------------------------------------------------------- RBAC ------
def test_rbac_ok_allows(engine):
    d = engine.authorize(FINANCE, "coupon.create", log=False)
    assert d.allowed and d.policy == "RBAC"


def test_rbac_x_denies_without_abac(engine):
    # Admin cannot create coupons or view payments (matrix X).
    for action in ("coupon.create", "payment.list_all"):
        d = engine.authorize(ADMIN, action, log=False)
        assert not d.allowed and d.policy == "RBAC" and d.evaluated[-1]["policy"] != "P1_OWNERSHIP"
    # Finance cannot check out, even with a resource that would pass P3.
    d = engine.authorize(FINANCE, "checkout.pay", CheckoutResource([product(10)]), log=False)
    assert not d.allowed and d.policy == "RBAC"


def test_anonymous_only_public(engine):
    assert engine.authorize(ANON, "catalog.browse", log=False).allowed
    assert engine.authorize(ANON, "auth.register", log=False).allowed
    assert engine.authorize(ANON, "auth.login", log=False).allowed
    for action in ("checkout.pay", "order.list_own", "product.create", "coupon.create", "seller.verify"):
        assert not engine.authorize(ANON, action, log=False).allowed


def test_unknown_action_default_deny(engine):
    d = engine.authorize(ADMIN, "something.not.configured", log=False)
    assert not d.allowed and d.policy == "DEFAULT_DENY"


# ------------------------------------------------------------ P1 Ownership --
def test_p1_buyer_own_order_allowed(engine):
    assert engine.authorize(BUYER, "order.view_own", order(1, 10, "paid"), log=False).allowed


def test_p1_buyer_other_order_denied(engine):
    d = engine.authorize(OTHER_BUYER, "order.view_own", order(1, 10, "paid"), log=False)
    assert not d.allowed and d.policy == "P1_OWNERSHIP"


def test_p1_seller_own_product_allowed(engine):
    assert engine.authorize(SELLER_V, "product.update", product(10), log=False).allowed


def test_p1_seller_other_product_denied(engine):
    d = engine.authorize(SELLER_U, "product.update", product(10), log=False)
    assert not d.allowed and d.policy == "P1_OWNERSHIP"


def test_p1_seller_orders_scope(engine):
    assert engine.authorize(SELLER_V, "seller_order.list", OwnerScope(seller_id=10), log=False).allowed
    assert not engine.authorize(SELLER_V, "seller_order.list", OwnerScope(seller_id=11), log=False).allowed


# ---------------------------------------------------- P2 Seller verification --
def test_p2_verified_can_publish(engine):
    d = engine.authorize(SELLER_V, "product.publish", product(10, ProductStatus.DRAFT), log=False)
    assert d.allowed


def test_p2_unverified_cannot_publish(engine):
    d = engine.authorize(SELLER_U, "product.publish", product(11, ProductStatus.DRAFT), log=False)
    assert not d.allowed and d.policy == "P2_SELLER_VERIFICATION"


def test_p2_unverified_can_create_draft_but_not_published(engine):
    assert engine.authorize(SELLER_U, "product.create", NewProduct(11, ProductStatus.DRAFT), log=False).allowed
    d = engine.authorize(SELLER_U, "product.create", NewProduct(11, ProductStatus.PUBLISHED), log=False)
    assert not d.allowed and d.policy == "P2_SELLER_VERIFICATION"


# ---------------------------------------------------- P3 No self-dealing -----
def test_p3_buying_others_products_allowed(engine):
    assert engine.authorize(SELLER_V, "checkout.pay", CheckoutResource([product(11)]), log=False).allowed


def test_p3_buying_own_product_denied(engine):
    d = engine.authorize(SELLER_V, "checkout.pay", CheckoutResource([product(11), product(10, pid=6)]),
                         log=False)
    assert not d.allowed and d.policy == "P3_NO_SELF_DEALING"


# ---------------------------------------------------- P4 Order state ---------
def test_p4_ship_paid_order_allowed(engine):
    assert engine.authorize(SELLER_V, "seller_order.ship", order(1, 10, "paid"), log=False).allowed


@pytest.mark.parametrize("status", ["failed", "shipped", "delivered"])
def test_p4_ship_non_paid_denied(engine, status):
    d = engine.authorize(SELLER_V, "seller_order.ship", order(1, 10, status), log=False)
    assert not d.allowed and d.policy == "P4_ORDER_STATE"


def test_p4_confirm_delivery_only_shipped(engine):
    assert engine.authorize(BUYER, "order.confirm_delivery", order(1, 10, "shipped"), log=False).allowed
    d = engine.authorize(BUYER, "order.confirm_delivery", order(1, 10, "paid"), log=False)
    assert not d.allowed and d.policy == "P4_ORDER_STATE"


def test_deny_overrides(engine):
    # P4 would permit (shipped -> delivered) but P1 denies: overall DENY.
    d = engine.authorize(OTHER_BUYER, "order.confirm_delivery", order(1, 10, "shipped"), log=False)
    assert not d.allowed and d.policy == "P1_OWNERSHIP"
    # P1 permits but P4 denies: overall DENY.
    d = engine.authorize(BUYER, "order.confirm_delivery", order(1, 10, "delivered"), log=False)
    assert not d.allowed and d.policy == "P4_ORDER_STATE"


# ---------------------------------------------------- global policies --------
def test_suspended_account_denied_everything(engine):
    s = subj(1, Role.BUYER, status=AccountStatus.SUSPENDED)
    d = engine.authorize(s, "order.list_own", OwnerScope(buyer_id=1), log=False)
    assert not d.allowed and d.policy == "ACCOUNT_ACTIVE"


def test_admin_must_change_credentials_first(engine):
    a = subj(30, Role.ADMIN, must_change=True)
    d = engine.authorize(a, "seller.verify", log=False)
    assert not d.allowed and d.policy == "CREDENTIALS_CHANGE_REQUIRED"
    assert engine.authorize(a, "admin.change_credentials", log=False).allowed
    assert engine.authorize(ADMIN, "seller.verify", log=False).allowed


# ---------------------------------------------------- fail closed ------------
def test_policy_exception_fails_closed(engine, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("database exploded")
    monkeypatch.setitem(pol.REGISTRY, "P1_OWNERSHIP", boom)
    d = engine.authorize(BUYER, "order.view_own", order(1, 10, "paid"), log=False)
    assert not d.allowed and "fail closed" in d.reason


def test_policy_missing_attribute_fails_closed(engine):
    d = engine.authorize(BUYER, "order.view_own", object(), log=False)  # resource lacks buyer_id
    assert not d.allowed


def test_c_permission_without_policies_is_denied(config):
    cfg = copy.deepcopy(config)
    cfg["abac"].pop("order.view_own")
    e = PolicyEngine(cfg)
    d = e.authorize(BUYER, "order.view_own", order(1, 10, "paid"), log=False)
    assert not d.allowed and d.policy == "DEFAULT_DENY"


def test_matrix_is_configuration_driven(config):
    """Changing the YAML (not code) changes behaviour."""
    cfg = copy.deepcopy(config)
    cfg["permissions"]["payment.list_all"]["admin"] = "OK"
    assert PolicyEngine(cfg).authorize(ADMIN, "payment.list_all", log=False).allowed


@pytest.mark.parametrize("mutate", [
    lambda c: c["permissions"]["coupon.create"].update({"admin": "MAYBE"}),
    lambda c: c["permissions"]["coupon.create"].update({"hacker": "OK"}),
    lambda c: c["abac"]["checkout.pay"].append({"policy": "P9_UNKNOWN"}),
])
def test_invalid_config_refused(config, mutate):
    cfg = copy.deepcopy(config)
    mutate(cfg)
    with pytest.raises(PolicyConfigError):
        PolicyEngine(cfg)


def test_policy_functions_directly():
    assert pol.p1_ownership(BUYER, order(1, 2, "paid"), {"as": "buyer"}).effect == pol.Effect.PERMIT
    assert pol.p1_ownership(BUYER, order(3, 2, "paid"), {"as": "buyer"}).effect == pol.Effect.DENY
    assert pol.p2_seller_verification(SELLER_V, product(10), {}).effect == pol.Effect.PERMIT
    assert pol.p2_seller_verification(SELLER_U, product(11), {}).effect == pol.Effect.DENY
    assert pol.p3_no_self_dealing(BUYER, CheckoutResource([product(10)]), {}).effect == pol.Effect.PERMIT
    assert pol.p3_no_self_dealing(SELLER_V, CheckoutResource([product(10)]), {}).effect == pol.Effect.DENY
    assert pol.p4_order_state(BUYER, order(1, 2, "shipped"), {"to": "delivered", "trigger": "buyer"}).effect \
        == pol.Effect.PERMIT
    assert pol.p4_order_state(BUYER, order(1, 2, "paid"), {"to": "delivered", "trigger": "buyer"}).effect \
        == pol.Effect.DENY
