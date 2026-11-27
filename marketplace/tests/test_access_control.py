"""End-to-end authorization tests through the HTTP layer."""
import json
import logging
from contextlib import contextmanager

import pytest

from app.policy import POLICY_ATTR

from .conftest import PASSWORDS, checkout_body, login, product_id, token_for, user_id


@contextmanager
def audit_events():
    """Collect the JSON audit events written while the block runs."""
    seen = []
    handler = logging.Handler()
    handler.emit = lambda record: seen.append(json.loads(record.getMessage()))
    audit_log = logging.getLogger("marketplace.audit")
    audit_log.addHandler(handler)
    try:
        yield seen
    finally:
        audit_log.removeHandler(handler)


# ------------------------------------------------- every route uses the PEP --
def test_every_route_is_registered_with_policy_module(app):
    missing = [ep for ep, fn in app.view_functions.items() if not getattr(fn, POLICY_ATTR, None)]
    assert missing == []


def test_undecorated_route_fails_closed(app, client):
    app.add_url_rule("/api/backdoor", "backdoor", lambda: "secret")
    r = client.get("/api/backdoor")
    assert r.status_code == 403


# ------------------------------------------------------- public / visitors --
def test_visitor_sees_only_published(app, client):
    r = client.get("/api/products?per_page=100")
    names = {p["name"] for p in r.get_json()["products"]}
    assert "Wireless Mouse" in names and "Prototype Drone" not in names and "Handmade Vase" not in names
    assert client.get(f"/api/products/{product_id(app, 'Prototype Drone')}").status_code == 404


def test_draft_visible_to_its_seller_only(app, client, auth):
    pid = product_id(app, "Prototype Drone")
    assert client.get(f"/api/products/{pid}", headers=auth("sam@example.com")).status_code == 200
    assert client.get(f"/api/products/{pid}", headers=auth("vera@example.com")).status_code == 404


def test_search_is_injection_safe(app, client):
    r = client.get("/api/products", query_string={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and r.get_json()["products"] == []
    r = client.get("/api/products", query_string={"q": "%"})
    assert r.get_json()["products"] == []


@pytest.mark.parametrize("path", ["/api/orders", "/api/seller/products", "/api/finance/payments",
                                  "/api/admin/users", "/api/auth/me"])
def test_visitor_blocked_from_private_routes(client, path):
    assert client.get(path).status_code == 401


# ---------------------------------------------------------- registration ----
def test_register_always_buyer(client):
    r = client.post("/api/auth/register", json={"full_name": "Eve", "email": "eve@example.com",
                                                "phone": "+961 70 123456", "password": "Str0ng!Passw0rd"})
    assert r.status_code == 201 and r.get_json()["user"]["roles"] == ["buyer"]
    r = client.post("/api/auth/register", json={"full_name": "Mallory", "email": "m@example.com",
                                                "phone": "+961 70 123456", "password": "Str0ng!Passw0rd",
                                                "roles": ["admin"]})
    assert r.status_code == 400


def test_weak_password_rejected(client):
    r = client.post("/api/auth/register", json={"full_name": "Eve", "email": "eve2@example.com",
                                                "phone": "+961 70 123456", "password": "password"})
    assert r.status_code == 400


# ------------------------------------------------------------------ login ---
def test_failed_login_generic(client):
    r1 = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrong-password"})
    r2 = client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "wrong-password"})
    assert r1.status_code == r2.status_code == 401
    assert r1.get_json()["message"] == r2.get_json()["message"]


def test_suspended_cannot_login(client):
    with audit_events() as seen:
        right = client.post("/api/auth/login", json={"email": "suspended@example.com",
                                                     "password": PASSWORDS["suspended@example.com"]})
    assert right.status_code == 401 and "access_token" not in right.get_json()
    # The real reason is logged server-side only.
    assert any(e["event"] == "auth.login_failed" and e["reason"] == "account_suspended" for e in seen)


def test_suspended_login_does_not_confirm_password(client):
    """A suspended account must answer a correct password exactly like a wrong
    one (and like an unknown email), or 'suspended' would leak the password."""
    def attempt(email, password):
        r = client.post("/api/auth/login", json={"email": email, "password": password})
        body = r.get_json()
        return r.status_code, body["error"], body["message"]

    right = attempt("suspended@example.com", PASSWORDS["suspended@example.com"])
    wrong = attempt("suspended@example.com", "Wrong#Password2026")
    unknown = attempt("nobody@example.com", "Wrong#Password2026")
    assert right == wrong == unknown == (401, "unauthorized", "Invalid email or password.")


def _admin_ready(client):
    h = token_for(client, "admin@marketplace.local")
    r = client.post("/api/admin/change-credentials", headers=h, json={
        "current_password": PASSWORDS["admin@marketplace.local"], "new_email": "root@marketplace.local",
        "new_password": "N3w!Admin-Secret"})
    assert r.status_code == 200, r.get_json()
    return h


def test_suspension_kills_existing_sessions_immediately(app, client, auth):
    bob = auth("bob@example.com")
    assert client.get("/api/orders", headers=bob).status_code == 200
    admin = _admin_ready(client)
    r = client.post(f"/api/admin/users/{user_id(app, 'bob@example.com')}/suspend", headers=admin)
    assert r.status_code == 200
    assert client.get("/api/orders", headers=bob).status_code == 401
    # reactivation does not resurrect old sessions
    client.post(f"/api/admin/users/{user_id(app, 'bob@example.com')}/reactivate", headers=admin)
    assert client.get("/api/orders", headers=bob).status_code == 401
    assert login(client, "bob@example.com")["access_token"]


def test_logout_revokes_token(client):
    h = token_for(client, "alice@example.com")
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401


def test_password_change_revokes_other_sessions(client):
    h1 = token_for(client, "alice@example.com")
    h2 = token_for(client, "alice@example.com")
    r = client.post("/api/account/password", headers=h1, json={
        "current_password": PASSWORDS["alice@example.com"], "new_password": "Another!Pass2026"})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers=h1).status_code == 200
    assert client.get("/api/auth/me", headers=h2).status_code == 401


# ----------------------------------------------------------------- CSRF -----
def test_cookie_session_requires_csrf_header(app, client):
    data = login(client, "alice@example.com", mode="cookie")
    pid = product_id(app, "USB-C Cable")
    body = checkout_body([(pid, 1)])
    assert client.post("/api/checkout", json=body).status_code == 403
    assert client.post("/api/checkout", json=body, headers={"X-CSRF-Token": "forged"}).status_code == 403
    r = client.post("/api/checkout", json=body, headers={"X-CSRF-Token": data["csrf_token"]})
    assert r.status_code == 201


def test_session_cookie_flags(client):
    r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORDS["alice@example.com"],
                                             "mode": "cookie"})
    cookies = r.headers.getlist("Set-Cookie")
    session = next(c for c in cookies if c.startswith("mp_session="))
    assert "HttpOnly" in session and "SameSite=Strict" in session
    assert "access_token" not in r.get_json()


# ------------------------------------------------- admin first login + SoD --
def test_admin_must_change_credentials_before_anything(client):
    h = token_for(client, "admin@marketplace.local")
    assert client.get("/api/admin/users", headers=h).status_code == 403
    assert client.get("/api/admin/sellers", headers=h).status_code == 403
    # cannot "change" to the same email / password
    r = client.post("/api/admin/change-credentials", headers=h, json={
        "current_password": PASSWORDS["admin@marketplace.local"], "new_email": "admin@marketplace.local",
        "new_password": "N3w!Admin-Secret"})
    assert r.status_code == 400
    r = client.post("/api/admin/change-credentials", headers=h, json={
        "current_password": PASSWORDS["admin@marketplace.local"], "new_email": "root@marketplace.local",
        "new_password": "N3w!Admin-Secret"})
    assert r.status_code == 200
    assert client.get("/api/admin/users", headers=h).status_code == 200
    # old credentials no longer work
    r = client.post("/api/auth/login", json={"email": "admin@marketplace.local",
                                             "password": PASSWORDS["admin@marketplace.local"]})
    assert r.status_code == 401


def test_admin_cannot_suspend_self(app, client):
    h = _admin_ready(client)
    me = user_id(app, "root@marketplace.local")
    with audit_events() as seen:
        for action in ("suspend", "reactivate"):
            r = client.post(f"/api/admin/users/{me}/{action}", headers=h)
            assert r.status_code == 403
    # The denial comes from the central policy module, not from route code.
    denials = [e for e in seen if e["event"] == "authz.decision" and e["decision"] == "deny"]
    assert [(e["action"], e["policy"]) for e in denials] == [
        ("account.suspend", "SOD_NOT_SELF"), ("account.reactivate", "SOD_NOT_SELF")]
    assert client.get("/api/admin/users", headers=h).status_code == 200  # still active


@pytest.mark.parametrize("who", ["finance1@marketplace.local"])
def test_privileged_accounts_cannot_become_sellers(client, auth, who):
    r = client.post("/api/seller/apply", json={"store_name": "Shady Store"}, headers=auth(who))
    assert r.status_code == 403


def test_admin_cannot_apply_as_seller(client):
    h = _admin_ready(client)
    assert client.post("/api/seller/apply", json={"store_name": "Admin Shop"}, headers=h).status_code == 403


def test_sod_enforced_at_model_level(app):
    from app.extensions import db
    from app.models import Role, SeparationOfDutiesError, User
    with app.app_context():
        fin = User.query.filter_by(email="finance1@marketplace.local").one()
        with pytest.raises(SeparationOfDutiesError):
            fin.add_role(Role.BUYER)
        db.session.rollback()


def test_admin_cannot_view_payments_or_create_coupons(client):
    h = _admin_ready(client)
    assert client.get("/api/finance/payments", headers=h).status_code == 403
    r = client.post("/api/finance/coupons", headers=h, json={
        "code": "ADMIN99", "type": "percentage", "percent": "99", "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z", "max_uses": 5})
    assert r.status_code == 403


def test_finance_cannot_admin(app, client, auth):
    h = auth("finance1@marketplace.local")
    assert client.get("/api/admin/users", headers=h).status_code == 403
    assert client.post(f"/api/admin/sellers/{user_id(app, 'uma@example.com')}/verify", headers=h).status_code == 403


# ------------------------------------------------------------- finance ------
def test_finance_creates_coupon_and_views_payments(client, auth):
    h = auth("finance1@marketplace.local")
    r = client.post("/api/finance/coupons", headers=h, json={
        "code": "spring-25", "type": "percentage", "percent": "25", "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z", "max_uses": 5})
    assert r.status_code == 201 and r.get_json()["coupon"]["code"] == "SPRING-25"
    assert client.get("/api/finance/payments", headers=h).status_code == 200


@pytest.mark.parametrize("bad", [
    {"type": "fixed", "amount": "-5"}, {"type": "fixed", "amount": 0}, {"type": "percentage", "percent": "150"},
    {"type": "percentage", "percent": "-10"}, {"type": "fixed", "amount": "5.555"}, {"type": "bogus"},
])
def test_finance_coupon_validation(client, auth, bad):
    body = {"code": "BADCOUPON", "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z",
            "max_uses": 5, **bad}
    r = client.post("/api/finance/coupons", headers=auth("finance1@marketplace.local"), json=body)
    assert r.status_code == 400, r.get_json()


def test_buyer_cannot_create_coupon(client, auth):
    r = client.post("/api/finance/coupons", headers=auth("alice@example.com"), json={
        "code": "FREE", "type": "percentage", "percent": "100", "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2030-01-01T00:00:00Z", "max_uses": 5})
    assert r.status_code == 403


# ------------------------------------------------------- sellers / P2 -------
def test_unverified_seller_cannot_publish_until_verified(app, client, auth):
    uma = auth("uma@example.com")
    pid = product_id(app, "Handmade Vase")
    assert client.post(f"/api/seller/products/{pid}/publish", headers=uma).status_code == 403
    r = client.post("/api/seller/products", headers=uma, json={"name": "Clay Pot", "price": "12.00", "stock": 3,
                                                               "status": "published"})
    assert r.status_code == 403
    r = client.post("/api/seller/products", headers=uma, json={"name": "Clay Pot", "price": "12.00", "stock": 3})
    assert r.status_code == 201 and r.get_json()["product"]["status"] == "draft"

    admin = _admin_ready(client)
    assert client.post(f"/api/admin/sellers/{user_id(app, 'uma@example.com')}/verify", headers=admin).status_code == 200
    assert client.post(f"/api/seller/products/{pid}/publish", headers=uma).status_code == 200


def test_seller_cannot_set_status_via_update(app, client, auth):
    pid = product_id(app, "Handmade Vase")
    r = client.patch(f"/api/seller/products/{pid}", headers=auth("uma@example.com"), json={"status": "published"})
    assert r.status_code == 400


def test_seller_cannot_touch_other_sellers_products(app, client, auth):
    pid = product_id(app, "Wireless Mouse")  # Sam's
    vera = auth("vera@example.com")
    assert client.patch(f"/api/seller/products/{pid}", headers=vera, json={"price": "0.01"}).status_code == 403
    assert client.post(f"/api/seller/products/{pid}/unpublish", headers=vera).status_code == 403
    assert client.get(f"/api/seller/products/{pid}", headers=vera).status_code == 403


def test_seller_cannot_spoof_owner(app, client, auth):
    r = client.post("/api/seller/products", headers=auth("vera@example.com"),
                    json={"name": "X", "price": "1.00", "stock": 1, "seller_id": user_id(app, "sam@example.com")})
    assert r.status_code == 400


@pytest.mark.parametrize("price", ["-1.00", "1.001", "NaN", "Infinity", "abc", True, None, [1]])
def test_product_price_validation(client, auth, price):
    r = client.post("/api/seller/products", headers=auth("sam@example.com"),
                    json={"name": "Thing", "price": price, "stock": 1})
    assert r.status_code == 400


def test_negative_stock_rejected(client, auth):
    r = client.post("/api/seller/products", headers=auth("sam@example.com"),
                    json={"name": "Thing", "price": "1.00", "stock": -5})
    assert r.status_code == 400


def test_pure_buyer_cannot_manage_products(client, auth):
    assert client.get("/api/seller/products", headers=auth("alice@example.com")).status_code == 403


# ------------------------------------------------ orders: P1 + P4 via API ---
def _paid_order(app, client, buyer_h):
    pid = product_id(app, "Wireless Mouse")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=buyer_h)
    assert r.status_code == 201
    return r.get_json()["order"]["id"]


def test_order_idor_between_buyers(app, client, auth):
    oid = _paid_order(app, client, auth("alice@example.com"))
    assert client.get(f"/api/orders/{oid}", headers=auth("alice@example.com")).status_code == 200
    assert client.get(f"/api/orders/{oid}", headers=auth("bob@example.com")).status_code == 403
    assert all(o["buyer_id"] != user_id(app, "alice@example.com")
               for o in client.get("/api/orders", headers=auth("bob@example.com")).get_json()["orders"])


def test_order_workflow_full(app, client, auth):
    alice, sam, vera = auth("alice@example.com"), auth("sam@example.com"), auth("vera@example.com")
    oid = _paid_order(app, client, alice)

    # buyer cannot confirm delivery of a Paid order (skip a step)
    assert client.post(f"/api/orders/{oid}/confirm-delivery", headers=alice).status_code == 403
    # buyer cannot ship (RBAC)
    assert client.post(f"/api/seller/orders/{oid}/ship", headers=alice,
                       json={"tracking_number": "TRACK123456"}).status_code == 403
    # another seller cannot ship (P1)
    assert client.post(f"/api/seller/orders/{oid}/ship", headers=vera,
                       json={"tracking_number": "TRACK123456"}).status_code == 403
    # tracking number required
    assert client.post(f"/api/seller/orders/{oid}/ship", headers=sam, json={}).status_code == 400
    r = client.post(f"/api/seller/orders/{oid}/ship", headers=sam, json={"tracking_number": "TRACK123456"})
    assert r.status_code == 200 and r.get_json()["order"]["status"] == "shipped"
    # cannot ship twice (repeat a step)
    assert client.post(f"/api/seller/orders/{oid}/ship", headers=sam,
                       json={"tracking_number": "TRACK999999"}).status_code == 403
    # other buyer cannot confirm
    assert client.post(f"/api/orders/{oid}/confirm-delivery", headers=auth("bob@example.com")).status_code == 403
    r = client.post(f"/api/orders/{oid}/confirm-delivery", headers=alice)
    assert r.status_code == 200 and r.get_json()["order"]["status"] == "delivered"
    assert client.post(f"/api/orders/{oid}/confirm-delivery", headers=alice).status_code == 403


def test_failed_order_cannot_be_shipped(app, client, auth):
    pid = product_id(app, "Wireless Mouse")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], card="TEST-DECLINE"),
                    headers=auth("alice@example.com"))
    oid = r.get_json()["order"]["id"]
    assert client.post(f"/api/seller/orders/{oid}/ship", headers=auth("sam@example.com"),
                       json={"tracking_number": "TRACK123456"}).status_code == 403


def test_seller_sees_only_own_orders(app, client, auth):
    _paid_order(app, client, auth("alice@example.com"))
    assert client.get("/api/seller/orders", headers=auth("vera@example.com")).get_json()["orders"] == []
    assert len(client.get("/api/seller/orders", headers=auth("sam@example.com")).get_json()["orders"]) == 1


def test_no_endpoint_marks_order_paid(app):
    """The browser can never tell the server a payment succeeded."""
    rules = {r.rule for r in app.url_map.iter_rules() if "pay" in r.rule or "paid" in r.rule}
    assert rules == {"/api/finance/payments"}  # read-only list for Finance; checkout is the only writer


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_errors_do_not_leak_internals(client):
    r = client.post("/api/auth/login", data="{not json", content_type="application/json")
    assert r.status_code == 400 and "Traceback" not in r.get_data(as_text=True)
