"""Business-logic and payment-integrity attacks against checkout."""
import json
import threading

import pytest

from app.extensions import db
from app.models import Coupon, CouponRedemption, Order, Payment, Product

from .conftest import checkout_body, product_id


def _stock(app, pid):
    with app.app_context():
        return db.session.get(Product, pid).stock


def _coupon(app, code):
    with app.app_context():
        c = Coupon.query.filter_by(code=code).one()
        return c.used_count, CouponRedemption.query.filter_by(coupon_id=c.id).count()


def test_happy_path_paid(app, client, auth):
    pid = product_id(app, "Wireless Mouse")
    r = client.post("/api/checkout", json=checkout_body([(pid, 2)]), headers=auth("alice@example.com"))
    assert r.status_code == 201, r.get_json()
    o = r.get_json()["order"]
    assert o["status"] == "paid" and o["total_cents"] == 4998 and o["charge_id"].startswith("ch_")
    assert _stock(app, pid) == 48


@pytest.mark.parametrize("extra", [{"total": 1}, {"price": "0.01"}, {"amount": 1}, {"discount_cents": 9999},
                                   {"status": "paid"}, {"payment_status": "approved"}, {"buyer_id": 2}])
def test_client_cannot_send_prices_or_status(app, client, auth, extra):
    pid = product_id(app, "Wireless Mouse")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], **extra), headers=auth("alice@example.com"))
    assert r.status_code == 400
    assert _stock(app, pid) == 50


def test_price_inside_items_rejected(app, client, auth):
    pid = product_id(app, "Wireless Mouse")
    body = checkout_body([(pid, 1)])
    body["items"][0]["unit_price"] = 1
    r = client.post("/api/checkout", json=body, headers=auth("alice@example.com"))
    assert r.status_code == 400


@pytest.mark.parametrize("qty", [0, -1, 1.5, "2", True, 10**9, None])
def test_invalid_quantities(app, client, auth, qty):
    pid = product_id(app, "Wireless Mouse")
    body = checkout_body([(pid, 1)])
    body["items"][0]["quantity"] = qty
    r = client.post("/api/checkout", json=body, headers=auth("alice@example.com"))
    assert r.status_code == 400


def test_quantity_above_stock(app, client, auth):
    pid = product_id(app, "Last-One Lamp")
    r = client.post("/api/checkout", json=checkout_body([(pid, 2)]), headers=auth("alice@example.com"))
    assert r.status_code == 409
    assert _stock(app, pid) == 1


def test_duplicate_lines_rejected(app, client, auth):
    pid = product_id(app, "Last-One Lamp")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1), (pid, 1)]), headers=auth("alice@example.com"))
    assert r.status_code == 400


def test_draft_cannot_be_bought(app, client, auth):
    pid = product_id(app, "Prototype Drone")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=auth("alice@example.com"))
    assert r.status_code == 404


def test_multi_seller_cart_rejected(app, client, auth):
    a, b = product_id(app, "Wireless Mouse"), product_id(app, "Cryptography Notebook")
    r = client.post("/api/checkout", json=checkout_body([(a, 1), (b, 1)]), headers=auth("alice@example.com"))
    assert r.status_code == 400 and "one seller" in r.get_json()["message"]


def test_self_dealing_denied_p3(app, client, auth):
    pid = product_id(app, "Wireless Mouse")  # Sam's product
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=auth("sam@example.com"))
    assert r.status_code == 403
    # Sam (buyer+seller) can still buy from Vera.
    pid2 = product_id(app, "Cryptography Notebook")
    r = client.post("/api/checkout", json=checkout_body([(pid2, 1)]), headers=auth("sam@example.com"))
    assert r.status_code == 201


@pytest.mark.parametrize("who", ["finance1@marketplace.local"])
def test_non_buyers_cannot_checkout(app, client, auth, who):
    pid = product_id(app, "Wireless Mouse")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=auth(who))
    assert r.status_code == 403


def test_anonymous_cannot_checkout(app, client):
    pid = product_id(app, "Wireless Mouse")
    assert client.post("/api/checkout", json=checkout_body([(pid, 1)])).status_code == 401


def test_declined_card_failed_and_nothing_changes(app, client, auth):
    pid = product_id(app, "Last-One Lamp")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="SINGLEUSE50", card="TEST-DECLINE"),
                    headers=auth("alice@example.com"))
    assert r.status_code == 402
    assert r.get_json()["order"]["status"] == "failed"
    assert _stock(app, pid) == 1
    assert _coupon(app, "SINGLEUSE50") == (0, 0)


def test_unknown_card_label_declined(app, client, auth):
    pid = product_id(app, "USB-C Cable")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], card="4111111111111111"),
                    headers=auth("alice@example.com"))
    assert r.status_code == 402


# ---------------------------------------------------------------- coupons ---
def test_percentage_coupon_and_half_up_rounding(app, client, auth):
    pid = product_id(app, "Twenty Cent Sticker")  # 20 cents
    # 12.5 % of 20c = 2.5c -> rounds HALF UP to 3c
    r = client.post("/api/coupons/validate", json={"items": [{"product_id": pid, "quantity": 1}],
                                                    "coupon_code": "round125"}, headers=auth("alice@example.com"))
    assert r.status_code == 200, r.get_json()
    q = r.get_json()["quote"]
    assert (q["subtotal_cents"], q["discount_cents"], q["total_cents"]) == (20, 3, 17)


def test_coupon_validate_changes_nothing(app, client, auth):
    pid = product_id(app, "USB-C Cable")
    client.post("/api/coupons/validate", json={"items": [{"product_id": pid, "quantity": 1}],
                                               "coupon_code": "SINGLEUSE50"}, headers=auth("alice@example.com"))
    assert _coupon(app, "SINGLEUSE50") == (0, 0)


def test_fixed_discount_never_exceeds_total(app, client, auth):
    pid = product_id(app, "USB-C Cable")  # $9.99, coupon is $100
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="BIGFIXED100"),
                    headers=auth("alice@example.com"))
    o = r.get_json()["order"]
    assert r.status_code == 201 and o["discount_cents"] == 999 and o["total_cents"] == 0


@pytest.mark.parametrize("code", ["EXPIRED20", "FUTURE15", "NOPE-NOT-REAL"])
def test_invalid_coupons_rejected_generically(app, client, auth, code):
    pid = product_id(app, "USB-C Cable")
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon=code), headers=auth("alice@example.com"))
    assert r.status_code == 422
    assert r.get_json()["message"] == "This coupon is not valid for this order."


def test_coupon_once_per_buyer(app, client, auth):
    pid = product_id(app, "USB-C Cable")
    h = auth("alice@example.com")
    assert client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="WELCOME10"), headers=h).status_code == 201
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="WELCOME10"), headers=h)
    assert r.status_code == 422
    # another buyer can still use it
    assert client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="WELCOME10"),
                       headers=auth("bob@example.com")).status_code == 201


def test_single_use_coupon_global_limit(app, client, auth):
    pid = product_id(app, "USB-C Cable")
    assert client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="SINGLEUSE50"),
                       headers=auth("alice@example.com")).status_code == 201
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="SINGLEUSE50"),
                    headers=auth("bob@example.com"))
    assert r.status_code == 422
    assert _coupon(app, "SINGLEUSE50") == (1, 1)


# --------------------------------------------------------- double charging --
def test_idempotent_replay_does_not_charge_twice(app, client, auth, transport):
    pid = product_id(app, "Wireless Mouse")
    body = checkout_body([(pid, 1)])
    h = auth("alice@example.com")
    r1 = client.post("/api/checkout", json=body, headers=h)
    r2 = client.post("/api/checkout", json=body, headers=h)
    assert r1.status_code == 201 and r2.status_code == 200
    assert r2.get_json()["idempotent_replay"] is True
    assert r1.get_json()["order"]["id"] == r2.get_json()["order"]["id"]
    assert transport.calls == 1
    assert _stock(app, pid) == 49


def test_idempotency_key_reuse_with_different_cart(app, client, auth):
    pid = product_id(app, "Wireless Mouse")
    h = auth("alice@example.com")
    body = checkout_body([(pid, 1)])
    client.post("/api/checkout", json=body, headers=h)
    body["items"][0]["quantity"] = 3
    assert client.post("/api/checkout", json=body, headers=h).status_code == 409


def test_charge_id_attached_to_one_order_only(app, client, auth, transport):
    """A (validly signed) gateway response re-used for a second order must not
    mark it Paid."""
    pid = product_id(app, "USB-C Cable")
    h = auth("alice@example.com")
    r1 = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=h)
    first_charge = r1.get_json()["order"]["charge_id"]

    from app.gateway_client import ChargeResult
    client_obj = app.extensions["gateway_client"]
    original = client_obj.charge
    client_obj.charge = lambda *a, **k: ChargeResult("approved", first_charge, True, "approved")
    try:
        r2 = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=h)
    finally:
        client_obj.charge = original
    assert r2.get_json()["order"]["status"] == "failed"
    with app.app_context():
        assert Order.query.filter_by(charge_id=first_charge).count() == 1


# --------------------------------------------------- payment verification ---
def _tamper_body(fn):
    def tamper(status, headers, body):
        data = json.loads(body)
        fn(data)
        return status, headers, json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return tamper


@pytest.mark.parametrize("tamper", [
    _tamper_body(lambda d: d.update(status="approved")),            # declined -> approved
    _tamper_body(lambda d: d.update(amount=1)),                     # amount changed
    lambda s, h, b: (s, {k: v for k, v in h.items() if k != "X-Gateway-Signature"}, b),   # unsigned
    lambda s, h, b: (s, {**h, "X-Gateway-Signature": "0" * 64}, b),  # forged signature
])
def test_tampered_gateway_response_never_paid(app, client, auth, transport, tamper):
    pid = product_id(app, "Last-One Lamp")
    transport.tamper = tamper
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], card="TEST-DECLINE"),
                    headers=auth("alice@example.com"))
    transport.tamper = None
    assert r.get_json()["order"]["status"] == "failed"
    assert _stock(app, pid) == 1
    with app.app_context():
        p = Payment.query.one()
        assert p.outcome in ("rejected", "declined")


def test_amount_mismatch_with_valid_signature_rejected(app, client, auth, transport):
    """Gateway (validly) reports a different amount than the server computed."""
    from app.gateway_client import GatewayClient
    gw = app.extensions["gateway_client"]
    real_charge = GatewayClient.charge

    def lowball(self, card, amount, currency, key):
        return real_charge(self, card, 1, currency, key)  # gateway charges 1 cent

    pid = product_id(app, "Mechanical Keyboard")
    sent = {}
    orig_verify = gw._verify

    def verify(status, headers, body, nonce, payload):
        sent["payload"] = payload
        payload = dict(payload, amount=8999)  # what the server expected
        return orig_verify(status, headers, body, nonce, payload)
    gw._verify = verify
    gw.charge = lowball.__get__(gw)
    try:
        r = client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=auth("alice@example.com"))
    finally:
        del gw.charge
        gw._verify = orig_verify
    assert r.get_json()["order"]["status"] == "failed"
    assert _stock(app, pid) == 20


def test_replayed_old_approval_rejected(app, client, auth, transport):
    """An old, validly signed 'approved' response replayed for a new request is
    rejected because it is bound to the old request's nonce."""
    pid = product_id(app, "USB-C Cable")
    captured = {}

    def capture(status, headers, body):
        captured["resp"] = (status, headers, body)
        return status, headers, body
    transport.tamper = capture
    client.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=auth("alice@example.com"))
    transport.tamper = lambda *_: captured["resp"]
    r = client.post("/api/checkout", json=checkout_body([(pid, 1)], card="TEST-DECLINE"),
                    headers=auth("bob@example.com"))
    transport.tamper = None
    assert r.get_json()["order"]["status"] == "failed"


# --------------------------------------------------------------- races ------
def test_concurrent_checkouts_for_last_item(app, auth):
    pid = product_id(app, "Last-One Lamp")
    buyers = [auth("alice@example.com"), auth("bob@example.com")]
    results = []

    def go(h):
        c = app.test_client()
        results.append(c.post("/api/checkout", json=checkout_body([(pid, 1)]), headers=h).status_code)

    threads = [threading.Thread(target=go, args=(h,)) for h in buyers * 3]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count(201) == 1, results
    assert _stock(app, pid) == 0


def test_concurrent_last_coupon_use(app, auth):
    pid = product_id(app, "USB-C Cable")
    buyers = [auth("alice@example.com"), auth("bob@example.com")]
    results = []

    def go(h):
        c = app.test_client()
        results.append(c.post("/api/checkout", json=checkout_body([(pid, 1)], coupon="SINGLEUSE50"),
                              headers=h).status_code)

    threads = [threading.Thread(target=go, args=(h,)) for h in buyers]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == [201, 422], results
    assert _coupon(app, "SINGLEUSE50") == (1, 1)
