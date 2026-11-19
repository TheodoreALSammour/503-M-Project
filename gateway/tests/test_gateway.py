import json
import os
import secrets
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway_app import create_app, signing  # noqa: E402

REQ_KEY = "r" * 64
RESP_KEY = "s" * 64


@pytest.fixture
def client(tmp_path):
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'gw.db'}",
                      "REQUEST_KEY": REQ_KEY, "RESPONSE_KEY": RESP_KEY, "TESTING": True})
    return app.test_client()


def signed(payload, *, key=REQ_KEY, ts=None, nonce=None, merchant="marketplace"):
    body = json.dumps(payload).encode()
    ts = str(ts if ts is not None else int(time.time()))
    nonce = nonce or secrets.token_hex(16)
    sig = signing.sign(key.encode(), signing.request_canonical(ts, nonce, "POST", "/v1/charges", body))
    return body, {"X-Merchant-Id": merchant, "X-Timestamp": ts, "X-Nonce": nonce, "X-Signature": sig,
                  "Content-Type": "application/json"}, nonce


def charge(client, payload=None, **kw):
    payload = payload or {"card_label": "TEST-APPROVE", "amount": 1000, "currency": "USD",
                          "idempotency_key": "key-" + secrets.token_hex(8)}
    body, headers, nonce = signed(payload, **kw)
    r = client.post("/v1/charges", data=body, headers=headers)
    return r, nonce


def response_valid(r, nonce):
    msg = signing.response_canonical(r.headers["X-Gateway-Timestamp"], nonce, r.status_code, r.get_data())
    return signing.verify(RESP_KEY.encode(), msg, r.headers["X-Gateway-Signature"])


def test_approve_and_decline_labels(client):
    r, n = charge(client)
    assert r.status_code == 200 and r.get_json()["status"] == "approved" and response_valid(r, n)
    r, n = charge(client, {"card_label": "TEST-DECLINE", "amount": 1000, "currency": "USD",
                           "idempotency_key": "key-decline-1"})
    assert r.get_json()["status"] == "declined" and response_valid(r, n)


def test_bad_signature_rejected(client):
    r, _ = charge(client, key="x" * 64)
    assert r.status_code == 401


def test_unknown_merchant_rejected(client):
    r, _ = charge(client, merchant="evil")
    assert r.status_code == 401


def test_stale_timestamp_rejected(client):
    r, _ = charge(client, ts=int(time.time()) - 3600)
    assert r.status_code == 401


def test_replayed_nonce_rejected(client):
    payload = {"card_label": "TEST-APPROVE", "amount": 1000, "currency": "USD", "idempotency_key": "key-replay-1"}
    body, headers, _ = signed(payload)
    assert client.post("/v1/charges", data=body, headers=headers).status_code == 200
    assert client.post("/v1/charges", data=body, headers=headers).status_code == 401


def test_body_tampering_breaks_signature(client):
    payload = {"card_label": "TEST-APPROVE", "amount": 1000, "currency": "USD", "idempotency_key": "key-tamper-1"}
    _body, headers, _ = signed(payload)
    tampered = json.dumps({**payload, "amount": 1}).encode()
    assert client.post("/v1/charges", data=tampered, headers=headers).status_code == 401


@pytest.mark.parametrize("bad", [{"amount": -1}, {"amount": 10.5}, {"amount": "100"}, {"amount": True},
                                 {"currency": "EUR"}, {"extra": 1}])
def test_invalid_input(client, bad):
    payload = {"card_label": "TEST-APPROVE", "amount": 1000, "currency": "USD", "idempotency_key": "key-invalid-1"}
    payload.update(bad)
    r, n = charge(client, payload)
    assert r.status_code == 400 and response_valid(r, n)


def test_idempotency(client):
    payload = {"card_label": "TEST-APPROVE", "amount": 1000, "currency": "USD", "idempotency_key": "key-idem-1"}
    r1, _ = charge(client, payload)
    r2, _ = charge(client, payload)
    assert r1.get_json()["charge_id"] == r2.get_json()["charge_id"]
    r3, _ = charge(client, {**payload, "amount": 5})
    assert r3.status_code == 409
