import os
import sys
import uuid
from urllib.parse import urlparse

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))  # marketplace/
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "gateway"))  # gateway/

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.gateway_client import GatewayClient  # noqa: E402
from app.seed import seed  # noqa: E402

REQ_KEY = "r" * 64
RESP_KEY = "s" * 64

PASSWORDS = {
    "admin@marketplace.local": "ChangeMe#Default2026",
    "finance1@marketplace.local": "Finance#One2026",
    "alice@example.com": "Market#Buyer2026",
    "bob@example.com": "Market#Buyer2027",
    "sam@example.com": "Market#Seller2026",
    "vera@example.com": "Market#Seller2027",
    "uma@example.com": "Market#Seller2028",
    "suspended@example.com": "Market#Buyer2029",
}


class Transport:
    """Routes marketplace -> gateway HTTP calls to the in-process gateway app.
    ``tamper`` lets a test modify the gateway response (MITM simulation)."""

    def __init__(self, gw_client):
        self.gw = gw_client
        self.tamper = None
        self.calls = 0

    def __call__(self, method, url, headers, body):
        self.calls += 1
        r = self.gw.open(urlparse(url).path, method=method, headers=headers, data=body)
        result = (r.status_code, dict(r.headers), r.get_data())
        if self.tamper:
            result = self.tamper(*result)
        return result


@pytest.fixture
def gateway_app(tmp_path):
    from gateway_app import create_app as create_gateway
    return create_gateway({
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'gateway.db'}",
        "REQUEST_KEY": REQ_KEY, "RESPONSE_KEY": RESP_KEY, "TESTING": True,
    })


@pytest.fixture
def app(tmp_path, gateway_app):
    application = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'marketplace.db'}",
        "RATELIMIT_ENABLED": False,
        "LOG_DIR": str(tmp_path / "logs"),
        "GATEWAY_REQUEST_KEY": REQ_KEY,
        "GATEWAY_RESPONSE_KEY": RESP_KEY,
    })
    transport = Transport(gateway_app.test_client())
    application.extensions["gateway_client"] = GatewayClient(
        "http://gateway", "marketplace", REQ_KEY, RESP_KEY, transport=transport)
    application.extensions["test_transport"] = transport
    with application.app_context():
        db.create_all()
        seed()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def transport(app):
    return app.extensions["test_transport"]


def login(client, email, password=None, mode="bearer"):
    r = client.post("/api/auth/login", json={"email": email, "password": password or PASSWORDS[email],
                                             "mode": mode})
    assert r.status_code == 200, r.get_json()
    return r.get_json()


def token_for(client, email):
    return {"Authorization": "Bearer " + login(client, email)["access_token"]}


@pytest.fixture
def auth(client):
    cache = {}

    def _auth(email):
        if email not in cache:
            cache[email] = token_for(client, email)
        return cache[email]
    return _auth


def product_id(app, name):
    from app.models import Product
    with app.app_context():
        return Product.query.filter_by(name=name).one().id


def user_id(app, email):
    from app.models import User
    with app.app_context():
        return User.query.filter_by(email=email).one().id


def checkout_body(items, coupon=None, card="TEST-APPROVE", key=None, **extra):
    body = {"items": [{"product_id": p, "quantity": q} for p, q in items],
            "shipping_address": "Bliss Street, Beirut", "card_label": card,
            "idempotency_key": key or str(uuid.uuid4())}
    if coupon:
        body["coupon_code"] = coupon
    body.update(extra)
    return body
