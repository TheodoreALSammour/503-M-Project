"""Login, coupon validation and checkout are rate limited."""
import pytest

from app import create_app
from app.extensions import db
from app.seed import seed

from .conftest import PASSWORDS, REQ_KEY, RESP_KEY, checkout_body


@pytest.fixture
def limited(tmp_path):
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'rl.db'}",
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
        "LOGIN_RATE_LIMIT_IP": "100 per minute",
        "LOGIN_RATE_LIMIT_ACCOUNT": "3 per minute",
        "COUPON_RATE_LIMIT": "3 per minute",
        "CHECKOUT_RATE_LIMIT": "3 per minute",
        "LOG_DIR": str(tmp_path),
        "GATEWAY_REQUEST_KEY": REQ_KEY, "GATEWAY_RESPONSE_KEY": RESP_KEY,
    })
    from app.extensions import limiter
    limiter.reset()
    with app.app_context():
        db.create_all()
        seed()
    yield app
    with app.app_context():
        db.session.remove()
        db.engine.dispose()


def test_login_bruteforce_limited_per_account(limited):
    c = limited.test_client()
    codes = [c.post("/api/auth/login", json={"email": "alice@example.com", "password": f"guess-{i}"}).status_code
             for i in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]
    # even the right password is refused while the account is throttled
    r = c.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORDS["alice@example.com"]})
    assert r.status_code == 429


def test_coupon_bruteforce_limited(limited):
    c = limited.test_client()
    tok = c.post("/api/auth/login", json={"email": "bob@example.com", "password": PASSWORDS["bob@example.com"]})
    h = {"Authorization": "Bearer " + tok.get_json()["access_token"]}
    codes = [c.post("/api/coupons/validate", headers=h,
                    json={"items": [{"product_id": 1, "quantity": 1}], "coupon_code": f"GUESS{i:03d}"}).status_code
             for i in range(5)]
    assert codes[-1] == 429 and codes.count(429) == 2


def test_checkout_limited(limited):
    c = limited.test_client()
    tok = c.post("/api/auth/login", json={"email": "bob@example.com", "password": PASSWORDS["bob@example.com"]})
    h = {"Authorization": "Bearer " + tok.get_json()["access_token"]}
    codes = [c.post("/api/checkout", headers=h, json=checkout_body([(999999, 1)])).status_code for _ in range(5)]
    assert codes[-1] == 429


def test_attacker_cannot_lock_victim_out_from_another_ip(limited):
    """F3: failed logins from the attacker's IP must not lock the victim out of their own IP."""
    c = limited.test_client()
    attacker = {"REMOTE_ADDR": "203.0.113.66"}
    victim = {"REMOTE_ADDR": "198.51.100.7"}
    codes = [c.post("/api/auth/login", json={"email": "alice@example.com", "password": f"guess-{i}"},
                    environ_base=attacker).status_code for i in range(5)]
    assert codes[-1] == 429  # the attacker is still throttled
    r = c.post("/api/auth/login", json={"email": "alice@example.com", "password": PASSWORDS["alice@example.com"]},
               environ_base=victim)
    assert r.status_code == 200
