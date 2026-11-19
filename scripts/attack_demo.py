"""Live attack / race-condition demo against the running system.

    docker compose up --build -d
    python scripts/attack_demo.py            # default http://localhost:8000

Uses only the Python standard library. Re-runnable: every run creates its own
fresh product (stock 1), single-use coupon and two new buyers.
Each check prints PASS when the attack was BLOCKED.
"""
import json
import sys
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:8000"
RESULTS = []


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def login(email, password):
    status, data = call("POST", "/api/auth/login", {"email": email, "password": password})
    if status != 200:
        sys.exit(f"login failed for {email}: {status} {data}")
    return data["access_token"]


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def checkout(token, pid, qty=1, coupon=None, card="TEST-APPROVE", key=None, **extra):
    body = {"items": [{"product_id": pid, "quantity": qty}], "shipping_address": "Hamra Street, Beirut",
            "card_label": card, "idempotency_key": key or str(uuid.uuid4())}
    if coupon:
        body["coupon_code"] = coupon
    body.update(extra)
    return call("POST", "/api/checkout", body, token)


def main():
    print(f"Target: {BASE}\n")
    run = uuid.uuid4().hex[:6].upper()

    sam = login("sam@example.com", "Market#Seller2026")
    fin = login("finance1@marketplace.local", "Finance#One2026")

    buyers = []
    for i in range(2):
        email = f"attacker{run.lower()}{i}@example.com"
        s, d = call("POST", "/api/auth/register", {"full_name": f"Attacker {i}", "email": email,
                                                    "phone": "+961 70 000000", "password": "Att@cker-Pass-2026"})
        if s != 201:
            sys.exit(f"registration failed: {s} {d}")
        buyers.append(login(email, "Att@cker-Pass-2026"))
    a, b = buyers

    s, d = call("POST", "/api/seller/products", {"name": f"Race Item {run}", "price": "10.00", "stock": 1,
                                                  "status": "published"}, sam)
    pid = d["product"]["id"]
    s, d = call("POST", "/api/seller/products", {"name": f"Plenty Item {run}", "price": "19.99", "stock": 500,
                                                  "status": "published"}, sam)
    plenty = d["product"]["id"]
    now = datetime.now(timezone.utc)
    code = f"RACE{run}"
    call("POST", "/api/finance/coupons", {"code": code, "type": "percentage", "percent": "50",
                                          "valid_from": (now - timedelta(minutes=1)).isoformat(),
                                          "valid_until": (now + timedelta(days=1)).isoformat(), "max_uses": 1}, fin)

    # 1. Race for the last item
    with ThreadPoolExecutor(6) as ex:
        res = list(ex.map(lambda t: checkout(t, pid), [a, b, a, b, a, b]))
    paid = [r for r in res if r[0] == 201]
    s, d = call("GET", f"/api/products/{pid}")
    check("6 simultaneous checkouts for the last item -> exactly one Paid", len(paid) == 1 and d["product"]["stock"] == 0,
          f"statuses={sorted(r[0] for r in res)}, stock={d['product']['stock']}")

    # 2. Race for a coupon's last use
    with ThreadPoolExecutor(2) as ex:
        res = list(ex.map(lambda t: checkout(t, plenty, coupon=code), [a, b]))
    check("2 simultaneous checkouts with a single-use coupon -> one discount", sorted(r[0] for r in res) == [201, 422],
          f"statuses={sorted(r[0] for r in res)}")

    # 3. Double submit / replay with the same idempotency key
    key = str(uuid.uuid4())
    with ThreadPoolExecutor(3) as ex:
        res = list(ex.map(lambda _: checkout(a, plenty, key=key), range(3)))
    order_ids = {r[1].get("order", {}).get("id") for r in res if r[1].get("order")}
    check("3 parallel requests with the same idempotency key -> one order/charge", len(order_ids) == 1,
          f"statuses={sorted(r[0] for r in res)}, orders={order_ids}")

    # 4. Price / total tampering
    s, _ = checkout(b, plenty, total_cents=1, price="0.01")
    check("client-supplied price/total rejected", s == 400, f"status={s}")

    # 5. Negative / fractional quantity
    s, _ = checkout(b, plenty, qty=-3)
    check("negative quantity rejected", s == 400, f"status={s}")

    # 6. Coupon reuse by the same buyer (coupon already used by whoever won race 2)
    s, _ = call("POST", "/api/coupons/validate", {"items": [{"product_id": plenty, "quantity": 1}], "coupon_code": code}, a)
    s2, _ = call("POST", "/api/coupons/validate", {"items": [{"product_id": plenty, "quantity": 1}], "coupon_code": code}, b)
    check("exhausted single-use coupon rejected for everyone", s == 422 and s2 == 422, f"statuses={s},{s2}")

    # 7. IDOR on someone else's order
    my_order = next(iter(order_ids))
    s, _ = call("GET", f"/api/orders/{my_order}", token=b)
    check("buyer cannot read another buyer's order (P1)", s == 403, f"status={s}")

    # 8. Skip workflow step: confirm delivery of a Paid order
    s, _ = call("POST", f"/api/orders/{my_order}/confirm-delivery", {}, a)
    check("cannot confirm delivery of a Paid (not Shipped) order (P4)", s == 403, f"status={s}")

    # 9. Buyer tries to ship
    s, _ = call("POST", f"/api/seller/orders/{my_order}/ship", {"tracking_number": "FAKE123456"}, a)
    check("buyer cannot mark an order shipped (RBAC)", s == 403, f"status={s}")

    # 10. Seller buys own product
    s, _ = checkout(sam, plenty)
    check("seller cannot buy own product (P3)", s == 403, f"status={s}")

    # 11. Declined card leaves stock untouched
    before = call("GET", f"/api/products/{plenty}")[1]["product"]["stock"]
    s, d = checkout(b, plenty, card="TEST-DECLINE")
    after = call("GET", f"/api/products/{plenty}")[1]["product"]["stock"]
    check("declined payment -> Failed order, stock unchanged", s == 402 and before == after,
          f"status={s}, stock {before}->{after}")

    # 12. Finance views payments, buyer cannot
    s1, _ = call("GET", "/api/finance/payments", token=fin)
    s2, _ = call("GET", "/api/finance/payments", token=a)
    check("only Finance can view payments", s1 == 200 and s2 == 403, f"finance={s1}, buyer={s2}")

    # 13. Coupon brute force is rate limited
    codes = [call("POST", "/api/coupons/validate", {"items": [{"product_id": plenty, "quantity": 1}],
                                                    "coupon_code": f"GUESS{i:04d}"}, b)[0] for i in range(15)]
    check("coupon guessing is rate limited", 429 in codes, f"first 429 after {codes.index(429) if 429 in codes else '-'} tries")

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} attacks blocked")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
