# Multi-Vendor Marketplace — EECE 503M Software Security Project

A Flask marketplace where independent sellers list products and buyers pay with simulated
test cards and platform coupons. The project focuses on **business-logic and payment integrity**
and on a **central RBAC + ABAC policy module**.

The security document (threat model + traceability) is in **[docs/SECURITY.md](docs/SECURITY.md)**.

---

## 1. Quick start (one command)

Requirements: Docker Desktop (with Docker Compose v2), running.

```bash
git clone https://github.com/TheodoreALSammour/503-M-Project.git
cd 503-M-Project
docker compose up --build
```

Wait for `Listening at: http://0.0.0.0:8000` in the output, then open the URLs below.

| What | URL |
|---|---|
| Buyer / Seller web app | http://localhost:8000 |
| Swagger UI (every endpoint, used for Admin & Finance) | http://localhost:8000/api/docs |
| OpenAPI document | http://localhost:8000/api/openapi.yaml |

On first start the system automatically:
1. generates random secrets (DB password, signing keys) into a private Docker volume (`secrets-init`),
2. creates the database tables and runs the **seed script** (`marketplace/app/seed.py`).

To start again from a clean database: `docker compose down -v && docker compose up --build`.

### Services

```
 browser ──HTTP──► marketplace (Flask, :8000) ──signed HTTP──► gateway (Flask, internal only)
                        │        │                                   │
                   PostgreSQL   Redis (rate-limit counters)      SQLite (own DB)
```

| Service | Description | Exposed to host |
|---|---|---|
| `marketplace` | Flask app: JSON API + Buyer/Seller frontend | `127.0.0.1:8000` |
| `gateway` | Payment Gateway Simulator (separate Flask service, own SQLite DB) | no (internal network) |
| `db` | PostgreSQL 16 for the marketplace | no |
| `redis` | shared rate-limit storage for all gunicorn workers | no |
| `secrets-init` | one-shot job generating secrets | — |

---

## 2. Seeded accounts

> Demo credentials for a local test system only.

| Role | Email | Password | Notes |
|---|---|---|---|
| **Admin** | `admin@marketplace.local` | `ChangeMe#Default2026` | Must change email **and** password first (`POST /api/admin/change-credentials`); every other action is denied until then |
| Finance Officer | `finance1@marketplace.local` | `Finance#One2026` | API only |
| Finance Officer | `finance2@marketplace.local` | `Finance#Two2026` | API only |
| Buyer | `alice@example.com` | `Market#Buyer2026` | |
| Buyer | `bob@example.com` | `Market#Buyer2027` | second buyer for ownership (IDOR) tests |
| Buyer + Seller (**Verified**) | `sam@example.com` | `Market#Seller2026` | store "Sam's Gadgets" |
| Buyer + Seller (**Verified**) | `vera@example.com` | `Market#Seller2027` | store "Vera's Books" (for the one-seller-per-order rule) |
| Buyer + Seller (**Unverified**) | `uma@example.com` | `Market#Seller2028` | store "Uma's Crafts": drafts only |
| Buyer (**Suspended**) | `suspended@example.com` | `Market#Buyer2029` | cannot log in |

### Seeded products

| Product | Seller | Price | Stock | Status | Purpose |
|---|---|---|---|---|---|
| Wireless Mouse | Sam | $24.99 | 50 | Published | |
| Mechanical Keyboard | Sam | $89.99 | 20 | Published | |
| USB-C Cable | Sam | $9.99 | 200 | Published | |
| **Last-One Lamp** | Sam | $45.00 | **1** | Published | race condition on the last item |
| Prototype Drone | Sam | $299.00 | 5 | **Draft** | drafts are invisible / not purchasable |
| Security Engineering (book) | Vera | $59.99 | 10 | Published | |
| Cryptography Notebook | Vera | $12.50 | 30 | Published | |
| Twenty Cent Sticker | Vera | $0.20 | 100 | Published | rounding demo with `ROUND125` |
| Handmade Vase | Uma | $35.00 | 3 | **Draft** | unverified seller cannot publish |

### Seeded coupons

| Code | Type | Value | Validity | Max uses | Purpose |
|---|---|---|---|---|---|
| `WELCOME10` | percentage | 10 % | valid (1 year) | 1000 | normal coupon, once per buyer |
| `SAVE5` | fixed | $5.00 | valid | 1000 | fixed amount |
| `BIGFIXED100` | fixed | $100.00 | valid | 1000 | discount capped at the order total |
| `ROUND125` | percentage | 12.5 % | valid | 1000 | half-up rounding (12.5 % of $0.20 = 2.5¢ → **3¢**) |
| `SINGLEUSE50` | percentage | 50 % | valid | **1** | single-use (global) / race on last use |
| `EXPIRED20` | percentage | 20 % | **expired** | 1000 | rejected |
| `FUTURE15` | percentage | 15 % | **not yet valid** | 1000 | rejected |

Test card labels: **`TEST-APPROVE`** (approved) and **`TEST-DECLINE`** (declined). Any other label is declined.

---

## 3. Using the system

### Buyers and sellers (web UI)
* Browse/search as a visitor at http://localhost:8000.
* Log in as `alice@example.com`, add products from **one** store to the cart, open **Cart**,
  enter an address, optionally **Check coupon**, choose a test card and **Pay now**.
* **My orders** lists your orders; once shipped you can **Confirm delivery**.
* **Seller** page: apply as seller (buyers), create products, publish (verified sellers only),
  update price/stock, and ship paid orders with a tracking number.

### Admin and Finance Officer (Swagger UI: API only)
1. Open http://localhost:8000/api/docs.
2. `POST /api/auth/login` with e.g. `{"email": "admin@marketplace.local", "password": "ChangeMe#Default2026"}`
   (default `mode` is `bearer`). Copy `access_token`, click **Authorize**, paste it.
3. Admin: first `POST /api/admin/change-credentials`, then e.g. `GET /api/admin/sellers?status=unverified`,
   `POST /api/admin/sellers/{user_id}/verify`, `POST /api/admin/users/{user_id}/suspend`.
4. Finance: `POST /api/finance/coupons`, `GET /api/finance/coupons`, `GET /api/finance/payments`.

---

## 4. Logs (shown during the demo)

Every log entry is one JSON line. Logged: logins and failed logins, **every authorization decision with
the deciding policy**, every payment and order state change, admin and finance operations,
rate-limit hits, CSRF failures and gateway verification failures.

```bash
docker compose logs -f marketplace                       # everything (stdout)
docker compose exec marketplace tail -f /logs/security.log   # marketplace security log file
docker compose exec gateway tail -f /logs/gateway.log        # gateway log file

# examples
docker compose exec marketplace grep '"decision": "deny"' /logs/security.log
docker compose exec marketplace grep -E 'order.state_change|payment.result' /logs/security.log
docker compose exec marketplace grep -E 'auth.login' /logs/security.log
```

Example authorization log line:
```json
{"event": "authz.decision", "decision": "deny", "action": "seller_order.ship", "policy": "P4_ORDER_STATE",
 "reason": "shipped -> shipped not allowed for seller", "subject_id": 7, "subject_roles": ["buyer","seller"],
 "resource": {"type": "Order", "id": 3, "buyer_id": 4, "seller_id": 7, "status": "shipped"}, ...}
```

---

## 5. Tests

Run from the project root (Docker is not needed for these):

**Windows (PowerShell)**
```powershell
python -m venv .venv
.venv\Scripts\pip install -r marketplace\requirements.txt -r gateway\requirements.txt pytest
cd marketplace; ..\.venv\Scripts\python -m pytest -q; cd ..   # 135 tests (~3.5 min)
cd gateway; ..\.venv\Scripts\python -m pytest -q; cd ..       # 13 tests
```

**Linux / macOS**
```bash
python3 -m venv .venv
.venv/bin/pip install -r marketplace/requirements.txt -r gateway/requirements.txt pytest
(cd marketplace && ../.venv/bin/python -m pytest -q)   # 135 tests (~3.5 min)
(cd gateway && ../.venv/bin/python -m pytest -q)       # 13 tests
```

| Test file | Covers |
|---|---|
| `marketplace/tests/test_policy_engine.py` | **Authorization layer unit tests**: allow + deny for every policy (P1–P4, global policies), RBAC short-circuit, default deny, deny-overrides, fail-closed, config validation |
| `marketplace/tests/test_access_control.py` | HTTP-level access control: IDOR, visitors, SoD, admin first login, suspension kills sessions, CSRF, P2 publish flow, order workflow |
| `marketplace/tests/test_checkout.py` | business-logic attacks: price tampering, quantities, stock, drafts, multi-seller carts, coupons, rounding, idempotency, forged/tampered/replayed gateway responses, races |
| `marketplace/tests/test_rate_limits.py` | login, coupon validation, checkout rate limits |
| `marketplace/tests/test_openapi.py` | every Flask route is documented in OpenAPI |
| `gateway/tests/test_gateway.py` | gateway signature, replay, timestamp, validation, idempotency |

### Live attack script (against the running Docker stack, PostgreSQL row locks, 3 workers)

With the system running (`docker compose up`), in a second terminal:

```bash
python scripts/attack_demo.py        # standard library only; wait ~1 min between runs (rate limits)
```
It runs real concurrent requests (last item race, last coupon use race, parallel duplicate
idempotency keys) plus tampering/IDOR/workflow attacks, and prints `13/13 attacks blocked`.
Each run adds test products and buyers; reset with `docker compose down -v` before a demo.

---

## 6. Project structure

```
docker-compose.yml
scripts/gen_secrets.py            # first-start secret generation
scripts/attack_demo.py            # live attack demo
docs/SECURITY.md                  # threat model + traceability
gateway/                          # Payment Gateway Simulator (separate service + DB)
  gateway_app/__init__.py         #   POST /v1/charges: signature, replay, idempotency
  gateway_app/signing.py          #   HMAC-SHA256 signing helpers
marketplace/
  app/policy/policy_config.yaml   # RBAC permission matrix + ABAC assignment (configuration)
  app/policy/engine.py            # central policy decision point
  app/policy/policies.py          # P1–P4 + global policies
  app/policy/__init__.py          # @authorize decorator + route guard (enforcement point)
  app/checkout.py                 # pricing, atomic checkout, idempotency
  app/coupons.py                  # coupon rules
  app/state_machine.py            # order state machine
  app/gateway_client.py           # signed requests / verified responses
  app/auth.py                     # Argon2id, server-side sessions, CSRF
  app/audit.py                    # structured security logging
  app/models.py                   # SQLAlchemy models + DB constraints
  app/routes/                     # Flask blueprints (auth, catalog, buyer, seller, finance, admin, pages)
  app/openapi.yaml                # OpenAPI 3 document for every endpoint
  app/static/                     # frontend (vanilla JS, CSP-compatible, no innerHTML)
  app/seed.py                     # seed script
  tests/
```

### Changing access control without code changes
Edit `marketplace/app/policy/policy_config.yaml` (permission matrix + which ABAC policies apply
to which action) and restart the `marketplace` service. A malformed configuration is refused at
start-up (fail closed).
