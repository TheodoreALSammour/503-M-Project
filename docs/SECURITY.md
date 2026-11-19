# Security Document — Threat Model and Traceability

**System:** Multi-Vendor Marketplace + Payment Gateway Simulator. **Course:** EECE 503M Software Security.

This document identifies the assets, trust boundaries and threats of the system (STRIDE + business-logic
abuse cases), the control that mitigates each threat, **where it is implemented** and **which test verifies it**.

---

## 1. Scope and assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Money flow: order totals, charges, payment status | Paying less than the real price, getting goods without paying |
| A2 | Inventory (stock) | Overselling the last item |
| A3 | Coupons (usage counters, per-buyer usage) | Discount abuse, reusing single-use coupons |
| A4 | Orders and their state | Skipping steps (Delivered without Shipped, Paid without payment) |
| A5 | User accounts, credentials, sessions | Account takeover, privilege escalation |
| A6 | Roles, seller verification status | Unverified sellers publishing, buyers acting as sellers / admins |
| A7 | Gateway signing keys, DB password | Forging payment approvals, DB compromise |
| A8 | Personal data (name, email, phone, address) | Privacy, IDOR |
| A9 | Audit logs | Accountability, incident investigation |

## 2. Architecture and trust boundaries

```
                 TB1 (Internet / untrusted)
  ┌──────────┐   HTTP (JSON + cookies/Bearer)   ┌─────────────────────────────────────┐
  │ Browser  │ ───────────────────────────────► │ marketplace (Flask/gunicorn)         │
  │ Swagger  │                                  │  PEP: @authorize ─► PDP: engine.py   │
  │ Postman  │ ◄─────────────────────────────── │  checkout / coupons / state machine  │
  └──────────┘                                  └──────┬──────────────┬───────────────┘
                                         TB2 (internal │ network)     │ TB3 (payments network)
                                       ┌───────────────▼───┐  ┌───────▼───────────────────────┐
                                       │ PostgreSQL         │  │ gateway (Flask) + SQLite DB    │
                                       │ Redis (rate limits)│  │ HMAC-signed req/resp, nonces   │
                                       └────────────────────┘  └───────────────────────────────┘
                  shared_secrets volume (read-only mounts): DB password, signing keys
```

* **TB1:** everything from the client is untrusted: body, query, headers, cookies, and the totals the
  browser displays. The server never accepts prices, totals, roles, owners, statuses or payment results from the client.
* **TB2:** the DB and Redis are on an `internal: true` Docker network and are not published to the host.
* **TB3:** the gateway is a separate service with its own DB on a separate internal network. It is not
  reachable from the host or browser. The channel is authenticated and integrity-protected at the application layer (HMAC).

**Actors:** Visitor, Buyer, Seller (Unverified/Verified, always also a Buyer), Finance Officer, Admin,
plus attackers: a malicious buyer or seller (authenticated insider), an anonymous attacker, and a network attacker on the
marketplace↔gateway path.

## 3. Security design summary

| Area | Design |
|---|---|
| Access control | One central **policy decision point** (`app/policy/engine.py`). Every view is wrapped by `@authorize(action, loader)` (`app/policy/__init__.py`). A global `before_request` guard **denies any endpoint that is not registered** with the policy module, including static files and public pages. Evaluation order: global policies → RBAC (X ⇒ deny, no ABAC) → ABAC (deny-overrides, default deny, exception ⇒ deny). Matrix and ABAC assignment are configuration (`policy_config.yaml`), validated at start-up. |
| Attributes | Subject attributes (id, roles, seller verification, account status) are re-read from the DB on every request (`Subject.from_user`). Resource attributes come from DB rows loaded by the route's `loader`. Nothing is taken from the request. |
| Authentication | Argon2id hashes; dummy-hash verification for unknown emails (no user enumeration through timing); generic error messages; password policy (≥12 chars, 3 classes). |
| Sessions | Opaque 256-bit tokens, stored server-side as SHA-256 hashes; absolute (8 h) and idle (30 min) expiry; revoked on logout, password change and suspension; the user row is re-checked on every request, so **suspension takes effect immediately**. Browser: `HttpOnly; SameSite=Strict` cookie + synchronizer CSRF token (`X-CSRF-Token`). API clients: `Authorization: Bearer`. |
| Checkout | Server-side pricing from the DB; strict schema (unknown fields ⇒ 400); integer cents; Decimal half-up rounding; `SELECT … FOR UPDATE` on product and coupon rows for the whole checkout, gateway call included; stock and coupon usage change only in the same transaction that records the Paid order; DB CHECK and UNIQUE constraints as a backstop. |
| Payments | HMAC-SHA256 request signing (merchant authentication), timestamp + single-use nonce (anti-replay), HMAC-SHA256 response signing with a **different key** bound to the request nonce. The marketplace checks signature, freshness, amount, currency, idempotency key, charge-id format and charge-id uniqueness. Idempotency is enforced on both sides. |
| Orders | A single state-machine module; transitions use a conditional `UPDATE … WHERE status = <from>`, so steps cannot be skipped or repeated, even concurrently; P4 also enforces the state in the policy layer. Orders are only persisted as `paid` or `failed` (DB CHECK: no pending state). |
| Secrets | Generated randomly at first start (`scripts/gen_secrets.py`) into a Docker volume, mounted read-only; never in git. |
| Hardening | Strict CSP (`script-src 'self'`, no inline script), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on the API, 64 KB body limit, non-root containers, internal networks, no stack traces in responses. |
| Logging | JSON lines (stdout + file): logins and failures, every authz decision with the deciding policy, payments, order transitions, admin and finance operations, rate-limit hits, CSRF failures, gateway verification failures. JSON encoding prevents log injection. Secrets are never logged. |

## 4. Threat catalogue (STRIDE + business logic) with traceability

Legend: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege, **BL** business logic.

### 4.1 Business logic and payment integrity

| ID | Threat / abuse case | Cat. | Mitigation | Implementation | Verified by |
|---|---|---|---|---|---|
| T01 | Client sends a lower `price` / `total` / `discount` in the checkout request | T, BL | Strict allow-list schema rejects unknown fields; all amounts are computed from the DB | `validation.json_body`, `routes/buyer._load_cart_for_checkout`, `checkout._price_lines` | `test_checkout::test_client_cannot_send_prices_or_status`, `test_price_inside_items_rejected`; attack script #4 |
| T02 | Zero, negative, fractional, string or boolean quantities; quantity above stock | T, BL | Integers only (`bool` rejected), 1..1000, re-checked against **locked** stock | `checkout.parse_items`, `validation.as_int`, `checkout._price_lines` | `test_invalid_quantities`, `test_quantity_above_stock`; attack #5 |
| T03 | Same product split into several lines to bypass stock checks | BL | Duplicate product lines rejected | `checkout.parse_items` | `test_duplicate_lines_rejected` |
| T04 | Negative prices or amounts anywhere (product price, coupon amount, totals) | T, BL | Parsers reject negatives, NaN/Infinity, more than 2 decimals; DB CHECK constraints `>= 0` on all amounts | `money.parse_amount_to_cents`, `models` CHECKs | `test_product_price_validation`, `test_finance_coupon_validation`, `test_negative_stock_rejected` |
| T05 | Float rounding errors used to shave cents | T, BL | Integer cents everywhere; JSON floats are parsed as `Decimal`; percentage discount uses `Decimal` with `ROUND_HALF_UP` | `money.percentage_of`, `StrictJSONProvider` in `app/__init__.py` | `test_percentage_coupon_and_half_up_rounding` |
| T06 | Buying a Draft product | BL, E | Only `published` products can be priced; drafts return 404 like non-existent ones | `checkout._price_lines` | `test_draft_cannot_be_bought` |
| T07 | Cart mixing several sellers | BL | Exactly one seller per order | `checkout._price_lines` | `test_multi_seller_cart_rejected` |
| T08 | Seller buys own product (self-dealing, fake sales or ratings, coupon laundering) | BL, E | **P3** in the policy module, plus a re-check on the locked rows | `policies.p3_no_self_dealing`, `checkout._price_lines` | `test_policy_engine::test_p3_*`, `test_checkout::test_self_dealing_denied_p3`; attack #10 |
| T09 | Two buyers race for the last item (oversell) | T, BL | `SELECT … FOR UPDATE` on product rows (id order, no deadlock) during the whole checkout; stock decremented in the same transaction as the Paid order; CHECK `stock >= 0` | `checkout.load_products(lock=True)`, `checkout._locked_checkout` | `test_concurrent_checkouts_for_last_item`; attack #1 (PostgreSQL, 3 workers) |
| T10 | Two buyers race for a coupon's last use | T, BL | Coupon row locked `FOR UPDATE`; `used_count` incremented in the same transaction; CHECK `used_count <= max_uses` | `coupons.find_coupon(lock=True)` | `test_concurrent_last_coupon_use`; attack #2 |
| T11 | Same buyer reuses a coupon | BL | Redemption lookup plus UNIQUE `(coupon_id, user_id)` | `coupons.evaluate`, `CouponRedemption` constraint | `test_coupon_once_per_buyer`; attack #6 |
| T12 | Expired or not-yet-valid coupon; exhausted coupon | BL | Validity window and `max_uses` checks under lock | `coupons.evaluate` | `test_invalid_coupons_rejected_generically`, `test_single_use_coupon_global_limit` |
| T13 | Stacking several coupons | BL | Schema accepts a single `coupon_code` string | `checkout.parse_checkout` | `test_client_cannot_send_prices_or_status` (unknown fields) |
| T14 | Discount larger than the order total (negative total or credit) | BL | `discount = min(discount, subtotal)`; CHECK `discount <= subtotal`, `total = subtotal - discount` | `coupons.compute_discount`, `models.Order` | `test_fixed_discount_never_exceeds_total` |
| T15 | Coupon code brute force or enumeration | S, I | Rate limit (10/min per user); one generic error message for unknown/expired/used codes; real reason only in logs | `routes/buyer.validate_coupon`, `coupons.CouponError` | `test_coupon_bruteforce_limited`; attack #13 |
| T16 | Declined payment still decrements stock or consumes the coupon | BL | Changes are applied only on a verified approval; a Failed order is recorded with stock and coupon untouched | `checkout._locked_checkout` | `test_declined_card_failed_and_nothing_changes`; attack #11 |
| T17 | Double charge through double-click, retry or parallel duplicate requests | BL | Idempotency key claimed in its own transaction (UNIQUE `(user, key)`); concurrent duplicates get 409; later duplicates replay the original order; same key with a different cart gets 409; the gateway is also idempotent | `checkout.perform_checkout`, `IdempotencyRecord`, gateway `create_charge` | `test_idempotent_replay_does_not_charge_twice`, `test_idempotency_key_reuse_with_different_cart`, `gateway::test_idempotency`; attack #3 |
| T18 | One charge ID attached to several orders | T, BL | UNIQUE `orders.charge_id` and `payments.charge_id`, plus an explicit check before attaching | `checkout._locked_checkout`, `models` | `test_charge_id_attached_to_one_order_only` |
| T19 | Browser or attacker tells the server "payment succeeded" | S, T | No such endpoint exists. Only the server-side gateway call can produce Paid, and the DB requires a `charge_id` for non-failed orders | `routes/buyer.do_checkout`, CHECK `ck_order_paid_has_charge` | `test_no_endpoint_marks_order_paid` |
| T20 | Forged or modified gateway response (MITM turns Declined into Approved, changes the amount) | S, T | HMAC-SHA256 response signature with a separate key; amount, currency and idempotency key must equal the server's values | `gateway_client.GatewayClient._verify` | `test_tampered_gateway_response_never_paid` (4 variants), `test_amount_mismatch_with_valid_signature_rejected` |
| T21 | Replay of an old, validly signed "approved" response | S, T | Response signature covers the **request nonce** and a timestamp (5 min window) | `gateway_client._verify`, `gateway signing.response_canonical` | `test_replayed_old_approval_rejected` |
| T22 | Forged or replayed charge request to the gateway (fake merchant, modified amount) | S, T | Request HMAC over ts, nonce, method, path, body hash; merchant id check; 5 min window; each nonce usable once; strict body schema | `gateway_app.create_charge` | `gateway::test_bad_signature_rejected`, `test_unknown_merchant_rejected`, `test_stale_timestamp_rejected`, `test_replayed_nonce_rejected`, `test_body_tampering_breaks_signature`, `test_invalid_input` |
| T23 | Skipping or repeating order steps (Delivered without Shipped, shipping twice, shipping a Failed order) | T, BL | **P4** in the policy layer, plus an atomic conditional `UPDATE … WHERE status=<from>` in the single state-machine module; no other code writes `status` | `state_machine.transition`, `policies.p4_order_state` | `test_p4_*`, `test_order_workflow_full`, `test_failed_order_cannot_be_shipped`; attack #8 |
| T24 | Checkout or login flooding | D | Rate limits on login (IP and account), coupon validation, checkout and registration; Redis storage shared by all workers; body size limit | `extensions.limiter`, route decorators, `MAX_CONTENT_LENGTH` | `test_rate_limits.py` |

### 4.2 Access control (RBAC + ABAC)

| ID | Threat | Cat. | Mitigation | Implementation | Verified by |
|---|---|---|---|---|---|
| T30 | IDOR: buyer reads or acts on another buyer's order | I, E | **P1** ownership with `as: buyer` on every order action; list queries are scoped to the session user | `policies.p1_ownership`, `routes/buyer` | `test_p1_buyer_*`, `test_order_idor_between_buyers`; attack #7 |
| T31 | Seller edits, publishes or ships another seller's products or orders | T, E | P1 with `as: seller` | `routes/seller` loaders + config | `test_p1_seller_*`, `test_seller_cannot_touch_other_sellers_products`, `test_order_workflow_full` |
| T32 | Unverified seller publishes (directly, at create time, or by setting `status` through update) | E | **P2** on `product.create` (target status) and `product.publish`; `status` is not an updatable field | `policies.p2_seller_verification`, `routes/seller` | `test_p2_*`, `test_unverified_seller_cannot_publish_until_verified`, `test_seller_cannot_set_status_via_update` |
| T33 | Mass assignment: `roles`, `seller_id`, `status`, `buyer_id` in request bodies | E | Allow-list schemas everywhere; owner is always the session user | `validation.json_body` | `test_register_always_buyer`, `test_seller_cannot_spoof_owner` |
| T34 | Vertical escalation: buyer uses finance or admin APIs; admin creates coupons or views payments | E | RBAC matrix (X ⇒ deny without ABAC) | `engine._decide`, `policy_config.yaml` | `test_rbac_*`, `test_buyer_cannot_create_coupon`, `test_admin_cannot_view_payments_or_create_coupons`, `test_finance_cannot_admin` |
| T35 | Separation of duties: Admin or Finance also becomes Buyer or Seller; admin changes or suspends own account | E | RBAC (`seller.apply` is buyer-only); `User.add_role` and a `before_flush` listener refuse forbidden role combinations; no endpoint changes roles; admin cannot suspend or reactivate self | `models._roles_violate_sod`, `routes/admin.suspend_user` | `test_privileged_accounts_cannot_become_sellers`, `test_admin_cannot_apply_as_seller`, `test_sod_enforced_at_model_level`, `test_admin_cannot_suspend_self` |
| T36 | Route added without authorization (forgotten decorator) | E | Global guard denies undecorated endpoints (fail closed); a test asserts every endpoint is registered | `policy.enforce_route_registration` | `test_every_route_is_registered_with_policy_module`, `test_undecorated_route_fails_closed` |
| T37 | Policy error or misconfiguration allows access | E | Exceptions inside policies ⇒ deny; a C permission without policies ⇒ deny; unknown action ⇒ deny; invalid YAML refused at start-up | `engine._run`, `engine._validate` | `test_policy_exception_fails_closed`, `test_c_permission_without_policies_is_denied`, `test_unknown_action_default_deny`, `test_invalid_config_refused` |
| T38 | Client-controlled attributes used in decisions (e.g. `X-Role` header, `seller_status` in body) | E | Subject is built from the DB row on every request; resources from DB loaders | `Subject.from_user`, route loaders | design; `test_seller_cannot_spoof_owner` |
| T39 | Visitor reaches private functionality, or learns that drafts exist | E, I | `anonymous` pseudo-role allowed only for browse/search, register, login (plus static files and docs); drafts return 404 to non-owners; RBAC pre-check before resource lookup prevents probing IDs | config, `policy.authorize` | `test_anonymous_only_public`, `test_visitor_blocked_from_private_routes`, `test_visitor_sees_only_published`, `test_draft_visible_to_its_seller_only` |
| T40 | Admin acts with default credentials | E | Global policy `CREDENTIALS_CHANGE_REQUIRED` denies every admin action except `admin.change_credentials` until the email **and** password differ from the defaults | `policies.credentials_change_required` | `test_admin_must_change_credentials_first`, `test_admin_must_change_credentials_before_anything` |

### 4.3 Authentication, session and web threats

| ID | Threat | Cat. | Mitigation | Implementation | Verified by |
|---|---|---|---|---|---|
| T50 | Password guessing or credential stuffing | S | Rate limit per IP (10/min) and per account (5/min, 20/h); Argon2id; strong password policy | `routes/auth_routes.login`, `auth.verify_password`, `validation.validate_password` | `test_login_bruteforce_limited_per_account`, `test_weak_password_rejected` |
| T51 | User enumeration via login | I | Identical message for unknown email and wrong password; dummy Argon2 verification equalises timing | `auth.verify_password` | `test_failed_login_generic` |
| T52 | Suspended user keeps using an existing session | E | Account status re-read per request; all sessions revoked on suspension; global `ACCOUNT_ACTIVE` policy | `auth.load_request_user`, `routes/admin.suspend_user` | `test_suspension_kills_existing_sessions_immediately`, `test_suspended_account_denied_everything`, `test_suspended_cannot_login` |
| T53 | Session theft or fixation | S | Random server-side tokens issued at login (no fixation); only hashes stored; `HttpOnly`, `SameSite=Strict`, `Secure` when served over TLS; expiry; logout revokes | `auth.create_session`, `auth.set_session_cookies` | `test_session_cookie_flags`, `test_logout_revokes_token` |
| T54 | Stolen password: attacker keeps old sessions after the victim changes it | S | Password and credential change revokes all other sessions | `routes/auth_routes.change_password`, `routes/admin.change_credentials` | `test_password_change_revokes_other_sessions` |
| T55 | CSRF against cookie-authenticated state changes | T | Synchronizer token bound to the server-side session (`X-CSRF-Token`, constant-time compare) plus `SameSite=Strict`; Bearer requests are not ambient | `auth.load_request_user` | `test_cookie_session_requires_csrf_header` |
| T56 | Stored or reflected XSS (product names, addresses) stealing actions | T, E | Frontend only uses `textContent` and DOM APIs (no `innerHTML`); strict CSP without inline scripts; JSON API with `nosniff` | `static/js/common.js` (`el`), `app/__init__.py` headers | `test_security_headers` |
| T57 | SQL injection via search or IDs | T, I | ORM with bound parameters only; LIKE wildcards escaped; integer path converters | `routes/catalog.list_products` | `test_search_is_injection_safe` |
| T58 | Clickjacking | T | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'` | `app/__init__.py` | `test_security_headers` |
| T59 | Path traversal through docs assets or pages | I | Allow-listed file names; fixed page map | `routes/pages` | `test_docs_served` |
| T60 | Error messages leak internals (stack traces, SQL) | I | Global error handlers return generic JSON with a request id; details only in server logs | `_register_error_handlers` | `test_errors_do_not_leak_internals` |

### 4.4 Infrastructure, cryptography and repudiation

| ID | Threat | Cat. | Mitigation | Implementation |
|---|---|---|---|---|
| T70 | Secrets committed to git or shared between installations | I | Random secrets generated on first start into a Docker volume; mounted read-only; `.gitignore` | `scripts/gen_secrets.py`, `docker-compose.yml` |
| T71 | Direct access to DB, Redis or gateway from outside | S, T, I | Not published to the host; `internal: true` networks; the gateway is on a separate network shared only with the marketplace | `docker-compose.yml` |
| T72 | Container breakout impact | E | Services run as non-root `appuser` (uid 10001) | `Dockerfile`s |
| T73 | Weak password hashing | I | Argon2id (argon2-cffi, auto-rehash when parameters change) | `auth.py` |
| T74 | Timing attacks on signature or token comparison | I | `hmac.compare_digest` everywhere | `gateway_client`, `signing.verify`, `auth.load_request_user` |
| T75 | Repudiation: a user denies an action, or an attack goes unnoticed | R | Structured audit logs with request id, actor, IP, action, decision and policy; payment results, order transitions, admin and finance operations, login successes and failures, rate-limit and CSRF events | `audit.py` and calls throughout |
| T76 | Log injection or forging | T, R | JSON encoding with `ensure_ascii` (CR/LF escaped); secrets never logged | `audit.audit` |

## 5. Payment channel design (marketplace ↔ gateway)

Our approach follows the pattern used by real payment providers (Stripe webhook signatures, AWS SigV4 request
signing, idempotency keys):

1. **Request authentication and integrity.** `X-Signature = HMAC_SHA256(request_key, ts \n nonce \n METHOD \n path \n SHA256(body))`
   plus `X-Merchant-Id`. The gateway rejects an unknown merchant, a bad signature, |now − ts| > 300 s, or a reused nonce.
2. **Response authentication and integrity.** `X-Gateway-Signature = HMAC_SHA256(response_key, ts \n request_nonce \n http_status \n SHA256(body))`.
   A separate key prevents reflection. Binding to the request nonce prevents a recorded "approved" response
   from being replayed for a different request.
3. **Semantic verification.** Even with a valid signature, the marketplace marks an order Paid only if `status == approved`,
   `amount == server total`, `currency == USD`, `idempotency_key == ours`, the charge id is well formed, and the charge id is not
   already attached to another order. Anything else ⇒ order `failed`, payment `rejected`, plus a high-severity log entry.
4. **Idempotency.** The marketplace derives the gateway idempotency key from `(buyer, checkout key)`. The gateway returns the
   stored charge for a repeated key and 409 if the key is reused with different parameters.
5. **Network isolation.** The gateway is only reachable on an internal Docker network. In production the same
   protocol would run over mutual TLS, adding confidentiality and transport-level authentication.

## 6. Assumptions and residual risks

| Item | Notes |
|---|---|
| Gateway availability | As stated in the assignment, the gateway always responds (no timeouts). Row locks are held during the gateway call. With a slow gateway this would limit throughput; a production design would use reservations with expiry and a reconciliation job. |
| Charge approved, then local commit fails | Very unlikely (all validation happens before charging). The idempotency key is then "burned" and a critical log entry is written; a refund or reconciliation process would handle it in production. |
| TLS | Local deployment is plain HTTP on `127.0.0.1`. Set `SESSION_COOKIE_SECURE=true` behind a TLS reverse proxy (HSTS is then sent automatically). |
| Registration enumeration | `POST /api/auth/register` reveals that an email is taken (409). This is an accepted usability trade-off, mitigated by a 5/min rate limit. |
| Bearer tokens | Bearer tokens are intended for Swagger/Postman. The browser frontend never sees a token (HttpOnly cookie). |
| Demo credentials | Seeded passwords are public (README) by design of the assignment. The admin is forced to change them; other accounts are demo accounts. |
| SQLite fallback | Local development without Docker uses SQLite with a process-wide lock for checkout. The Docker deployment uses PostgreSQL row locks, which also work across the 3 gunicorn workers (verified by `scripts/attack_demo.py`). |

## 7. Requirements traceability matrix

| Requirement (assignment) | Implementation | Verification |
|---|---|---|
| 4 roles; Buyer+Seller dual role | `models.Role`, `UserRole`, `routes/auth_routes.apply_seller` | `test_self_dealing_denied_p3` (Sam buys from Vera) |
| Register as Buyer (name, email, phone, password) | `auth_routes.register` | `test_register_always_buyer` |
| Apply as Seller with store name, Unverified until verified | `auth_routes.apply_seller`, `admin.verify_seller` | `test_unverified_seller_cannot_publish_until_verified` |
| Finance accounts only via seed | `seed.py`; no endpoint creates them | `test_register_always_buyer` |
| Default admin must change email and password first | `CREDENTIALS_CHANGE_REQUIRED`, `admin.change_credentials` | `test_admin_must_change_credentials_before_anything` |
| Admin verifies sellers, suspends/reactivates; suspended sessions die immediately | `routes/admin.py`, `auth.load_request_user` | `test_suspension_kills_existing_sessions_immediately` |
| SoD: admin cannot change own role; admin and finance cannot be buyer or seller | `models._roles_violate_sod`, admin self-check | T35 tests |
| Products: name, description, price USD, stock, Draft/Published | `models.Product`, `routes/seller.py` | `test_unverified_seller_cannot_publish_until_verified` |
| Visitors browse and search Published; drafts only for their seller and not buyable | `routes/catalog.py`, `checkout._price_lines` | `test_visitor_sees_only_published`, `test_draft_visible_to_its_seller_only`, `test_draft_cannot_be_bought` |
| One seller per order | `checkout._price_lines` | `test_multi_seller_cart_rejected` |
| Checkout with address, optional coupon, card label; coupon preview | `routes/buyer.do_checkout`, `routes/buyer.validate_coupon` | `test_happy_path_paid`, `test_coupon_validate_changes_nothing` |
| Immediate payment: Paid or Failed, no pending state | `checkout._locked_checkout`, CHECK `ck_order_status` | `test_declined_card_failed_and_nothing_changes` |
| Gateway: separate service, one charge endpoint, TEST-APPROVE / TEST-DECLINE | `gateway/` | `gateway::test_approve_and_decline_labels` |
| Secure marketplace–gateway channel | §5 | T20–T22 tests |
| Buyers see own orders; sellers see orders for their products and ship with tracking | `routes/buyer.py`, `routes/seller.py` | `test_order_idor_between_buyers`, `test_seller_sees_only_own_orders`, `test_order_workflow_full` |
| Order state machine; no other transitions | `state_machine.py` | T23 tests |
| Coupons: code, type, validity dates, max uses, once per buyer, one per order, discount ≤ total | `coupons.py`, `routes/finance.create_coupon` | T10–T14 tests |
| Logging: logins, authz decisions with policy, payments and order changes, admin operations | `audit.py` | log output (README §4) |
| Server-side calculation | T01 | T01 tests |
| Valid inputs (positive integer quantities ≤ stock, no negative amounts) | T02, T04 | T02, T04 tests |
| Integer cents, half-up rounding | T05 | `test_percentage_coupon_and_half_up_rounding` |
| Atomic checkout; no double sale or double coupon use | T09, T10, T16 | race tests + attack script |
| No double charging; a charge ID on one order only | T17, T18 | T17, T18 tests |
| Payment verification: signature, amount, currency; browser never reports success | T19–T21 | T19–T21 tests |
| Workflow cannot be skipped or repeated | T23 | T23 tests |
| Rate limits on login, coupon validation, checkout | T24, T50, T15 | `test_rate_limits.py` |
| RBAC check first (X ⇒ no ABAC), ABAC for C | `engine._decide` | `test_rbac_x_denies_without_abac` |
| Default deny, deny overrides | `engine._decide` | `test_unknown_action_default_deny`, `test_deny_overrides` |
| Attributes only from DB or session | `Subject.from_user`, loaders | T38 |
| Policies P1–P4 | `policies.py` + `policy_config.yaml` | allow + deny tests for each in `test_policy_engine.py` |
| One central policy module; every route calls it (including public routes) | `policy/engine.py`, `@authorize`, route guard | `test_every_route_is_registered_with_policy_module` |
| Matrix and ABAC assignment in configuration | `policy_config.yaml` | `test_matrix_is_configuration_driven` |
| Fail closed | `engine._run` | `test_policy_exception_fails_closed` |
| Automated authz tests (allow + deny per policy) | `tests/test_policy_engine.py` | — |
| Flask backend; own policy, checkout and coupon code | `marketplace/app` | — |
| Web UI for Buyer and Seller; API-only Admin and Finance | `static/`, Swagger UI | — |
| Two services with separate DBs; single-command start | `docker-compose.yml` | `docker compose up --build` |
| Seed script (finance, buyer, verified and unverified seller, products, valid, expired and single-use coupons) | `seed.py`, README §2 | — |
| OpenAPI for every endpoint | `app/openapi.yaml`, `/api/docs` | `test_every_route_documented` |
