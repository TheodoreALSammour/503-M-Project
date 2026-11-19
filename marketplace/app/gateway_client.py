"""Client for the Payment Gateway Simulator.

Securing the marketplace <-> gateway channel:

* Request authentication: HMAC-SHA256 over timestamp, nonce, method, path and
  the SHA-256 of the body, with a shared *request key* (like Stripe / AWS
  SigV4 style request signing). The gateway rejects unsigned, modified,
  stale (> 5 min) or replayed (nonce reuse) requests.
* Response authentication: the gateway signs (timestamp, OUR request nonce,
  HTTP status, body hash) with a separate *response key*. We verify:
    - the signature (constant-time compare),
    - freshness of the timestamp,
    - that the response is bound to the nonce of THIS request,
    - that amount, currency and idempotency key equal what we asked for,
    - that the status is one of approved / declined and the charge id is well formed.
  Anything else is treated as a failed payment ("rejected"). The browser is
  never involved: it cannot tell the server that a payment succeeded.
* Idempotency key per checkout, so retries can never create a second charge.
* Keys are generated randomly at first start (scripts/gen_secrets.py) and
  shared through a Docker volume; they are never committed to git.
* In production the channel would additionally run over (mutual) TLS; inside
  the isolated Docker network the gateway is not published to the host.
"""
import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass

import requests
from flask import current_app

CHARGE_PATH = "/v1/charges"
CHARGE_ID_RE = re.compile(r"^ch_[a-f0-9]{24}$")


@dataclass
class ChargeResult:
    outcome: str  # approved | declined | rejected
    charge_id: str | None
    verified: bool
    detail: str


def _digest(body):
    return hashlib.sha256(body).hexdigest()


def _sign(key, message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _requests_transport(method, url, headers, body):
    resp = requests.request(method, url, headers=headers, data=body, timeout=10,
                            allow_redirects=False)
    return resp.status_code, dict(resp.headers), resp.content


class GatewayClient:
    def __init__(self, base_url, merchant_id, request_key, response_key, max_age=300, transport=None):
        if not request_key or not response_key:
            raise RuntimeError("Gateway signing keys are not configured (fail closed).")
        self.base_url = base_url.rstrip("/")
        self.merchant_id = merchant_id
        self.request_key = request_key.encode()
        self.response_key = response_key.encode()
        self.max_age = max_age
        self.transport = transport or _requests_transport

    def charge(self, card_label, amount_cents, currency, idempotency_key):
        payload = {"card_label": card_label, "amount": int(amount_cents), "currency": currency,
                   "idempotency_key": idempotency_key}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ts = str(int(time.time()))
        nonce = secrets.token_hex(16)
        canonical = "\n".join([ts, nonce, "POST", CHARGE_PATH, _digest(body)]).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Merchant-Id": self.merchant_id,
            "X-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Signature": _sign(self.request_key, canonical),
        }
        status, resp_headers, resp_body = self.transport("POST", self.base_url + CHARGE_PATH, headers, body)
        return self._verify(status, resp_headers, resp_body, nonce, payload)

    def _verify(self, status, headers, body, nonce, sent):
        h = {k.lower(): v for k, v in (headers or {}).items()}
        ts = h.get("x-gateway-timestamp", "")
        sig = h.get("x-gateway-signature", "")
        if not ts.isdigit() or not sig:
            return ChargeResult("rejected", None, False, "missing gateway signature")
        if abs(int(time.time()) - int(ts)) > self.max_age:
            return ChargeResult("rejected", None, False, "stale gateway response")
        canonical = "\n".join([ts, nonce, str(status), _digest(body)]).encode()
        if not hmac.compare_digest(_sign(self.response_key, canonical), sig):
            return ChargeResult("rejected", None, False, "invalid gateway signature")
        # Signature valid from here on.
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return ChargeResult("rejected", None, True, "malformed gateway body")
        if status != 200 or not isinstance(data, dict):
            code = data.get("error") if isinstance(data, dict) else "unknown"
            return ChargeResult("rejected", None, True, f"gateway error: {code}"[:120])
        charge_id = data.get("charge_id")
        outcome = data.get("status")
        amount = data.get("amount")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount != sent["amount"]:
            return ChargeResult("rejected", None, True, "amount mismatch")
        if data.get("currency") != sent["currency"]:
            return ChargeResult("rejected", None, True, "currency mismatch")
        if data.get("idempotency_key") != sent["idempotency_key"]:
            return ChargeResult("rejected", None, True, "idempotency key mismatch")
        if not isinstance(charge_id, str) or not CHARGE_ID_RE.match(charge_id):
            return ChargeResult("rejected", None, True, "malformed charge id")
        if outcome == "approved":
            return ChargeResult("approved", charge_id, True, "approved")
        if outcome == "declined":
            return ChargeResult("declined", charge_id, True, str(data.get("decline_reason") or "declined")[:64])
        return ChargeResult("rejected", None, True, "unknown charge status")


def get_client():
    client = current_app.extensions.get("gateway_client")
    if client is None:
        cfg = current_app.config
        client = GatewayClient(cfg["GATEWAY_URL"], cfg["GATEWAY_MERCHANT_ID"], cfg["GATEWAY_REQUEST_KEY"],
                               cfg["GATEWAY_RESPONSE_KEY"], cfg["GATEWAY_RESPONSE_MAX_AGE_SECONDS"])
        current_app.extensions["gateway_client"] = client
    return client
