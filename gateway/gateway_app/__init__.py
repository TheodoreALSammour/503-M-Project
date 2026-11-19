"""Payment Gateway Simulator.

A separate service with its own database. It exposes one business endpoint,
``POST /v1/charges``. Card label ``TEST-APPROVE`` is approved, everything else
(including ``TEST-DECLINE``) is declined.

Security controls:
* every request must carry a valid HMAC signature from the merchant
  (authenticity + integrity), a fresh timestamp and an unused nonce (replay
  protection);
* strict input validation (integer amounts only, no negatives, known currency);
* idempotency: the same idempotency key always returns the same charge, and a
  key reused with different parameters is rejected (no double charging);
* every response is signed with a separate response key.
"""
import json
import logging
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone

from flask import Flask, Response, g, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError

from . import signing

db = SQLAlchemy()

APPROVE_LABEL = "TEST-APPROVE"
DECLINE_LABEL = "TEST-DECLINE"
SUPPORTED_CURRENCIES = {"USD"}
MAX_AMOUNT_CENTS = 100_000_000  # $1,000,000.00
TIMESTAMP_TOLERANCE_SECONDS = 300
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9_.:\-]{8,128}$")
NONCE_RE = re.compile(r"^[A-Fa-f0-9]{32,64}$")
CARD_LABEL_RE = re.compile(r"^[A-Z0-9\-]{1,32}$")

log = logging.getLogger("gateway.audit")


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Charge(db.Model):
    __tablename__ = "charges"
    id = db.Column(db.Integer, primary_key=True)
    charge_id = db.Column(db.String(40), unique=True, nullable=False)
    merchant_id = db.Column(db.String(64), nullable=False)
    idempotency_key = db.Column(db.String(128), nullable=False)
    amount_cents = db.Column(db.BigInteger, nullable=False)
    currency = db.Column(db.String(3), nullable=False)
    card_label = db.Column(db.String(32), nullable=False)
    status = db.Column(db.String(16), nullable=False)
    decline_reason = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    __table_args__ = (
        db.UniqueConstraint("merchant_id", "idempotency_key", name="uq_charge_idempotency"),
        db.CheckConstraint("amount_cents >= 0", name="ck_charge_amount_nonneg"),
        db.CheckConstraint("status IN ('approved','declined')", name="ck_charge_status"),
    )


class UsedNonce(db.Model):
    __tablename__ = "used_nonces"
    nonce = db.Column(db.String(64), primary_key=True)
    seen_at = db.Column(db.Integer, nullable=False)


def _read_secret(name):
    path = os.environ.get(f"{name}_FILE")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(name)


def _setup_logging(app):
    log.setLevel(logging.INFO)
    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(handler)
        log_dir = app.config.get("LOG_DIR")
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            fh = logging.FileHandler(os.path.join(log_dir, "gateway.log"), encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(message)s"))
            log.addHandler(fh)
    log.propagate = False


def audit(event, **fields):
    record = {"ts": _utcnow().isoformat() + "Z", "service": "gateway", "event": event}
    record.update(fields)
    log.info(json.dumps(record, default=str))


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=os.environ.get("GATEWAY_DATABASE_URL", "sqlite:///gateway.db"),
        SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 30}} if os.environ.get(
            "GATEWAY_DATABASE_URL", "sqlite").startswith("sqlite") else {},
        MERCHANT_ID=os.environ.get("GATEWAY_MERCHANT_ID", "marketplace"),
        REQUEST_KEY=_read_secret("GATEWAY_REQUEST_KEY"),
        RESPONSE_KEY=_read_secret("GATEWAY_RESPONSE_KEY"),
        LOG_DIR=os.environ.get("LOG_DIR"),
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)
    if not app.config["REQUEST_KEY"] or not app.config["RESPONSE_KEY"]:
        raise RuntimeError("Gateway signing keys are not configured (fail closed).")
    if len(app.config["REQUEST_KEY"]) < 32 or len(app.config["RESPONSE_KEY"]) < 32:
        raise RuntimeError("Gateway signing keys are too short.")

    db.init_app(app)
    _setup_logging(app)
    with app.app_context():
        db.create_all()

    request_key = app.config["REQUEST_KEY"].encode()
    response_key = app.config["RESPONSE_KEY"].encode()

    def signed_response(payload, status_code):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ts = str(int(time.time()))
        req_nonce = getattr(g, "request_nonce", "") or ""
        sig = signing.sign(response_key, signing.response_canonical(ts, req_nonce, status_code, body))
        resp = Response(body, status=status_code, mimetype="application/json")
        resp.headers["X-Gateway-Timestamp"] = ts
        resp.headers["X-Gateway-Signature"] = sig
        return resp

    def error(code, message, status_code):
        return signed_response({"error": code, "message": message}, status_code)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/openapi.yaml")
    def openapi():
        return send_from_directory(os.path.dirname(os.path.dirname(__file__)), "openapi.yaml",
                                   mimetype="application/yaml")

    @app.post("/v1/charges")
    def create_charge():
        raw = request.get_data(cache=True)
        merchant = request.headers.get("X-Merchant-Id", "")
        ts = request.headers.get("X-Timestamp", "")
        nonce = request.headers.get("X-Nonce", "")
        sig = request.headers.get("X-Signature", "")
        g.request_nonce = nonce if NONCE_RE.match(nonce or "") else ""

        # 1. Authenticate the merchant and verify message integrity.
        if merchant != app.config["MERCHANT_ID"]:
            audit("charge.rejected", reason="unknown_merchant")
            return error("unauthorized", "Unknown merchant.", 401)
        if not ts.isdigit() or not g.request_nonce:
            audit("charge.rejected", reason="missing_auth_headers")
            return error("unauthorized", "Missing or malformed authentication headers.", 401)
        if abs(int(time.time()) - int(ts)) > TIMESTAMP_TOLERANCE_SECONDS:
            audit("charge.rejected", reason="stale_timestamp")
            return error("unauthorized", "Request timestamp outside the allowed window.", 401)
        canonical = signing.request_canonical(ts, nonce, request.method, request.path, raw)
        if not signing.verify(request_key, canonical, sig):
            audit("charge.rejected", reason="bad_signature")
            return error("unauthorized", "Invalid request signature.", 401)

        # 2. Replay protection: every nonce may be used exactly once.
        cutoff = int(time.time()) - 2 * TIMESTAMP_TOLERANCE_SECONDS
        UsedNonce.query.filter(UsedNonce.seen_at < cutoff).delete()
        db.session.add(UsedNonce(nonce=nonce.lower(), seen_at=int(time.time())))
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            audit("charge.rejected", reason="replayed_nonce")
            return error("unauthorized", "Nonce already used (replay).", 401)

        # 3. Strict input validation.
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return error("invalid_request", "Body must be JSON.", 400)
        if not isinstance(data, dict) or set(data) != {"card_label", "amount", "currency", "idempotency_key"}:
            return error("invalid_request",
                         "Body must contain exactly card_label, amount, currency, idempotency_key.", 400)
        amount = data["amount"]
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0 or amount > MAX_AMOUNT_CENTS:
            return error("invalid_request", "amount must be a non-negative integer number of cents.", 400)
        currency = data["currency"]
        if currency not in SUPPORTED_CURRENCIES:
            return error("invalid_request", "Unsupported currency.", 400)
        card_label = data["card_label"]
        if not isinstance(card_label, str) or not CARD_LABEL_RE.match(card_label):
            return error("invalid_request", "Malformed card label.", 400)
        idem = data["idempotency_key"]
        if not isinstance(idem, str) or not IDEMPOTENCY_KEY_RE.match(idem):
            return error("invalid_request", "Malformed idempotency key.", 400)

        # 4. Idempotency: same key -> same charge; same key + different params -> conflict.
        existing = Charge.query.filter_by(merchant_id=merchant, idempotency_key=idem).first()
        if existing is None:
            if card_label == APPROVE_LABEL:
                status, reason = "approved", None
            elif card_label == DECLINE_LABEL:
                status, reason = "declined", "card_declined"
            else:
                status, reason = "declined", "unknown_test_card"
            charge = Charge(charge_id="ch_" + secrets.token_hex(12), merchant_id=merchant,
                            idempotency_key=idem, amount_cents=amount, currency=currency,
                            card_label=card_label, status=status, decline_reason=reason)
            db.session.add(charge)
            try:
                db.session.commit()
                audit("charge.created", charge_id=charge.charge_id, status=status, amount=amount,
                      currency=currency, idempotency_key=idem)
            except IntegrityError:
                db.session.rollback()
                existing = Charge.query.filter_by(merchant_id=merchant, idempotency_key=idem).first()
                charge = None
        else:
            charge = None

        if charge is None:
            if (existing.amount_cents, existing.currency, existing.card_label) != (amount, currency, card_label):
                audit("charge.rejected", reason="idempotency_key_reuse_mismatch", idempotency_key=idem)
                return error("idempotency_conflict",
                             "Idempotency key already used with different parameters.", 409)
            audit("charge.replayed", charge_id=existing.charge_id, idempotency_key=idem)
            charge = existing

        return signed_response({
            "charge_id": charge.charge_id,
            "status": charge.status,
            "amount": charge.amount_cents,
            "currency": charge.currency,
            "idempotency_key": charge.idempotency_key,
            "decline_reason": charge.decline_reason,
            "created_at": charge.created_at.isoformat() + "Z",
        }, 200)

    @app.errorhandler(404)
    def not_found(_e):
        return error("not_found", "Not found.", 404)

    @app.errorhandler(405)
    def method_not_allowed(_e):
        return error("method_not_allowed", "Method not allowed.", 405)

    @app.errorhandler(413)
    def too_large(_e):
        return error("too_large", "Request body too large.", 413)

    @app.errorhandler(500)
    def internal(_e):
        return error("internal_error", "Internal error.", 500)

    return app
