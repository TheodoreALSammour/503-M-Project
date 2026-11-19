"""Multi-Vendor Marketplace - application factory."""
import json
import secrets
from decimal import Decimal

from flask import Flask, g, jsonify, request
from flask.json.provider import DefaultJSONProvider
from werkzeug.exceptions import HTTPException

from .audit import audit, request_id, setup_logging
from .auth import CSRFError, load_request_user
from .checkout import CheckoutError
from .config import Config
from .extensions import db, limiter
from .models import SeparationOfDutiesError
from .policy import authorize, enforce_route_registration
from .policy.engine import PolicyEngine
from .state_machine import InvalidTransition
from .validation import ValidationError


def _reject_constant(name):
    raise ValueError(f"invalid JSON constant {name}")


class StrictJSONProvider(DefaultJSONProvider):
    """Parse JSON numbers with a fraction as Decimal (never float) and reject
    NaN / Infinity."""
    def loads(self, s, **kwargs):
        kwargs.setdefault("parse_float", Decimal)
        kwargs.setdefault("parse_constant", _reject_constant)
        return json.loads(s, **kwargs)


CSP_DEFAULT = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
               "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
               "frame-ancestors 'none'; form-action 'self'")
# Swagger UI injects inline styles; scripts remain 'self' only.
CSP_DOCS = CSP_DEFAULT.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")


def create_app(overrides=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.from_object(Config)
    if overrides:
        app.config.update(overrides)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = secrets.token_hex(32)
    app.json = StrictJSONProvider(app)

    setup_logging(app)
    db.init_app(app)
    app.extensions["policy_engine"] = PolicyEngine.from_file(app.config["POLICY_CONFIG_PATH"])

    # --- request pipeline (order matters: identify the user BEFORE the rate
    #     limiter runs, so per-user limits work) -------------------------------
    @app.before_request
    def _identify():
        request_id()
        load_request_user()

    @app.before_request
    def _route_guard():
        enforce_route_registration()

    limiter.init_app(app)

    from .routes import admin, auth_routes, buyer, catalog, finance, pages, seller
    for module in (auth_routes, catalog, buyer, seller, finance, admin, pages):
        app.register_blueprint(module.bp)

    # Even static files go through the policy module.
    app.view_functions["static"] = authorize("static.read")(app.view_functions["static"])

    @app.after_request
    def _security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP_DOCS if request.path.startswith("/api/docs") else CSP_DEFAULT
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/") and not request.path.startswith("/api/docs"):
            resp.headers["Cache-Control"] = "no-store"
        resp.headers.pop("Server", None)
        return resp

    _register_error_handlers(app)
    _register_cli(app)
    return app


def _error(status, code, message, **extra):
    body = {"error": code, "message": message, "request_id": getattr(g, "request_id", None)}
    body.update(extra)
    return jsonify(body), status


def _register_error_handlers(app):
    @app.errorhandler(ValidationError)
    def _validation(e):
        return _error(400, "validation_error", e.message, field=e.field)

    @app.errorhandler(CheckoutError)
    def _checkout(e):
        return _error(e.status, "checkout_error", e.message)

    @app.errorhandler(InvalidTransition)
    def _transition(_e):
        return _error(409, "invalid_transition", "This action is not allowed in the order's current state.")

    @app.errorhandler(SeparationOfDutiesError)
    def _sod(_e):
        db.session.rollback()
        return _error(403, "forbidden", "Separation of duties: this account cannot hold that role.")

    @app.errorhandler(CSRFError)
    def _csrf(_e):
        return _error(403, "csrf_failed", "Missing or invalid CSRF token.")

    @app.errorhandler(HTTPException)
    def _http(e):
        messages = {
            400: "Bad request.", 401: "Authentication required.", 403: "You are not allowed to do this.",
            404: "Not found.", 405: "Method not allowed.", 413: "Request body too large.",
            429: "Too many requests. Slow down.",
        }
        if e.code == 429:
            audit("ratelimit.exceeded", limit=str(e.description))
        return _error(e.code or 500, (e.name or "error").lower().replace(" ", "_"),
                      messages.get(e.code, e.description or "Error."))

    @app.errorhandler(Exception)
    def _unhandled(e):
        db.session.rollback()
        audit("error.unhandled", error=type(e).__name__)
        app.logger.exception("Unhandled error")
        # Never leak stack traces or internals to the client.
        return _error(500, "internal_error", "An internal error occurred.")


def _register_cli(app):
    @app.cli.command("init-db")
    def init_db():
        db.create_all()
        print("database initialised")

    @app.cli.command("seed")
    def seed_cmd():
        from .seed import seed
        db.create_all()
        seed()
