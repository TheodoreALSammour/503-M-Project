"""Policy enforcement point (PEP) helpers.

``@authorize("action", loader=...)`` must decorate EVERY view function. A
global ``before_request`` guard (``enforce_route_registration``) denies any
request whose endpoint is not decorated, so no route can skip the check.
"""
from functools import wraps

from flask import abort, current_app, g, request

from ..audit import audit
from .engine import Decision, PolicyEngine, Subject  # noqa: F401
from .policies import CheckoutResource, NewProduct, OwnerScope  # noqa: F401

POLICY_ATTR = "_policy_action"


def engine():
    return current_app.extensions["policy_engine"]


def current_subject():
    return Subject.from_user(getattr(g, "user", None))


def check(action, resource=None):
    """Evaluate and enforce. Aborts with 401 (anonymous) or 403."""
    subject = current_subject()
    decision = engine().authorize(subject, action, resource)
    if not decision.allowed:
        g.authz_denied = decision
        abort(401 if subject.is_anonymous else 403)
    return decision


def is_allowed(action, resource=None):
    """Evaluate without aborting (still logged)."""
    return engine().authorize(current_subject(), action, resource).allowed


def authorize(action, loader=None):
    """Decorator: load the resource from the DB (optional) then enforce."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            resource = None
            if loader is not None:
                # 1. RBAC pre-check before touching the request body or the DB,
                #    so callers whose role can never act get 401/403 straight away.
                subject = current_subject()
                if not engine().authorize(subject, action, None, rbac_only=True).allowed:
                    abort(401 if subject.is_anonymous else 403)
                # 2. Load the resource attributes from the database.
                resource = loader(**kwargs)
                if resource is None:
                    abort(404)
            # 3. Full decision (global + RBAC + ABAC) on the loaded resource.
            check(action, resource)
            g.resource = resource
            return fn(*args, **kwargs)
        setattr(wrapper, POLICY_ATTR, action)
        return wrapper
    return decorator


def enforce_route_registration():
    """before_request: fail closed for any endpoint that bypasses the PEP."""
    endpoint = request.endpoint
    if endpoint is None:
        return  # 404 / 405 handled by Flask
    view = current_app.view_functions.get(endpoint)
    if view is None or not getattr(view, POLICY_ATTR, None):
        audit("authz.decision", decision="deny", action=f"endpoint:{endpoint}",
              policy="ROUTE_NOT_REGISTERED", reason="route has no policy action (fail closed)")
        abort(403)
