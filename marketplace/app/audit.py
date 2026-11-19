"""Security / audit logging.

Structured JSON lines are written to stdout (``docker compose logs``) and to
``$LOG_DIR/security.log``. Logged events include logins and failed logins,
every authorization decision with the deciding policy, every payment and
order state change, and every admin / finance operation.

Secrets (passwords, session tokens, signing keys) are never logged. Values
derived from user input are JSON-encoded, which neutralises log injection
(CR/LF cannot forge extra log lines).
"""
import json
import logging
import os
import sys
import uuid

from flask import g, has_request_context, request

from .models import utcnow

_logger = logging.getLogger("marketplace.audit")


def setup_logging(app):
    _logger.setLevel(logging.INFO)
    _logger.propagate = False
    for h in list(_logger.handlers):
        _logger.removeHandler(h)
    fmt = logging.Formatter("%(message)s")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    _logger.addHandler(stream)
    log_dir = app.config.get("LOG_DIR")
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            fh = logging.FileHandler(os.path.join(log_dir, "security.log"), encoding="utf-8")
            fh.setFormatter(fmt)
            _logger.addHandler(fh)
        except OSError:
            _logger.warning("could not open log file in %s", log_dir)


def request_id():
    if not has_request_context():
        return None
    rid = getattr(g, "request_id", None)
    if rid is None:
        rid = g.request_id = uuid.uuid4().hex[:16]
    return rid


def audit(event, **fields):
    record = {"ts": utcnow().isoformat() + "Z", "service": "marketplace", "event": event}
    if has_request_context():
        user = getattr(g, "user", None)
        record.update({
            "request_id": request_id(),
            "ip": request.remote_addr,
            "method": request.method,
            "path": request.path,
            "actor_id": user.id if user is not None else None,
        })
    record.update(fields)
    _logger.info(json.dumps(record, default=str, ensure_ascii=True))
