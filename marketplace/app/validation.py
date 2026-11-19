"""Small, strict input validation helpers (allow-list based)."""
import re

from flask import request

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 \-]{6,19}$")
NAME_RE = re.compile(r"^[^\x00-\x1f<>]{2,120}$")
CARD_LABEL_RE = re.compile(r"^[A-Z0-9\-]{1,32}$")
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9\-]{16,64}$")
COUPON_CODE_RE = re.compile(r"^[A-Z0-9\-]{3,32}$")
TRACKING_RE = re.compile(r"^[A-Za-z0-9\-]{6,64}$")
STORE_NAME_RE = re.compile(r"^[^\x00-\x1f<>]{2,80}$")


class ValidationError(Exception):
    def __init__(self, message, field=None):
        super().__init__(message)
        self.message = message
        self.field = field


def json_body(allowed, required=()):
    """Return the JSON object body. Unknown fields are REJECTED so a client can
    never smuggle in extra attributes (e.g. ``price``, ``total``, ``role``,
    ``seller_id``, ``status``)."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        raise ValidationError("Request body must be a JSON object.")
    unknown = set(body) - set(allowed)
    if unknown:
        raise ValidationError(f"Unknown field(s): {', '.join(sorted(unknown))}", field=sorted(unknown)[0])
    for f in required:
        if f not in body or body[f] is None:
            raise ValidationError(f"Field '{f}' is required.", field=f)
    return body


def get_str(body, key, *, min_len=1, max_len=255, pattern=None, required=True, strip=True):
    value = body.get(key)
    if value is None:
        if required:
            raise ValidationError(f"Field '{key}' is required.", field=key)
        return None
    if not isinstance(value, str):
        raise ValidationError(f"Field '{key}' must be a string.", field=key)
    if strip:
        value = value.strip()
    if "\x00" in value:
        raise ValidationError(f"Field '{key}' contains invalid characters.", field=key)
    if len(value) < min_len or len(value) > max_len:
        raise ValidationError(f"Field '{key}' must be {min_len}-{max_len} characters.", field=key)
    if pattern is not None and not pattern.match(value):
        raise ValidationError(f"Field '{key}' has an invalid format.", field=key)
    return value


def get_int(body, key, *, min_value=None, max_value=None, required=True):
    value = body.get(key)
    if value is None:
        if required:
            raise ValidationError(f"Field '{key}' is required.", field=key)
        return None
    return as_int(value, key, min_value=min_value, max_value=max_value)


def as_int(value, name, *, min_value=None, max_value=None):
    # bool is a subclass of int in Python - reject it explicitly. Floats and
    # numeric strings are rejected too: quantities must be real integers.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"'{name}' must be an integer.", field=name)
    if min_value is not None and value < min_value:
        raise ValidationError(f"'{name}' must be >= {min_value}.", field=name)
    if max_value is not None and value > max_value:
        raise ValidationError(f"'{name}' must be <= {max_value}.", field=name)
    return value


def validate_password(password, email=None):
    if not isinstance(password, str) or len(password) < 12 or len(password) > 128:
        raise ValidationError("Password must be 12-128 characters.", field="password")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes < 3:
        raise ValidationError(
            "Password must contain at least 3 of: lowercase, uppercase, digit, symbol.", field="password")
    if email and email.split("@")[0].lower() in password.lower():
        raise ValidationError("Password must not contain your email name.", field="password")
    return password


def query_int(name, default, *, min_value, max_value):
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default
    if not re.fullmatch(r"\d{1,9}", raw):
        raise ValidationError(f"Query parameter '{name}' must be a positive integer.", field=name)
    value = int(raw)
    if value < min_value or value > max_value:
        raise ValidationError(f"Query parameter '{name}' out of range.", field=name)
    return value


def empty_body():
    """For action endpoints that take no input: accept no body or ``{}`` only."""
    if not request.get_data(cache=True).strip():
        return {}
    return json_body(set())
