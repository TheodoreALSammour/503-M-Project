"""HMAC-SHA256 message signing between the marketplace and the gateway.

Two *different* keys are used, one per direction:

* ``request key``  - the marketplace signs every charge request with it, so the
  gateway knows the request really comes from the registered merchant and was
  not modified in transit.
* ``response key`` - the gateway signs every response with it, so the
  marketplace can verify the Approved/Declined verdict. Using a separate key
  prevents reflection attacks (replaying a signed request as if it were a
  signed response).

Each signature covers a timestamp and a single-use nonce, so a captured
message cannot be replayed later. The response signature also covers the
*request's* nonce, which ties every response to exactly one request: an old
"Approved" response cannot be swapped in for a new request.
"""
import hashlib
import hmac


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def request_canonical(timestamp: str, nonce: str, method: str, path: str, body: bytes) -> bytes:
    return "\n".join([timestamp, nonce, method.upper(), path, body_digest(body)]).encode()


def response_canonical(timestamp: str, request_nonce: str, status_code: int, body: bytes) -> bytes:
    return "\n".join([timestamp, request_nonce, str(status_code), body_digest(body)]).encode()


def sign(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify(key: bytes, message: bytes, signature: str) -> bool:
    if not signature or not isinstance(signature, str):
        return False
    expected = sign(key, message)
    # Constant-time comparison to avoid timing side channels.
    return hmac.compare_digest(expected, signature)
