"""Generate random secrets on first start (run by the `secrets-init` service).

Secrets live in a Docker volume shared read-only with the services that need
them. Nothing secret is committed to git, and every installation gets its own
keys. Existing files are never overwritten (keys are stable across restarts).
"""
import os
import secrets
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/secrets"
NAMES = ["db_password", "marketplace_secret_key", "gateway_request_key", "gateway_response_key"]

os.makedirs(TARGET, exist_ok=True)
for name in NAMES:
    path = os.path.join(TARGET, name)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        print(f"{name}: exists")
        continue
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(secrets.token_hex(32))
    # Readable by the unprivileged service users (postgres uid 70, app uid 10001)
    # that mount this volume read-only; the volume is not mounted anywhere else.
    os.chmod(path, 0o644)
    print(f"{name}: generated")
