#!/usr/bin/env python3
"""Generate (once) and persist the Vaultwarden ADMIN_TOKEN.

The admin panel (/admin) is gated by Vaultwarden's ADMIN_TOKEN. We generate
a strong random token on first boot and persist it to
``$OPENHOST_APP_DATA_DIR/admin_token.txt`` (mode 0600). The auth-proxy reads
it at runtime to mint a VW_ADMIN session for the zone owner (Pattern B1), so
the owner never has to see or type the token.

CREDENTIAL LEAK NOTE
====================

This file holds a usable admin credential in cleartext. Any other OpenHost
app granted ``access_all_app_data`` / ``access_all_data`` (e.g. a
file-browser) could read it. This is the inherent trade-off of Pattern B1:
the auth-proxy needs the token at runtime to re-mint sessions after a
restart. Vaultwarden has no trusted-header (REMOTE_USER) admin auth, so a
zero-on-disk-credential design would mean Pattern E (no SSO; the operator
sets the token by hand and logs in manually).

We store the RAW token (not an Argon2 PHC hash): the proxy must present the
literal token to ``POST /admin/`` to log in, and ``start.sh`` exports the
same value as ``ADMIN_TOKEN`` so Vaultwarden accepts it. Vaultwarden does
support hashed ADMIN_TOKENs, but a hash here would defeat the auto-login
(the proxy cannot reverse it), so raw-on-disk is required for SSO.

Generation is idempotent: if the file already exists non-empty, this is a
no-op, so a container restart never rotates the token and invalidates the
owner's active admin session.
"""

from __future__ import annotations

import logging
import os
import secrets
import sys

logging.basicConfig(
    level=logging.INFO,
    format="[bootstrap] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("bootstrap")


def main() -> int:
    data_dir = os.environ.get("OPENHOST_APP_DATA_DIR", "/data/app_data/vaultwarden")
    token_file = os.environ.get("AUTH_PROXY_TOKEN_FILE") or os.path.join(data_dir, "admin_token.txt")

    try:
        os.makedirs(data_dir, mode=0o755, exist_ok=True)
    except OSError as exc:
        log.error("could not create data dir %s: %s", data_dir, exc)
        return 1

    if os.path.exists(token_file):
        try:
            with open(token_file, encoding="utf-8") as fh:
                existing = fh.read().strip()
        except OSError as exc:
            log.error("could not read existing %s: %s", token_file, exc)
            return 1
        if existing:
            log.info("ADMIN_TOKEN already persisted at %s; skipping rotation", token_file)
            try:
                os.chmod(token_file, 0o600)
            except OSError:
                pass
            return 0
        log.warning("%s exists but is empty; regenerating", token_file)

    # 48 url-safe bytes -> 64-char token, ~286 bits of entropy. token_urlsafe
    # uses the [A-Za-z0-9_-] alphabet, which Vaultwarden accepts verbatim as
    # an ADMIN_TOKEN and which is safe to round-trip through a urlencoded POST
    # and a Set-Cookie value.
    token = secrets.token_urlsafe(48)

    tmp = token_file + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(token)
        os.chmod(tmp, 0o600)
        os.replace(tmp, token_file)
    except OSError as exc:
        log.error("could not write %s: %s", token_file, exc)
        try:
            os.remove(tmp)
        except OSError:
            pass
        return 1

    log.info("generated ADMIN_TOKEN and persisted to %s (mode 0600)", token_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
