"""Functional tests for the Vaultwarden OpenHost auth-proxy.

These run the real ``auth_proxy.AuthProxyHandler`` against a mock Vaultwarden
upstream (a stdlib ``ThreadingHTTPServer``), with no podman/containers needed,
so they exercise the actual SSO decision logic:

  * vault paths pass through unauthenticated (the vault API must be public);
  * ``/admin`` without the router's owner header is refused (403);
  * ``/admin`` as the owner with no ``VW_ADMIN`` cookie triggers the
    Pattern-B1 login dance and yields a 302 + ``Set-Cookie: VW_ADMIN=...``;
  * the owner header is stripped before reaching upstream;
  * ``/_healthz`` is served locally without touching upstream.

Run with: ``python -m pytest tests/test_auth_proxy.py -x`` (pytest), or
plain ``python tests/test_auth_proxy.py`` for a dependency-free smoke run.
"""

from __future__ import annotations

import http.client
import importlib.util
import os
import socket
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Import auth_proxy.py from the repo root without needing it on sys.path.
_AUTH_PROXY_PATH = Path(__file__).resolve().parent.parent / "auth_proxy.py"
_spec = importlib.util.spec_from_file_location("auth_proxy", _AUTH_PROXY_PATH)
assert _spec and _spec.loader
auth_proxy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(auth_proxy)

ADMIN_TOKEN = "test-admin-token-abc123"


class MockVaultwarden(BaseHTTPRequestHandler):
    """Stand-in for Vaultwarden's Rocket server.

    Records the headers of the last request it saw (so tests can assert the
    owner header was stripped), and emulates the admin login: ``POST /admin/``
    with the right ``token=`` sets ``VW_ADMIN`` and 200s; everything else 200s
    with a small body.
    """

    last_headers: dict[str, str] = {}

    def log_message(self, *args) -> None:  # noqa: A002, N802 - silence test noise
        pass

    def _record(self) -> None:
        type(self).last_headers = {k.lower(): v for k, v in self.headers.items()}

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        # Real Vaultwarden serves the admin dashboard at /admin/ to a request
        # bearing a valid VW_ADMIN cookie, and the web vault everywhere else.
        if self.path.startswith("/admin"):
            body = b"<title>Vaultwarden Admin</title>"
        else:
            body = b"<title>vault</title>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self._record()
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        if self.path == "/admin/":
            fields = urllib.parse.parse_qs(raw.decode("utf-8"))
            token = (fields.get("token") or [""])[0]
            self.send_response(200)
            if token == ADMIN_TOKEN:
                # success -> set the JWT cookie like real Vaultwarden does
                self.send_header("Set-Cookie", "VW_ADMIN=minted.jwt.value; Path=/; HttpOnly")
            body = b"<title>Vaultwarden Admin</title>"
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Harness:
    def __init__(self) -> None:
        self.token_dir = tempfile.mkdtemp(prefix="vw-proxy-test-")
        self.token_file = os.path.join(self.token_dir, "admin_token.txt")
        with open(self.token_file, "w", encoding="utf-8") as fh:
            fh.write(ADMIN_TOKEN)

        self.upstream_port = _free_port()
        self.proxy_port = _free_port()

        self.upstream = ThreadingHTTPServer(("127.0.0.1", self.upstream_port), MockVaultwarden)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()

        auth_proxy.AuthProxyHandler.upstream_host = "127.0.0.1"
        auth_proxy.AuthProxyHandler.upstream_port = self.upstream_port
        auth_proxy.AuthProxyHandler.token_file = self.token_file
        self.proxy = auth_proxy.IPv4ThreadingServer(("127.0.0.1", self.proxy_port), auth_proxy.AuthProxyHandler)
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()

    def request(
        self, method: str, path: str, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            body = resp.read()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body
        finally:
            conn.close()

    def close(self) -> None:
        self.proxy.shutdown()
        self.upstream.shutdown()


def _run_checks() -> None:
    h = _Harness()
    try:
        # 1. healthz served locally (never hits upstream).
        status, _, body = h.request("GET", "/_healthz")
        assert status == 200 and body == b"ok\n", (status, body)

        # 2. vault path is public: passes through with no auth, 200.
        MockVaultwarden.last_headers = {}
        status, _, body = h.request("GET", "/api/alive")
        assert status == 200, status
        assert b"vault" in body

        # 3. owner header is stripped before reaching upstream even when the
        #    client forges it on a public path.
        MockVaultwarden.last_headers = {}
        status, _, _ = h.request("GET", "/", headers={"X-OpenHost-Is-Owner": "true"})
        assert status == 200, status
        assert "x-openhost-is-owner" not in MockVaultwarden.last_headers, MockVaultwarden.last_headers

        # 4. /admin WITHOUT the router's owner header is refused (403).
        status, _, _ = h.request("GET", "/admin", headers={"Accept": "text/html"})
        assert status == 403, status

        # 5. /admin AS the owner, no VW_ADMIN cookie, HTML nav -> Pattern B1
        #    login dance: 302 back to /admin/ with a VW_ADMIN cookie set.
        status, hdrs, _ = h.request(
            "GET",
            "/admin/",
            headers={"X-OpenHost-Is-Owner": "true", "Accept": "text/html"},
        )
        assert status == 302, status
        assert hdrs.get("location") == "/admin/", hdrs
        assert "VW_ADMIN=minted.jwt.value" in hdrs.get("set-cookie", ""), hdrs

        # 6. /admin as owner WITH a VW_ADMIN cookie already -> pass-through to
        #    upstream (no re-login), reaches the admin page, owner header
        #    stripped.
        MockVaultwarden.last_headers = {}
        status, _, body = h.request(
            "GET",
            "/admin/",
            headers={
                "X-OpenHost-Is-Owner": "true",
                "Accept": "text/html",
                "Cookie": "VW_ADMIN=already.have.one",
            },
        )
        assert status == 200, status
        assert b"Admin" in body, body
        assert "x-openhost-is-owner" not in MockVaultwarden.last_headers

        print("all auth-proxy checks passed")
    finally:
        h.close()


# ---- pytest entrypoints (each is independent of the others) -------------


def test_healthz_and_vault_public() -> None:
    _run_checks()


def test_admin_gating_and_sso() -> None:
    # _run_checks covers gating + the SSO dance end-to-end; kept as a separate
    # named test so a pytest run shows both behaviors explicitly.
    _run_checks()


if __name__ == "__main__":
    _run_checks()
