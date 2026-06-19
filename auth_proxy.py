"""OpenHost auth-proxy sidecar for Vaultwarden (Pattern B1: HTTP login dance).

Sits between the OpenHost router (which terminates TLS and gates zone_auth)
and Vaultwarden's Rocket server on 127.0.0.1:8001.

What this proxy is for
======================

Vaultwarden has two very different request surfaces, and they need opposite
auth treatment:

  1. The VAULT itself ( ``/`` web vault, ``/api/``, ``/identity/``,
     ``/notifications/`` WebSocket, ``/icons/`` ... ). This is a public,
     end-to-end-encrypted Bitwarden-compatible API. Real Bitwarden clients
     (browser extension, mobile, desktop, CLI) log in with the user's own
     email + master password and carry NO OpenHost zone_auth cookie. These
     requests are pass-through, untouched. Their secrecy comes from
     client-side encryption + the master password, not from us.

  2. The server ADMIN PANEL ( ``/admin`` ). This configures the whole
     server (users, SMTP, backups, org policy) and is gated by
     Vaultwarden's ``ADMIN_TOKEN``. We bind it to the OpenHost zone owner:
       * the OpenHost router already requires zone_auth for ``/admin``
         (it is deliberately NOT in the manifest's ``public_paths``) and
         stamps ``X-OpenHost-Is-Owner: true`` on the owner's request;
       * this proxy refuses ``/admin*`` to anyone WITHOUT that header
         (defense in depth — a request that reached us without the gate is
         treated as hostile); and
       * for the owner with no ``VW_ADMIN`` cookie yet, this proxy performs
         Vaultwarden's admin login dance ( ``POST /admin/`` with
         ``token=<ADMIN_TOKEN>`` ), captures the returned ``VW_ADMIN`` JWT
         cookie, and 302s the owner back to ``/admin/`` with it set. The
         result is one-click admin SSO with no token ever shown to a human.

The ADMIN_TOKEN is generated once on first boot and persisted (see
bootstrap.py). This proxy re-reads it on every login attempt so a rotation
by the operator (delete the file + restart) takes effect without a rebuild.

Security notes
==============

  * ``X-OpenHost-Is-Owner`` is ALWAYS stripped before forwarding upstream.
    The OpenHost router stamps it only on requests whose zone_auth it has
    verified; a client that supplies it directly is forging, so we both
    refuse to act on a forged value (the router would have bounced it) and
    never let it reach Vaultwarden.
  * Auto-login is attempted ONLY for ``/admin`` HTML navigations by a
    verified owner who lacks a valid ``VW_ADMIN`` cookie. API/asset/XHR
    requests under ``/admin`` are passed through so the admin SPA's own
    fetches are never turned into 302s.
  * If the ADMIN_TOKEN file is missing/unreadable, or the login POST fails,
    we fall through to a plain pass-through. The owner then lands on
    Vaultwarden's own ``/admin`` token form and can paste the token by hand.
    Never break the human's ability to log in manually.
  * WebSocket upgrades ( ``/notifications/hub`` ) are detected and handed to
    a raw bidirectional tunnel so live client sync works.

Skeleton (BaseHTTPRequestHandler -> ThreadingHTTPServer, hop-by-hop header
stripping, buffered-body forwarding) follows the shape of
``openhost-pihole/auth_proxy.py`` and ``openhost-miniflux/auth_proxy.py``.
"""

from __future__ import annotations

import http.client
import logging
import os
import select
import socket
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
VW_ADMIN_COOKIE = "VW_ADMIN"

# Headers we must drop before proxying upstream: the standard hop-by-hop set
# (RFC 7230 §6.1), plus Host (we set it ourselves) and Content-Length (we
# recompute it from the buffered body). NB: for WebSocket upgrades we take a
# separate code path that intentionally preserves Connection/Upgrade.
HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Defense in depth: never let a client inject the owner header; only the
# OpenHost router is allowed to stamp it.
ALWAYS_STRIP_HEADERS = frozenset(h.lower() for h in (OWNER_HEADER_NAME,))

# Vaultwarden's web vault serves modest static assets and the admin panel
# handles small config posts; 128 MiB covers file-attachment uploads (the
# server default org attachment limit is well under this) with headroom.
MAX_BODY_BYTES = 128 * 1024 * 1024

CLIENT_READ_TIMEOUT_SECONDS = 60
WS_IDLE_TIMEOUT_SECONDS = 600

ADMIN_PREFIX = "/admin"
ADMIN_LOGIN_PATH = "/admin/"
HEALTHZ_PATH = "/_healthz"

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    if not cookie_header:
        return {}
    result: dict[str, str] = {}
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        result.setdefault(name.strip(), value.strip())
    return result


def _strip_headers(headers: Iterable[tuple[str, str]], drop: AbstractSet[str]) -> list[tuple[str, str]]:
    drop_lower = {h.lower() for h in drop}
    return [(k, v) for k, v in headers if k.lower() not in drop_lower]


def _read_admin_token(token_file: str) -> str | None:
    """Read the persisted ADMIN_TOKEN.

    Returns None if the file is missing or empty, in which case auto-login
    falls through to a plain pass-through and the owner gets Vaultwarden's
    own admin token form.
    """
    try:
        with open(token_file, encoding="utf-8") as fh:
            value = fh.read().strip()
    except OSError as exc:
        log.warning("could not read admin-token file %s: %s", token_file, exc)
        return None
    return value or None


def _is_path_under(path: str, prefix: str) -> bool:
    """True if `path` is `prefix` exactly or a child of it (not /adminxyz)."""
    if path == prefix:
        return True
    return path.startswith(prefix + "/") or path.startswith(prefix + "?")


def _admin_login(
    upstream_host: str,
    upstream_port: int,
    token: str,
) -> str | None:
    """POST /admin/ with the token; return the VW_ADMIN cookie value or None.

    Vaultwarden's admin login route is
        POST /admin/  Content-Type: application/x-www-form-urlencoded
        body: token=<ADMIN_TOKEN>
    On success it sets a Set-Cookie: VW_ADMIN=<jwt> and renders the admin
    page (HTTP 200). On a bad token it re-renders the login form (also 200),
    but without the cookie — so "did we get a VW_ADMIN cookie?" is the
    success signal, not the status code.
    """
    payload = urllib.parse.urlencode({"token": token}).encode("utf-8")
    conn = http.client.HTTPConnection(upstream_host, upstream_port, timeout=15)
    try:
        conn.request(
            "POST",
            ADMIN_LOGIN_PATH,
            body=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": str(len(payload)),
                "Host": f"{upstream_host}:{upstream_port}",
            },
        )
        resp = conn.getresponse()
        # Drain the body so the connection can be reused/closed cleanly.
        resp.read()
        for key, value in resp.getheaders():
            if key.lower() != "set-cookie":
                continue
            cookies = _parse_cookie_header(value.split(";", 1)[0])
            if VW_ADMIN_COOKIE in cookies and cookies[VW_ADMIN_COOKIE]:
                return cookies[VW_ADMIN_COOKIE]
        log.warning(
            "admin auto-login: POST /admin/ returned %d but no %s cookie "
            "(bad/rotated ADMIN_TOKEN?)",
            resp.status,
            VW_ADMIN_COOKIE,
        )
        return None
    except (OSError, http.client.HTTPException) as exc:
        log.warning("admin auto-login: HTTP error during POST /admin/: %s", exc)
        return None
    finally:
        try:
            conn.close()
        except Exception:  # noqa: BLE001 - best effort
            pass


class AuthProxyHandler(BaseHTTPRequestHandler):
    upstream_host: str = "127.0.0.1"
    upstream_port: int = 8001
    token_file: str = "/data/app_data/vaultwarden/admin_token.txt"

    # protocol_version stays HTTP/1.1 so keep-alive + chunked work for the
    # web vault. We always send Content-Length on the responses we build,
    # and close-delimit the WebSocket tunnel explicitly.
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        if path == HEALTHZ_PATH or path.startswith(HEALTHZ_PATH + "?"):
            return
        log.info("%s - " + format, self.address_string(), *args)

    # ---- HTTP method handlers ----------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _serve_healthz(self) -> None:
        """Static 200 for the OpenHost healthcheck.

        We must not proxy the healthcheck to Vaultwarden's "/", which 302s
        unauthenticated browsers to the web-vault login; the OpenHost probe
        does not follow redirects and would mark the app unhealthy.
        """
        body = b"ok\n"
        try:
            self.send_response(200, "OK")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError as exc:
            log.debug("client disconnected during healthz: %s", exc)

    # ---- main dispatch -----------------------------------------------

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        raw_path = self.path or "/"
        path_only = urllib.parse.urlsplit(raw_path).path
        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"

        if path_only == HEALTHZ_PATH:
            self._serve_healthz()
            return

        is_admin = _is_path_under(path_only, ADMIN_PREFIX)

        if is_admin:
            # The OpenHost router gates /admin behind zone_auth and stamps
            # the owner header. If we got an /admin request WITHOUT that
            # header, either the router gate is misconfigured or someone is
            # probing — refuse rather than expose the admin surface.
            if not is_owner:
                log.warning("refusing %s %s: /admin requires owner (no owner header)", self.command, path_only)
                self._safe_send_error(403, "admin panel is restricted to the zone owner")
                return

            cookies = _parse_cookie_header(self.headers.get("Cookie"))
            has_admin_cookie = bool(cookies.get(VW_ADMIN_COOKIE))
            accept = self.headers.get("Accept", "")
            is_html_navigation = self.command == "GET" and "text/html" in accept.lower()

            # Only auto-login on a top-level HTML navigation with no admin
            # cookie. The admin SPA's own POSTs/XHRs carry the cookie (or
            # are the user's own token submit) and must pass through.
            if is_html_navigation and not has_admin_cookie:
                if self._maybe_admin_login(raw_path):
                    return

        # WebSocket upgrade (live notifications). Detect before the buffered
        # proxy path, which cannot carry a streaming bidirectional upgrade.
        upgrade = self.headers.get("Upgrade", "").strip().lower()
        connection_hdr = self.headers.get("Connection", "").lower()
        if upgrade == "websocket" and "upgrade" in connection_hdr:
            self._proxy_websocket()
            return

        self._proxy()

    def _maybe_admin_login(self, target_path: str) -> bool:
        token = _read_admin_token(self.token_file)
        if not token:
            log.warning(
                "admin auto-login: ADMIN_TOKEN missing/unreadable at %s; "
                "falling through to Vaultwarden's own /admin login form",
                self.token_file,
            )
            return False

        cookie_value = _admin_login(self.upstream_host, self.upstream_port, token)
        if not cookie_value:
            return False

        # Open-redirect defense: never honor an absolute URL even if our
        # incoming path somehow carried one; only ever redirect within /admin.
        parsed = urllib.parse.urlsplit(target_path)
        if parsed.scheme or parsed.netloc:
            target_path = ADMIN_LOGIN_PATH
        if not _is_path_under(parsed.path or "/", ADMIN_PREFIX):
            target_path = ADMIN_LOGIN_PATH

        try:
            self.send_response(302)
            self.send_header("Location", target_path)
            # Mirror Vaultwarden's own cookie flags: HttpOnly + SameSite=Lax;
            # Secure because the OpenHost router always serves over HTTPS.
            self.send_header(
                "Set-Cookie",
                f"{VW_ADMIN_COOKIE}={cookie_value}; Path=/admin; HttpOnly; Secure; SameSite=Lax",
            )
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError as exc:
            log.debug("client disconnected during admin auto-login redirect: %s", exc)
            return False

        log.info("admin auto-login: minted VW_ADMIN session for owner; redirected to %s", target_path)
        return True

    def _proxy(self) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        # Vaultwarden builds absolute URLs from its DOMAIN env var, not from
        # Host, so a fixed loopback Host is fine and avoids leaking the
        # public host into upstream-side logic.
        cleaned_headers.append(("Host", f"{self.upstream_host}:{self.upstream_port}"))

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        conn = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=120)
        try:
            try:
                conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            try:
                payload = upstream.read(MAX_BODY_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream read error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                try:
                    upstream.close()
                except Exception as close_exc:  # noqa: BLE001 - best effort
                    log.debug("upstream.close() after read error raised: %s", close_exc)
                return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001 - best effort
                log.debug("upstream.close() raised (ignored): %s", exc)
            if len(payload) > MAX_BODY_BYTES:
                self._safe_send_error(502, "upstream response too large")
                return

            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                saw_content_length = False
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    if key.lower() == "content-length":
                        saw_content_length = True
                    self.send_header(key, value)
                # Guarantee framing: if upstream used chunked TE (which we
                # strip) and gave no Content-Length, set one from the body
                # we buffered so HTTP/1.1 keep-alive stays in sync.
                if not saw_content_length and self.command != "HEAD":
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
            except OSError as exc:
                log.debug("client disconnected mid-response: %s", exc)
        finally:
            conn.close()

    def _proxy_websocket(self) -> None:
        """Tunnel a WebSocket upgrade to Vaultwarden and pump bytes both ways.

        Vaultwarden serves live notifications at /notifications/hub. We replay
        the client's upgrade request line + headers to the upstream over a raw
        socket, relay the 101 response, then splice the two sockets until one
        closes. The OpenHost router has already handled the outer (TLS) upgrade
        with the browser; from here it is a plain TCP upgrade on loopback.
        """
        cleaned = _strip_headers(self.headers.items(), ALWAYS_STRIP_HEADERS | {"host"})
        cleaned.append(("Host", f"{self.upstream_host}:{self.upstream_port}"))

        request_lines = [f"{self.command} {self.path} HTTP/1.1\r\n"]
        for key, value in cleaned:
            request_lines.append(f"{key}: {value}\r\n")
        request_lines.append("\r\n")
        request_blob = "".join(request_lines).encode("latin-1")

        try:
            upstream = socket.create_connection((self.upstream_host, self.upstream_port), timeout=15)
        except OSError as exc:
            log.warning("websocket upstream connect failed: %s", exc)
            self._safe_send_error(502, "Bad Gateway")
            return

        client_sock = self.connection
        try:
            upstream.sendall(request_blob)
            # BaseHTTPRequestHandler reads the request line + headers through a
            # buffered rfile, so a few client bytes that arrived in the same
            # packet as the handshake can sit in that buffer rather than on the
            # raw socket. peek() returns the buffered bytes without consuming
            # and without a socket read; read() then consumes exactly those so
            # we never block. Forward them before splicing the raw fds.
            pending = self.rfile.peek(0) if hasattr(self.rfile, "peek") else b""
            if pending:
                upstream.sendall(self.rfile.read(len(pending)))
            self._splice(client_sock, upstream)
        except OSError as exc:
            log.debug("websocket tunnel error: %s", exc)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    @staticmethod
    def _splice(a: socket.socket, b: socket.socket) -> None:
        a.setblocking(False)
        b.setblocking(False)
        socks = [a, b]
        try:
            while True:
                readable, _, exceptional = select.select(socks, [], socks, WS_IDLE_TIMEOUT_SECONDS)
                if exceptional or not readable:
                    return
                for src in readable:
                    dst = b if src is a else a
                    try:
                        chunk = src.recv(65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        return
                    if not chunk:
                        return
                    try:
                        dst.sendall(chunk)
                    except OSError:
                        return
        finally:
            for s in socks:
                try:
                    s.setblocking(True)
                except OSError:
                    pass


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 8001)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip() or "127.0.0.1"
    token_file = os.environ.get("AUTH_PROXY_TOKEN_FILE", "/data/app_data/vaultwarden/admin_token.txt")

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port
    AuthProxyHandler.token_file = token_file

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error("failed to bind auth-proxy listener on 0.0.0.0:%d: %s", listen_port, exc)
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (admin token file=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        token_file,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
