#!/bin/bash
# OpenHost supervisor for Vaultwarden.
#
# `bash` (not `sh`) is required for `wait -n`: we block until the first of two
# backgrounded processes (Vaultwarden, auth-proxy) exits, then tear down the
# survivor so OpenHost restarts the container cleanly.
#
# Responsibilities:
#   1. Point Vaultwarden's DATA_FOLDER at the persistent OpenHost volume so
#      the SQLite vault DB, RSA keys, attachments, icon cache and sends
#      survive restarts + are backed up.
#   2. Bind Vaultwarden's Rocket server to loopback :8001 — the auth-proxy is
#      the sole public-facing listener (on :8080). Nothing else can reach the
#      admin panel except through the proxy.
#   3. Mint or read the ADMIN_TOKEN (bootstrap.py) and export it so
#      Vaultwarden accepts the same token the proxy uses to auto-login the
#      owner into /admin.
#   4. Derive DOMAIN from the OpenHost environment so Vaultwarden builds
#      correct absolute URLs (web vault, attachment links, WebAuthn origin).
#   5. Launch Vaultwarden + the auth-proxy and supervise both.
set -euo pipefail

log() { printf '[start.sh] %s\n' "$*" >&2; }

# --- environment plumbing ---------------------------------------------

DATA_DIR="${OPENHOST_APP_DATA_DIR:-/data/app_data/vaultwarden}"
VW_DATA="$DATA_DIR/vw-data"
TOKEN_FILE="$DATA_DIR/admin_token.txt"

ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-vaultwarden}"
PUBLIC_HOST="$APP_NAME.$ZONE_DOMAIN"

UPSTREAM_PORT="${AUTH_PROXY_UPSTREAM_PORT:-8001}"
LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}"

mkdir -p "$DATA_DIR" "$VW_DATA"

# --- mint or read the ADMIN_TOKEN -------------------------------------
#
# bootstrap.py writes $TOKEN_FILE (mode 0600) on first boot and just reads it
# thereafter (idempotent — a restart never rotates it). The auth-proxy reads
# the same file to mint VW_ADMIN sessions for the owner.
#
# CREDENTIAL LEAK NOTE: $TOKEN_FILE holds a usable admin credential. Any app
# with access_all_data over this zone could read it. This is the core
# trade-off of Pattern B1 (see README.md).
log "running bootstrap.py"
python3 /opt/openhost-vaultwarden/bootstrap.py
ADMIN_TOKEN_VALUE="$(cat "$TOKEN_FILE")"
chmod 0600 "$TOKEN_FILE"

# --- Vaultwarden configuration ----------------------------------------
#
# Rocket binds loopback only; the auth-proxy is the sole client.
export ROCKET_ADDRESS="127.0.0.1"
export ROCKET_PORT="$UPSTREAM_PORT"

# All persistent state under the OpenHost-mounted, backed-up volume.
export DATA_FOLDER="$VW_DATA"

# Live client sync. Modern Vaultwarden serves the notifications WebSocket on
# the SAME Rocket port, so no extra port is needed; the auth-proxy tunnels the
# Upgrade and the OpenHost router proxies it end-to-end.
export ENABLE_WEBSOCKET="${ENABLE_WEBSOCKET:-true}"

# Admin panel auth — the value the proxy will POST to /admin/ to log the
# owner in. Stored raw (not hashed) precisely so the proxy can present it.
export ADMIN_TOKEN="$ADMIN_TOKEN_VALUE"

# Derive DOMAIN so Vaultwarden emits correct absolute URLs + WebAuthn origin.
# On localhost-style dev zones the router may run on a non-443 port; honor it.
case "$ZONE_DOMAIN" in
    lvh.me|*.lvh.me|localhost|*.localhost)
        ROUTER_PORT=""
        if [ -n "${OPENHOST_ROUTER_URL:-}" ]; then
            ROUTER_PORT="$(printf '%s' "$OPENHOST_ROUTER_URL" | sed -n 's/.*:\([0-9]*\)$/\1/p')"
        fi
        export DOMAIN="http://${PUBLIC_HOST}${ROUTER_PORT:+:$ROUTER_PORT}"
        ;;
    *)
        export DOMAIN="https://${PUBLIC_HOST}"
        ;;
esac

# First-run bootstrap. There is no SMTP out of the box, so the owner must be able
# to create their account directly from the web vault — that needs signups ON and
# email verification OFF (verification can never complete without SMTP). This is
# the standard Vaultwarden self-host bootstrap; an admin invite WITHOUT SMTP does
# not let the invitee finish registration, so closed-signups + invites is a trap.
#
# IMPORTANT: once you've created your account, lock the vault to single-tenant by
# setting SIGNUPS_ALLOWED=false (admin panel runtime toggle, or redeploy with the
# env override) — otherwise anyone who reaches the URL can register.
export SIGNUPS_ALLOWED="${SIGNUPS_ALLOWED:-true}"
export SIGNUPS_VERIFY="${SIGNUPS_VERIFY:-false}"
export INVITATIONS_ALLOWED="${INVITATIONS_ALLOWED:-true}"

log "DATA_FOLDER=$DATA_FOLDER  DOMAIN=$DOMAIN  Rocket=127.0.0.1:$ROCKET_PORT  ws=$ENABLE_WEBSOCKET"

# --- launch Vaultwarden + the auth-proxy ------------------------------

VW_PID=""
PROXY_PID=""
# Trap before backgrounding so a SIGTERM in the small window between the two
# `&` lines doesn't orphan a child.
trap 'kill -TERM ${VW_PID:-} ${PROXY_PID:-} 2>/dev/null; wait' TERM INT

log "starting vaultwarden on 127.0.0.1:$ROCKET_PORT"
/vaultwarden &
VW_PID=$!

# Wait for Vaultwarden to bind before the proxy starts taking traffic. Not
# strictly required (the proxy returns 502 until it's up), but avoids a noisy
# first-request failure right after deploy.
for _ in $(seq 1 20); do
    if VW_PORT="$UPSTREAM_PORT" python3 -c 'import os,socket,sys
p=int(os.environ["VW_PORT"]); s=socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(("127.0.0.1", p))==0 else 1)' 2>/dev/null; then
        break
    fi
    # Surface an early crash instead of waiting the full loop.
    if ! kill -0 "$VW_PID" 2>/dev/null; then
        wait "$VW_PID"
        exit $?
    fi
    sleep 0.5
done

log "starting auth-proxy on 0.0.0.0:$LISTEN_PORT -> 127.0.0.1:$UPSTREAM_PORT"
export AUTH_PROXY_LISTEN_PORT="$LISTEN_PORT"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="$UPSTREAM_PORT"
export AUTH_PROXY_TOKEN_FILE="$TOKEN_FILE"
python3 /opt/openhost-vaultwarden/auth_proxy.py &
PROXY_PID=$!

set +e
wait -n "$VW_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

log "child exited (code=$EXIT_CODE); stopping container"
kill -TERM "$VW_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
