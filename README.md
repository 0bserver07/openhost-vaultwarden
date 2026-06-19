# openhost-vaultwarden

[Vaultwarden](https://github.com/dani-garcia/vaultwarden) — a lightweight,
Bitwarden-compatible password manager — packaged as an OpenHost app. Wraps
the official `docker.io/vaultwarden/server` image with an OpenHost auth-proxy
that gates the server **admin panel** (`/admin`) behind the zone owner and
auto-logs them in, while leaving the **vault API itself public** so real
Bitwarden clients (browser extension, mobile, desktop, CLI) can sync.

You get an end-to-end-encrypted vault you fully own: passwords, passkeys,
TOTP, secure notes, sends, and file attachments, all stored on your own
OpenHost compute under `app_data` (backed up).

## what you get

- The Bitwarden web vault at `https://vaultwarden.<your-zone>/`.
- Full Bitwarden client compatibility — point any official Bitwarden app at
  that URL as a "self-hosted" server. Your master password never leaves the
  client; the server only ever sees ciphertext.
- Live sync via WebSocket notifications (same URL, no extra port).
- A server admin panel at `/admin`, reachable **only** by the OpenHost zone
  owner, with one-click login (no token to copy).

## how to deploy

From the OpenHost dashboard, "Deploy New App" and paste this repo's git URL.
The router reads `openhost.toml`, builds the `Dockerfile` with rootless
podman, and routes `https://vaultwarden.<your-zone>/` to it.

Or via the CLI:

```bash
oh app deploy https://github.com/<you>/openhost-vaultwarden --name vaultwarden --wait
oh app logs vaultwarden --follow
```

First-run setup:

1. Open `https://vaultwarden.<your-zone>/` and **create your account**
   (email + master password). `INVITATIONS_ALLOWED=true` lets you make the
   first account without SMTP; `SIGNUPS_ALLOWED=false` keeps the public
   registration form closed so the vault stays single-tenant.
2. Install a Bitwarden client, choose **self-hosted**, and enter the same
   URL as the server. Log in with your account.
3. Visit `/admin` (as the zone owner) to configure SMTP, org policy, user
   invitations, backups, etc. You are logged in automatically.

## auth model

Vaultwarden has two request surfaces with **opposite** auth needs, and the
manifest + auth-proxy treat them differently:

| Surface | Examples | Auth | Why |
|---|---|---|---|
| **Vault API** (public) | `/`, `/api/`, `/identity/`, `/notifications/`, web vault, icons | **No OpenHost gate.** Bitwarden's own email + master-password auth + client-side E2E encryption. | Clients hold no OpenHost cookie; the vault's secrecy is the master password, not the login gate. The router would break every client if it gated these. |
| **Admin panel** | `/admin` | **OpenHost zone owner only**, auto-login. | Configures the whole server; must be owner-restricted. |

Concretely:

1. **Router layer.** `openhost.toml` lists `public_paths = ["/"]`, so the
   router lets vault traffic through unauthenticated — but `/admin` is
   deliberately **not** public, so the router keeps requiring zone_auth for
   it and stamps `X-OpenHost-Is-Owner: true` on the owner's request.
2. **Auth-proxy layer** (`auth_proxy.py`, **Pattern B1** — HTTP login dance):
   - Refuses any `/admin*` request that arrives **without** the owner header
     (defense in depth — `403`).
   - For the owner with no `VW_ADMIN` cookie yet, it POSTs Vaultwarden's
     admin login (`POST /admin/` with `token=<ADMIN_TOKEN>`), captures the
     returned `VW_ADMIN` JWT cookie, and `302`s the owner back to `/admin/`
     with it set. One click, no token shown.
   - Everything else (vault API, the admin SPA's own XHRs, WebSocket
     upgrades) is plain pass-through.
   - `X-OpenHost-Is-Owner` is always stripped before forwarding upstream so
     a client can never forge it.

The `ADMIN_TOKEN` is generated once on first boot (`bootstrap.py`, 286 bits)
and persisted to `$OPENHOST_APP_DATA_DIR/admin_token.txt` (mode `0600`).

### credential-leak warning

Pattern B1 requires the auth-proxy to know the `ADMIN_TOKEN` at runtime so it
can re-mint admin sessions after a restart, so the token is stored **raw**
on disk. **Any other OpenHost app granted `access_all_data` (e.g. a
file-browser) could read it.** Treat your zone's user list as the same trust
boundary as the Vaultwarden admin password. This only affects the **admin
panel** — your actual vault entries are end-to-end encrypted with your
master password and are *not* readable from this file.

If that trade-off is unacceptable, run Pattern E instead: set a hashed
`ADMIN_TOKEN` of your own (`vaultwarden hash`), delete `admin_token.txt`,
and don't rely on the proxy's auto-login — you'll paste the token into
Vaultwarden's own `/admin` form by hand once and the `VW_ADMIN` cookie
carries you after that. (Note the auto-login falls through to exactly this
form whenever the token file is missing, so manual login always works.)

## persistence

Everything lives under `$OPENHOST_APP_DATA_DIR/vw-data/` (= `DATA_FOLDER`),
which OpenHost mounts as the app's permanent, backed-up volume:

- `db.sqlite3` (+ WAL) — the vault database
- `rsa_key.*` — this install's signing keys (rotating them logs everyone out)
- `attachments/`, `sends/`, `icon_cache/`

The sibling `admin_token.txt` holds the admin credential (see above).

## ports & rootless-podman notes

- **Single HTTP port (8080).** The auth-proxy listens on `0.0.0.0:8080`
  (what the router proxies to); Vaultwarden's Rocket server binds
  `127.0.0.1:8001`. No privileged ports — clears the rootless `<25` floor.
- **WebSockets.** Modern Vaultwarden serves notifications on the **same**
  port (`ENABLE_WEBSOCKET=true`), so no `[[ports]]` entry is needed. The
  proxy detects the `Upgrade: websocket` handshake and tunnels it
  bidirectionally; the OpenHost router proxies the outer upgrade. (Older
  guides mention a separate WebSocket port 3012 — not used here.)
- **No extra capabilities or devices.** Vaultwarden is a plain userspace
  HTTP server; the manifest requests none.
- **SQLite on local disk.** The DB stays in `app_data` (local disk), never
  the archive tier — the archive's network FS can corrupt SQLite WAL.

## verifying the SSO (once a deploy is green-lit)

Replace `HOST` with your zone and `TOKEN` with an owner API token
(`oh instance token --instance <name>` — keep it out of anything committed):

```bash
HOST=vaultwarden.yad.selfhost.imbue.com
TOKEN=...

# 1. Vault must be PUBLIC: the web vault loads with no auth (HTTP 200).
curl -sk -o /dev/null -w 'vault / HTTP=%{http_code}\n' "https://$HOST/"
# expect 200 (the web vault), NOT a 302 to OpenHost /login.

# 2. Vault API alive endpoint, also public:
curl -sk "https://$HOST/api/alive"            # expect an ISO timestamp, 200

# 3. /admin must be GATED: anonymous hits the OpenHost login redirect.
curl -sk -o /dev/null -w 'admin anon HTTP=%{http_code}\n' "https://$HOST/admin"
# expect 302/307 to OpenHost /login.

# 4. /admin as the owner: auto-login lands on the admin dashboard, not the
#    token form.
rm -f /tmp/vwjar
curl -sk -H "Authorization: Bearer $TOKEN" -H "Accept: text/html" \
  -L --max-redirs 10 -c /tmp/vwjar -b /tmp/vwjar -o /tmp/vw.html \
  "https://$HOST/admin/" -w 'admin owner HTTP=%{http_code} FINAL=%{url_effective}\n'
grep -oE '<title>[^<]*</title>' /tmp/vw.html
# expect the Vaultwarden admin dashboard title — NOT the "enter admin token" page.
# the VW_ADMIN cookie should be present in /tmp/vwjar.
```

In a browser, logged in as the owner, `https://$HOST/admin` should drop you
straight onto the admin dashboard. To test as the owner with Playwright,
inject the API token as a `Bearer` header (matches the owner's login
cookies).

End-to-end client check: install the Bitwarden browser extension → Settings →
self-hosted → server URL = `https://$HOST` → log in with the account you
created → add an item on the web vault and confirm it syncs to the extension
(exercises the WebSocket path).

## known limitations

- **Single-tenant by design.** `SIGNUPS_ALLOWED=false` keeps the vault to the
  zone owner (+ anyone they invite via `/admin`). The OpenHost zone owner is
  effectively the server admin. Don't deploy on a shared/multi-tenant zone if
  that's not intended.
- **Admin token lives on disk (raw).** See the credential-leak warning above.
- **No SMTP out of the box.** Email (invitations, verification, password
  hints) needs `SMTP_*` env vars or admin-panel config. `INVITATIONS_ALLOWED`
  lets the owner bootstrap the first account without it.
- **SQLite backend only here.** Fine for a personal/family vault. Vaultwarden
  supports MySQL/Postgres, but that's out of scope for this single-container
  app; add a DB sidecar + set `DATABASE_URL` if you outgrow SQLite.
- **`latest` image tag.** This artifact tracks upstream `vaultwarden/server`.
  Pin a digest in `Dockerfile` for a reproducible production deploy.

## configuration

Any [Vaultwarden setting](https://github.com/dani-garcia/vaultwarden/blob/main/.env.template)
can be passed as an env var at deploy time, e.g.:

```bash
oh app deploy ... --env SMTP_HOST=smtp.example.com --env SMTP_FROM=vault@example.com
```

`start.sh` sets safe OpenHost-aware defaults for `DATA_FOLDER`, `ROCKET_*`,
`DOMAIN`, `ENABLE_WEBSOCKET`, `ADMIN_TOKEN`, and the signup knobs; explicit
env vars passed at deploy time override the defaults (except the
container-wiring ones — `ROCKET_ADDRESS/PORT`, `DATA_FOLDER`, `ADMIN_TOKEN` —
which are managed by the supervisor).

## layout

```
openhost-vaultwarden/
  Dockerfile        # FROM vaultwarden/server + python3 + tini + our supervisor
  openhost.toml     # port=8080; public vault, gated /admin; app_data
  start.sh          # bash + wait -n; runs vaultwarden (loopback) + auth-proxy
  bootstrap.py      # one-shot: generate + persist ADMIN_TOKEN (mode 0600)
  auth_proxy.py     # SSO sidecar (Pattern B1) + WebSocket tunnel
  README.md         # you are here
  .gitignore
```
