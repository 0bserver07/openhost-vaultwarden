# OpenHost wrapper around the official Vaultwarden image.
#
# The upstream image (docker.io/vaultwarden/server, Debian trixie-slim) ships:
#   - /vaultwarden            the server binary (Rust/Rocket; SQLite by default)
#   - /web-vault              the bundled Bitwarden web vault static assets
#   - EXPOSE 80               its default HTTP port
#   - ENTRYPOINT /start.sh    upstream init wrapper
#
# We add python3 + tini for the auth-proxy + clean signal handling, and
# REPLACE the entrypoint with our own supervisor (/opt/openhost-vaultwarden/
# start.sh) so we can run Vaultwarden on loopback behind the OpenHost
# auth-proxy. We invoke the /vaultwarden binary directly rather than going
# through upstream /start.sh, because all the env upstream sets up
# (DATA_FOLDER, ROCKET_*, etc.) we configure ourselves with OpenHost-aware
# values.
#
# Pin a digest/tag in production; `latest` is used here for the portfolio
# artifact so it tracks upstream during review.
FROM docker.io/vaultwarden/server:latest

# tini reaps zombies + forwards SIGTERM to our supervisor; python3 runs the
# auth-proxy + bootstrap; argon2 hashes the ADMIN_TOKEN so Vaultwarden stores a
# hash, not plaintext. ca-certificates is already present in the upstream image
# (Vaultwarden needs it for icon fetching / HIBP), listed defensively.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 tini ca-certificates argon2 \
    && rm -rf /var/lib/apt/lists/*

# Our supervisor + auth-proxy + bootstrap live outside / so they don't shadow
# the upstream /start.sh or the /web-vault assets.
RUN mkdir -p /opt/openhost-vaultwarden
COPY auth_proxy.py /opt/openhost-vaultwarden/auth_proxy.py
COPY bootstrap.py  /opt/openhost-vaultwarden/bootstrap.py
COPY start.sh      /opt/openhost-vaultwarden/start.sh
RUN chmod 0755 \
    /opt/openhost-vaultwarden/start.sh \
    /opt/openhost-vaultwarden/auth_proxy.py \
    /opt/openhost-vaultwarden/bootstrap.py

# The OpenHost router proxies to this port (the auth-proxy listens here);
# Vaultwarden itself binds 127.0.0.1:8001 inside the container.
EXPOSE 8080

# tini as PID 1 so SIGTERM from OpenHost reaches start.sh, which supervises
# Vaultwarden + the auth-proxy via `wait -n`.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-vaultwarden/start.sh"]
