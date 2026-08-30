#!/bin/sh
# Entrypoint — TLS options, then start server.js
#
#   SELF_SIGNED=true  — generate a self-signed cert, skip certbot
#   DOMAIN + LE_EMAIL — obtain a Let's Encrypt cert via certbot (port 80 must be open)
#   TLS_CERT + TLS_KEY — use an existing certificate (skips everything above)
#   (none)            — plain HTTP on PORT (default 8888)
#
# Runs as the non-root `node` user (see Dockerfile) — the whole container should be started
# with --cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN for least-privilege.

# ── One-time ownership self-heal for pre-existing volumes ──────────────────────
# The Dockerfile pre-chowns /etc/letsencrypt and /app/data so a *fresh* named volume mount
# inherits correct ownership automatically. A volume that already existed from a prior
# root-run deployment of this container won't have picked that up, though — this best-effort
# fixes it in place if CAP_CHOWN was granted. Silent on failure so this never turns into a hard
# startup failure — including the one case CAP_CHOWN alone can't fully cover: it lets this
# non-root process change a file's *owner* without already owning it, but it does NOT grant
# directory *traversal* into a restrictively-permissioned (e.g. 0700) tree it can't otherwise
# read into, so a deeply-locked-down existing volume may only get partially fixed here. If
# certbot/the app still can't write after this runs, do a one-time host-side fix instead:
#   docker run --rm -v letsencrypt:/etc/letsencrypt -v rca-cache:/app/data alpine \
#     chown -R 1000:1000 /etc/letsencrypt /app/data
chown -R node:node /etc/letsencrypt /app/data 2>/dev/null || true

SS_DIR="/tmp/selfsigned"
CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

# ── Option 1: self-signed ─────────────────────────────────────────────────────
if [ "${SELF_SIGNED}" = "true" ] && [ -z "$TLS_CERT" ]; then
  if [ -f "${SS_DIR}/fullchain.pem" ] && [ -f "${SS_DIR}/privkey.pem" ]; then
    echo "[tls] SELF_SIGNED=true — reusing existing self-signed certificate (${SS_DIR})"
  else
    echo "[tls] SELF_SIGNED=true — generating self-signed certificate …"
    mkdir -p "$SS_DIR"
    CN="${DOMAIN:-localhost}"
    openssl req -x509 -newkey rsa:2048 \
      -keyout "${SS_DIR}/privkey.pem" \
      -out    "${SS_DIR}/fullchain.pem" \
      -days 3650 -nodes \
      -subj "/C=US/ST=CA/O=Fortinet/CN=${CN}" \
      -addext "subjectAltName=DNS:${CN},IP:127.0.0.1" \
      2>/dev/null
    echo "[tls] Self-signed cert ready (CN=${CN}) — browser will warn once, click Advanced → Proceed"
  fi
  export TLS_CERT="${SS_DIR}/fullchain.pem"
  export TLS_KEY="${SS_DIR}/privkey.pem"

# ── Option 2: Let's Encrypt ───────────────────────────────────────────────────
elif [ -n "$DOMAIN" ] && [ -z "$TLS_CERT" ]; then
  if [ -z "$LE_EMAIL" ]; then
    echo "[tls] WARNING: LE_EMAIL not set — skipping certbot, running HTTP only"
  else
    echo "[tls] Domain: $DOMAIN — running certbot …"
    if certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "$LE_EMAIL" \
        --domain "$DOMAIN" \
        --keep-until-expiring \
        --http-01-port 80; then
      export TLS_CERT="${CERT_DIR}/fullchain.pem"
      export TLS_KEY="${CERT_DIR}/privkey.pem"
      echo "[tls] Cert obtained: $TLS_CERT"
    else
      echo "[tls] WARNING: certbot failed (DNS not ready?) — falling back to HTTP only"
      echo "[tls] Tip: set SELF_SIGNED=true in .env to use HTTPS without DNS"
    fi
  fi
fi

# ── Start server ───────────────────────────────────────────────────────────────
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  echo "[tls] HTTPS mode — cert: $TLS_CERT"
else
  echo "[tls] No cert — running HTTP only on port ${PORT:-8888}"
fi

exec node /app/server.js
