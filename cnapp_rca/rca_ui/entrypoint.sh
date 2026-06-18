#!/bin/sh
# Entrypoint — TLS options, then start server.js
#
# Environment variables:
#   DOMAIN        — your public domain (e.g. rca.example.com)
#                   When set without SELF_SIGNED, certbot obtains a cert via HTTP-01.
#                   Port 80 must be publicly reachable.
#   LE_EMAIL      — contact email for Let's Encrypt (required with DOMAIN)
#   SELF_SIGNED   — set to "true" to skip certbot and generate a self-signed cert.
#                   Browser will show a warning but HTTPS works immediately.
#   TLS_CERT      — path to an existing fullchain.pem — skips certbot and self-signed
#   TLS_KEY       — path to an existing privkey.pem  — skips certbot and self-signed

set -e

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
SS_DIR="/tmp/selfsigned"

# ── Option 1: self-signed cert ─────────────────────────────────────────────────
if [ "${SELF_SIGNED}" = "true" ] && [ -z "$TLS_CERT" ]; then
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
  export TLS_CERT="${SS_DIR}/fullchain.pem"
  export TLS_KEY="${SS_DIR}/privkey.pem"
  echo "[tls] Self-signed cert generated for CN=${CN}"

# ── Option 2: Let's Encrypt via certbot ───────────────────────────────────────
elif [ -n "$DOMAIN" ] && [ -z "$TLS_CERT" ]; then
  echo "[tls] Domain: $DOMAIN — running certbot …"

  if [ -z "$LE_EMAIL" ]; then
    echo "[tls] ERROR: LE_EMAIL must be set when DOMAIN is set" >&2
    exit 1
  fi

  certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$LE_EMAIL" \
    --domain "$DOMAIN" \
    --keep-until-expiring \
    --http-01-port 80

  export TLS_CERT="${CERT_DIR}/fullchain.pem"
  export TLS_KEY="${CERT_DIR}/privkey.pem"
  echo "[tls] Cert obtained: $TLS_CERT"
fi

# ── Start server ───────────────────────────────────────────────────────────────
if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  echo "[tls] HTTPS mode — cert: $TLS_CERT"
else
  echo "[tls] No cert configured — running HTTP only on port ${PORT:-8080}"
fi

exec node /app/server.js
