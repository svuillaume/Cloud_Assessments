#!/bin/sh
# Entrypoint — optional Let's Encrypt cert acquisition, then start server.js
#
# Environment variables:
#   DOMAIN      — your public domain (e.g. rca.example.com)
#                 When set, certbot obtains/renews a cert via HTTP-01 challenge.
#                 Port 80 must be publicly reachable.
#   LE_EMAIL    — contact email for Let's Encrypt (required when DOMAIN is set)
#   TLS_CERT    — (optional) path to an existing fullchain.pem — skips certbot
#   TLS_KEY     — (optional) path to an existing privkey.pem  — skips certbot

set -e

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"

if [ -n "$DOMAIN" ] && [ -z "$TLS_CERT" ]; then
  echo "[tls] Domain: $DOMAIN — running certbot …"

  if [ -z "$LE_EMAIL" ]; then
    echo "[tls] ERROR: LE_EMAIL must be set when DOMAIN is set" >&2
    exit 1
  fi

  # Use --standalone; port 80 must be free (map -p 80:80 in docker run)
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

if [ -n "$TLS_CERT" ] && [ -n "$TLS_KEY" ]; then
  echo "[tls] HTTPS mode — cert: $TLS_CERT"
else
  echo "[tls] No cert configured — running HTTP only on port ${PORT:-8080}"
fi

exec node /app/server.js
