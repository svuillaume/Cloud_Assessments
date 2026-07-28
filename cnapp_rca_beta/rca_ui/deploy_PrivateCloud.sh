#!/bin/sh
set -e

# Load DUCKDNS_TOKEN from .env
. ./.env

sudo docker build -f Dockerfile -t rca-dashboard .

# Stop existing rca container if running
if sudo docker ps --format '{{.Names}}' | grep -qx "rca"; then
  sudo docker stop rca
  sleep 1
fi

sudo docker run --rm -d \
  --name rca \
  -p 80:80 \
  -p 443:8443 \
  --env-file .env \
  -v letsencrypt:/etc/letsencrypt \
  rca-dashboard
