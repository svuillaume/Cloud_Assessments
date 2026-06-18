#!/bin/bash
set -e

. ./.env

sudo docker build -f Dockerfile -t rca-dashboard .

if sudo docker ps --format '{{.Names}}' | grep -qx "rca"; then
  sudo docker stop rca
  sleep 1
fi

sudo docker run --rm -d \
  --name rca \
  -p 80:80 \
  --env-file .env \
  rca-dashboard
