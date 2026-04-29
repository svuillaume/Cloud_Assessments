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

# Fetch EC2 public IP (IMDSv2)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/public-ipv4)

# Map rapidassessment.duckdns.org -> PUBLIC_IP
curl -s "https://www.duckdns.org/update?domains=rapidassessment&token=${DUCKDNS_TOKEN}&ip=${PUBLIC_IP}"
echo ""

echo "https://rapidassessment.duckdns.org/ -> https://${PUBLIC_IP}"
