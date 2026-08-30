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

# NOTE: this HTTP-only run block previously had -p 443:8443 and -v letsencrypt:/etc/letsencrypt
# commented out mid-command, which (since a `#` starting a continued line ends that logical
# shell command right there) silently truncated the whole `docker run` invocation before
# --env-file/rca-dashboard were ever reached. Left as HTTP-only intentionally, just fixed to
# actually be valid shell.
sudo docker run --rm -d \
  --name rca \
  -p 80:80 \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --cap-add=CHOWN \
  --env-file .env \
  rca-dashboard

# Fetch EC2 public IP (IMDSv2)
#TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
#  -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
#PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
#  http://169.254.169.254/latest/meta-data/public-ipv4)

# Map rapidassessment.duckdns.org -> PUBLIC_IP
#curl -s "https://www.duckdns.org/update?domains=rapidassessment&token=${DUCKDNS_TOKEN}&ip=${PUBLIC_IP}"
#echo ""

#echo "https://rapidassessment.duckdns.org/ -> https://${PUBLIC_IP}"
