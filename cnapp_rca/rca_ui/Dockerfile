FROM node:18-alpine
RUN apk add --no-cache certbot openssl chromium
WORKDIR /app
COPY server.js .
COPY roi-calculator.html .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Least-privilege: run as the `node` user (uid/gid 1000) baked into the node:* base images,
# not root. Everything the app writes at runtime — /app itself (contacts.csv, rca*.html/pdf,
# data/cache.json) plus certbot's config/work/log dirs — needs to be owned by that user ahead
# of time. Docker seeds a *fresh* named volume's initial content and ownership from whatever
# already exists at the mount path in the image, so pre-creating and chowning /etc/letsencrypt
# and /app/data here means a first-time `-v letsencrypt:/etc/letsencrypt` / `-v
# rca-cache:/app/data` mount inherits the right ownership automatically — no root needed at
# runtime for that case. An *existing* volume from a prior root-run deployment can still be
# root-owned though; entrypoint.sh self-heals that at startup if CAP_CHOWN is granted (see
# `docker run` flags below).
RUN mkdir -p /app/data /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt && \
    chown -R node:node /app /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt

USER node
EXPOSE 80 8443
ENTRYPOINT ["/entrypoint.sh"]

# Run with least-privilege flags — rootless (USER node above) plus every Linux capability
# dropped except the two actually needed: NET_BIND_SERVICE (both Node and certbot's standalone
# ACME challenge bind port 80, a privileged port <1024) and CHOWN (entrypoint.sh's one-time
# ownership self-heal on pre-existing, root-owned volumes — see comment above):
#   docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN ...
# (already wired into install.sh / deploy_CASignedCert.sh)
