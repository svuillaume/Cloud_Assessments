FROM node:18-alpine
RUN apk add --no-cache certbot openssl chromium libcap
# `docker run --cap-add=X` on a non-root (USER node) process only populates the container's
# capability BOUNDING set — verified empirically that it does NOT also populate the EFFECTIVE/
# AMBIENT sets a non-root exec actually needs to use that capability (CapBnd showed the granted
# caps present, CapEff/CapAmb both stayed all-zero, and `chown` failed "Operation not permitted"
# despite --cap-add=CHOWN being set). File capabilities sidestep this entirely — they're checked
# directly against the binary's own extended attributes at execve() time, independent of ambient
# propagation, and only require the capability to already be within the container's bounding set
# (which --cap-add establishes) — so they're the reliable way to make NET_BIND_SERVICE/CHOWN
# actually usable by the non-root `node` user set below, on any host, regardless of whether that
# host also happens to have net.ipv4.ip_unprivileged_port_start=0 (which — separately — already
# make privileged-port binds work for everyone regardless of capabilities, and is NOT something
# to rely on, since a hardened host can and often does set it back to 1024).
RUN setcap cap_chown=+ep "$(readlink -f "$(which chown)")" && \
    setcap cap_net_bind_service=+ep "$(readlink -f "$(which node)")" && \
    setcap cap_net_bind_service=+ep "$(readlink -f "$(which python3)")"
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
# dropped except the two actually needed: NET_BIND_SERVICE (Node/certbot/python3's port-80
# binds, made effective via the setcap block above) and CHOWN (entrypoint.sh's one-time
# ownership self-heal on pre-existing, root-owned volumes, likewise via setcap):
#   docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN ...
# (already wired into install.sh / deploy_CASignedCert.sh) — --cap-add alone, without the
# setcap block above, does NOT actually make these usable by the non-root user; see that
# comment for why.
