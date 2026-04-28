<div align="center">

# Fortinet Rapid Cloud Assessment

**A live security dashboard and customer-ready PDF report powered by the FortiCNAPP API.**

[![📄 View Sample Report](https://img.shields.io/badge/📄_View-Sample_Report-blue?style=for-the-badge)](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>

---

## What this is

Two tools that work together:

| Tool | File | What it does |
|------|------|--------------|
| **Live Dashboard** | `rca_ui/server.js` | Real-time web UI — Cloud Security Posture Management Score, alerts, CVEs, secrets, identities, compliance | 
---

## Running the Dashboard

The dashboard is a single Node.js file with no npm dependencies. Run it directly or inside Docker.

### Prerequisites

| Requirement | Install |
|-------------|---------|
| Node.js 18+ **or** Docker | [nodejs.org](https://nodejs.org) · [docker.com](https://docs.docker.com/get-docker/) |
| FortiCNAPP API key JSON | Settings → API Keys → Download (skip for mock mode) |
| Proper Applicaiton domain | USe your best DNS provider - I personally use "DuckDNS.org" |

---


###  HTTPS / TLS (production) w/ Lets Encrypt Signed Certificate

The container handles TLS automatically via `entrypoint.sh`. When `DOMAIN` is set, **certbot** runs the Let's Encrypt HTTP-01 challenge on port 80, obtains a signed certificate, and starts the Node server in HTTPS mode on port 8443. HTTP on port 80 then redirects to HTTPS.

**Requirements:**
- A public domain pointing to your server's IP
- Port **80** publicly reachable (for the ACME HTTP-01 challenge)
- Port **8443** open for HTTPS traffic

**`.env` file on your server:**
```bash
PORT=80
DOMAIN=domain.yourdomain.com
LE_EMAIL=you@example.com
LW_ACCOUNT=your-tenant.lacework.net
LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX
LW_SECRET=_xxxxxxxxxxxxxxxxxxxx
```

> **No quotes** around values — Docker reads `.env` literally.

**Build and run:**
```bash
cd rca_ui
sudo docker build -t rca-dashboard .

sudo docker run --rm -d \
    --name rca \
    -p 80:80 \
    -p 8443:8443 \
    --env-file .env \
    -v letsencrypt:/etc/letsencrypt \
    rca-dashboard
```

The `-v letsencrypt:/etc/letsencrypt` volume persists the certificate across container restarts so certbot does not re-issue on every start (`--keep-until-expiring` is set). Check progress with:

```bash
sudo docker logs -f rca
```

Expected output:
```
[tls] Domain: rapidassessment.yourdomain.com — running certbot …
[tls] Cert obtained: /etc/letsencrypt/live/rapidassessment.yourdomain.com/fullchain.pem
[tls] HTTPS mode — cert: /etc/letsencrypt/live/…/fullchain.pem
│  Open     : https://domain.yourdomain.com:8443
```

Dashboard will be available at **https://domain.yourdomain.com:8443**.

**Supply your own existing certificate** (skip certbot):
```bash
sudo docker run --rm -d \
    --name rca \
    -p 80:80 \
    -p 8443:8443 \
    -v /path/to/certs:/certs:ro \
    -e TLS_CERT=/certs/fullchain.pem \
    -e TLS_KEY=/certs/privkey.pem \
    --env-file .env \
    rca-dashboard
```

# Hot-deploy a server.js change without full rebuild:
docker cp rca_ui/server.js rca:/app/server.js && docker restart rca
```
---

See [SCORING_GUIDE.md](SCORING_GUIDE.md) for the full formula and worked example.

---

## Collecting Visitor Contacts

Every login is saved automatically inside the container:

```bash
docker cp rca:/app/contacts.csv ./contacts.csv
cat contacts.csv
```

---

## Troubleshooting

```

**Authentication failed**
- Confirm `LW_ACCOUNT` is the full hostname: `xxx.lacework.net`
- Confirm `LW_KEY_ID` and `LW_SECRET` match the downloaded JSON exactly
- Check the key hasn't been revoked in the FortiCNAPP console

**Dashboard shows no data / spinner**
- Check logs: `docker logs -f rca` or watch the terminal output
- Phase 2 (compliance) can take 30–60s — wait for the live dot to turn green


Made with ❤️ for the FortiCNAPP community

