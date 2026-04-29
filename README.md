<div align="center">

# Fortinet Rapid Cloud Assessment

**A live security dashboard and customer-ready PDF report powered by the FortiCNAPP API.**

[![📄 View Sample Report](https://img.shields.io/badge/📄_View-Sample_Report-blue?style=for-the-badge)](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>

---

## What this is

A single-file Node.js dashboard with a built-in report generator:

| Feature | How to access |
|---------|---------------|
| **Live Dashboard** (desktop) | `/` or `/desktop` |
| **Mobile view** | `/mobile` — gauge + score band + hyperlinked next steps |
| **CSA Report** (HTML + PDF) | `/report?customer=Acme&author=YourName` |

---

## Running the Dashboard

The dashboard is a single Node.js file with no npm dependencies. Run it directly or inside Docker.

### Prerequisites

| Requirement | Install |
|-------------|---------|
| Node.js 18+ **or** Docker | [nodejs.org](https://nodejs.org) · [docker.com](https://docs.docker.com/get-docker/) |
| FortiCNAPP API key JSON | Settings → API Keys → Download (skip for mock mode) |

---

### Option A — Mock mode (no credentials, works offline)

Perfect for demos and offline presentations.

**With Node.js:**
```bash
cd rca_ui
PORT=8080 MOCK_FILE=mock_data.json node server.js
```

**With Docker:**
```bash
cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d --name rca -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

Open **http://localhost:8080** — sample data loads immediately, no login to FortiCNAPP required.

---

### Option B — Live mode (connects to FortiCNAPP)

You need a FortiCNAPP API key JSON file. Download it from:
> **FortiCNAPP console → Settings → Configuration → API Keys → Create New → Download**

The JSON file looks like:
```json
{
  "keyId":   "FORTINET_XXXXXXXXXXXXXXXX",
  "secret":  "_xxxxxxxxxxxxxxxxxxxx",
  "account": "your-tenant.lacework.net"
}
```

**With Node.js (recommended for development):**
```bash
cd rca_ui
LW_ACCOUNT=your-tenant.lacework.net \
LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX \
LW_SECRET=_xxxxxxxxxxxxxxxxxxxx \
PORT=8080 \
node server.js
```

Or read directly from the key file:
```bash
cd rca_ui
KEY_FILE=../your-key.json
LW_ACCOUNT=$(python3 -c "import json; print(json.load(open('$KEY_FILE'))['account'])") \
LW_KEY_ID=$(python3 -c "import json; print(json.load(open('$KEY_FILE'))['keyId'])") \
LW_SECRET=$(python3 -c "import json; print(json.load(open('$KEY_FILE'))['secret'])") \
PORT=8080 \
node server.js
```

**With Docker:**
```bash
cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d --name rca -p 8080:8080 \
  -e LW_ACCOUNT=your-tenant.lacework.net \
  -e LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX \
  -e LW_SECRET=_xxxxxxxxxxxxxxxxxxxx \
  forticnapp-dashboard
```

Open **http://localhost:8080** — data loads in the background (Phase 1: alerts/CVEs/identities/secrets ~5s, Phase 2: compliance ~30–60s).

---

### Option C — HTTPS / TLS (production)

The container handles TLS automatically via `entrypoint.sh`. When `DOMAIN` is set, **certbot** runs the Let's Encrypt HTTP-01 challenge on port 80, obtains a signed certificate, and starts the Node server in HTTPS mode on port 8443. HTTP on port 80 then redirects to HTTPS.

**Requirements:**
- A public domain pointing to your server's IP
- Port **80** publicly reachable (for the ACME HTTP-01 challenge)
- Port **443** open for HTTPS traffic

**`.env` file on your server:**
```bash
PORT=80
DOMAIN=rapidassessment.yourdomain.com
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
    -p 443:8443 \
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
│  Open     : https://rapidassessment.yourdomain.com
```

Dashboard will be available at **https://rapidassessment.yourdomain.com**.

**Supply your own existing certificate** (skip certbot):
```bash
sudo docker run --rm -d \
    --name rca \
    -p 80:80 \
    -p 443:8443 \
    -v /path/to/certs:/certs:ro \
    -e TLS_CERT=/certs/fullchain.pem \
    -e TLS_KEY=/certs/privkey.pem \
    --env-file .env \
    rca-dashboard
```

---

### Docker management

```bash
docker stop rca          # stop
docker start rca         # restart
docker rm -f rca         # delete (required before re-running with new keys)
docker logs -f rca       # view logs

# Hot-deploy a server.js change without full rebuild:
docker cp rca_ui/server.js rca:/app/server.js && docker restart rca
```

---

### run-rca.sh — Quick start script

`run-rca.sh` assumes the image is already built. It stops any existing `rca` container and starts a fresh one from the `rca-dashboard` image using your `.env` file.

```bash
#!/usr/bin/env bash
#
# run-rca.sh - Manage RCA Dashboard Docker container
#
# Logic:
#   1. Check if 'rca-dashboard' image exists locally.
#   2. If a container named 'rca' already exists, stop and remove it.
#   3. Run 'rca-dashboard' as container 'rca' on port 8080 with .env file.
#

set -euo pipefail

# ---- Configuration ----------------------------------------------------------
IMAGE_NAME="rca-dashboard"
CONTAINER_NAME="rca"
HOST_PORT=80
CONTAINER_PORT=80
ENV_FILE=".env"

# ---- Helpers ----------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date +'%H:%M:%S')" "$*"; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

image_exists() {
    sudo docker images --format '{{.Repository}}' | grep -Fxq "$1"
}

container_exists() {
    sudo docker ps -a --format '{{.Names}}' | grep -Fxq "$1"
}

# ---- Pre-flight checks ------------------------------------------------------
command -v docker >/dev/null 2>&1 || fail "docker is not installed or not in PATH"
[[ -f "${ENV_FILE}" ]] || fail "Env file '${ENV_FILE}' not found in $(pwd)"

# ---- Main logic -------------------------------------------------------------
if ! image_exists "${IMAGE_NAME}"; then
    fail "Image '${IMAGE_NAME}' not found locally. Build it first (e.g. 'sudo docker build -t ${IMAGE_NAME} .') or pull it."
fi

log "Image '${IMAGE_NAME}' is present."

if container_exists "${CONTAINER_NAME}"; then
    log "Existing container '${CONTAINER_NAME}' found - stopping and removing..."
    sudo docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    sudo docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    log "Container '${CONTAINER_NAME}' removed."
fi

log "Starting container '${CONTAINER_NAME}' from image '${IMAGE_NAME}'..."
sudo docker run --rm -d \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:${CONTAINER_PORT}" \
    --env-file "${ENV_FILE}" \
    "${IMAGE_NAME}"

log "Container '${CONTAINER_NAME}' started. Listening on http://localhost:${HOST_PORT}"
```

> **`.env` must include `PORT=80`** so Node binds inside the container on port 80.

Save as `run-rca.sh` in `rca_ui/`, then:

```bash
chmod +x run-rca.sh
./run-rca.sh
```

---

## Generating a CSA Report

The dashboard has a built-in report generator — no Python, no extra tools required.

### 1. Open the report URL

Navigate to the report endpoint from the desktop dashboard, or open directly:

```
https://your-host/report?customer=Customer+Corp&author=Your+Name
```

The page renders immediately in the browser.

### 2. Saved files (auto-generated on every report request)

The server writes two files to `/app/` inside the container:

| File | Format |
|------|--------|
| `rca.html` | Full standalone HTML report |
| `rca.pdf` | PDF generated by headless Chromium |

### 3. Retrieve from the container

```bash
docker cp rca:/app/rca.html ./rca.html
docker cp rca:/app/rca.pdf  ./rca.pdf
```

---

## Cloud Security Posture Management Score

The dashboard computes a **0–100 posture score** — **higher is better**:

```
postureScore = max(0, round(100 − mean(findingRiskScores)))
```

| Category | Risk Weight |
|----------|:-----------:|
| High Fidelity Alerts | 95 |
| Internet Threat Exposure (CVE risk ≥ 9.0) | `riskScore × 10` |
| Critical Misconfigurations | 80 |
| Identities (no MFA) | `risk_score × 100` |
| Secrets | 75 |

| Score | Band |
|:-----:|------|
| 90–100 | Proactive Security 🟢 |
| 50–89 | Some Attention Needed 🟠 |
| 0–49 | URGENT – Attention Needed 🔴 |

See [SCORING_GUIDE.md](SCORING_GUIDE.md) for the full formula and worked example.

---

## Collecting Visitor Contacts

Every login is saved automatically inside the container:

```bash
docker cp rca:/app/contacts.csv ./contacts.csv
cat contacts.csv
```

Columns: `Timestamp, FirstName, LastName, Company, Role, Email`

---

## Troubleshooting

**Port 8080 already in use**
```bash
# Use a different port:
PORT=9090 MOCK_FILE=mock_data.json node server.js
# or with Docker: -p 9090:8080
```

**Authentication failed**
- Confirm `LW_ACCOUNT` is the full hostname: `xxx.lacework.net`
- Confirm `LW_KEY_ID` and `LW_SECRET` match the downloaded JSON exactly
- Check the key hasn't been revoked in the FortiCNAPP console

**Dashboard shows no data / spinner**
- Check logs: `docker logs -f rca` or watch the terminal output
- Phase 2 (compliance) can take 30–60s — wait for the live dot to turn green

**PDF generation fails / `rca.pdf` not produced**
- Chromium is bundled in the Docker image — rebuild if using an older image: `docker build -t rca-dashboard .`
- Check container logs: `docker logs -f rca`

---

<div align="center">

Made with ❤️ for the FortiCNAPP community

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html) · [🐛 Issues](../../issues)

</div>
