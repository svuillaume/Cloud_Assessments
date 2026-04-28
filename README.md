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
| **CSA Report Generator** | `lw_report_gen.py` | Generates a PDF/HTML Cloud Security Assessment report |

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

Run behind HTTPS using Let's Encrypt (requires a public domain with port 80 reachable):

```bash
docker run -d --name rca \
  -p 80:80 -p 8443:8443 \
  -e DOMAIN=rca.yourdomain.com \
  -e LE_EMAIL=you@example.com \
  -e LW_ACCOUNT=your-tenant.lacework.net \
  -e LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX \
  -e LW_SECRET=_xxxxxxxxxxxxxxxxxxxx \
  -v letsencrypt:/etc/letsencrypt \
  forticnapp-dashboard
```

Or supply an existing certificate:
```bash
docker run -d --name rca \
  -p 8080:8080 -p 8443:8443 \
  -v /path/to/certs:/certs:ro \
  -e TLS_CERT=/certs/fullchain.pem \
  -e TLS_KEY=/certs/privkey.pem \
  -e LW_ACCOUNT=your-tenant.lacework.net \
  -e LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX \
  -e LW_SECRET=_xxxxxxxxxxxxxxxxxxxx \
  forticnapp-dashboard
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
HOST_PORT=8080
CONTAINER_PORT=8080
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

Save as `run-rca.sh` in `rca_ui/`, then:

```bash
chmod +x run-rca.sh
./run-rca.sh
```

---

## Generating a CSA Report

### 1. Set up Python environment

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 2. Generate

```bash
python lw_report_gen.py \
  --author "Your Name" \
  --customer "Customer Corp" \
  --api-key-file your-key.json
```

Default output: HTML file in the current folder. Open in any browser.

### 3. Common options

| Flag | Description | Example |
|------|-------------|---------|
| `--report-format` | `html` or `pdf` | `--report-format pdf` |
| `--api-key-file` | Path to key JSON | `--api-key-file ./my_key.json` |
| `--cache-data` | Reuse previous API data (faster) | `--cache-data` |
| `--compliance-framework` | Framework to score against | `--compliance-framework CIS` |

Supported frameworks: `CIS` · `PCI` · `NIST_CSF` · `SOC2` · `HIPAA` · `ISO_27001` · `CSA_CCM`

---

## Cloud Security Posture Management Score

The dashboard computes a **0–100 posture score** — **higher is better**:

```
postureScore = max(0, round(100 − mean(findingRiskScores) − secretCount × 0.5))
```

| Category | Risk Weight |
|----------|:-----------:|
| High Fidelity Alerts | 95 |
| Internet Threat Exposure (CVE risk ≥ 9.0) | `riskScore × 10` |
| Critical Misconfigurations | 80 |
| Identities (no MFA) | `risk_score × 100` |
| Secrets (per secret, outside mean) | −0.5 pts |

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

**PDF generation fails**
- Requires headless Chromium: `pip install weasyprint`
- Or use `--report-format html` instead

---

<div align="center">

Made with ❤️ for the FortiCNAPP community

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html) · [🐛 Issues](../../issues)

</div>
