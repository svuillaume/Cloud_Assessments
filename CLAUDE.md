# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo structure

Each subdirectory is an independent Rapid Cloud Assessment tool for a different Fortinet product:

| Directory | Product | Status |
|-----------|---------|--------|
| `cnapp_rca/` | FortiCNAPP dashboard + PDF report | Live |
| `sspm_rca/` | FortiCASB / SSPM | Placeholder |
| `waap_rca/` | FortiWAAP | Placeholder |

## cnapp_rca — Dashboard

Single-file Node.js server (`cnapp_rca/rca_ui/server.js`, ~3000 lines). No npm dependencies.

### Run & develop

```bash
cd cnapp_rca/rca_ui

# Live mode
LW_ACCOUNT=your-tenant.lacework.net \
LW_KEY_ID=FORTINET_XXXXXXXX \
LW_SECRET=_xxxxxxxx \
PORT=8888 \
node server.js

# Hot-deploy after editing server.js (running container named 'rca'):
docker cp server.js rca:/app/server.js && docker restart rca
```

### Docker (production — EC2 / public server)

```bash
cd cnapp_rca/rca_ui

# With Let's Encrypt (auto TLS):
sudo docker build -t rca-dashboard .
sudo docker run --rm -d --name rca \
  -p 80:80 -p 443:8443 \
  --env-file .env \
  -v letsencrypt:/etc/letsencrypt \
  rca-dashboard

# Or use deploy.sh (builds + runs + updates DuckDNS):
chmod +x deploy.sh && ./deploy.sh

# Private cloud (no DuckDNS update):
chmod +x deploy_PrivateCloud.sh && ./deploy_PrivateCloud.sh
```

Copy `cnapp_rca/rca_ui/.env.example` → `.env` and fill in credentials + `DOMAIN`/`LE_EMAIL` for HTTPS.

### Architecture: server.js

Key sections in order:

- **Config** — env vars (`LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, `PORT`, `TLS_CERT`, `TLS_KEY`, `DOMAIN`)
- **`dynamicDaysBack`** — runtime assessment window (7 or 14 days), set via Admin Settings UI
- **API fetchers** — `fetchAlerts`, `fetchVulns`, `fetchCompliance`, `fetchIdentities`, `fetchSecretsAll`
  - Alerts: two parallel calls (Critical + High), split into 7-day chunks if `dynamicDaysBack > 7` (API hard cap)
  - Vulns: always capped at 7 days (API hard cap)
  - `withRetry()` retries on 5xx and network timeouts (3× with 2/4/6s backoff), 30s timeout per request
- **`buildHtml()`** — returns full desktop dashboard HTML as a template literal
- **`MOBILE_HTML`** — separate single-page mobile view at `/mobile`
- **`buildReportHtml(data, meta)`** — generates the customer-ready HTML/PDF report
- **TLS** — `entrypoint.sh` handles Let's Encrypt via certbot when `DOMAIN`+`LE_EMAIL` set; HTTPS on port 8443, HTTP redirects to HTTPS

### Routing

| URL | Behaviour |
|-----|-----------|
| `/` | Desktop dashboard; mobile UA → 302 `/mobile` |
| `/mobile` | Single-scroll mobile view with hyperlinked next steps |
| `/desktop` | Forces desktop regardless of UA; accepts `#section` hash to auto-navigate |
| `/report?customer=X&author=Y` | Generates HTML report, saves `rca.html` + `rca.pdf` to `/app/` |
| `/api/data` | JSON cache snapshot |
| `/api/settings` | GET/POST refresh interval + assessment window |
| `/api/register` | POST — saves visitor to `contacts.csv` (fields: Timestamp, First, Last, Title, Company, Email, Handle) |

### Scoring

```
postureScore = max(0, round(100 − mean(findingRiskScores)))
```

Risk weights: alerts→95, vulns→`riskScore×10` (max 100), compliance→80, identities→`risk_score×100` (max 100), secrets→75.
Bands: ≥90 green · ≥50 amber · <50 red.

### Report retrieval

```bash
docker cp rca:/app/rca.html ./rca.html
docker cp rca:/app/rca.pdf  ./rca.pdf
```
