# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`cnapp_rca/` is the FortiCNAPP Rapid Cloud Assessment tool — a live security dashboard and customer-ready PDF report, powered by FortiCNAPP (Lacework) API data. Everything lives in one Node.js file with no npm dependencies.

## Run locally

```bash
cd rca_ui

# Plain HTTP on :8080 (no creds needed — data will be empty/error but server starts)
node server.js

# With real API credentials
LW_ACCOUNT=your-tenant.lacework.net \
LW_KEY_ID=FORTINET_XXXXXXXX \
LW_SECRET=_xxxxxxxx \
node server.js

# Mock mode — load a JSON snapshot instead of calling the API
MOCK_FILE=mock_data.json node server.js
```

## Hot-deploy to a running Docker container

```bash
docker cp rca_ui/server.js rca:/app/server.js && docker restart rca
```

## Docker (production)

```bash
cd rca_ui

# With Let's Encrypt TLS (requires DOMAIN + LE_EMAIL in .env, port 80 open publicly)
sudo docker build -t rca-dashboard .
sudo docker run --rm -d --name rca \
  -p 80:80 -p 443:8443 \
  --env-file .env \
  -v letsencrypt:/etc/letsencrypt \
  rca-dashboard

# Convenience scripts (both build + run):
./deploy.sh              # public EC2 — also updates DuckDNS A record
./deploy_PrivateCloud.sh # private cloud — skips DuckDNS
```

Copy `.env.example` → `.env` and fill in credentials. Values must NOT be quoted (Docker reads the file literally).

## Architecture of server.js

The entire application is one file (`rca_ui/server.js`, ~3150 lines). Sections in order:

### Server-side (Node.js)

| Section | Lines | What it does |
|---------|-------|-------------|
| Config | ~19–37 | Env vars: `LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, `PORT`, `PORT_TLS`, `TLS_CERT`, `TLS_KEY`, `MOCK_FILE`, `dynamicDaysBack` |
| HTTP helpers | ~50–165 | `request()`, `withRetry()`, `get()`, `post()`, DNS resolution with IP blacklisting |
| Auth | ~109–125 | `ensureToken()` — OAuth2 token cached for ~56 min |
| API fetchers | ~179–467 | `fetchAlerts`, `fetchVulns`, `fetchCompliance`, `fetchIdentities`, `fetchSecretsAll`, `fetchSecrets` |
| `refreshData()` | ~408–467 | Phase 1: parallel fast fetch; Phase 2: compliance (sequential to avoid rate-limit collision) |
| `buildHtml()` | ~471–1793 | Returns full desktop dashboard HTML as a template literal (CSS + HTML + inline `<script>`) |
| `MOBILE_HTML` | ~1798–~2574 | Static mobile view with score gauge and next-step links |
| `buildReportHtml()` | ~2575–2955 | Generates the customer PDF/HTML report from cached data |
| HTTP server + routing | ~2956–3153 | `requestHandler`, server startup, TLS branch |

### Client-side (inline in `buildHtml`)

The dashboard JS (starting ~line 1604 inside the template literal) fetches `/api/data` and renders all panels. Key client functions:

- `load()` — fetches `/api/data`, calls all `render*()` functions
- `renderAlerts/Vulns/Compliance/Identities/SecretsAll()` — populate their panels
- `calcPostureScore(d)` — computes the posture score from cached data (mirrors server formula)
- `nav(name)` — switches between dashboard sections (alerts, vulns, compliance, identities, secrets-all, asset-risk, lab)
- `submitLogin()` / `showUserBadge()` — visitor registration flow; POSTs to `/api/register`

### Routes

| URL | Behaviour |
|-----|-----------|
| `GET /` | Desktop dashboard; mobile UA → 302 `/mobile` |
| `GET /mobile` | Mobile single-scroll view |
| `GET /desktop` | Force desktop regardless of UA; supports `#section` hash |
| `GET /report?customer=X&author=Y` | HTML report from cache; saves `rca.html` + `rca.pdf` via headless Chromium |
| `GET /api/data` | JSON cache snapshot |
| `GET/POST /api/settings` | Read/write refresh interval and `daysBack` assessment window |
| `POST /api/register` | Save visitor to `contacts.csv` |

## Key behaviours and constraints

**API limits**
- Alerts API hard-caps at 7 days per request — `alertTimeWindows()` splits into 7-day chunks when `daysBack > 7`
- Vulns API always capped at 7 days regardless of `daysBack`
- `withRetry()` retries 5xx + network errors 3× with 2/4/6s backoff; 30s timeout per request
- Compliance results are retained from last successful fetch if the new one returns empty (rate-limit guard)

**DNS / IP pool**
- `resolveReachableIP()` probes all DNS IPs at startup via TCP on port 443 and caches the first reachable one
- Blacklisted IPs expire after 12h; DNS is re-probed every 24h

**Two-phase refresh**
- `refreshData()` runs alerts + vulns + identities + secrets in parallel (Phase 1), then compliance sequentially (Phase 2) to avoid triggering rate limits from concurrent LQL queries

**Mock mode**
- Set `MOCK_FILE=/path/to/mock_data.json` to bypass all API calls; the file is loaded once at startup and serves as the cache

**Posture score formula**
```
postureScore = max(0, round(100 − mean(findingRiskScores) − min(20, secretCount × 0.5)))
```
Risk weights: alerts→95, CVEs→`riskScore×10` (max 100), compliance→80, identities→`risk_score×100` (max 100). Secrets apply a separate −0.5 pt penalty each, capped at −20 pts.

**Correlated Risk Findings per Asset — scoring formula**

Four factors ranked Critical → Low, summed per host then normalized 0–100:

| Factor | Severity | Points | Data source |
|--------|----------|--------|-------------|
| CIEM High-Perm credential | Critical | +100 per secret | `secretsAll` where `SECRET_TYPE` ∈ SSH key / AWS / GCP / Azure credential types |
| Secret (generic) | High | +50 per secret | `secretsAll` — all other secret types |
| CVE Internet Threat Exposure | Medium | `riskScore × 10` per CVE (max 100) | `vulns` — Lacework composite score (CVSS + exploitability + network exposure) |
| Critical Misconfiguration | Low | `min(60, criticalPolicyCount × 10)` flat | `compliance` — account-wide critical policies; same boost applied to every at-risk host |

```
assetRawRisk = Σ(CIEM×100) + Σ(secret×50) + Σ(cve.riskScore×10) + min(60, critCompliance×10)
normalizedScore = round(assetRawRisk / maxAssetRawRisk × 100)
```

Assets with `normalizedScore ≤ 20` or `powerState = stopped/terminated` are excluded.
CIEM and Misconfig are account-wide (no per-host data in the API); Threat Exposure and Secrets are per-host.

## Collect artefacts from a running container

```bash
docker cp rca:/app/rca.html ./rca.html   # latest report HTML
docker cp rca:/app/rca.pdf  ./rca.pdf    # latest report PDF
docker cp rca:/app/contacts.csv ./contacts.csv
```
