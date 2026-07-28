# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`rca_ui/` is the FortiCNAPP Rapid Cloud Assessment tool — a live security dashboard and two customer-ready HTML/PDF report generators, powered by FortiCNAPP (Lacework) API data. The entire app is one Node.js file, `server.js` (~8,200 lines), with **no npm dependencies** (no `package.json`, no `node_modules`).

> Ancestor `CLAUDE.md` files (`../CLAUDE.md`, `../../CLAUDE.md`, etc.) describe an older ~3,150-line version of `server.js` and are stale on route lists, the posture-score formula, and several features added since (true internet-exposure verification, public storage exposure, governance reports, role-trust correlation, per-CSP scores, in-dashboard AI assistant, report sanitization, a second report format). Treat *this* file as authoritative for `rca_ui/`.

## Run locally

```bash
# Plain HTTP on :8888 (no creds needed — data will be empty/error but server starts)
node server.js

# With real API credentials
LW_ACCOUNT=your-tenant.lacework.net \
LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
LW_SECRET=_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
PORT=8888 \
node server.js

# Sub-account tenant (partner demo orgs) also needs:
LW_SUBACCOUNT=your-subaccount-name

# Alternative to LW_KEY_ID/LW_SECRET/LW_SUBACCOUNT: point at a downloaded key JSON
LW_KEY_FILE=/path/to/keys.json

# Mock mode — load a JSON snapshot instead of calling the API at all
MOCK_FILE=mock_data.json node server.js

# Syntax-check without running (fastest sanity check after an edit — no test suite exists)
node --check server.js
```

## Hot-deploy to a running Docker container

```bash
docker cp server.js rca:/app/server.js && docker restart rca
```

## Docker (production)

```bash
# With Let's Encrypt TLS (requires DOMAIN + LE_EMAIL in .env, port 80 open publicly)
sudo docker build -t rca-dashboard .
sudo docker run --rm -d --name rca \
  -p 80:80 -p 8443:8443 \
  --env-file .env \
  -v letsencrypt:/etc/letsencrypt \
  rca-dashboard

# Convenience scripts (both build + stop-existing + run):
./deploy.sh               # public EC2, ports 80/8443
./deploy_PrivateCloud.sh  # private cloud, ports 80/443
```

Copy `.env.example` → `.env` and fill in credentials. Values must NOT be quoted (Docker reads the file literally). `SELF_SIGNED=true` generates a local cert when DNS isn't propagated yet; supplying `TLS_CERT`/`TLS_KEY` skips both certbot and self-signed. The Dockerfile installs `certbot`, `openssl`, and `chromium` (headless Chromium is invoked by both report builders to render PDFs — `entrypoint.sh` handles the TLS branch at container start).

## Architecture of server.js

Everything lives in one file. Rough layout, in order:

### Server-side (Node.js)

| Section | ~Lines | What it does |
|---|---|---|
| Config | 1–45 | Env vars: `LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, `LW_SUBACCOUNT`, `LW_KEY_FILE`, `PORT`, `PORT_TLS`, `TLS_CERT`, `TLS_KEY`, `MOCK_FILE` |
| HTTP + DNS helpers | 71–270 | `tcpReachable`, `resolveReachableIP`, `request`, `ensureToken`, `withRetry`, `get`/`post`/`postRaw`/`putRaw` |
| API fetchers | 300–1191 | `fetchAlerts`, `fetchTrueExposure`, `fetchVulns`, `fetchCompliance`, `fetchIdentities`, `fetchGovernanceTargets`, `fetchSecretsAll`/`fetchSecrets`, `fetchPublicStorage`, `fetchCveDetails` |
| `refreshData()` | 1198 | Orchestrates the fetchers into the in-memory `cache` object |
| `buildHtml()` | 1291–5606 | Returns the full desktop dashboard as one template literal (CSS + HTML + inline client `<script>`) |
| `MOBILE_HTML` | 5607–~6465 | Static single-scroll mobile view, its own scoring/step logic duplicated inline |
| `sanitizeCacheData()` | 6466 | Deterministically replaces hostnames/ARNs/IPs/emails/account IDs/secret IDs with stable fake values — used by `?sanitize=1` on both report routes |
| Shared report helpers | 6545–6741 | `groupVulnsByHost`, `computeAssetRiskMap`, `computeCspScores`, `tocCardHtml`, `assetRiskTier`, `hostRiskDiagramSvg`, `governanceReportToComplianceRows` |
| `buildReportHtml()` | 6742 | Original customer report → `/report`, saves `rca.html`/`rca.pdf` |
| `buildReportHtml2()` | 7297 | **Beta** wider-scope report → `/report2`, saves `rca2.html`/`rca2.pdf`. Adds per-cloud risk score, exploit-simulation layer, per-host risk diagrams, MFA gaps, high-privilege role/service-account findings |
| `requestHandler()` + routing | 7684–8125 | All HTTP routes (table below) |
| `startApp()` | 8126 | Picks HTTP-only / HTTP+TLS / self-signed based on env, starts listeners |

### Client-side (inline in `buildHtml`, starting ~line 2510)

- `load()` (4453) — fetches `/api/data`, calls all `render*()` functions
- `renderAlerts/Vulns/Compliance/PublicStorage/Identities/SecretsAll/AssetRisk/Lab()` — populate their panels
- `calcPostureScore(d)` (3968) — mirrors the posture-score formula below
- `calcGlobalScoreFromCsp(d)` / `calcCspScore(d,csp)` / `renderCspLab` — per-cloud (AWS/Azure/GCP) score gauges
- `buildAssetRiskMap(d)` / `renderAssetRisk(d)` / `openHostGraph()` — Correlated Risk Findings per Asset + interactive exploit graph
- `nav(name)` — switches dashboard sections (alerts, vulns, compliance, identities, secrets-all, asset-risk, lab)
- `openAiChat`/`sendAiMessage`/`pickAiPrompt` — in-dashboard AI assistant chat backed by `/api/ai/*`
- `loadTrustPrincipals`/`renderIdentityGraph`/`updateGraphEdges` — identity role-trust correlation graph
- `openGeoPanel`/`openCveDetails`/`openComplianceDetails`/`openIdentityDetails`/`openMachineDetails` — detail-drawer modals, each backed by its own `/api/*` route
- `submitLogin()`/`showUserBadge()` — visitor registration flow; POSTs to `/api/register`

### Routes

| URL | Behaviour |
|---|---|
| `GET /` | Desktop dashboard; mobile UA → 302 `/mobile` |
| `GET /mobile` | Mobile single-scroll view |
| `GET /desktop` | Force desktop regardless of UA; supports `#section` hash |
| `GET /health` | Liveness check |
| `GET /api/data` | JSON cache snapshot |
| `GET/POST /api/settings` | Read/write refresh interval and `daysBack` assessment window |
| `POST /api/register` | Save visitor to `contacts.csv` |
| `POST /api/login` | Visitor login (cookie-based) |
| `POST /api/ai/start` | Opens a FortiCNAPP AI Assistant thread for an alert (`AiAssistants/start`, Bedrock Claude provider) |
| `POST /api/ai/message` | Sends a follow-up question on an existing thread (`AiAssistants/{threadId}`) |
| `POST /api/ai/rate` | Records thumbs up/down on an AI response |
| `GET /api/cve` | CVE detail lookup (`fetchCveDetails`) |
| `GET /api/geoip` | IP geolocation for the exploit graph |
| `GET /api/identity-trust` | Trust-principal lookup for the identity graph |
| `GET /api/identity` | Single identity detail |
| `GET /api/machine` | Single host/machine detail |
| `GET /api/governance/targets` | Enumerate cloud accounts eligible for a governance (named-framework) report |
| `GET /api/governance/report` | Run/fetch a governance report for one target |
| `GET /api/fg-facts` | Rotating "did you know" facts shown in the dashboard footer |
| `GET /report[?customer=X&author=Y&sanitize=1]` | Original report → `rca.html`/`rca.pdf` |
| `GET /report2[?customer=X&author=Y&sanitize=1]` | Beta wider-scope report → `rca2.html`/`rca2.pdf` |

## Key behaviours and constraints

**API limits**
- Alerts API hard-caps at 7 days per request — `alertTimeWindows()` splits into 7-day chunks when `daysBack > 7`
- Vulns API always capped at 7 days regardless of `daysBack`
- `withRetry()` retries 5xx + network errors 5× with exponential backoff; 30s timeout per request (120s for AI Assistant calls)
- Compliance results are retained from last successful fetch if the new one returns empty (rate-limit guard)

**DNS / IP pool**
- `resolveReachableIP()` probes all DNS IPs at startup via TCP on port 443 and caches the first reachable one
- Blacklisted IPs expire after 12h; DNS is re-probed every 24h

**Mock mode**
- Set `MOCK_FILE=/path/to/mock_data.json` to bypass all API calls; the file is loaded once at startup and serves as the cache — the fastest way to iterate on dashboard/report UI without live credentials

**Report sanitization**
- `?sanitize=1` on `/report` or `/report2` runs `sanitizeCacheData()` first, deterministically replacing real hostnames, ARNs, account IDs, IPs, emails, and secret IDs with stable fake values (same real value → same fake value within one render) — for sharing screenshots/demos without leaking customer data

**Two report formats, not two phases**
- `/report` and `/report2` are independently maintained builders reading the same `cache`; `/report2` is explicitly commented as beta/wider-scope. Changes to shared logic (asset risk, CSP scores, host grouping) belong in the shared helpers (`computeAssetRiskMap`, `computeCspScores`, `groupVulnsByHost`, `assetRiskTier`), not duplicated per-builder.

**Posture score formula** (server `calcRiskScore` is a *different*, cheaper approximation used only during `refreshData()` logging — the score shown in the UI is `calcPostureScore`, computed client-side and mirrored nowhere server-side):
```
postureScore = max(0, round(100 − mean(findingRiskScores)))
```
Risk weights per finding: alerts→95, CVEs→`riskScore×10` (max 100), compliance→80, identities→`risk_score×100` (max 100), secrets→75. There is no separate secret-count penalty.
Bands: ≥90 green · ≥50 amber · <50 red.

**Correlated Risk Findings per Asset** (`computeAssetRiskMap`, shared by dashboard + both reports)

Four factors summed per host, then normalized 0–100:

| Factor | Points | Source |
|---|---|---|
| CIEM high-perm credential | +100 per secret | `secretsAll` where `SECRET_TYPE` is an SSH key / AWS / GCP / Azure credential type |
| Secret (generic) | +50 per secret | `secretsAll` — all other secret types |
| CVE threat exposure | `riskScore × 10` per CVE (max 100) | `vulns`, matched to host via `machineTags.Hostname` / `evalCtx.hostname` / `mid` |
| Critical misconfiguration | `min(60, criticalPolicyCount × 10)` flat | `compliance` — account-wide, same boost applied to every host with existing risk |

```
assetRawRisk   = Σ(ciem×100) + Σ(genericSecret×50) + Σ(cve.riskScore×10) + min(60, critCompliance×10)
normalizedScore = round(assetRawRisk / maxAssetRawRisk × 100)
```

Risk tier (`assetRiskTier`) — internet exposure (from `fetchTrueExposure`, i.e. an actual open security-group/NSG/firewall rule from a public source, not just a public IP) adjusts the tier:

| Base score | Internet Exposed | Tier |
|---|---|---|
| ≥ 75 | Yes | CRITICAL |
| ≥ 75 | No | MEDIUM (downgraded — no external attack surface) |
| 50–74 | Yes | HIGH |
| 50–74 | No | LOW (downgraded) |
| 30–49 | Any | MEDIUM |
| < 30 | Any | LOW |

**Per-CSP score** (`computeCspScores`, server; mirrored client-side by `calcCspScore`) — rate-based, not raw-count-based, so a cloud with 2 findings and a cloud with 200 findings are scored on the same scale:
```
penalty = 40×(critical/total) + 30×(high/total) + 20×(medium/total) + 10×(low/total)
score   = max(0, round(100 − penalty))
```
Alerts/compliance/identities are bucketed into a cloud by keyword matching on alert type/name, `cloud` field, or `PROVIDER_TYPE`/`CLOUD_PROVIDER`. Overall score is the mean of the three CSP scores (clouds with zero findings score 100, not excluded).

## Collect artefacts from a running container

```bash
docker cp rca:/app/rca.html ./rca.html     # original report
docker cp rca:/app/rca.pdf  ./rca.pdf
docker cp rca:/app/rca2.html ./rca2.html   # beta wider-scope report
docker cp rca:/app/rca2.pdf  ./rca2.pdf
docker cp rca:/app/contacts.csv ./contacts.csv
```
