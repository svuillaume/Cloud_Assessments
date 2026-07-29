# Fortinet Rapid Cloud Assessment

A live security dashboard and customer-ready Cloud Rapid Assessment Report powered by FortiCNAPP.

---

## Table of Contents

1. [Overview](#overview)
2. [New Here? Start With This](#new-here-start-with-this)
3. [Dashboard Sections](#dashboard-sections)
4. [How the Posture Score Works](#how-the-posture-score-works)
5. [Correlated Risk Findings per Asset](#correlated-risk-findings-per-asset)
6. [Identity & Access Risk](#identity--access-risk)
7. [Assessment Windows](#assessment-windows)
8. [Prerequisites](#prerequisites)
9. [Quick Start](#quick-start)
10. [Step-by-Step Setup](#step-by-step-setup)
11. [Production Deployment with HTTPS](#production-deployment-with-https)
12. [Using Your Own TLS Certificate](#using-your-own-tls-certificate)
13. [Persistent Cache](#persistent-cache)
14. [Updating the Dashboard](#updating-the-dashboard)
15. [Collecting Visitor Contacts](#collecting-visitor-contacts)
16. [Troubleshooting](#troubleshooting)
17. [Additional Resources](#additional-resources)

---

## Overview

This project provides two tools that work together to deliver cloud security insights from FortiCNAPP:

| Tool | File | Purpose |
|------|------|---------|
| Live Dashboard | `rca_ui/server.js` | Real-time web UI displaying posture score, alerts, CVEs, secrets, identities, compliance, and correlated asset risk |
| PDF Report | (generated via `/report`) | Customer-ready HTML/PDF report exported from live data |

The dashboard is a single Node.js file with **no npm dependencies**. Run it directly with Node.js or inside Docker.

---

## New Here? Start With This

A few things that make this codebase different from a typical web app, worth knowing before you dive in:

- **It's one file, on purpose.** `rca_ui/server.js` (~9,200 lines) is the entire application — server and client — with no `package.json`, no `npm install`, no build step, and no framework (no Express, no React). You run it with a single command: `node server.js`.
- **Two programs live in that one file.** The Node.js *server* code (talks to the FortiCNAPP API, keeps a data cache, handles HTTP requests) is completely separate from the *browser* code (the dashboard you see on screen). The trick: the server code has a giant function, `buildHtml()`, that builds the entire webpage — including all of its JavaScript — as one big text string, then sends that string to your browser. Once your browser has it, that JavaScript runs *there*, not on the server. So if you're reading a function and wondering "does this run on the server or in my browser?" — that's the single most useful question to ask, and the answer changes what the function can and can't do (server code can read secrets and call the FortiCNAPP API; browser code can only call the dashboard's own `/api/*` routes and manipulate the page you see).
- **No database.** Everything the dashboard shows lives in one in-memory JavaScript object called `cache`, refreshed on a timer (once a day by default) by pulling fresh data from FortiCNAPP. It's also saved to a small file (`data/cache.json`) so a restart doesn't show a blank dashboard while new data loads.
- **Three different "reports" exist** (`/report`, `/report2`, `/report3`) — they're not versions of each other, they're three different documents (a conservative customer report, a detailed "beta" report, and a condensed executive overview) that all read the same underlying data.
- **Want to know what a specific function does?** See [`FUNCTION_REFERENCE.md`](./rca_ui/FUNCTION_REFERENCE.md) — a plain-English walkthrough of every function in `server.js`, organized by section, written for someone seeing this codebase for the first time.

---

## Dashboard Sections

### Dashboard (sidebar)

| Section | What it shows |
|---------|--------------|
| **CSPM Score** | "Cloud Security Risk Score" gauge (global posture score) + per-finding risk table |
| **CSPM Score per CSP** | Per-cloud (AWS / Azure / GCP) posture breakdown |
| **Exploit Simulation Layer** | AI-assisted attack path simulation, lab scenarios, and Correlated Risk Findings per Asset (hosts ranked by combined CIEM + Secrets + CVE + Misconfig risk, tiered by internet exposure) |

### Threat Center (sidebar)

| Section | What it shows |
|---------|--------------|
| **High Fidelity Alerts** | Anomaly + Composite alerts, Critical & High severity; AI Triage button auto-fires when ready |

### Risk Findings (sidebar)

| Section | What it shows |
|---------|--------------|
| **Private Host Most Exposed** | Non-internet-exposed hosts with CVE risk ≥ 9, enriched with correlated Secrets/CIEM credentials — rendered as asset-detail cards (Asset Details, Cloud Context, Security Findings, full CVE table). Internet-exposed hosts are tracked separately, not shown here — see the Beta tab and Risk Findings Inventory's Host Exposure category below |
| **Identities** | Admin-privilege identities only, one uniform rule across AWS/Azure/GCP: (User type **and** Full Admin) OR (IAM Role type **and** Full Admin) OR Root/root-equivalent. Service Accounts, Service Principals, Instance Profiles, Groups, and Assumed Roles are excluded regardless of privilege |
| **Critical Misconfigurations** | CSPM policy violations, Critical & High severity |
| **Secrets** | Discovered secrets and credentials across hosts |
| **Public Storage Exposure** | S3 / Azure Blob buckets confirmed public via policy/ACL, or via a traced Internet→bucket network path (`LW_APA_EXPOSURE_PATHS`) |
| **FortiGate** | Fortinet appliance inventory — FortiGate plus other Fortinet product lines (FortiManager, FortiADC, etc.), discovered via compute inventory and exposure-path scans, with click-to-filter summary tiles |
| **Internet Exposed Assets** | Unfiltered view of every asset FortiCNAPP's Attack Path Analysis (`LW_APA_EXPOSURE_PATHS`) has traced a route to from the internet, across all target types, with click-to-filter tiles |
| **Internet-Exposed Host — Beta** | A second, independently-filtered view matching the FortiCNAPP console's own filter exactly: Online/Launched machines, Vulnerable, Internet Exposed = Yes, CVE risk score ≥ 9 — enriched with Critical CSPM findings, Secrets, and high-permission IAM role/instance profile (AWS). Same asset-card format as Private Host Most Exposed; kept as a separate tab for side-by-side comparison |
| **Attack Paths** | `LW_APA_ATTACK_PATHS` results with click-to-filter severity tiles (Critical / High / Medium / Low) |
| **Risk Findings Inventory** | Consolidated list of every finding feeding the posture score — Alerts, Host Exposure, Identities, Critical Misconfigurations, Secrets — grouped by category, each collapsed by default (click a header to expand its list, or the "N findings ↗" link to jump to that tab) |

---

## How the Posture Score Works

Every cloud environment gets a single score from **0 to 100 — higher is better.**

### Score bands

| Score | Meaning | Action |
|:-----:|---------|--------|
| 90 – 100 | **Proactive Security** | Strong posture. Keep monitoring. |
| 50 – 89 | **Some Attention Needed** | Real gaps exist. Prioritise Critical and High findings. |
| 0 – 49 | **URGENT** | High risk. Immediate action required. |

### Global score formula

```
postureScore = max(0, round(100 − mean(findingRiskScores)))
```

Risk weights per finding type:

| Finding type | Risk weight |
|-------------|------------|
| High-Fidelity Alert — Critical | 80 |
| High-Fidelity Alert — High | 60 |
| High-Fidelity Alert — Medium | 40 |
| CVE (Internet Threat Exposure, `riskScore ≥ 8` only — lower-risk CVEs are excluded) | `riskScore × 10` (max 100) |
| Critical Misconfiguration | 80 |
| Identity — Admin + No-MFA + (unused entitlements ≥ 80% OR an access key ≥ 180 days old) | 80 |
| Identity — otherwise | `risk_score × 100` (max 100) |
| Secret (discovered credential) | 10 |

> **Three different CVE thresholds exist in this tool — don't confuse them.** The posture score above weights CVEs at `riskScore ≥ 8`. The Private Host Most Exposed / Internet-Exposed Host (Beta) panels display CVEs at `cveRiskScore ≥ 9`. The Risk Findings Inventory's "Host Exposure" category is stricter still, at `cveRiskScore ≥ 9.95` (a separate, fully-paginated fetch, not the 500-row-capped one behind the posture score). Each exists for a different purpose — see [`SCORING_GUIDE.md`](./SCORING_GUIDE.md) for the full breakdown.

> For the full per-CSP formula, worked examples, and scoring rationale see [`SCORING_GUIDE.md`](./SCORING_GUIDE.md).

---

## Correlated Risk Findings per Asset

Hosts are ranked by a combined four-factor risk score that correlates CVEs, secrets, CIEM credentials, and misconfigurations **per host**.

### Scoring factors (Critical → Low)

| Factor | Severity | Points | Data source |
|--------|----------|--------|-------------|
| CIEM High-Perm credential | Critical | +100 per credential | `secretsAll` — SSH keys, AWS/GCP/Azure credentials |
| Secret (generic) | High | +50 per secret | `secretsAll` — all other secret types |
| CVE Internet Threat Exposure | Medium | `riskScore × 10` per CVE | `vulns` — Lacework composite risk score |
| Critical Misconfiguration | Low | `min(60, criticalPolicyCount × 10)` flat | `compliance` — account-wide, same boost per at-risk host |

```
assetRawRisk    = Σ(CIEM×100) + Σ(secret×50) + Σ(cve.riskScore×10) + min(60, critCompliance×10)
normalizedScore = round(assetRawRisk / maxAssetRawRisk × 100)
```

Assets with `normalizedScore ≤ 20` or `powerState = stopped/terminated` are excluded.

### Risk tier — adjusted by internet exposure

Internet exposure is a critical amplifier. A host with high raw risk but no public attack surface is deprioritised:

| Base score | Internet Exposed | Displayed tier |
|-----------|-----------------|---------------|
| ≥ 75 | Yes | 🔴 **CRITICAL** |
| ≥ 75 | No  | 🟡 **MEDIUM** — high score, no external attack surface |
| 50–74 | Yes | 🟠 **HIGH** |
| 50–74 | No  | ⚪ **LOW** — no internet exposure |
| 30–49 | Either | 🟡 **MEDIUM** |
| < 30  | Either | ⚪ **LOW** |

Each card shows a circular score ring, a gradient risk bar, and per-factor breakdown tiles (CIEM, Secrets, Threat Exposure, Misconfig). A GeoIP lookup button appears for assets with a known public IP.

---

## Identity & Access Risk

Queries `LW_CE_IDENTITIES` across AWS, Azure, and GCP, then applies one uniform admin-only rule across all three clouds (`pruneToAdmin()`).

### Filter criteria

Keep an identity only if **one of these is true**:

- **User type** (IAM User / Azure User) **and** the `ALLOWS_FULL_ADMIN` risk flag
- **IAM Role type** **and** the `ALLOWS_FULL_ADMIN` risk flag
- **Root or root-equivalent** — AWS root account, Azure Global Administrator, GCP Workspace Super Admin (always included, regardless of the Admin flag — these are inherently top-privilege by definition)

Everything else is dropped **regardless of privilege level** — Service Accounts, Service Principals, Instance Profiles, IAM Groups, and Assumed Roles are excluded entirely, even ones with Full Admin. This keeps the tab focused on identities a human or role could actually be held accountable for, not machine-to-machine service identities.

> The Risk Findings Inventory's "Identities" count narrows this further — Admin identities only, `risk_severity = Critical`, and **root/root-equivalent accounts are explicitly excluded** (unlike the Identity tab itself, which always keeps them).

### Three-tab view — flat sortable table

Each tab renders a flat table with columns: **#** · **Identity name** · **Identity type** · **Risk severity** · **Risk flags** · **Unused / Total entitlements**.

| Tab | Contents |
|-----|----------|
| **Root / Admin — No MFA** | Root accounts and Full Admin identities with no MFA enabled — highest remediation priority |
| **All Identities** | All qualifying identities sorted by risk score descending; Copy ARN + Trust button per row |
| **Correlated Identities** | Identities grouped by type (Roles / Users / Service Accounts) with section headers |

### Risk flag circles

Eight fixed-position circles appear per row — colored when active, gray when not. Hover shows full risk name.

| Circle | Risk flag |
|--------|-----------|
| **FA** | Full Admin (`ALLOWS_FULL_ADMIN`) |
| **PE** | Privilege Escalation (`ALLOWS_PRIVILEGE_ESCALATION`) |
| **MFA** | No MFA (`PASSWORD_LOGIN_NO_MFA`) |
| **EP** | Excessive Permissions (`EXCESSIVE_PERMISSIONS`) |
| **XA** | Cross-Account Access (`CROSS_ACCOUNT_ACCESS`) |
| **CON** | Console Access (`HAS_CONSOLE_ACCESS`) |
| **UP** | Permissions Unused 90d (`UNUSED_PERMISSION_90_DAYS`) |
| **UK** | Access Key Unused 90d (`UNUSED_ACCESS_KEY_90_DAYS`) |

### Trust principal lookup

`/api/identity-trust?pid=<PRINCIPAL_ID>` — queries `LW_CE_IDENTITIES` for the single identity's `TRUST_POLICY` and `METRICS.lateral_movement_principals`, returns a list of `{ type, principal }` pairs representing who can assume the role.

---

## Assessment Windows

| Finding Type | Severities Fetched | Look-back Window | Notes |
|---|---|---|---|
| High-Fidelity Alerts | Critical, High | **14 days** | Policy + Anomaly + Composite; chunked into 7-day API calls |
| Compliance | Critical, High | **14 days** | Sequential fetch to avoid rate-limit collisions |
| Identities | Critical + 75%+ unused + Full Admin | **7 days** | AWS / Azure / GCP roles, users, service accounts; hard-capped at 7d (LQL limit) |
| Secrets (SSH keys) | All | **7 days** | Hard-capped at 7d (LQL limit) |
| Secrets All | All | **7 days** | Hard-capped at 7d (LQL limit) |
| CVEs / Vulnerabilities | Critical, High · riskScore ≥ 8 · Unpatched (Active) | **7 days** | Hard cap imposed by Lacework API; two parallel calls merged, capped at 500 rows. Not restricted to internet-exposed hosts at fetch time — exposure is a separate, per-host signal checked afterward by each panel individually |
| Host Exposure (Risk Findings Inventory) | Any severity · cveRiskScore ≥ 9 | **7 days** | Separate, fully-paginated fetch (`fetchHighRiskVulns()`) — not capped at 500 rows like the row above. The Risk Findings Inventory further narrows this to ≥ 9.95 (displayed risk score rounds to 100) and to hosts also confirmed internet-exposed in the CVE fetch above |

The default window is **14 days** and can be adjusted in the Admin Settings panel (7 / 14 / 21 / 30 days). CVEs, Identities, and Secrets always remain at 7 days due to API/LQL limits.

---

## Prerequisites

### 1. Runtime Environment

| Option | Download |
|--------|----------|
| Node.js 18+ | https://nodejs.org |
| Docker | https://docs.docker.com/get-docker/ |

### 2. FortiCNAPP API Key

1. Log in to your FortiCNAPP console
2. Go to **Settings → API Keys**
3. Click **Download** to save the JSON file — you'll need `LW_ACCOUNT`, `LW_KEY_ID`, and `LW_SECRET`

> Skip this step to test in mock mode (`MOCK_FILE=mock_data.json node server.js`).

### 3. Public Domain Name (production HTTPS only)

A domain pointing to your server's public IP. Free option: [DuckDNS](https://www.duckdns.org).

---

## Quick Start

```bash
cd rca_ui
node server.js
```

Open `http://localhost:8888`. For production HTTPS, follow the full setup below.

---

## Step-by-Step Setup

### Step 1: Get the Code

```bash
cd rca_ui
```

### Step 2: Create Your Configuration File

Create `.env` in the `rca_ui` folder:

```bash
DUCKDNS_TOKEN=your-token-here
PORT=80
DOMAIN=domain.yourdomain.com
LE_EMAIL=you@example.com
LW_ACCOUNT=your-tenant.lacework.net
LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX
LW_SECRET=_xxxxxxxxxxxxxxxxxxxx
```

**Rules:** No quotes around values. Docker reads the file literally.

### Step 3: Deploy

- **Production HTTPS** → see [Production Deployment with HTTPS](#production-deployment-with-https)
- **Existing certificate** → see [Using Your Own TLS Certificate](#using-your-own-tls-certificate)

---

## Production Deployment with HTTPS

### How it works

When `DOMAIN` is set, `entrypoint.sh`:
1. Runs `certbot` for the Let's Encrypt HTTP-01 challenge on port 80
2. Obtains a signed certificate
3. Starts Node.js in HTTPS mode on port 8443
4. Redirects HTTP → HTTPS

### Requirements checklist

- [ ] Domain DNS A record points to server IP
- [ ] Port **80** publicly reachable (ACME challenge)
- [ ] Port **443** open for HTTPS
- [ ] `.env` filled in correctly

### Build and run

```bash
sudo docker build -t rca-dashboard .

sudo docker run --rm -d \
    --name rca \
    -p 80:80 \
    -p 443:8443 \
    --env-file .env \
    -v letsencrypt:/etc/letsencrypt \
    -v rca-cache:/app/data \
    rca-dashboard
```

`-v rca-cache:/app/data` persists the fetched-data cache to a named Docker volume — see [Persistent Cache](#persistent-cache) below. Omitting it still works, it just means every container recreation starts from a blank cache instead of last-known-good data.

Or use the convenience scripts:

```bash
./deploy.sh              # Public EC2 — also updates DuckDNS A record
./deploy_PrivateCloud.sh # Private cloud — skips DuckDNS
```

### Verify

```bash
sudo docker logs -f rca
```

---

## Using Your Own TLS Certificate

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

Set `SELF_SIGNED=true` in `.env` to generate a self-signed cert automatically (no Let's Encrypt, no domain required).

---

## Persistent Cache

The dashboard's fetched-data cache (alerts, CVEs, identities, compliance, secrets, etc.) is written to `/app/data/cache.json` after every refresh cycle and restored automatically on startup — **before** the first live API fetch even begins. This means the dashboard shows last-known-good data immediately after a restart or redeploy, instead of blank panels while `refreshData()` runs (which can take several minutes — the compliance scan alone evaluates every enabled Critical/High policy in throttled batches).

### How it's persisted

- **`docker restart rca`** (hot-deploy) already preserves it with no extra setup — the container's writable filesystem layer survives a restart on its own.
- **A full `docker rm` + recreate** (e.g. via `deploy.sh`/`deploy_PrivateCloud.sh`) needs the cache directory mounted to a Docker volume, which both scripts do automatically:
  ```
  -v rca-cache:/app/data
  ```
  `rca-cache` is a **named volume** (not a host path), so this works identically on any machine — Docker creates and manages the actual storage location per-host, with no manual directory setup required.

### What it does *not* change

- A restart still immediately triggers a full `refreshData()` in the background, same as before — the cache file just means panels show the *previous* cycle's data while that runs, instead of showing nothing.
- The persisted cache has no separate expiry — it's simply overwritten by the next successful `refreshData()` cycle (twice: once after the fast Phase 1 fetch, again after Phase 2 compliance/secrets/public-storage complete).
- To start completely fresh (e.g. testing), remove the volume: `docker volume rm rca-cache` (only after stopping the `rca` container).

---

## Updating the Dashboard

Hot-deploy a change to `server.js` without rebuilding the image:

```bash
docker cp rca_ui/server.js rca:/app/server.js && docker restart rca
```

---

## Collecting Artefacts

```bash
docker cp rca:/app/rca.html    ./rca.html      # latest report HTML
docker cp rca:/app/rca.pdf     ./rca.pdf       # latest report PDF
docker cp rca:/app/contacts.csv ./contacts.csv  # visitor registrations
```

---

## API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Desktop dashboard; mobile UA → 302 `/mobile` |
| `/mobile` | GET | Mobile single-scroll view |
| `/desktop` | GET | Force desktop; supports `#section` hash |
| `/report?customer=X&author=Y` | GET | Generate HTML/PDF report from cache |
| `/api/data` | GET | Full JSON data cache snapshot |
| `/api/settings` | GET / POST | Read / write refresh interval and `daysBack` |
| `/api/register` | POST | Save visitor to `contacts.csv` |
| `/api/login` | POST | Email login — returns dashboard HTML directly |
| `/api/identity-trust?pid=<ARN>` | GET | Trust principals for an identity (who can assume this role) |
| `/api/geoip?ip=<IPv4>` | GET | GeoIP lookup via ipinfo.io (server-side proxy, cached) |

---

## Troubleshooting

### Authentication Failed

- Confirm `LW_ACCOUNT` is the full hostname, e.g. `xxx.lacework.net`
- Confirm `LW_KEY_ID` and `LW_SECRET` match the downloaded JSON exactly
- Check the API key has not been revoked in the FortiCNAPP console

### Dashboard Shows No Data or a Spinner

```bash
docker logs -f rca
```

Phase 2 (compliance then secretsAll) runs sequentially after Phase 1 and can take 60–120 s. Wait for the live indicator to turn green.

### HTTPS Certificate Not Issued

- Port 80 must be publicly reachable for the ACME challenge
- DNS A record must point to the server's public IP
- `LE_EMAIL` must be a valid address

---

## Additional Resources

- [`FUNCTION_REFERENCE.md`](./rca_ui/FUNCTION_REFERENCE.md) — beginner-friendly, function-by-function walkthrough of `server.js`
- [`SCORING_GUIDE.md`](./SCORING_GUIDE.md) — full scoring formula and worked example
- [`CLAUDE.md`](./CLAUDE.md) — developer guide for Claude Code (architecture, scoring, key behaviours)
- FortiCNAPP documentation: https://docs.fortinet.com
- Let's Encrypt: https://letsencrypt.org
- DuckDNS (free DNS): https://www.duckdns.org

---

Made for the FortiCNAPP community.
