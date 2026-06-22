# Fortinet Rapid Cloud Assessment

A live security dashboard and customer-ready Cloud Rapid Assessment Report powered by FortiCNAPP.

---

## Table of Contents

1. [Overview](#overview)
2. [Dashboard Sections](#dashboard-sections)
3. [How the Posture Score Works](#how-the-posture-score-works)
4. [Correlated Risk Findings per Asset](#correlated-risk-findings-per-asset)
5. [Identity & Access Risk](#identity--access-risk)
6. [Assessment Windows](#assessment-windows)
7. [Prerequisites](#prerequisites)
8. [Quick Start](#quick-start)
9. [Step-by-Step Setup](#step-by-step-setup)
10. [Production Deployment with HTTPS](#production-deployment-with-https)
11. [Using Your Own TLS Certificate](#using-your-own-tls-certificate)
12. [Updating the Dashboard](#updating-the-dashboard)
13. [Collecting Visitor Contacts](#collecting-visitor-contacts)
14. [Troubleshooting](#troubleshooting)
15. [Additional Resources](#additional-resources)

---

## Overview

This project provides two tools that work together to deliver cloud security insights from FortiCNAPP:

| Tool | File | Purpose |
|------|------|---------|
| Live Dashboard | `rca_ui/server.js` | Real-time web UI displaying posture score, alerts, CVEs, secrets, identities, compliance, and correlated asset risk |
| PDF Report | (generated via `/report`) | Customer-ready HTML/PDF report exported from live data |

The dashboard is a single Node.js file with **no npm dependencies**. Run it directly with Node.js or inside Docker.

---

## Dashboard Sections

### Dashboard (sidebar)

| Section | What it shows |
|---------|--------------|
| **CSPM Score** | Global posture gauge + per-finding risk table |
| **CSPM Score per CSP** | Per-cloud (AWS / Azure / GCP) posture breakdown |
| **Correlated Risk / Asset** | Hosts ranked by combined CIEM + Secrets + CVE + Misconfig risk, tiered by internet exposure |
| **Exploit Simulation Layer** | AI-assisted attack path simulation and lab scenarios |

### Threat Center (sidebar)

| Section | What it shows |
|---------|--------------|
| **High Fidelity Alerts** | Anomaly + Composite alerts, Critical & High severity; AI Triage button auto-fires when ready |

### Risk Findings (sidebar)

| Section | What it shows |
|---------|--------------|
| **Internet Threat Exposure** | CVEs: Critical + High severity · Unpatched (Active) · riskScore ≥ 8 · internet-exposed hosts only |
| **Identities** | High-permissive IAM roles, users, and service accounts across AWS / Azure / GCP — flat table, 3-tab view |
| **Critical Misconfigurations** | CSPM policy violations, Critical & High severity |
| **Secrets** | Discovered secrets and credentials across hosts |

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
postureScore = max(0, round(100 − mean(findingRiskScores) − min(20, secretCount × 0.5)))
```

Risk weights per finding type:

| Finding type | Risk weight |
|-------------|------------|
| High-Fidelity Alert | 95 |
| CVE (Internet Threat Exposure) | `riskScore × 10` (max 100) |
| Critical Misconfiguration | 80 |
| Identity (high-perm) | `risk_score × 100` (max 100) |
| Secret (discovered credential) | −0.5 pts each, capped at −20 |

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

Queries `LW_CE_IDENTITIES` for high-permissive cloud identities across AWS, Azure, and GCP.

### Filter criteria (any match qualifies)

- Risk severity = **Critical**
- Unused permissions ≥ **75%**
- **Full Admin** flag (`ALLOWS_FULL_ADMIN`)

Identity types included: IAM Roles, IAM Users, Service Accounts, Service Principals (AWS / Azure / GCP). Root accounts are always included.

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
| CVEs / Vulnerabilities | Critical, High · riskScore ≥ 8 · Unpatched · Internet-exposed hosts | **7 days** | Hard cap imposed by Lacework API; two parallel calls merged |

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
    rca-dashboard
```

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

- [`SCORING_GUIDE.md`](./SCORING_GUIDE.md) — full scoring formula and worked example
- [`CLAUDE.md`](./CLAUDE.md) — developer guide for Claude Code (architecture, scoring, key behaviours)
- FortiCNAPP documentation: https://docs.fortinet.com
- Let's Encrypt: https://letsencrypt.org
- DuckDNS (free DNS): https://www.duckdns.org

---

Made for the FortiCNAPP community.
