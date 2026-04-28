# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Two tools that work together for Fortinet Rapid Cloud Assessment:

1. **Live Dashboard** (`rca_ui/server.js`) — single-file Node.js server, no npm, runs in Docker on port 8080. Connects to the FortiCNAPP (Lacework) v2 API and serves a white-theme Fortinet-branded UI.
2. **CSA Report Generator** (`lw_report_gen.py`) — Python script that produces HTML/PDF Cloud Security Assessment reports via Jinja2 templates.

## Dashboard — build & run

```bash
cd rca_ui

# Build image (once, or after server.js changes)
docker build -t forticnapp-dashboard .

# Live mode
docker run -d --name rca -p 8080:8080 \
  -e LW_ACCOUNT=your-account.lacework.net \
  -e LW_KEY_ID=YOUR_KEY_ID \
  -e LW_SECRET=YOUR_SECRET \
  forticnapp-dashboard

# Mock mode (no credentials)
docker run -d --name rca -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

**Hot-deploy without rebuild** (used throughout this project):
```bash
docker cp rca_ui/server.js <container_name>:/app/server.js && docker restart <container_name>
```
The running container is named `forticnapp-summary`.

**Retrieve visitor contacts:**
```bash
docker cp rca:/app/contacts.csv ./contacts.csv
```

## Report generator — setup & run

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python lw_report_gen.py \
  --author "Name" --customer "Company" \
  --api-key-file my_key.json \
  --report-format html      # or pdf
  --cache-data              # reuse previous API data
```

## Architecture: server.js

`server.js` is a **single self-contained file** (~1200 lines). It contains the full HTTP server, all API fetch logic, and the entire HTML/CSS/JS of the dashboard as a template literal. Key sections in order:

- **Config** — env vars (`LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, `MOCK_FILE`, `PORT`)
- **API fetchers** — `fetchAlerts`, `fetchVulns`, `fetchCompliance`, `fetchIdentities`
  - `fetchCompliance` uses `GET /api/v2/Policies` + `POST /api/v2/Queries/execute` per policy (not `ComplianceEvaluations/search` — that endpoint returns HTTP 400)
  - `refreshData()` runs Phase 1 (alerts/vulns/identities fast) then Phase 2 (compliance, slower due to per-policy queries at 1.2s throttle)
- **`buildHtml(account, intervalSec)`** — returns the full dashboard HTML as a string
- **`MOBILE_HTML`** — separate single-page mobile view served at `/mobile`
- **HTTP server** — routes: `/api/data`, `/api/register`, `/health`, `/mobile`, `/desktop`, `/` (auto-redirects mobile UA to `/mobile`)

**Mock mode**: when `MOCK_FILE` is set, `mock_data.json` is loaded directly into `cache` — no API calls are made. The mock data structure must match what the fetchers return.

## Scoring — Cloud Security Posture Score

Score is 0–100, **higher = better posture**:
```
postureScore = 100 − mean(findingRiskScores)
```
Per-category risk weights fed into the mean: alerts→95, vulns→`riskScore×10` (capped 100), compliance→80, identities→`risk_score×100` (capped 100), secrets→90. No findings → score 100.

Bands: ≥90 Green (Proactive Security) · 60–89 Orange (Some Attention Needed) · 0–59 Red (URGENT – Attention Needed).

See `SCORING_GUIDE.md` for the full formula and worked example.

## Architecture: report generator

`lw_report_gen.py` is the entry point; all data-fetch and rendering logic lives in `modules/`:
- `lacework_interface.py` — FortiCNAPP API client
- `reportgen.py` — orchestrates data fetch → Jinja2 render → HTML/PDF output
- `modules/reports/` — per-section report logic
- `templates/csa_detailed_report.jinja2` — main report template (all CSS inline, self-contained HTML)

PDF generation uses headless Chrome (auto-detected). If Chrome is unavailable, use `--report-format html`.

## Routing

| URL | Served to |
|-----|-----------|
| `/` | Desktop → full dashboard; Mobile UA → 302 to `/mobile` |
| `/mobile` | Single-scroll mobile page (gauge + tiles + next steps) |
| `/desktop` | Forces full dashboard regardless of UA |
| `/api/data` | JSON cache snapshot |
| `/api/register` | POST — saves visitor to `contacts.csv` |
