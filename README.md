# FortiCNAPP Rapid Cloud Assessment

> **[📄 View Sample RCA Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)**

This repository contains two complementary tools:

| Tool | File | Purpose |
|------|------|---------|
| **Live Dashboard** | `rca_ui/server.js` | Real-time web UI — alerts, CVEs, identities, compliance in one view |
| **CSA Report Generator** | `lw_report_gen.py` | Generates full PDF + HTML Cloud Security Assessment reports |

---

## Prerequisites

- **Node.js 18+** (for the dashboard)
- **Python 3.9+** (for the report generator)
- A **FortiCNAPP / Lacework API key** (see Authentication below)
- **Docker** (optional, for containerised dashboard)

---

## Authentication

You need a FortiCNAPP API key before using either tool.

### Create an API key

1. Log in to `https://<your-account>.lacework.net`
2. Go to **Settings → Configuration → API Keys**
3. Click **+ Create New**, give it a name, click **Create**
4. Download the generated JSON file:

```json
{
  "keyId":   "YOURACCOUNTNAME_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "secret":  "_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
}
```

| Variable      | Where to find it           | Example                              |
|---------------|----------------------------|--------------------------------------|
| `LW_ACCOUNT`  | Your console hostname      | `partner-demo.lacework.net`          |
| `LW_KEY_ID`   | `keyId` in the JSON file   | `FORTINET_67A1D371E0F19273...`       |
| `LW_SECRET`   | `secret` in the JSON file  | `_8dd983bbcac982efa1859d7...`        |

---

## Part 1 — Live Dashboard (rca_ui/)

See **[rca_ui/README.md](rca_ui/README.md)** for full Docker setup and run instructions.

### Quick start

```bash
cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d --name forticnapp-dashboard -p 8080:8080 \
  -e LW_ACCOUNT=your-account.lacework.net \
  -e LW_KEY_ID=YOUR_KEY_ID \
  -e LW_SECRET=YOUR_SECRET \
  forticnapp-dashboard
```

Open **http://localhost:8080**.

### Mock mode (no credentials needed)

```bash
docker run -d --name forticnapp-dashboard -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

---

## Part 2 — CSA Report Generator (lw_report_gen.py)

### Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Generate a report

```bash
python lw_report_gen.py --author "John Smith" --customer "Acme Corp"
```

### Common options

| Flag | Description |
|------|-------------|
| `--author NAME` | Author name inserted into the report |
| `--customer NAME` | Customer / company name |
| `--report-format html\|pdf` | Output format (default: html) |
| `--report-path PATH` | Output filename |
| `--api-key-file FILE` | JSON API key file |
| `--cache-data` | Reuse locally cached API data |
| `--compliance-framework` | CIS, PCI, NIST_CSF, SOC2, HIPAA, ISO_27001, CSA_CCM |
| `--list-reports` | Show available report types |

---

## Files

| File | Description |
|------|-------------|
| `rca_ui/server.js` | Live dashboard server |
| `rca_ui/mock_data.json` | API data snapshot for offline/demo mode |
| `rca_ui/Dockerfile` | Dashboard container |
| `rca_ui/report_runner.js` | Host-side runner for report generation |
| `lw_report_gen.py` | CSA report generator (Python) |
| `SCORING_GUIDE.md` | Risk score formulas for both tools |
