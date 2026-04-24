# FortiCNAPP Rapid Cloud Assessment

> **[📄 View Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)**

Two tools, one repository:

| Tool | File | Purpose |
|------|------|---------|
| **Live Dashboard** | `rca_ui/server.js` | Real-time web UI — alerts, CVEs, identities, compliance |
| **CSA Report Generator** | `lw_report_gen.py` | Generates PDF + HTML Cloud Security Assessment reports |

---

## API Key Setup

1. Log in to `https://<your-account>.lacework.net`
2. Go to **Settings → Configuration → API Keys → + Create New**
3. Download the JSON file and note these values:

| Variable | Where to find it | Example |
|----------|-----------------|---------|
| `LW_ACCOUNT` | Console hostname | `partner-demo.lacework.net` |
| `LW_KEY_ID` | `keyId` in the JSON | `FORTINET_67A1D371...` |
| `LW_SECRET` | `secret` in the JSON | `_8dd983bbcac9...` |

---

## Live Dashboard

```bash
cd rca_ui

# Build
docker build -t forticnapp-dashboard .

# Run (live)
docker run -d --name rca -p 8080:8080 \
  -e LW_ACCOUNT=your-account.lacework.net \
  -e LW_KEY_ID=YOUR_KEY_ID \
  -e LW_SECRET=YOUR_SECRET \
  forticnapp-dashboard

# Run (mock — no credentials needed)
docker run -d --name rca -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

Open **http://localhost:8080**

---

## CSA Report Generator

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

python lw_report_gen.py --author "John Smith" --customer "Acme Corp"
```

| Flag | Description |
|------|-------------|
| `--report-format html\|pdf` | Output format (default: html) |
| `--api-key-file FILE` | JSON API key file |
| `--cache-data` | Reuse cached API data |
| `--compliance-framework` | CIS, PCI, NIST_CSF, SOC2, HIPAA, ISO_27001, CSA_CCM |

---

## Visitor Contacts

Each dashboard login is recorded automatically. To retrieve the contact list:

```bash
# 1 — Find the container name
docker ps -a

# 2 — Copy contacts.csv from the container to your host
docker cp rca:/app/contacts.csv ./contacts.csv

# 3 — View
cat contacts.csv
```

The file contains: `Timestamp, FirstName, LastName, Company, Role, Email`

---

## Files

| File | Description |
|------|-------------|
| `rca_ui/server.js` | Dashboard server |
| `rca_ui/Dockerfile` | Dashboard container |
| `rca_ui/mock_data.json` | Offline data snapshot |
| `rca_ui/report_runner.js` | Host-side report runner |
| `lw_report_gen.py` | CSA report generator |
| `SCORING_GUIDE.md` | Risk score formulas |
