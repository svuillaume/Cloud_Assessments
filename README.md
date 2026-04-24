# FortiCNAPP Rapid Cloud Assessment

[![View Sample RCA Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

Live dashboard for real-time cloud security posture + automated CSA report generator for FortiCNAPP (Lacework CNAPP).

## ðŸŽ¯ Quick Demo

| Tool | Description | Run Command |
|------|-------------|-------------|
| **Live Dashboard** | Real-time alerts, CVEs, identities, compliance | `docker run -p 8080:8080 ...` |
| **CSA Report Gen** | PDF/HTML Cloud Security Assessment reports | `python lw_report_gen.py ...` |

## ðŸš€ Quick Start

### 1. Get FortiCNAPP API Key
```
https://<account>.lacework.net â†’ Settings â†’ API Keys â†’ Create New â†’ Download JSON
```

**Env vars needed:**
```
LW_ACCOUNT=your-account.lacework.net
LW_KEY_ID=your_key_id
LW_SECRET=your_secret
```

### 2. Live Dashboard (Docker)
```bash
cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d -p 8080:8080 \
  -e LW_ACCOUNT=your-account.lacework.net \
  -e LW_KEY_ID=your_key_id \
  -e LW_SECRET=your_secret \
  forticnapp-dashboard
```
**Open:** http://localhost:8080

**Mock mode (no creds):**
```bash
docker run -d -p 8080:8080 -e MOCK_FILE=/app/mock_data.json forticnapp-dashboard
```

### 3. Generate Report
```bash
pip install -r requirements.txt
python lw_report_gen.py --author "Your Name" --customer "Acme Corp"
```

---

## ðŸ“Š Features

### Live Dashboard (`rca_ui/`)
- **Real-time alerts** & compliance violations
- **CVE prioritization** (runtime context)
- **Identity exposure** & privilege risks  
- **Custom risk scoring** (0-10, Building/Maturing/Optimizing)
- **Export contacts** for customer reports

### Report Generator (`lw_report_gen.py`)
- **Full PDF/HTML** CSA reports
- **Compliance frameworks**: CIS, PCI, NIST, SOC2, HIPAA, ISO27001, CSA CCM
- **Custom scoring** & risk heatmaps
- **Author/customer branding**

---

## ðŸ“ˆ Risk Scoring (0-10)

Maps maturity stages:

| Stage | Maturity % | Risk (0-10) | Color | Focus |
|-------|------------|-------------|-------|-------|
| **BUILDING** | 0-49 | 7-10 | ðŸ”´ Red | Inventory, MFA, patching |
| **MATURING** | 50-89 | 4-6 | ðŸŸ  Orange | Policies, automation, DevSecOps |
| **OPTIMIZING** | 90-100 | 0-3 | ðŸŸ¢ Green | AI triage, zero-trust, runtime |

**Gauge visualization** included in both tools.

---

## ðŸ“± Fetch Contacts for Reports

1. **Create empty file:**
   ```bash
   touch rca_ui/contacts.csv
   ```

2. **Start dashboard** (container `rca` in your example)

3. **Copy generated contacts:**
   ```bash
   sudo docker cp rca:/app/contacts.csv rca_ui/contacts.csv
   ```

4. **View:**
   ```bash
   cat rca_ui/contacts.csv
   ```

**Use:** Add customer contacts to personalize reports.

---
