# FortiCNAPP Rapid Cloud Assessment
Modern and beginner-friendly cloud security posture review tool for **FortiCNAPP (Lacework CNAPP)**.
Use this project to quickly generate dashboards, security findings, maturity scores, and customer-ready reports.
[View Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)
---
## Contents
- Overview
- Features
- Requirements
- Quick Start
- Dashboard
- Report Generator
- Risk Score Model
- Export Contacts
- Common Use Cases
- License
---
## Overview
FortiCNAPP Rapid Cloud Assessment helps you understand the security state of your cloud environment in minutes.
It is designed for:
- Beginners learning CNAPP tools  
- Security Engineers  
- Cloud Architects  
- Sales Engineers  
- Consultants  
- Customer assessments  
---
## Features
### Live Dashboard
Monitor your environment with:
- Alerts and incidents  
- Vulnerabilities and CVEs  
- Identity exposure  
- Compliance findings  
- Risk score summary  
### Automated Reports
Generate professional reports in:
- PDF  
- HTML  
Includes:
- Executive summary  
- Risk heatmaps  
- Security posture summary  
- Customer branding  
### Supported Frameworks
- CIS  
- PCI DSS  
- NIST  
- SOC 2  
- HIPAA  
- ISO 27001  
- CSA CCM  
---
## Requirements
Before starting, install:
- Docker  
- Python 3.10+  
- FortiCNAPP API credentials  
---
# Quick Start
## Step 1 — Create API Credentials
In FortiCNAPP:
```text
Settings > API Keys > Create New

Set variables:

export LW_ACCOUNT=your-account.lacework.net
export LW_KEY_ID=your_key_id
export LW_SECRET=your_secret

⸻

Step 2 — Launch Dashboard

cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d -p 8080:8080 \
-e LW_ACCOUNT=$LW_ACCOUNT \
-e LW_KEY_ID=$LW_KEY_ID \
-e LW_SECRET=$LW_SECRET \
forticnapp-dashboard

Open:

http://localhost:8080

⸻

Step 3 — Demo Mode (No Credentials)

Use sample data:

docker run -d -p 8080:8080 \
-e MOCK_FILE=/app/mock_data.json \
forticnapp-dashboard

⸻

Step 4 — Generate Report

Install dependencies:

pip install -r requirements.txt

Run:

python lw_report_gen.py \
--author "Your Name" \
--customer "Acme Corp"

⸻

Dashboard

The dashboard gives a quick overview of:

* Active alerts
* Critical vulnerabilities
* Identity risks
* Compliance gaps
* Overall posture score

Ideal for demos, workshops, and fast reviews.

⸻

Report Generator

Create professional reports for customers or leadership teams.

Output formats:

* PDF
* HTML

Best for:

* Executive reviews
* Customer assessments
* Internal audits
* Security summaries

⸻

Risk Score Model

Score	Level	Meaning
7 - 10	Building	Security basics need improvement
4 - 6	Maturing	Good progress with some gaps
0 - 3	Optimizing	Strong mature security posture

⸻

Export Contacts

Create local file:

touch rca_ui/contacts.csv

Copy contacts from container:

docker cp rca:/app/contacts.csv rca_ui/contacts.csv

View file:

cat rca_ui/contacts.csv

⸻

Common Use Cases

* Rapid Cloud Security Assessments
* FortiCNAPP demonstrations
* Customer posture reviews
* Compliance readiness checks
* Executive reporting
* Internal security audits

⸻

Beginner Tips

If you are new:

1. Start with Demo Mode
2. Explore the dashboard
3. Connect real credentials later
4. Generate your first report
5. Review findings and score


