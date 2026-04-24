FortiCNAPP Rapid Cloud Assessment

A simple tool to review your cloud security posture using FortiCNAPP (Lacework CNAPP).

It provides:

* Live dashboard for risks and alerts
* PDF / HTML assessment reports
* Risk scoring for cloud maturity
* Compliance visibility

View Sample Report￼

⸻

What This Project Does

This project helps beginners and security teams understand:

* Current cloud risks
* Vulnerabilities that need attention
* Identity and permission exposure
* Compliance gaps
* Overall security maturity

⸻

Requirements

Install:

* Docker (for dashboard)
* Python 3 (for reports)
* FortiCNAPP API key

⸻

Step 1 — Create API Key

In FortiCNAPP:

Settings > API Keys > Create New

Set your credentials:

export LW_ACCOUNT=your-account.lacework.net
export LW_KEY_ID=your_key_id
export LW_SECRET=your_secret

⸻

Step 2 — Start Dashboard

cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d -p 8080:8080 \
-e LW_ACCOUNT=$LW_ACCOUNT \
-e LW_KEY_ID=$LW_KEY_ID \
-e LW_SECRET=$LW_SECRET \
forticnapp-dashboard

Open in browser:

http://localhost:8080

⸻

Step 3 — Run Without Credentials (Demo Mode)

docker run -d -p 8080:8080 \
-e MOCK_FILE=/app/mock_data.json \
forticnapp-dashboard

⸻

Step 4 — Generate Report

pip install -r requirements.txt
python lw_report_gen.py \
--author "Your Name" \
--customer "Acme Corp"

⸻

Dashboard Features

* Live alerts
* Vulnerability tracking
* Identity risk visibility
* Compliance findings
* Risk score summary

⸻

Report Features

* PDF reports
* HTML reports
* Executive summaries
* Risk heatmaps
* Customer branding

Supported frameworks:

* CIS
* PCI DSS
* NIST
* SOC 2
* HIPAA
* ISO 27001
* CSA CCM

⸻

Risk Score Guide

Score	Level	Meaning
7–10	Building	Basic controls need improvement
4–6	Maturing	Good progress with room to improve
0–3	Optimizing	Strong mature security posture

⸻

Export Contacts

Create file:

touch rca_ui/contacts.csv

Copy from container:

docker cp rca:/app/contacts.csv rca_ui/contacts.csv

View:

cat rca_ui/contacts.csv

⸻

Best Uses

* Rapid cloud assessments
* Customer security reviews
* Compliance checks
* CNAPP demonstrations
* Executive reporting

⸻

License

Internal / Custom Use
