<div align="center">

# FortiCNAPP Rapid Cloud Assessment

**Modern, beginner-friendly cloud security posture review tool for [FortiCNAPP](https://www.fortinet.com/products/forticnapp) (Lacework CNAPP).**

Generate dashboards, security findings, maturity scores, and customer-ready reports in minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![FortiCNAPP](https://img.shields.io/badge/FortiCNAPP-Lacework-EE3124)](https://www.fortinet.com/products/forticnapp)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

[**View Live Sample Report →**](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Dashboard](#dashboard)
- [Report Generator](#report-generator)
- [Risk Score Model](#risk-score-model)
- [Export Contacts](#export-contacts)
- [Common Use Cases](#common-use-cases)
- [Beginner Tips](#beginner-tips)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

FortiCNAPP Rapid Cloud Assessment helps you understand the security state of your cloud environment in minutes.

**Built for:**

| Role | Use Case |
| :--- | :--- |
| 🧑‍🎓 Beginners | Learn how CNAPP tools work |
| 🛡️ Security Engineers | Triage findings and exposure |
| ☁️ Cloud Architects | Validate posture and guardrails |
| 💼 Sales Engineers | Run customer demos |
| 🧭 Consultants | Deliver rapid assessments |

---

## Features

### 📊 Live Dashboard

- Alerts and incidents
- Vulnerabilities and CVEs
- Identity exposure
- Compliance findings
- Risk score summary

### 📑 Automated Reports

Professional reports in **PDF** and **HTML**, including:

- Executive summary
- Risk heatmaps
- Security posture summary
- Customer branding

### ✅ Supported Compliance Frameworks

`CIS` · `PCI DSS` · `NIST` · `SOC 2` · `HIPAA` · `ISO 27001` · `CSA CCM`

---

## Requirements

Before you begin, make sure you have:

- 🐳 [Docker](https://docs.docker.com/get-docker/)
- 🐍 [Python 3.10+](https://www.python.org/downloads/)
- 🔑 FortiCNAPP API credentials ([how to create](https://docs.fortinet.com/product/lacework-forticnapp))

---

## Quick Start

### 1️⃣ Create API Credentials

In FortiCNAPP, navigate to:

> **Settings → API Keys → Create New**

Then export them in your shell:

```bash
export LW_ACCOUNT=your-account.lacework.net
export LW_KEY_ID=your_key_id
export LW_SECRET=your_secret
```

> 💡 **Tip:** Add these to a `.env` file (and `.gitignore` it) to avoid re-exporting each session.

### 2️⃣ Launch the Dashboard

```bash
cd rca_ui
docker build -t forticnapp-dashboard .
docker run -d -p 8080:8080 \
  -e LW_ACCOUNT=$LW_ACCOUNT \
  -e LW_KEY_ID=$LW_KEY_ID \
  -e LW_SECRET=$LW_SECRET \
  forticnapp-dashboard
```

Open **[http://localhost:8080](http://localhost:8080)** in your browser.

### 3️⃣ Demo Mode (No Credentials Needed)

Want to try it first? Run with sample data:

```bash
docker run -d -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

### 4️⃣ Generate a Report

```bash
pip install -r requirements.txt

python lw_report_gen.py \
  --author "Your Name" \
  --customer "Acme Corp"
```

---

## Dashboard

A unified view of your cloud posture — built for demos, workshops, and fast reviews.

- 🚨 Active alerts
- 🐛 Critical vulnerabilities
- 👤 Identity risks
- 📋 Compliance gaps
- 🎯 Overall posture score

---

## Report Generator

Create polished reports for customers and leadership teams.

**Output formats:** `PDF` · `HTML`

**Best for:**

- Executive reviews
- Customer assessments
- Internal audits
- Security summaries

---

## Risk Score Model

| Score | Level | Meaning |
| :---: | :--- | :--- |
| **7 – 10** | 🔴 Building | Security basics need improvement |
| **4 – 6** | 🟡 Maturing | Good progress with some gaps |
| **0 – 3** | 🟢 Optimizing | Strong, mature security posture |

---

## Export Contacts

Create a local file and copy contacts from the container:

```bash
# Create an empty file
touch rca_ui/contacts.csv

# Copy from the running container
docker cp rca:/app/contacts.csv rca_ui/contacts.csv

# View
cat rca_ui/contacts.csv
```

---

## Common Use Cases

- ⚡ Rapid cloud security assessments
- 🎬 FortiCNAPP demonstrations
- 👥 Customer posture reviews
- 📜 Compliance readiness checks
- 📈 Executive reporting
- 🔍 Internal security audits

---

## Beginner Tips

New to CNAPP? Follow this path:

1. **Start in Demo Mode** — no credentials required
2. **Explore the dashboard** — click around, break nothing
3. **Connect real credentials** when ready
4. **Generate your first report**
5. **Review findings** and interpret your score

---

## Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repo
2. Create a branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please open an [issue](../../issues) to discuss major changes first.

---

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

Made with ❤️ for the FortiCNAPP community

</div>
