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
