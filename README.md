<div align="center">

# 🛡️ FortiCNAPP Rapid Cloud Assessment

**A beginner-friendly toolkit to assess the security of any cloud environment using [FortiCNAPP](https://www.fortinet.com/products/forticnapp) (Lacework CNAPP).**

In 10 minutes you'll have a live security dashboard — powered by the **Fortinet Cloud Risk IQ** score — and a customer-ready PDF report.

[![📄 View Sample Report](https://img.shields.io/badge/📄_View-Sample_Report-blue?style=for-the-badge)](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>

---

## 📖 Table of Contents

1. [What is this?](#-what-is-this)
2. [Before you start](#-before-you-start)
3. [Step 1 — Get your API Keys](#-step-1--get-your-api-keys)
4. [Step 2 — Run the Live Dashboard](#-step-2--run-the-live-dashboard)
5. [Step 3 — Generate a CSA Report](#-step-3--generate-a-csa-report)
6. [Collecting Visitor Contacts](#-collecting-visitor-contacts)
7. [Project Files](#-project-files)
8. [Troubleshooting](#-troubleshooting)
9. [FAQ](#-faq)

---

## 🧭 What is this?

This repository contains **two tools** that work together to help you assess a cloud environment:

| # | Tool | File | What it does | When to use it |
|---|------|------|--------------|----------------|
| 1 | **Live Dashboard** | `rca_ui/server.js` | Real-time white-theme UI showing the **Fortinet Cloud Risk IQ** score, alerts, CVEs, identities, and compliance | Demos, workshops, live customer reviews |
| 2 | **CSA Report Generator** | `lw_report_gen.py` | Generates a professional Cloud Security Assessment report in PDF or HTML | Leave-behinds, executive summaries, audits |

> 💡 **New to CNAPP?** Start with the Dashboard in **mock mode** (no credentials required — see [Step 2](#-step-2--run-the-live-dashboard)).

### Cloud Security Posture Score

The dashboard computes a **0–100 posture score** — **higher is better** — using the formula:

```
postureScore = max(0, round(100 − mean(findingRiskScores) − secretCount × 0.5))
```

| Category | Risk Weight |
|----------|:-----------:|
| Critical Alerts | 95 (in mean) |
| Critical CVEs (risk ≥ 9.0) | `riskScore × 10` (in mean) |
| Compliance Violations | 80 (in mean) |
| Identity Risk (no MFA) | `risk_score × 100` (in mean) |
| Secrets (per detected secret) | −0.5 pts (outside mean) |

| Score | Band | Color |
|:-----:|------|:-----:|
| 90–100 | Proactive Security | 🟢 |
| 60–89 | Some Attention Needed | 🟠 |
| 0–59 | URGENT – Attention Needed | 🔴 |

See [SCORING_GUIDE.md](SCORING_GUIDE.md) for the full formula and worked example.

---

## ✅ Before you start

You'll need these installed on your machine. Click a link if you don't have one yet.

| Tool | Why you need it | Install |
|------|-----------------|---------|
| 🐳 **Docker** | Runs the dashboard in a container so you don't have to install Node.js | [Get Docker](https://docs.docker.com/get-docker/) |
| 🐍 **Python 3.10+** | Runs the CSA report generator | [Get Python](https://www.python.org/downloads/) |
| 🔑 **FortiCNAPP account** | Source of the security data (skip if you only use mock mode) | Ask your admin |
| 💻 **Terminal / shell** | To run the commands below | Built into macOS/Linux; Windows users: use WSL or Git Bash |

Verify everything is installed:

```bash
docker --version     # should print: Docker version 2x.x.x
python3 --version    # should print: Python 3.10+ or higher
```

---

## 🔑 Step 1 — Get your API Keys

> ⏭ **Want to skip this step?** You can — run the dashboard in **mock mode** (see Step 2). Come back here when you're ready to connect to a real account.

### 1.1 Log in to FortiCNAPP

Open your FortiCNAPP console in a browser:

```
https://<your-account>.lacework.net
```

Replace `<your-account>` with your tenant name (e.g. `partner-demo.lacework.net`).

### 1.2 Create an API Key

Inside the console, navigate to:

> **Settings → Configuration → API Keys → `+ Create New`**

Give it a clear name (e.g. *"RCA Assessment — Sebastien"*) and click **Save**.

### 1.3 Download the JSON file

After creation, click **Download**. You'll get a JSON file that looks like this:

```json
{
  "keyId":   "FORTINET_67A1D371ABCDEF1234567890",
  "secret":  "_8dd983bbcac9a1b2c3d4e5f6g7h8",
  "account": "partner-demo"
}
```

### 1.4 Note the three values you'll need

These are the three pieces of information the tools use to connect:

| Variable | Where to find it | Example |
|----------|-----------------|---------|
| `LW_ACCOUNT` | Your console hostname (the part before `.lacework.net`) | `partner-demo.lacework.net` |
| `LW_KEY_ID` | `keyId` field in the JSON file | `FORTINET_67A1D371...` |
| `LW_SECRET` | `secret` field in the JSON file | `_8dd983bbcac9...` |

> ⚠️ **Keep this JSON file secret.** Never commit it to git or paste it into Slack. Treat it like a password.

---

## 🖥️ Step 2 — Run the Live Dashboard

The dashboard is a web app that runs inside a Docker container. You'll build it once, then run it either with real credentials or in mock mode.

### 2.1 Enter the dashboard folder

```bash
cd rca_ui
```

### 2.2 Build the Docker image

This downloads everything the dashboard needs and packages it up. Only needs to be done **once** (or again after code updates).

```bash
docker build -t forticnapp-dashboard .
```

☕ *First build can take 1–3 minutes. Later runs are instant.*

### 2.3 Choose how to run it

#### Option A — Live mode (connects to FortiCNAPP)

Use the keys from [Step 1](#-step-1--get-your-api-keys):

```bash
docker run -d --name rca -p 8080:8080 \
  -e LW_ACCOUNT=your-account.lacework.net \
  -e LW_KEY_ID=YOUR_KEY_ID \
  -e LW_SECRET=YOUR_SECRET \
  forticnapp-dashboard
```

#### Option B — Mock mode (no credentials needed)

Perfect for first-time users, demos, or offline presentations:

```bash
docker run -d --name rca -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

### 2.4 Open the dashboard

In your browser, go to:

👉 **[http://localhost:8080](http://localhost:8080)**

You should see alerts, CVEs, identity risks, and compliance widgets.

> 💡 **What do the flags mean?**
> - `-d` → run in the background (detached)
> - `--name rca` → give the container a name so you can stop or copy from it
> - `-p 8080:8080` → expose port 8080 on your machine
> - `-e VAR=value` → pass an environment variable into the container

### 2.5 Stop or restart the dashboard

```bash
docker stop rca        # stops it
docker start rca       # restarts it
docker rm -f rca       # deletes the container (use before re-running with new keys)
```

---

## 📑 Step 3 — Generate a CSA Report

The CSA (Cloud Security Assessment) report is a polished deliverable you can email to customers or executives.

### 3.1 Create a Python virtual environment

A virtual environment keeps this project's Python packages isolated from the rest of your system.

```bash
python3 -m venv venv
source venv/bin/activate
```

> On Windows (PowerShell), use: `venv\Scripts\Activate.ps1`

You'll know it's active because your prompt will change to show `(venv)`.

### 3.2 Install dependencies

```bash
pip install -r requirements.txt
```

### 3.3 Generate a report

The minimum command you need:

```bash
python lw_report_gen.py \
  --author "John Smith" \
  --customer "Acme Corp" \
  --api-key-file "lw_foo.json"
```

This produces an HTML report in the current folder. Open it in any browser.

### 3.4 Useful flags

| Flag | Description | Example |
|------|-------------|---------|
| `--report-format` | Output format: `html` or `pdf` (default: `html`) | `--report-format pdf` |
| `--api-key-file` | Path to the JSON key file from Step 1 (alternative to env vars) | `--api-key-file ./my_key.json` |
| `--cache-data` | Reuse previously downloaded data (faster, offline-friendly) | `--cache-data` |
| `--compliance-framework` | Which framework to score against | `--compliance-framework CIS` |

**Supported frameworks:** `CIS` · `PCI` · `NIST_CSF` · `SOC2` · `HIPAA` · `ISO_27001` · `CSA_CCM`

### 3.5 Example: Full PDF report against CIS

```bash
python lw_report_gen.py \
  --author "John Smith" \
  --customer "Acme Corp" \
  --report-format pdf \
  --compliance-framework CIS
```

---

## 📇 Collecting Visitor Contacts

Every time someone logs into the dashboard, their details are saved automatically into a CSV file inside the container. Here's how to retrieve it.

### Step 1 — Find the container

```bash
docker ps -a
```

Look for the one named `rca` (or whatever `--name` you used).

### Step 2 — Copy the file out of the container

```bash
docker cp rca:/app/contacts.csv ./contacts.csv
```

### Step 3 — View the results

```bash
cat contacts.csv
```

The file columns are:

```
Timestamp, FirstName, LastName, Company, Role, Email
```

> 💡 Open `contacts.csv` in Excel, Numbers, or Google Sheets for a cleaner view.

---

## 📂 Project Files

Quick reference for what each file does:

| File | What it's for |
|------|----------------|
| `rca_ui/server.js` | Dashboard web server — white Fortinet-themed UI, Fortinet Cloud Risk IQ gauge |
| `rca_ui/Dockerfile` | Build instructions for the dashboard container |
| `rca_ui/mock_data.json` | Sample data used in mock mode |
| `rca_ui/report_runner.js` | Runs reports from the dashboard UI |
| `lw_report_gen.py` | Python script that generates CSA reports |
| `SCORING_GUIDE.md` | Fortinet Cloud Risk IQ formula, bands, and worked example |
| `requirements.txt` | Python dependencies for the report generator |

---

## 🛠️ Troubleshooting

<details>
<summary><strong>Port 8080 is already in use</strong></summary>

Another process is using that port. Either stop it, or map a different port:

```bash
docker run -d --name rca -p 9090:8080 ... forticnapp-dashboard
```

Then open [http://localhost:9090](http://localhost:9090) instead.
</details>

<details>
<summary><strong>Dashboard shows "Authentication failed"</strong></summary>

- Double-check `LW_ACCOUNT` includes the full hostname (`xxx.lacework.net`)
- Check `LW_KEY_ID` and `LW_SECRET` match exactly what's in the JSON file
- Make sure the API key hasn't been revoked in the FortiCNAPP console
</details>

<details>
<summary><strong>Python says "command not found: python"</strong></summary>

Use `python3` instead of `python` on most macOS/Linux systems.
</details>

<details>
<summary><strong>PDF generation fails</strong></summary>

PDF export requires a headless Chromium. Install it via:

```bash
pip install weasyprint
```

Or generate an HTML report instead (`--report-format html`).
</details>

<details>
<summary><strong>How do I see dashboard logs?</strong></summary>

```bash
docker logs -f rca
```

Press `Ctrl+C` to stop watching.
</details>

---

## ❓ FAQ

**Q: Do I need a FortiCNAPP account to try this?**
No. Use mock mode — see [Step 2.3 Option B](#option-b--mock-mode-no-credentials-needed).

**Q: Is this an official Fortinet product?**
No, it's a community/partner toolkit built on top of the FortiCNAPP API.

**Q: Can I customize the report branding?**
Yes — edit the templates referenced by `lw_report_gen.py`. See `SCORING_GUIDE.md` for scoring internals.

**Q: Where is my data stored?**
Nowhere external. The dashboard runs entirely on your machine in Docker. Reports are saved locally.

**Q: Can I share the dashboard with a customer over the internet?**
Only if you expose it securely (e.g., via a reverse proxy with HTTPS and authentication). By default it's local-only.

---

<div align="center">

Made with ❤️ for the FortiCNAPP community

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html) · [🐛 Issues](../../issues) · [⭐ Star this repo](../../stargazers)

</div>
