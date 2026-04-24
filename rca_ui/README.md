<div align="center">

# 🖥️ FortiCNAPP Rapid Cloud Assessment — Dashboard

**A single-file Node.js dashboard (no npm required) that proxies the FortiCNAPP v2 API and renders a live dark-theme UI.**

See your alerts, CVEs, identities, and compliance — all on one screen, refreshed every 60 minutes.

[![📄 View Sample Report](https://img.shields.io/badge/📄_View-Sample_Report-blue?style=for-the-badge)](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>

---

## 📖 Table of Contents

1. [What is this?](#-what-is-this)
2. [Project files](#-project-files)
3. [Before you start](#-before-you-start)
4. [Step 1 — Create a `.env` file](#-step-1--create-a-env-file)
5. [Step 2 — Build the Docker image](#-step-2--build-the-docker-image)
6. [Step 3 — Run the dashboard](#-step-3--run-the-dashboard)
7. [Day-to-day operations](#-day-to-day-operations)
8. [Environment variables](#-environment-variables)
9. [Report Runner (optional)](#-report-runner-optional)
10. [Troubleshooting](#-troubleshooting)
11. [FAQ](#-faq)

---

## 🧭 What is this?

This folder contains the **Live Dashboard** half of the Rapid Cloud Assessment toolkit.

It's a self-contained web app that:

- 🔌 Connects to your **FortiCNAPP** tenant via the v2 API
- 📊 Displays alerts, vulnerabilities (CVEs), identities, and compliance in one dark-theme UI
- 🔄 Refreshes automatically every **60 minutes**
- 💾 Also runs in **mock mode** — no account required, great for demos

> 💡 **No Node.js knowledge needed.** The whole dashboard is one `server.js` file, packaged in Docker. If you can run two commands, you can run this.

---

## 📂 Project files

| File | Purpose |
|------|---------|
| `server.js` | Dashboard server — entire UI is self-contained |
| `mock_data.json` | API snapshot for offline / demo mode |
| `Dockerfile` | Builds the dashboard container |
| `report_runner.js` | Host-side runner for generating PDF/HTML reports (optional) |

---

## ✅ Before you start

| Tool | Why you need it | Install |
|------|-----------------|---------|
| 🐳 **Docker** | Runs the dashboard in a container | [Get Docker](https://docs.docker.com/get-docker/) |
| 🔑 **FortiCNAPP account** | Source of the security data (skip if using mock mode) | Ask your admin |
| 💻 **Terminal / shell** | To run the commands below | Built into macOS/Linux; Windows: use WSL or Git Bash |

Verify Docker is working:

```bash
docker --version     # should print: Docker version 2x.x.x
```

---

## 🔑 Step 1 — Create a `.env` file

The `.env` file holds your API credentials. Docker reads it when the container starts, so your secrets never get hardcoded into the image.

### 1.1 Create the file

In the `rca_ui` folder, create a new file named exactly `.env` with this content:

```env
LW_ACCOUNT=your-account.lacework.net
LW_KEY_ID=YOUR_KEY_ID
LW_SECRET=YOUR_SECRET
```

### 1.2 Where to find those values

Log in to your FortiCNAPP console and go to:

> **Settings → Configuration → API Keys → `+ Create New`**

Download the JSON file and copy:

| Variable | Matches which JSON field? |
|----------|---------------------------|
| `LW_ACCOUNT` | Your console hostname (e.g. `partner-demo.lacework.net`) |
| `LW_KEY_ID` | `keyId` |
| `LW_SECRET` | `secret` |

> ⚠️ **Never commit `.env` to git.** Add it to `.gitignore` if it isn't already.

> ⏭ **Want to skip this step?** Use **mock mode** — no `.env` needed (see [Step 3 Option B](#option-b--mock--offline-mode-no-credentials-needed)).

---

## 🛠️ Step 2 — Build the Docker image

This packages the dashboard into a container. Only needs to be done **once** (or again after updating `server.js`).

```bash
docker build -t forticnapp-dashboard .
```

☕ *First build takes 1–2 minutes. Subsequent builds are cached and near-instant.*

Verify it built:

```bash
docker images | grep forticnapp-dashboard
```

---

## ▶️ Step 3 — Run the dashboard

Pick **one** of the two modes below.

### Option A — Live mode (calls the real FortiCNAPP API)

Uses the `.env` file from [Step 1](#-step-1--create-a-env-file):

```bash
docker run -d \
  --name forticnapp-dashboard \
  -p 8080:8080 \
  --env-file .env \
  forticnapp-dashboard
```

### Option B — Mock / offline mode (no credentials needed)

Perfect for demos, workshops, or offline presentations:

```bash
docker run -d \
  --name forticnapp-dashboard \
  -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

### Open the dashboard

👉 **[http://localhost:8080](http://localhost:8080)**

Data refreshes every **60 minutes** automatically.

> 💡 **What do the flags mean?**
> - `-d` → run in the background (detached)
> - `--name forticnapp-dashboard` → name the container so you can stop or copy from it
> - `-p 8080:8080` → expose port 8080 on your machine
> - `--env-file .env` → load credentials from your `.env` file
> - `-e VAR=value` → pass a single env var inline

---

## 🔧 Day-to-day operations

### Push a code update without rebuilding the image

Useful when you tweak `server.js` and want to see the change immediately:

```bash
docker cp server.js forticnapp-dashboard:/app/server.js
docker restart forticnapp-dashboard
```

### Watch live logs

```bash
docker logs -f forticnapp-dashboard
```

Press `Ctrl+C` to stop watching (the container keeps running).

### Stop / start / remove

```bash
docker stop forticnapp-dashboard          # stop the container
docker start forticnapp-dashboard         # start it again
docker rm -f forticnapp-dashboard         # delete it (use before running with new credentials)
```

---

## 🌐 Environment variables

Full reference for every variable the dashboard supports:

| Variable | Required? | Description |
|----------|:---------:|-------------|
| `LW_ACCOUNT` | ✅ (live mode) | Full FortiCNAPP account hostname (e.g. `co.lacework.net`) |
| `LW_KEY_ID` | ✅ (live mode) | API key ID from the JSON file |
| `LW_SECRET` | ✅ (live mode) | API secret from the JSON file |
| `PORT` | ❌ | HTTP port the dashboard listens on (default: `8080`) |
| `MOCK_FILE` | ❌ | Path to a JSON snapshot — set to enable offline mode |

---

## 📑 Report Runner (optional)

The **Generate Report** button in the dashboard opens the sample report hosted on GitHub Pages.

If you want to generate **live** reports locally instead, run `report_runner.js` **on your host machine** (not inside Docker — it needs Chrome / WeasyPrint, which aren't in the container):

```bash
node report_runner.js
```

This starts a listener on port `8081` that the dashboard can talk to for on-demand report generation.

> ⚠️ The Report Runner requires Node.js installed on your host and either Chrome or WeasyPrint for PDF rendering.

---

## 🛠️ Troubleshooting

<details>
<summary><strong>Port 8080 is already in use</strong></summary>

Another process is bound to that port. Either stop it, or map a different one:

```bash
docker run -d --name forticnapp-dashboard -p 9090:8080 \
  --env-file .env forticnapp-dashboard
```

Then open [http://localhost:9090](http://localhost:9090).
</details>

<details>
<summary><strong>"Authentication failed" in the dashboard</strong></summary>

- Make sure `LW_ACCOUNT` includes the full hostname (`xxx.lacework.net`, not just `xxx`)
- Check `LW_KEY_ID` and `LW_SECRET` match exactly what's in the JSON file — no quotes, no trailing spaces
- Verify the API key hasn't been disabled in the FortiCNAPP console
</details>

<details>
<summary><strong>"Container name already in use"</strong></summary>

An old container with the same name is still around. Remove it:

```bash
docker rm -f forticnapp-dashboard
```

Then re-run your `docker run` command.
</details>

<details>
<summary><strong>Dashboard loads but shows no data</strong></summary>

- In live mode: check `docker logs -f forticnapp-dashboard` for API errors
- Confirm your API key has permission to read alerts, vulnerabilities, and compliance
- Try mock mode (Option B) to rule out a network or credential problem
</details>

<details>
<summary><strong>Code changes to server.js aren't showing up</strong></summary>

You either need to rebuild the image:

```bash
docker build -t forticnapp-dashboard .
docker rm -f forticnapp-dashboard
# then run again
```

…or push the change in place:

```bash
docker cp server.js forticnapp-dashboard:/app/server.js
docker restart forticnapp-dashboard
```
</details>

---

## ❓ FAQ

**Q: Do I need Node.js installed?**
No — Docker ships with everything. Node is only needed on the host if you run the optional Report Runner.

**Q: How often does the data refresh?**
Every 60 minutes automatically. Refresh the browser to force an update sooner (subject to the API cache).

**Q: Can I run this in the cloud instead of my laptop?**
Yes — any Docker host works (AWS EC2, Azure VM, GCE, Fly.io, etc.). Expose it securely with a reverse proxy and TLS.

**Q: Is my data sent anywhere?**
No. The dashboard runs entirely on your host. API calls go directly from your container to FortiCNAPP over HTTPS.

**Q: Where are visitor contacts stored?**
In `contacts.csv` inside the container at `/app/contacts.csv`. See the main [README](../README.md#-collecting-visitor-contacts) for how to extract them.

---

<div align="center">

← [Back to main README](../README.md) · [📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html) · [🐛 Issues](../../../issues)

</div>
