# FortiCNAPP Rapid Cloud Assessment — Dashboard

A single-file Node.js dashboard (no npm) that proxies the FortiCNAPP v2 API and renders a live dark-theme UI showing alerts, CVEs, identities, and compliance in one view.

> **[View Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)**

---

## Files

| File | Purpose |
|------|---------|
| `server.js` | Dashboard server — entire UI is self-contained |
| `mock_data.json` | API snapshot for offline / demo mode |
| `Dockerfile` | Builds the dashboard container |
| `report_runner.js` | Host-side runner for generating PDF/HTML reports (optional) |

---

## Step 1 — Create a `.env` file

```env
LW_ACCOUNT=your-account.lacework.net
LW_KEY_ID=YOUR_KEY_ID
LW_SECRET=YOUR_SECRET
```

Get these values from **Settings → Configuration → API Keys** in your FortiCNAPP console.

---

## Step 2 — Build the Docker image

```bash
docker build -t forticnapp-dashboard .
```

---

## Step 3 — Run

### Live mode (calls the FortiCNAPP API)

```bash
docker run -d \
  --name forticnapp-dashboard \
  -p 8080:8080 \
  --env-file .env \
  forticnapp-dashboard
```

Open **http://localhost:8080** — data refreshes every 60 minutes.

### Mock / offline mode (no credentials needed)

```bash
docker run -d \
  --name forticnapp-dashboard \
  -p 8080:8080 \
  -e MOCK_FILE=/app/mock_data.json \
  forticnapp-dashboard
```

---

## Day-to-day operations

```bash
# Push a code update without rebuilding
docker cp server.js forticnapp-dashboard:/app/server.js
docker restart forticnapp-dashboard

# View logs
docker logs -f forticnapp-dashboard

# Stop / start
docker stop forticnapp-dashboard
docker start forticnapp-dashboard
```

---

## Environment variables

| Variable     | Description                                         |
|--------------|-----------------------------------------------------|
| `LW_ACCOUNT` | Full FortiCNAPP account hostname (e.g. `co.lacework.net`) |
| `LW_KEY_ID`  | API key ID                                          |
| `LW_SECRET`  | API secret                                          |
| `PORT`       | HTTP port (default: `8080`)                         |
| `MOCK_FILE`  | Path to JSON snapshot — set to enable offline mode  |

---

## Report Runner (optional)

The **Generate Report** button opens the sample report hosted on GitHub Pages.

To generate live reports locally, run `report_runner.js` on the host (not inside Docker — it needs Chrome/WeasyPrint):

```bash
node report_runner.js
```

This starts a listener on port `8081`.
