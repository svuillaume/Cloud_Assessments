# Fortinet Rapid Cloud Assessment

A live security dashboard and Customer-ready Cloud Rapid Assessment Report powererd by FortiCNAPP.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Step-by-Step Setup](#step-by-step-setup)
5. [Production Deployment with HTTPS](#production-deployment-with-https)
6. [Using Your Own TLS Certificate](#using-your-own-tls-certificate)
7. [Updating the Dashboard](#updating-the-dashboard)
8. [Collecting Visitor Contacts](#collecting-visitor-contacts)
9. [Troubleshooting](#troubleshooting)
10. [Additional Resources](#additional-resources)

---

## Overview

This project provides two tools that work together to deliver cloud security insights from FortiCNAPP:

| Tool | File | Purpose |
|------|------|---------|
| Live Dashboard | `rca_ui/server.js` | Real-time web UI displaying Cloud Security Posture Management score, alerts, CVEs, secrets, identities, and compliance data |
| PDF Report | (generated from dashboard) | Customer-ready report exported from the live data |

The dashboard is a single Node.js file with no npm dependencies. You can run it directly with Node.js or inside a Docker container.

---

## Prerequisites

Before you begin, make sure you have the following ready.

### 1. Runtime Environment

Choose one of the following:

| Option | Download Link |
|--------|---------------|
| Node.js 18 or higher | https://nodejs.org |
| Docker | https://docs.docker.com/get-docker/ |

### 2. FortiCNAPP API Key

1. Log in to your FortiCNAPP console
2. Go to **Settings** → **API Keys**
3. Click **Download** to save the JSON file
4. Keep this file safe — you will need the values inside it

> If you only want to test the dashboard, you can skip this step and run in mock mode.

### 3. Public Domain Name (for production HTTPS only)

You will need a domain name that points to your server's public IP address. Any DNS provider works. A free option is [DuckDNS](https://www.duckdns.org).

---

## Quick Start

If you just want to see the dashboard running locally as fast as possible:

```bash
cd rca_ui
node server.js
```

Then open `http://localhost:8080` in your browser.

For a production deployment with HTTPS, follow the full step-by-step guide below.

---

## Step-by-Step Setup

### Step 1: Get the Code

Clone or download the repository to your server, then move into the dashboard folder:

```bash
cd rca_ui
```

### Step 2: Create Your Configuration File

Create a file named `.env` in the `rca_ui` folder. This file holds your settings and secrets.

```bash
DUCKDNS_TOKEN=your-token-here
PORT=80
DOMAIN=domain.yourdomain.com
LE_EMAIL=you@example.com
LW_ACCOUNT=your-tenant.lacework.net
LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXX
LW_SECRET=_xxxxxxxxxxxxxxxxxxxx
```

**Important rules for the `.env` file:**

- Do NOT put quotes around any values. Docker reads the file literally.
- Replace `domain.yourdomain.com` with your real domain
- Replace `you@example.com` with your real email (used by Let's Encrypt)
- Replace `LW_ACCOUNT`, `LW_KEY_ID`, and `LW_SECRET` with values from your FortiCNAPP API key JSON file

### Step 3: Choose Your Deployment Path

You now have two options:

- **Option A:** Production deployment with automatic HTTPS — see [Production Deployment with HTTPS](#production-deployment-with-https)
- **Option B:** Use your own existing TLS certificate — see [Using Your Own TLS Certificate](#using-your-own-tls-certificate)

---

## Production Deployment with HTTPS

This option uses Let's Encrypt to automatically obtain a signed TLS certificate.

### How It Works

When you set the `DOMAIN` variable, the container's `entrypoint.sh` script does the following:

1. Runs `certbot` to perform the Let's Encrypt HTTP-01 challenge on port 80
2. Obtains a signed certificate for your domain
3. Starts the Node.js server in HTTPS mode on port 8443
4. Redirects all HTTP traffic on port 80 to HTTPS

### Requirements Checklist

Before running the container, confirm:

- [ ] Your public domain points to your server's IP address
- [ ] Port **80** is publicly reachable (required for the ACME HTTP-01 challenge)
- [ ] Port **443** is open for incoming HTTPS traffic
- [ ] Your `.env` file is filled in correctly (see Step 2 above)

### Step 1: Build the Docker Image

From inside the `rca_ui` folder, run:

```bash
sudo docker build -t rca-dashboard .
```

### Step 2: Run the Container

```bash
sudo docker run --rm -d \
    --name rca \
    -p 80:80 \
    -p 443:8443 \
    --env-file .env \
    -v letsencrypt:/etc/letsencrypt \
    rca-dashboard
```

**Explanation of the flags:**

| Flag | Purpose |
|------|---------|
| `--rm` | Removes the container automatically when stopped |
| `-d` | Runs in detached (background) mode |
| `--name rca` | Names the container `rca` for easy reference |
| `-p 80:80` | Maps host port 80 to container port 80 (HTTP / ACME) |
| `-p 443:8443` | Maps host port 443 to container port 8443 (HTTPS) |
| `--env-file .env` | Loads your configuration |
| `-v letsencrypt:/etc/letsencrypt` | Persists certificates across restarts so certbot does not re-issue every time |

### Step 3: Verify It Is Running

Watch the container logs:

```bash
sudo docker logs -f rca
```

You should see output similar to:

```
[tls] Domain: rapidassessment.yourdomain.com — running certbot …
[tls] Cert obtained: /etc/letsencrypt/live/rapidassessment.yourdomain.com/fullchain.pem
[tls] HTTPS mode — cert: /etc/letsencrypt/live/…/fullchain.pem
│  Open : https://domain.yourdomain.com:8443
```

### Step 4: Open the Dashboard

In your browser, go to:

```
https://domain.yourdomain.com
```

(Replace with your actual domain.)

---

## Using Your Own TLS Certificate

If you already have a signed certificate and want to skip certbot, use this command instead.

### Step 1: Place Your Certificates

Make sure your certificate and key files are on the host, for example at `/path/to/certs/`:

- `fullchain.pem` — the certificate
- `privkey.pem` — the private key

### Step 2: Run the Container

```bash
sudo docker run --rm -d \
    --name rca \
    -p 80:80 \
    -p 8443:8443 \
    -v /path/to/certs:/certs:ro \
    -e TLS_CERT=/certs/fullchain.pem \
    -e TLS_KEY=/certs/privkey.pem \
    --env-file .env \
    rca-dashboard
```

The `:ro` flag mounts the certificate folder read-only for safety.

---

## Updating the Dashboard

To deploy a change to `server.js` without rebuilding the entire image:

```bash
docker cp rca_ui/server.js rca:/app/server.js
docker restart rca
```

This copies your updated file into the running container and restarts it.

---

## Collecting Visitor Contacts

Every login on the dashboard is automatically saved inside the container in `contacts.csv`.

To export the contacts file to your host:

```bash
docker cp rca:/app/contacts.csv ./contacts.csv
cat contacts.csv
```

---

## Troubleshooting

### Authentication Failed

If the dashboard cannot connect to FortiCNAPP, check the following:

- Confirm `LW_ACCOUNT` is the full hostname, for example `xxx.lacework.net`
- Confirm `LW_KEY_ID` and `LW_SECRET` match the downloaded JSON file exactly
- Verify the API key has not been revoked in the FortiCNAPP console

### Dashboard Shows No Data or a Spinner

- Check the container logs:
  ```bash
  docker logs -f rca
  ```
- Phase 2 (compliance data) can take 30 to 60 seconds to load. Wait for the live indicator dot to turn green.

### HTTPS Certificate Not Issued

- Verify port 80 is reachable from the public internet (required for the ACME challenge)
- Confirm your domain's DNS A record points to the server's public IP
- Check that `LE_EMAIL` in `.env` is a valid email address

---

## Additional Resources

- See `SCORING_GUIDE.md` for the full scoring formula and a worked example
- FortiCNAPP documentation: https://docs.fortinet.com
- Let's Encrypt: https://letsencrypt.org
- DuckDNS (free DNS): https://www.duckdns.org

---

Made for the FortiCNAPP community.
