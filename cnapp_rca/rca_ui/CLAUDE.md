# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`rca_ui/` is the FortiCNAPP Rapid Cloud Assessment tool — a live security dashboard and four customer-ready HTML/PDF report generators, powered by FortiCNAPP (Lacework) API data. The entire app is one Node.js file, `server.js` (~10,900 lines), with **no npm dependencies** (no `package.json`, no `node_modules`).

> Ancestor `CLAUDE.md` files (`../CLAUDE.md`, `../../CLAUDE.md`, etc.) describe an older ~3,150-line version of `server.js` and are stale on route lists, the posture-score formula, and several features added since (true internet-exposure verification, public storage exposure, governance reports, role-trust correlation, per-CSP scores, in-dashboard AI assistant, report sanitization, a second report format, and — more recently — the standalone ROI/FAIR calculator and manual cache refresh). Treat *this* file as authoritative for `rca_ui/`.

## Run locally

```bash
# Plain HTTP on :8888 (no creds needed — data will be empty/error but server starts)
node server.js

# With real API credentials
LW_ACCOUNT=your-tenant.lacework.net \
LW_KEY_ID=FORTINET_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
LW_SECRET=_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
PORT=8888 \
node server.js

# Sub-account tenant (partner demo orgs) also needs:
LW_SUBACCOUNT=your-subaccount-name

# Alternative to LW_KEY_ID/LW_SECRET/LW_SUBACCOUNT: point at a downloaded key JSON
LW_KEY_FILE=/path/to/keys.json

# Mock mode — load a JSON snapshot instead of calling the API at all
MOCK_FILE=mock_data.json node server.js

# Syntax-check without running (fastest sanity check after an edit — no test suite exists)
node --check server.js
```

## Hot-deploy to a running Docker container

```bash
docker cp server.js rca:/app/server.js && docker restart rca
```

**The in-memory `cache` object is persisted to `/app/data/cache.json`** (`saveCacheToDisk()`/`loadCacheFromDisk()`), written after Phase 1 and again after Phase 2 of every `refreshData()` cycle, and restored immediately on startup — before the first live fetch even begins — so the dashboard shows last-known-good data right away instead of blank panels. In production, `/app/data` is bind-mounted to a named `rca-cache` Docker volume (see `deploy.sh`/`deploy_PrivateCloud.sh`), so it survives both `docker restart` (which already preserves the container's own writable layer on its own) and a full `docker rm`+recreate. A restart still immediately re-triggers a full `refreshData()` in the background — including the compliance scan, which evaluates up to `COMPLIANCE_POLICY_CAP` policies in batches of 3 with gaps between batches and can take several minutes — so panels will still visibly update (from restored-cache data to fresh data) over the following minutes; they just won't go blank first. Also expect the *browser* to keep serving its previously-loaded page/JS after a deploy — a hard reload (not just a normal refresh) is usually needed to pick up server-side changes.

## Docker (production)

```bash
# With Let's Encrypt TLS (requires DOMAIN + LE_EMAIL in .env, port 80 open publicly)
sudo docker build -t rca-dashboard .
sudo docker run --rm -d --name rca \
  -p 80:80 -p 8443:8443 \
  --cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN \
  --env-file .env \
  -v letsencrypt:/etc/letsencrypt \
  rca-dashboard

# Convenience scripts (both build + stop-existing + run):
./install.sh               # ports 80/443, includes the cap flags above
./deploy_CASignedCert.sh   # HTTP-only variant for a pre-issued/CA-signed cert flow
```

Both scripts already run the container rootless with the least-privilege flags above (see
"Rootless / least-privilege container" below) — the flags aren't optional extras layered on top,
they're baked into `install.sh`/`deploy_CASignedCert.sh` themselves.

Copy `.env.example` → `.env` and fill in credentials. Values must NOT be quoted (Docker reads the file literally). `SELF_SIGNED=true` generates a local cert when DNS isn't propagated yet; supplying `TLS_CERT`/`TLS_KEY` skips both certbot and self-signed. The Dockerfile installs `certbot`, `openssl`, and `chromium` (headless Chromium is invoked by both report builders to render PDFs — `entrypoint.sh` handles the TLS branch at container start).

`entrypoint.sh`'s self-signed cert (`/tmp/selfsigned/`) is reused across `docker restart` if it already exists — it's only (re)generated once, on first boot of a given container. This matters because a browser's "proceed anyway" click on a self-signed cert isn't durably remembered the way a real CA cert is; if the cert changed on every restart (the original behavior), every hot-deploy would force re-clicking through the warning. A full container recreation (`docker rm` + fresh `docker run`, e.g. via `deploy.sh`) still generates a new cert on its first boot, as expected.

## Architecture of server.js

Everything lives in one file. Rough layout, in order:

### Server-side (Node.js)

| Section | ~Lines | What it does |
|---|---|---|
| Config | 1–70 | Env vars: `LW_ACCOUNT`, `LW_KEY_ID`, `LW_SECRET`, `LW_SUBACCOUNT`, `LW_KEY_FILE`, `PORT`, `PORT_TLS`, `TLS_CERT`, `TLS_KEY`, `MOCK_FILE` |
| `ROI_CALCULATOR_HTML` | ~115 | Reads `roi-calculator.html` from disk once at startup (see "Standalone ROI/FAIR calculator" below); a missing file only 404s `/roi-calculator`, it doesn't crash the server |
| HTTP + DNS helpers | 71–270 | `tcpReachable`, `resolveReachableIP`, `request`, `fetchCveDetails`, `ensureToken`, `withRetry`, `get`/`post`/`postRaw`/`putRaw` |
| API fetchers | 271–1247 | `fetchAlerts`, `fetchTrueExposure`, `fetchExposurePaths`, `fetchVulns`, `fetchCompliance`, `fetchIdentities`, `fetchGovernanceTargets`, `fetchSecretsAll`/`fetchSecrets`, `fetchPublicStorage` |
| `refreshData()` | 1248 | Orchestrates the fetchers into the in-memory `cache` object |
| `buildHtml()` | 1343–5329 | Returns the full desktop dashboard as one template literal (CSS + HTML + inline client `<script>`) |
| `MOBILE_HTML` | 5330–6188 | Static single-scroll mobile view, its own scoring/step logic duplicated inline |
| `sanitizeCacheData()` | 6189 | Deterministically replaces hostnames/ARNs/IPs/emails/account IDs/secret IDs with stable fake values — used by `?sanitize=1` on both report routes |
| Shared report helpers | 6268–6595 | `groupVulnsByHost`, `computeAssetRiskMap`, `computeCspScores`, `tocCardHtml`, `assetRiskTier`, `hexKillChainSvg`, `hostRiskDiagramSvg`, `governanceReportToComplianceRows` |
| `buildReportHtml()` | 6596 | Original customer report → `/report`, saves `rca.html`/`rca.pdf` |
| `buildReportHtml2()` | 7151 | **Beta** wider-scope report → `/report2`, saves `rca2.html`/`rca2.pdf`. Adds per-cloud risk score, exploit-simulation layer, per-host risk diagrams, MFA gaps, high-privilege role/service-account findings |
| `requestHandler()` + routing | 7518–7959 | All HTTP routes (table below) |
| `startApp()` | 7960 | Picks HTTP-only / HTTP+TLS / self-signed based on env, starts listeners |

### Client-side (inline in `buildHtml`, starting ~line 2510)

- `load()` (4176) — fetches `/api/data`, calls all `render*()` functions
- `renderAlerts/Vulns/Compliance/Identities/SecretsAll/SSHKeys/AssetRisk/Lab()` — populate their panels. `renderPublicStorage()` still exists but is no longer called from `load()` — its dashboard tab was removed (see "Public Storage Exposure" below); `renderSSHKeys()` is new — a live-dashboard tab for `cache.secrets` (permissive SSH keys) that previously only surfaced in reports
- `calcPostureScore(d)` (3799) — mirrors the posture-score formula below
- `computeEffectivePublicStorage(d)` (2859) — merges `publicStorage` policy/ACL findings with `exposurePaths` (s3/azureBlob) traced-path findings, minus a hardcoded known-stale-CSPM-snapshot exclusion list; still called by the Exploit Simulation Layer's storage-exposed badge and all four report builders even though the dashboard's own `renderPublicStorage()` tab was removed
- `exposurePathHopsStr(rec)` (2343) / `exposurePathChips(epRecs)` (2604) — render a traced `LW_APA_EXPOSURE_PATHS` hop chain (e.g. `internet → sg-xxx → i-xxx`) as a "Verified Path" chip, used by the Host Internet Exposure panel (and, before its removal, the Public Storage Exposure panel)
- `calcGlobalScoreFromCsp(d)` / `calcCspScore(d,csp)` / `renderCspLab` — per-cloud (AWS/Azure/GCP) score gauges
- `buildAssetRiskMap(d)` / `renderAssetRisk(d)` / `openHostGraph()` — Correlated Risk Findings per Asset + interactive exploit graph
- `nav(name)` — switches dashboard sections (alerts, vulns, compliance, identities, secrets-all, ssh-keys, asset-risk, lab)
- `openAiChat`/`sendAiMessage`/`pickAiPrompt` — in-dashboard AI assistant chat backed by `/api/ai/*`
- `loadTrustPrincipals`/`renderIdentityGraph`/`updateGraphEdges` — identity role-trust correlation graph
- `openGeoPanel`/`openCveDetails`/`openComplianceDetails`/`openIdentityDetails`/`openMachineDetails` — detail-drawer modals, each backed by its own `/api/*` route
- `submitLogin()`/`showUserBadge()` — visitor registration flow; POSTs to `/api/register`

### Routes

| URL | Behaviour |
|---|---|
| `GET /` | Desktop dashboard; mobile UA → 302 `/mobile` |
| `GET /mobile` | Mobile single-scroll view |
| `GET /desktop` | Force desktop regardless of UA; supports `#section` hash |
| `GET /health` | Liveness check |
| `GET /api/data` | JSON cache snapshot |
| `GET/POST /api/settings` | Read/write refresh interval and `daysBack` assessment window |
| `POST /api/refresh-cache` | Manual "Refresh Cache" button (Management sidebar) — kicks off `refreshData()` immediately; `@fortinet.com`-only, 4h cooldown (`MANUAL_REFRESH_COOLDOWN_MS`), no-ops under `MOCK_FILE` |
| `POST /api/register` | Save visitor to `contacts.csv` |
| `POST /api/login` | Visitor login (cookie-based) |
| `POST /api/ai/start` | Opens a FortiCNAPP AI Assistant thread for an alert (`AiAssistants/start`, Bedrock Claude provider) |
| `POST /api/ai/message` | Sends a follow-up question on an existing thread (`AiAssistants/{threadId}`) |
| `POST /api/ai/rate` | Records thumbs up/down on an AI response |
| `GET /api/cve` | CVE detail lookup (`fetchCveDetails`) |
| `GET /api/geoip` | IP geolocation for the exploit graph |
| `GET /api/identity-trust` | Trust-principal lookup for the identity graph |
| `GET /api/identity` | Single identity detail |
| `GET /api/machine` | Single host/machine detail |
| `GET /api/governance/targets` | Enumerate cloud accounts eligible for a governance (named-framework) report |
| `GET /api/governance/report` | Run/fetch a governance report for one target |
| `GET /api/fg-facts` | Rotating "did you know" facts shown in the dashboard footer |
| `GET /report[?customer=X&author=Y&sanitize=1]` | Original report → `rca.html`/`rca.pdf` |
| `GET /report2[?customer=X&author=Y&sanitize=1]` | Beta wider-scope report → `rca2.html`/`rca2.pdf` |
| `GET /report3[?customer=X&author=Y&sanitize=1]` | Condensed, chart-first Cloud Overview report → `rca3.html`/`rca3.pdf` |
| `GET /report4[?customer=X&author=Y&sanitize=1]` | **Generate Report_BETA** — narrative assessment-style report (Scope/Methodology/Risk Findings Categories/Evidence/Internet Exposed Resources/Actions) → `rca4.html`/`rca4.pdf` |
| `GET /roi-calculator[?...]` | Standalone FAIR/ROI calculator (`roi-calculator.html`, served as a static file — see below); the dashboard's report-download button links here with query params to auto-populate its Cloud Risk tab from live counts |

## Key behaviours and constraints

**API limits**
- Alerts API hard-caps at 7 days per request — `alertTimeWindows()` splits into 7-day chunks when `daysBack > 7`
- Vulns API always capped at 7 days regardless of `daysBack`
- `withRetry()` retries 5xx + network errors 5× with exponential backoff; 30s timeout per request (120s for AI Assistant calls)
- Compliance results are retained from last successful fetch if the new one returns empty (rate-limit guard)

**DNS / IP pool**
- `resolveReachableIP()` probes all DNS IPs at startup via TCP on port 443 and caches the first reachable one
- Blacklisted IPs expire after 12h; DNS is re-probed every 24h

**Rootless / least-privilege container**
- The Dockerfile sets `USER node` — the container runs as the `node` user (uid/gid 1000) baked into the `node:18-alpine` base image, never as root. `install.sh` and `deploy_CASignedCert.sh` both run it with `--cap-drop=ALL --cap-add=NET_BIND_SERVICE --cap-add=CHOWN`, dropping every Linux capability except the two actually needed: `NET_BIND_SERVICE` (both Node itself and certbot's standalone ACME challenge bind port 80, a privileged port) and `CHOWN` (entrypoint.sh's one-time ownership self-heal, below). Verified end-to-end against a real build: non-root PID 1, `/proc/1/status`'s `CapBnd` decodes to exactly those two capabilities, port 80 binds successfully, and PDF report generation (headless Chromium, already invoked everywhere with `--no-sandbox`, so it needs no extra capability) still works.
- The Dockerfile pre-creates and chowns `/app`, `/app/data`, `/etc/letsencrypt`, `/var/lib/letsencrypt`, and `/var/log/letsencrypt` to `node:node` at build time. Docker seeds a *fresh* named volume's initial content and ownership from whatever already exists at that mount path in the image, so a first-time `-v letsencrypt:/etc/letsencrypt` / `-v rca-cache:/app/data` mount inherits correct ownership automatically — no root needed at runtime for that case.
- `entrypoint.sh` runs a best-effort `chown -R node:node /etc/letsencrypt /app/data` at startup, silently ignored on failure, to self-heal an *existing* volume left root-owned by a prior root-run deployment. `CAP_CHOWN` lets a non-root process change a file's owner, but it does **not** grant directory traversal into a restrictively-permissioned tree it otherwise can't read — a deeply-locked-down pre-existing volume may only get partially fixed by this. The guaranteed fallback for migrating an existing deployment is a one-time host-side fix: `docker run --rm -v letsencrypt:/etc/letsencrypt -v rca-cache:/app/data alpine chown -R 1000:1000 /etc/letsencrypt /app/data`.

**Mock mode**
- Set `MOCK_FILE=/path/to/mock_data.json` to bypass all API calls; the file is loaded once at startup and serves as the cache — the fastest way to iterate on dashboard/report UI without live credentials

**Critical Misconfigurations — Critical-severity only, High dropped**
- `fetchCompliance()`'s Step 1 policy filter (`sevOk`) was narrowed from `['critical','high'].includes(severity)` to `severity === 'critical'` only, on request. `cache.compliance` (and the "Critical Misconfigurations" dashboard tab that renders it directly, `renderCompliance()`) now only ever contains Critical-severity findings — no High-severity ones reach it anymore.
- This didn't change the posture score, `computeAssetRiskMap`'s Critical Misconfiguration factor, or the Private Host panel's "Critical Misconfigs" badge — all of those already independently filtered `compliance` down to `severity === 'critical'` themselves (see `_critCompl` in `_renderVulns`, and the equivalent inside `computeAssetRiskMap`), so this change actually just makes the raw fetch match what those consumers were already narrowing to. It reduces what appears in the Critical Misconfigurations *tab* itself (fewer, Critical-only rows) and reduces `Queries/execute` call volume (fewer policies evaluated per refresh), but doesn't change any score.
- The now-pointless Critical-first `.sort()` in Step 1 (a no-op once every policy is already Critical) was removed alongside this change — don't reintroduce it without also reintroducing High severity.

**Standalone ROI/FAIR calculator (`roi-calculator.html`)**
- Lives as its own static HTML file rather than an embedded template literal like `MOBILE_HTML`, because its client-side script is full of backtick template literals and `${...}` interpolation that would collide with `buildHtml()`'s own outer template-literal syntax if inlined. Read once at startup into `ROI_CALCULATOR_HTML`; edits to it need a container restart (or hot-`docker cp` of the file itself) to take effect, not just `server.js`
- `calculator.md` (repo root of `rca_ui/`) is the user-facing guide explaining the FAIR ALE (Annualized Loss Expectancy) methodology behind the calculator's numbers
- The dashboard's report-download button opens `/roi-calculator` with query-string params so its Cloud Risk tab auto-populates from the live dashboard's current finding counts, rather than requiring manual entry

**Shared `@fortinet.com` courtesy access gate**
- Admin Settings, the manual `POST /api/refresh-cache` button, and similar sidebar "Management" actions are all gated the same way: read the `rca_email` cookie (set client-side, user-supplied at the `/api/login` email gate) and require it to end in `@fortinet.com`, both client-side (hide the control) and server-side (reject the request). This is **not** real access control — the cookie isn't cryptographically signed or verified against any identity provider — it's a courtesy lock against accidental clicks by non-Fortinet visitors, not a security boundary. Don't treat passing this check as authorization for anything sensitive

**Verified Exposure Paths (`fetchExposurePaths`, `cache.exposurePaths = {s3, ec2, azureVm, azureBlob}`)**
- Queries `LW_APA_EXPOSURE_PATHS` (Lacework's own graph-traced Internet→Target attack-path engine) for four target types: `s3:bucket`, `ec2:instance`, `microsoft.compute/virtualmachines`, `microsoft.storage/storageaccounts/blobservices`. Each record's `TARGET` field (capitalized in the API response despite being aliased `target` in the query) carries a `PATH` (hop-by-hop Internet→Gateway→SG/NSG→resource chain) and `METRICS.path_length` (hop count)
- Purely additive: does **not** feed `fetchTrueExposure`'s SG/NSG/FW-rule detection, dashboard counts, posture score, or reports — it's a second, independently-computed signal
- Matched onto existing rows client-side (not server-side) and rendered as a green "Verified Path" chip: in Host Internet Exposure by EC2 instance ID (`TARGET.key.id` ↔ `machineTags.InstanceId`) or Azure VM name (`TARGET.displayName` ↔ `machineTags.Hostname`, case-insensitive); in Public Storage Exposure by bucket/container name. A bucket/VM with no traced path just shows nothing — not every asset has API coverage (e.g. this table can return as few as 1 row for `ec2:instance` tenant-wide)
- Buckets found *only* via a traced path (not by the existing policy/ACL check) are added as their own Public Storage Exposure row at severity `high` (vs `critical` for confirmed-public policy/ACL findings) — a real network path was confirmed, not that the bucket's own policy grants public access

**Resource ID / Resource Name (`fetchTrueExposure`'s `azureComputerNames`)**
- `fetchTrueExposure()` returns `{getExposureEvidence, azureComputerNames}` (not just the evidence function) — the latter maps Azure VM ARM resource name (lowercase) → OS computer name, from `LW_CFG_AZURE_COMPUTE_VIRTUALMACHINES`'s `RESOURCE_CONFIG.extended.instanceView.computerName`. `fetchVulns()` uses it to backfill `machineTags.Name` for Azure hosts, which otherwise have no equivalent to AWS's Name tag
- Matters because Azure's ARM resource name (`machineTags.Hostname`, e.g. `RJ-EMSONPREM`) can differ from the actual OS computer name FortiCNAPP's own console displays/searches by (e.g. `EMS-FranLab`) — without this, a host findable in this dashboard could appear unfindable when searching the FortiCNAPP console directly
- The Host Internet Exposure panel shows both `machineTags.InstanceId` (Resource ID) and `machineTags.Name` (Resource Name) per host, uniformly for both clouds

**Known-stale CSPM findings**
- `STALE_STORAGE_FINDINGS` (inside `computeEffectivePublicStorage`, client-side) hardcodes an exclusion list for public-storage findings confirmed to reference resources no longer existing in the live cloud account (verify via a live anonymous HTTP request to the resource — Azure returns `ResourceNotFound`, not a public-access-denied error, when the container itself is gone). This is a workaround for FortiCNAPP CSPM scan staleness, not a detection-logic bug — the real fix is a fresh CSPM re-scan in FortiCNAPP itself. Don't add entries here without confirming via a live check first (a resource can also legitimately still be public)

**Public Storage Exposure — dashboard tab removed, underlying data/computation still live**
- The dedicated `view-storage`/`nav-storage` dashboard tab and its `renderPublicStorage()` client function were removed from `buildHtml()` per an explicit request to drop the tab from the UI — `renderPublicStorage()` itself is still defined but is dead code now (no longer called from `load()`), left in place rather than deleted since it wasn't part of what was asked.
- `computeEffectivePublicStorage()` (both the client-side copy and its server-side port) was **not** removed and is still very much alive — it's independently called by the Exploit Simulation Layer's `lab-storage-badge` count (Lab tab), and by all four report builders (`/report`, `/report2`, `/report3`, `/report4`). None of those consumers depended on the dashboard tab's DOM elements, so removing the tab didn't affect them.
- `lab-storage-badge`'s `onclick="nav('storage')"` was removed (it would otherwise silently no-op on a dead hash — `nav()` guards missing elements rather than erroring) — it's now a static, non-clickable info badge showing the same count.

**"Internet Exposed Resource" panel (formerly "Internet Exposed Host", `id="view-iehb"`/`cnt-iehb`/`body-iehb` — internal `iehb`-prefixed IDs and function names were NOT renamed, only the user-visible label) — a direct listing of cache.attackPaths resources, decoupled from cache.highRiskVulns**
- This panel went through several iterations (raw exposure tag + hostRiskScore≥7 → Attack Path + riskScore≥4 → Attack Path + PathSev → Attack Path only, hostname-matched against `highRiskVulns` hosts) before landing here. The `highRiskVulns`-intersection approach was dropped entirely because it was structurally too narrow: it required a host to appear in *both* `cache.highRiskVulns` (CVE-driven) *and* `cache.attackPaths` (graph-driven), and this tenant's `LW_APA_ATTACK_PATHS` coverage has **zero EC2 targets**, so the intersection topped out at 2 hosts no matter how the match/threshold logic was tuned.
- Current implementation (`_renderInternetHostExposedBeta`) sources **exclusively from `cache.attackPaths`** (`LW_APA_ATTACK_PATHS`, `FILTER { METRICS:"path_score" >= 40 }` server-side — see `fetchAttackPaths()`) — no `cache.highRiskVulns`, no `cache.vulns`, no cross-referencing at all. It flattens every `TARGET` across every attack-path record into one row per distinct resource (deduped by `type+name`, keeping the highest `path_score` seen), at *any* `path_severity` — no additional threshold.
- Resource types are **not** restricted to compute hosts, despite the panel's name — S3 bucket `TARGET`s (`s3:bucket`) are listed alongside VM targets (`microsoft.compute/virtualmachines`, `ec2:instance`, etc.). This was a deliberate scope decision, not an oversight.
- Rendered as two-column cards deliberately styled to match the **Private Host Most Exposed** panel (`_renderVulns`) — cloud-icon + name header, severity/score badge pills, a left "Resource Details" column (`detailRow()` pairs: Resource Name, Resource ID, Type, Domain/Account). Since this panel has no vuln/host findings data at all (no `cache.highRiskVulns` dependency), the right column shows "Attack Path Details" (hop chain via `exposurePathHopsStr()`, hop count, first-seen date) instead of Private Host's "Security Findings" — everything else Private Host's cards have (CVE table, correlated asset-risk score, matched compliance violations, attached IAM role, "View all findings" expand/collapse) has no equivalent here and was not carried over.
- `hostHasAttackPath()` (hostname/display-name match only against `TARGETS`' `tags.Name`/`displayName` — instance ID/ARN matching was tried and dropped) is still kept, but now used **only** by `iehbQualifyingHostSet()`, which `_renderVulns()` (Private Host Most Exposed) calls to exclude any host with a computed attack path from that panel — this cross-panel exclusion is independent of how this panel itself renders.
- `fetchAttackPaths()`'s `path_score >= 40` server-side floor is shared with the **Attack Paths** tab, which applies its own tighter `path_score >= 80` client-side on top — raising the shared floor above 80 would silently start dropping rows that tab needs.
- The panel's static header subtitle (`buildHtml()`, the `.vh-sub` div) still reads "Matches the FortiCNAPP console's own Hosts with Internet exposed = True" — stale/inaccurate against the actual `hostHasAttackPath()` logic above, left as-is per an earlier explicit user instruction not to "fix" it, and not updated as part of the rename either. Don't "fix" it without checking first.

**"Permissive SSH Keys" tab (`nav-ssh-keys`/`view-ssh-keys`/`cnt-ssh`/`body-ssh-keys`) — new, live-dashboard exposure of data that previously only appeared in reports**
- `renderSSHKeys(rows, err)` reads `cache.secrets` (`d.secrets` from `/api/data`) — the same `fetchSecrets()` data (`LW_HE_SECRETS_SSH_PRIVATE_KEYS`, `FILTER FILE_PERMISSIONS > 33024` i.e. looser than chmod 400 on a regular file) that `buildReportHtml2`'s "Permissive SSH Keys Access" section (`sshKeyRows`) already rendered — this tab is the first time that data has been surfaced in the live dashboard itself rather than only in a generated report.
- No new server-side fetching was needed — `cache.secrets`/`cache.errors.secrets` were already populated by `refreshData()`'s existing Phase 1 `fetchSecrets()` call; this was purely a client-side (`buildHtml()`) addition: a sidebar nav item, a `view` section, and `renderSSHKeys()` wired into `load()`.
- Table columns (Hostname, File Path, Key Type, Permissions as an octal `0NNN` badge) mirror the report's `sshKeyRows` formatting for consistency between the two surfaces.
- **Cross-panel consistency:** `iehbQualifyingHostSet(d)` (client-side, pure/stateless) recomputes the same qualifying-hostname set and is also called from `_renderVulns()` (Private Host Most Exposed) to exclude any host that qualifies for Internet Exposed Host — otherwise the same physical host could appear in both tabs at once. If you add a third panel with its own exposure definition, extend this exclusion rather than letting a host appear in two places under contradictory labels.

**Report sanitization**
- `?sanitize=1` on `/report`, `/report2`, `/report3`, or `/report4` runs `sanitizeCacheData()` first, deterministically replacing real hostnames, ARNs, account IDs, IPs, emails, and secret IDs with stable fake values (same real value → same fake value within one render) — for sharing screenshots/demos without leaking customer data

**Four report formats, not four phases**
- `/report`, `/report2`, `/report3`, and `/report4` are independently maintained builders reading the same `cache`; `/report2` is explicitly commented as beta/wider-scope, `/report3` is a condensed chart-first executive overview, and `/report4` (**Generate Report_BETA**) is a narrative assessment-style report. Changes to shared logic (asset risk, CSP scores, host grouping) belong in the shared helpers (`computeAssetRiskMap`, `computeCspScores`, `groupVulnsByHost`, `assetRiskTier`), not duplicated per-builder.
- **`buildReportHtml4()`'s "Risk Findings Categories" section is deliberately NOT a keyword classifier** over every finding type (unlike an earlier iteration of this section) — it's four curated buckets: Identity & Access (true full-admin — `ALLOWS_FULL_ADMIN` — identities without MFA, root accounts excluded, plus high-permission IAM/RBAC roles), Misconfiguration (Critical-severity compliance findings only), Secrets on Exposed Host, and Internet Accessible Storage. Don't reintroduce a broad alerts/compliance keyword classifier here without re-confirming that's what's wanted — it was deliberately narrowed.
- `/report4`'s Section 6a (Internet-Exposed Hosts) renders each host as an expandable `<details>`/`<summary>` card — collapsed by default, showing a per-finding table on expand with CVE package/current-version/fix-version and secret absolute file path (`FILE_PATH`), re-joined from the raw `vulns`/`secretsAll` arrays rather than `computeAssetRiskMap`'s aggregated (type-string-only) lists.
- `groupVulnsByHost()` and `buildReportHtml2()`'s "High Vulnerability — Internet-Exposed Hosts" section sort/filter on `cveRiskScore` (falling back to `riskScore`), not `riskScore` alone — `riskScore` is a broader composite metric that can diverge significantly from a CVE's actual severity (seen live: one CVE at `cveRiskScore` 9.95 had `riskScore` 6.3), which previously caused genuinely-critical, internet-exposed hosts to be silently dropped from that report section entirely. `computeAssetRiskMap`'s own CVE-factor scoring intentionally still uses `riskScore` (a separate, unrelated code path) — don't conflate the two when touching either.

**SVG diagram element IDs must be globally unique per render**
- `hexKillChainSvg()` (used by the Exploit Simulation Layer's Global tab, each per-CSP tab, and the per-host Attack Path modal) generates its own `<defs>` gradient/filter IDs via a running counter (`hexKillChainSvg._seq`), not a hash of the diagram's shape. Inactive tabs'/panels' SVGs are hidden via CSS, not removed from the DOM, so multiple diagram instances can coexist on the page at once — if two of them ever computed the same ID again (as a shape-based hash briefly did, since every per-CSP tab has the same factor count), the browser resolves `url(#id)` fill/filter references against whichever matching element it finds first in document order, silently breaking the *other* diagram's rendering (transparent/unreadable hexagons). Keep ID generation counter-based, not derived from renderable content.

**Score field glossary — `riskScore` vs `cveRiskScore` vs `hostRiskScore` vs `normalizedScore` vs identity `risk_score` vs `path_score`. Don't confuse these — they are five unrelated numbers that happen to share the word "risk"/"score" in their name, on different scales, from different sources, gating different thresholds.**

| Field | Lives on | Scale | What it actually measures | Where it's used |
|---|---|---|---|---|
| `cveRiskScore` | a CVE record (`fetchVulns`) | ~0–10 (practically maxes ~9.95, not 10) | FortiCNAPP's proprietary **"Risk Score"** as documented at [docs.fortinet.com/.../risk-score](https://docs.fortinet.com/document/forticnapp/latest/administration-guide/903844/risk-score) — an environment-specific *impact* score, NOT plain CVSS: it blends CVE severity/CVSS with prevalence (number of hosts/images/packages affected), internet exposure, and known/active exploit signals, recalculated daily. Per that doc's own example: a low-CVSS CVE detected across a large or internet-facing portion of the environment scores **high** here even though its CVSS is low. This is the same field the FortiCNAPP console filters on when someone sets "Risk score ≥ N" | The authoritative field everywhere in this file now — see `HIGH_RISK_CVE_THRESHOLD` below. Standard fallback pattern: `cveRiskScore ?? riskScore ?? 0` |
| `riskScore` | the *same* CVE record, a separate field | ~0–10 | A distinct score Fortinet's public docs don't name separately from "Risk Score" above — but it's empirically **not** the same number: one live CVE sat at `cveRiskScore` 9.95 while its `riskScore` was only 6.3 for the identical record. Because `cveRiskScore` is confirmed to be the documented, console-matching Risk Score, treat `riskScore` as the less-trustworthy/less-current of the two, used only as a fallback | Only read directly (no `cveRiskScore` fallback) by `fetchVulns()`'s own base API filter (`cveRiskScore>=8`, the widest net — everything below unifies as a strict subset of it) and `calcRiskScore()`'s server-side logging approximation (intentionally *not* meant to mirror the real posture score — see below) |
| `hostRiskScore` | also on the CVE record, despite the name — it's actually a **host**-level composite | ~0–10 | Per Fortinet's docs, host-level risk is a *probability of compromise*: for every vulnerability on the host, FortiCNAPP estimates a per-CVE exploit probability, combines them into an overall probability that at least one succeeds, discounts that by the host's internet exposure, then ×10 for the final score — a fundamentally different calculation from the per-CVE `cveRiskScore` above, not just a different aggregation of the same inputs | Deliberately **not** used as the primary CVE-severity signal (a host can sit at `hostRiskScore` 0.22 while carrying a CVE at `cveRiskScore` 9.74 — one severe CVE gets diluted across everything else factored into that host's compromise probability). Only appears as a last-resort fallback (`cveRiskScore ?? riskScore ?? hostRiskScore ?? 0`) in a couple of display/sort spots |
| identity `METRICS.risk_score` | an identity record (`fetchIdentities`), not a CVE at all | 0–1 | FortiCNAPP's CIEM identity risk score | `identityRiskScore(r)` multiplies it ×100 so it sits on the same 0–100 scale as everything else in the posture score's mean |
| `normalizedScore` | not an API field — locally computed by `computeAssetRiskMap`/`buildAssetRiskMap` | 0–100 | A host's summed CIEM+secret+CVE+misconfig points, divided by the max across all hosts in this tenant | Feeds `assetRiskTier()`'s `ASSET_TIER_THRESHOLDS` cutoffs (75/50/30) — **not** compared against any raw `riskScore`/`cveRiskScore` value |
| `path_score` | an attack-path record (`LW_APA_ATTACK_PATHS`) | 0–100 | The Attack Paths engine's own traced-exploitability score — unrelated to any of the above | `fetchAttackPaths()`'s `≥40` server floor; Attack Paths tab's tighter `≥80` client filter |

**The unified "high-risk CVE" gate — `HIGH_RISK_CVE_THRESHOLD = 9.85`** (defined once, server-side, next to `SEVERITY_WEIGHTS`/`ASSET_TIER_THRESHOLDS`; embedded into `buildHtml()`'s and `MOBILE_HTML`'s client `<script>` via `JSON.stringify()`, same pattern as those two). This used to be a scattered, drifting mix — `fetchHighRiskVulns()`'s server query at `≥9`, `_renderVulns()`'s client filter at `≥9`, `riskFindingHostExposure()`'s gate (first documented as `≥9.5`, silently changed to `≥9.95` without updating that comment), `buildReportHtml2`'s `hostExposureVulns` at `≥9`, `buildReportHtml`'s CVE listing at `≥9` — all now read `cveRiskScore ?? riskScore ?? ...` against this one constant. Two consumers that previously read plain `riskScore` (the less-trusted field, no fallback) were switched onto the same `cveRiskScore ?? riskScore` preference at the same time: **posture score's CVE factor** (`calcPostureScore`, both desktop and mobile copies) and **the asset risk map's CVE factor** (`computeAssetRiskMap`/`buildAssetRiskMap`) — the asset map didn't have any floor before, so this is a new behavior change there, not just a field swap: a CVE below 9.85 now still gets listed on its host but contributes zero risk weight, instead of always contributing `min(100, riskScore×10)`.

Two deliberate exceptions, both in `buildReportHtml` and both kept apart from the 9.85 baseline on purpose via a second constant, `MAX_SEVERITY_CVE_THRESHOLD = 9.95`: the CVE listing's `outcome` copy (a CVE at/above this reads as "full system compromise" instead of "remote code execution"), its risk-chip badge styling, and the per-host `critCnt` badge. Collapsing these onto `HIGH_RISK_CVE_THRESHOLD` would have made `critCnt` equal every row already passing the listing's own floor, erasing the "even more severe" distinction it exists for — so they instead moved from the old, now-unreachable `riskScore ≥ 10` (once `rs` prefers `cveRiskScore`, whose practical ceiling is ~9.95, a literal `≥10` check would never fire again) to `cveRiskScore ?? riskScore ?? 0 ≥ 9.95`, the same "practically maxed out" cutoff `riskFindingHostExposure()` already used. `fetchVulns()`'s own base API filter (`cveRiskScore ≥ 8`) was deliberately left untouched — it's the widest net, and every 9.85/9.95 gate above is already a strict subset of it, so nothing needed to change there.

**Not part of this unification, kept separate on purpose:** `calcRiskScore()` (server-side, `refreshData()` logging only — explicitly documented as a cheaper approximation never shown in the UI, so its own `riskScore ≥ 8` floor was left as-is) and `buildReportHtml2`'s `vulnScoreSeverity()` display bucketing (`≥9`/`≥7`/`≥4`, a 4-tier label function applied to rows already pre-filtered by `HIGH_RISK_CVE_THRESHOLD`, not itself an inclusion gate).

**Posture score formula** (server `calcRiskScore` is a *different*, cheaper approximation used only during `refreshData()` logging — the score shown in the UI is `calcPostureScore`, computed client-side and mirrored nowhere server-side):
```
postureScore = max(0, round(100 − mean(findingRiskScores)))
```
Risk weights per finding, drawn from the shared `SEVERITY_WEIGHTS = { critical: 100, high: 70, medium: 40, low: 10 }` table (also used by the asset risk map and CSP score below, so a "critical" means the same 100 points everywhere):
- Alert: `SEVERITY_WEIGHTS.critical/high/medium` by severity (100/70/40)
- CVE: `(cveRiskScore ?? riskScore)×10` (max 100) — **only counted when that value ≥ `HIGH_RISK_CVE_THRESHOLD` (9.85)**; lower-severity CVEs are excluded from the average entirely, not included at a low weight. See the score field glossary above for why `cveRiskScore` is preferred
- Compliance: flat `SEVERITY_WEIGHTS.critical` (100) — compliance findings reaching this point are already critical-only (see "Critical Misconfigurations" below)
- Identity: `identityRiskScore(r)` — 80 if it's an admin, no-MFA identity with either ≥80% unused permissions or an old access key; otherwise `min(100, METRICS.risk_score×100)`
- Secret: flat `SEVERITY_WEIGHTS.low` (10)

There is no separate secret-count penalty. Bands: ≥90 green · ≥50 amber · <50 red.

**Correlated Risk Findings per Asset** (`computeAssetRiskMap`/`buildAssetRiskMap`, shared by dashboard + all four reports)

Four factors summed per host, then normalized 0–100:

| Factor | Points | Source |
|---|---|---|
| CIEM high-perm credential | `SEVERITY_WEIGHTS.critical` (+100) per secret | `secretsAll` where `SECRET_TYPE` is an SSH key / AWS / GCP / Azure credential type |
| Secret (generic) | `SEVERITY_WEIGHTS.high` (+70) per secret | `secretsAll` — all other secret types |
| CVE threat exposure | `(cveRiskScore ?? riskScore) × 10` per CVE (max 100), **only if ≥ `HIGH_RISK_CVE_THRESHOLD` (9.85)** — otherwise 0 | `vulns`, matched to host via `machineTags.Hostname` / `evalCtx.hostname` / `mid`. The CVE still appears in the host's finding list either way; only the risk-weight contribution is gated |
| Critical misconfiguration | `min(60, criticalPolicyCount × 10)` flat | `compliance` — account-wide, same boost applied to every host with existing risk. Not drawn from `SEVERITY_WEIGHTS` — this is a separate capped account-wide boost, not a per-finding severity weight |

```
assetRawRisk   = Σ(ciem×100) + Σ(genericSecret×70) + Σ(cve≥9.85 ? cve.riskScore×10 : 0) + min(60, critCompliance×10)
normalizedScore = round(assetRawRisk / maxAssetRawRisk × 100)
```

Risk tier (`assetRiskTier`, cutoffs in `ASSET_TIER_THRESHOLDS = { critical: 75, high: 50, medium: 30 }`) — internet exposure (from `fetchTrueExposure`, i.e. an actual open security-group/NSG/firewall rule from a public source, not just a public IP) adjusts the tier. These are score-bucketing cutoffs on `normalizedScore`, a different concept from `SEVERITY_WEIGHTS` (which weights individual findings) — kept as their own table on purpose:

| Base score | Internet Exposed | Tier |
|---|---|---|
| ≥ 75 | Yes | CRITICAL |
| ≥ 75 | No | MEDIUM (downgraded — no external attack surface) |
| 50–74 | Yes | HIGH |
| 50–74 | No | LOW (downgraded) |
| 30–49 | Any | MEDIUM |
| < 30 | Any | LOW |

**Per-CSP score** (`computeCspScores`, server; mirrored client-side by `calcCspScore`) — rate-based, not raw-count-based, so a cloud with 2 findings and a cloud with 200 findings are scored on the same scale:
```
penalty = SEVERITY_WEIGHTS.critical×(critical/total) + SEVERITY_WEIGHTS.high×(high/total) + SEVERITY_WEIGHTS.medium×(medium/total) + SEVERITY_WEIGHTS.low×(low/total)
score   = max(0, round(100 − penalty))
```
i.e. `penalty = 100×(critical/total) + 70×(high/total) + 40×(medium/total) + 10×(low/total)`. Because this now uses the same 100/70/40/10 scale as the posture score and asset risk map (previously its own 40/30/20/10 penalty scale, which floored the minimum possible score at 60 even for a 100%-critical cloud), **a cloud whose findings are entirely critical can now score as low as 0**, not 60 — a real behavior change from the old scale, not just a relabeling.
Alerts/compliance/identities are bucketed into a cloud by keyword matching on alert type/name, `cloud` field, or `PROVIDER_TYPE`/`CLOUD_PROVIDER`. Overall score is the mean of the three CSP scores (clouds with zero findings score 100, not excluded).

## Collect artefacts from a running container

```bash
docker cp rca:/app/rca.html ./rca.html     # original report
docker cp rca:/app/rca.pdf  ./rca.pdf
docker cp rca:/app/rca2.html ./rca2.html   # beta wider-scope report
docker cp rca:/app/rca2.pdf  ./rca2.pdf
docker cp rca:/app/rca3.html ./rca3.html   # condensed chart-first overview
docker cp rca:/app/rca3.pdf  ./rca3.pdf
docker cp rca:/app/rca4.html ./rca4.html   # narrative assessment-style report (BETA)
docker cp rca:/app/rca4.pdf  ./rca4.pdf
docker cp rca:/app/contacts.csv ./contacts.csv
```

`collect_report.sh` in this directory only grabs `contacts.csv` today — it predates `/report3`/`/report4` and hasn't been extended to pull every report variant.
