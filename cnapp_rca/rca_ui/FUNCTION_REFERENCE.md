# server.js Function Reference

This is a beginner-friendly, function-by-function walkthrough of `server.js` (~9,270 lines) — the entire FortiCNAPP Rapid Cloud Assessment app. It's aimed at someone new to the codebase who wants to understand what each function does and why, without having to read all 9,000+ lines first.

## The one thing you must know before reading this file

**`server.js` contains two programs glued into one file: a Node.js server, and a browser (client-side) web app.** There's no build step, no bundler, no `package.json` — so instead of separate `.js` files for frontend and backend, the entire client-side dashboard (HTML + CSS + JavaScript) is written as one giant string inside the server-side `buildHtml()` function (and a second giant string, `MOBILE_HTML`, for the mobile view). When a browser requests the dashboard, Node.js returns that string as the HTTP response; the browser then parses and executes the `<script>` block inside it — **at that point, none of that code is running in Node.js anymore. It's running in the visitor's browser**, with access to `document`, `window`, and `fetch`, and *no* access to the server's `cache` object, API credentials, or any Node.js-only function.

This matters constantly while reading the code: a function like `calcPostureScore()` that runs in the browser and a function like `calcRiskScore()` that runs on the server can look like they do the same thing (compute a risk score) but are completely separate pieces of code that happen to implement similar formulas — changing one does not change the other. This document calls out **[SERVER]** vs **[CLIENT]** for every function so this distinction stays clear.

## Table of contents

1. [Configuration, Cache & Low-Level HTTP/DNS Plumbing](#1-configuration-cache--low-level-httpdns-plumbing-server) — `[SERVER]`
2. [API Fetchers — Talking to FortiCNAPP/Lacework](#2-api-fetchers--talking-to-forticnapplacework-server) — `[SERVER]`
3. [Orchestration & the Desktop Dashboard Scaffold](#3-orchestration--the-desktop-dashboard-scaffold-server) — `[SERVER]`
4. [Client-Side Dashboard JavaScript](#4-client-side-dashboard-javascript-client) — `[CLIENT]` (this is the biggest section — it's the entire browser app)
5. [Mobile View & Shared Report Helpers](#5-mobile-view--shared-report-helpers-mixed) — mixed
6. [Report Builders (PDF/HTML reports)](#6-report-builders-pdfhtml-reports-server) — `[SERVER]`
7. [Request Routing & Startup](#7-request-routing--startup-server) — `[SERVER]`

---

## 1. Configuration, Cache & Low-Level HTTP/DNS Plumbing `[SERVER]`

This is the "plumbing" underneath the FortiCNAPP dashboard: it reads configuration (API keys, ports, look-back windows), sets up an in-memory `cache` object that the rest of the app reads from, and provides low-level helpers for talking to the Lacework/FortiCNAPP API over HTTPS — including manual DNS/TCP probing to dodge flaky network paths, token-based auth, and a retry wrapper that respects Lacework's rate limits. It also defines small time-formatting utilities used to build API time-window filters, and the first couple of "fetcher" functions and classification helpers that sit right above this plumbing layer.

### Config & environment variables (lines 14–46)
Loads settings from environment variables (or an optional `LW_KEY_FILE` JSON file) instead of hardcoding secrets: the Lacework account URL (`LW_ACCOUNT`), API key/secret (`LW_KEY_ID`/`LW_SECRET`), optional sub-account name, server ports, optional TLS cert/key paths, and the default look-back windows (`DAYS_BACK`, `ALERT_DAYS_BACK`). It also ensures a `contacts.csv` file exists on startup (creating it with a header row if missing) since the app appends visitor contact info to it later. Gotcha: if none of the env vars/key file are set, the placeholders `'YOUR_KEY_ID'`/`'YOUR_SECRET_KEY'` are used silently — auth will fail with a real API error rather than a clear "not configured" message.

### `cache` object (lines 56–61)
A single in-memory object holding every piece of data the dashboard displays (alerts, vulns, compliance, identities, public storage, Fortinet inventory, risk score, etc.) plus bookkeeping fields like `fetchedAt` and `errors`. It exists so the HTTP server can respond instantly to page requests using whatever was fetched last, rather than calling the FortiCNAPP API on every page load. Side effect/gotcha: this is mutated in place all over the file (not replaced), and `loadCacheFromDisk()`/`saveCacheToDisk()` persist it to `data/cache.json` so the dashboard isn't blank immediately after a container restart while the next refresh (which can take minutes) runs in the background.

### `startRefreshTimer()` (lines 38–41)
Schedules `refreshData()` to run repeatedly on an interval (default 24 hours, adjustable via `dynamicInterval`). It clears any existing timer first so calling it again (e.g. after a settings change) doesn't stack up duplicate timers.

### `loadCacheFromDisk()` (lines 73–85)
Reads `data/cache.json` from disk at startup and merges it into the in-memory `cache` so the dashboard shows the last-known-good data immediately instead of empty panels while the first live refresh runs. It spreads the loaded data *onto* the existing default `cache` shape (`{ ...cache, ...loaded }`), which matters because an older cache file written before a new field existed must not wipe out that field's in-code default. If the file doesn't exist (`ENOENT`), it silently does nothing; other read/parse errors are just logged.

### `saveCacheToDisk()` (lines 86–93)
Writes the current `cache` object to `data/cache.json` as JSON, creating the `data` directory first if needed. This is what makes the cache survive container restarts/redeploys; failures are logged but don't crash the app.

### `tcpReachable(ip, port)` (lines 103–111)
Checks whether a raw TCP connection can actually be opened to a given IP and port, resolving `true`/`false` (never rejects). It exists because DNS can return an IP that's technically valid but unreachable from this specific host (e.g. blocked by network policy), and this is a quick way to test connectivity before committing to using that address. Gotcha: it has a hardcoded 3-second timeout and always calls `resolve()` rather than `reject()`, so callers never need a `.catch()`.

### `resolveReachableIP(hostname)` (lines 113–124)
Resolves all IPv4 addresses for a hostname (like the Lacework account domain) and tests each one with `tcpReachable` until it finds one that actually responds on port 443, returning that IP (or `null` if none work). This exists because the environment this app runs in has occasionally hit DNS results that resolve but aren't reachable — probing manually and caching the good IP for the container's lifetime avoids repeatedly hitting a dead address on every request.

### `request(method, hostname, path, headers, body, timeoutMs = 30000)` (lines 126–154)
The lowest-level HTTP client in the file: makes a single raw HTTPS request and returns a promise resolving to `{ status, body, raw, headers }` (`body` is JSON-parsed automatically if possible, otherwise left as the raw string). Its one non-obvious trick: if the target hostname matches `LW_ACCOUNT` and a pre-verified `accountIP` exists (from `resolveReachableIP`), it overrides Node's normal DNS lookup via a custom `lookup` option so the request goes straight to the known-good IP instead of re-resolving DNS every call. It also enforces the given timeout by destroying the request and rejecting with an `Error` (not resolving) if the response is too slow.

### `fetchCveDetails(cveId)` (lines 157–208)
Given a CVE ID (e.g. `"CVE-2023-1234"`), looks it up against two external sources — the NVD API (structured JSON with CVSS score/severity/description) and FortiGuard's search page (scraped HTML, since it has no public JSON API) — and returns a merged object `{ id, nvd, fg, error }` with whatever details could be gathered from each source independently. It exists to enrich vulnerability rows in the dashboard with extra context beyond what Lacework provides. Gotcha: the FortiGuard part is regex-scraping HTML, which is inherently fragile and will silently return `null` fields if FortiGuard changes its page markup; each source's failure is captured independently so one source failing doesn't block the other.

### `ensureToken()` (lines 212–228)
Returns a valid Lacework API bearer token, reusing the cached `token` if it hasn't expired yet, otherwise requesting a fresh one via `POST /api/v2/access/tokens` using the configured key/secret. It exists so every other API call doesn't need to fetch a new token each time (tokens are cached for ~56 minutes, just under Lacework's 1-hour token lifetime). Gotcha: it treats both HTTP 200 and 201 as success since Lacework returns 201 Created for token generation, which is easy to miss if you only check for 200.

### `withRetry(fn, label, retries = 5)` (lines 232–257)
Wraps an API call (`fn`, which must return a `request()`-style promise) and automatically retries it on failure, up to `retries` times. It exists because Lacework enforces a strict rate limit (480 requests/hour per endpoint, shared across all callers hitting that path), so hammering the API without backoff would just produce a wall of 429 errors. Its behavior differs by failure type: a `429` (rate limited) makes it read the `RateLimit-Reset` response header and wait that many seconds (capped between 1–30s) before retrying, rather than guessing; a `5xx` or thrown error uses a simple linear backoff (`2000ms * attempt`); and a genuine timeout error is re-thrown immediately without exhausting all retries. Gotcha: any `status < 500` other than 429 (e.g. a 4xx like 403/404) is returned as-is without retrying — retries are only for rate limits and server errors.

### `subAccountHeaders(tok)` (lines 259–264)
Builds the standard auth headers for an API call — `Authorization: Bearer <token>` plus an `Account-Name` header, but only if `LW_SUBACCOUNT` is configured. This exists because Lacework organizations can have multiple sub-accounts, and omitting the header entirely (rather than sending an empty string) is required when no sub-account is set.

### `post(path, body, timeoutMs = 30000)` (lines 266–276)
A high-level helper for calling `POST /api/v2/<path>` on the Lacework API: it gets a token, wraps the actual request in `withRetry`, and normalizes the response into a plain array — Lacework typically returns `{ data: [...] }`, but this unwraps that (or returns `[]` for a 204 No Content) so every caller elsewhere in the file can just treat results as arrays. It throws an `Error` for any non-200/201/204 status, with a truncated snippet of the response body for debugging.

### `get(path)` (lines 278–288)
Same idea as `post`, but for `GET /api/v2/<path>` requests with no body. Unlike `post`, it returns the raw response body as-is (not normalized to an array), or `null` for a 204, since GET endpoints in this app have varying response shapes.

### `postRaw(path, body, timeoutMs = 30000)` (lines 290–294)
A stripped-down version of `post` that skips both `withRetry` and the array-normalization/error-throwing logic, just returning `{ status, resp }` directly. It exists for callers that need to inspect the raw status code themselves rather than having errors thrown automatically.

### `putRaw(path, body, timeoutMs = 30000)` (lines 296–300)
The same idea as `postRaw` but for `PUT` requests — makes the call, fetches a token first, and returns `{ status, resp }` untouched, leaving status handling to the caller.

### `timeFmt(d)` (line 303)
Formats a JavaScript `Date` into the ISO-8601 string format Lacework's API expects, stripping the milliseconds portion.

### `timeFilter(days)` (lines 305–310)
Builds a `{ startTime, endTime }` object spanning from `days` ago (or the current `dynamicDaysBack` default if `days` isn't passed) until now, formatted with `timeFmt`. This is the standard shape most Lacework v2 search endpoints expect for their time window. Gotcha: the field is singular `timeFilter`, not `timeFilters` — an easy typo to make since some other APIs use the plural.

### `timeArgs(days)` (lines 312–315)
Converts the same start/end window from `timeFilter` into the alternate `arguments: [{ name, value }, ...]` array format that Lacework's `Queries/execute` (custom LQL query) endpoint expects instead of a `timeFilter` object — same data, different shape for a different API.

### `alertTimeWindows(daysOverride)` (lines 320–330)
Splits a total look-back period (e.g. 14 days) into a series of 7-day `{ startTime, endTime }` chunks. This exists because the Alerts search API caps how far back a single request can look at 7 days, so fetching a longer window requires multiple sequential/parallel requests, each covering one chunk.

### `fetchAlerts()` (lines 332–350)
Fetches all alerts over the fixed `ALERT_DAYS_BACK` window (14 days) from Lacework, then narrows them down to a curated "High Fidelity Alerts" list for the dashboard. It builds a batch of API calls — one per (7-day time window) × (severity: Critical/High/Medium) — runs them all in parallel via `Promise.all`, flattens the results, then filters client-side to only alerts that are still open/in-progress and belong to the `anomaly` or `composite` categories (the two categories considered higher-signal in the UI). It returns at most the 500 most-recent matching alerts, sorted newest-first. Gotcha: severity and time-window filtering happen server-side (via the API's `filters`), but status/category filtering happens only after fetching, so a large volume of Low/Info alerts is never even requested, but "noisy" open Critical/High/Medium alerts are still fetched before being discarded.

### `isWildcardSource(cidr)` (lines 386–389)
Checks whether a security-group/NSG/firewall source string represents a fully open rule — matching `*`, `0.0.0.0/0`, `::/0`, `"internet"`, or `"any"` (case-insensitive). This is the strict definition of "reachable by anyone," used to decide what counts as truly "Internet Exposed" everywhere in the dashboard (as opposed to just narrowly allowlisted).

### `isPublicSource(cidr)` (lines 390–407)
Determines whether a given CIDR/IP source is a *public*, internet-routable address (as opposed to private/reserved), used to classify "restricted but still external" access rules that aren't wide-open but also aren't purely internal. It first defers to `isWildcardSource`, then parses a plain IPv4 address out of the string and excludes all private/reserved ranges — RFC1918, loopback, link-local, CGNAT, "this network," and multicast/reserved — returning `true` only if none of those match. Gotcha: anything that isn't a plain IPv4/CIDR string (a cloud-provider "service tag" name, or an IPv6 address) doesn't match the regex and is conservatively treated as *not* public (`false`), even though some such values could technically be internet-facing.

### `FORTI_PRODUCTS` (lines 414–425)
A lookup table of Fortinet product name/tag patterns (FortiGate, FortiManager, FortiAnalyzer, FortiADC, FortiWeb, FortiMail, FortiSandbox, FortiTester, FortiDDoS, and a catch-all "Other Fortinet"), each with a regex used to recognize that product from a resource's name or abbreviation. This is a best-effort heuristic — used to let the dashboard surface "you have Fortinet appliances in your cloud inventory" even for products Lacework doesn't specifically tag. Gotcha: order matters — the catch-all `'other'` entry must stay last, since it would otherwise swallow every more specific product match.

### `classifyFortiName(name)` (lines 426–430)
Given a resource name string, loops through `FORTI_PRODUCTS` in order and returns the first matching product entry, or `null` if the name doesn't look like any known Fortinet product. This is the actual function called against real inventory data to tag instances as Fortinet appliances for the dashboard's "Fortinet footprint" panel.

### `isMachineOffline(mt)` — shared "Machine status in (Online, Launched)" check
A small module-scope helper (hoisted out of `fetchVulns()`, which used to keep this logic as a private local) that reads a `machineTags` value (object or array shape, both handled) and returns `true` if its state string matches `OFFLINE_RE` (`stopped|terminated|deallocat|stopping|shutting|offline`). Both `fetchVulns()` and `refreshData()`'s `highRiskVulnsRaw` handling call this now — it exists specifically because `fetchHighRiskVulns()` itself applies no machine-status filter of its own, and without this shared check, stopped/deallocated hosts leaked into any dataset built from it (confirmed live).

---

## 2. API Fetchers — Talking to FortiCNAPP/Lacework `[SERVER]`

This section is the "data ingestion" layer — each function calls a specific Lacework LQL/REST endpoint and shapes the response into what the dashboard/report code expects.

### `fetchTrueExposure()` (line 432)
Pulls the full compute + network-security inventory (EC2 instances/security groups, Azure NICs/NSGs/VMs, GCP instances/firewalls) via LQL `LW_CFG_*` queries and cross-references it to determine which hosts are *actually* reachable from the internet — a wide-open (`0.0.0.0/0`) or specific-public-IP inbound rule **and** a real public IP on the instance. This is the ground-truth exposure engine that `fetchVulns()` and `refreshData()` reuse to correct Lacework's topological `lw_InternetExposure` tag, and it doubles as the source of the Fortinet-appliance inventory scan and AWS instance→IAM-profile linkage.
- **Returns:** `{ getExposureEvidence, azureComputerNames, fortiInventory, instanceIamProfile }`.
- **Gotchas:** a permissive SG/NSG/firewall rule alone is *not* exposure — the host also needs a populated external IP, otherwise the rule can't route anywhere. Azure has no native "Name" tag like AWS, so it maps the ARM resource name to the OS computer name Lacework's console actually displays/searches by. The AWS instance-profile→IAM-role linkage is a name-matching heuristic, not a guaranteed relationship. All CFG queries are capped at a 7-day window.

### `fetchExposurePaths()` (line 629)
Fetches Lacework's own graph-traced Internet→Target attack paths from `LW_APA_EXPOSURE_PATHS` for the resource types the dashboard already knows about (S3 buckets, EC2 instances, Azure VMs, Azure Blob storage, FortiGate), plus one unfiltered query covering every traced path regardless of target type. It's purely additive: results are matched onto existing panel rows client-side as a "Verified Path" chip and never feed the risk score, exposure counts, or reports.
- **Returns:** `{ s3, ec2, azureVm, azureBlob, fortigate, all }`, each an array of path rows (or `[]` on a per-query failure).
- **Gotchas:** the per-type queries filter targets by type, while the `all` query leaves targets as a raw unflattened array — different shapes for different consumers. `azureBlob` traces the storage-account blob *service*, not individual containers, and returned 0 rows as of writing.

### `fetchAttackPaths()` (line 664)
Fetches FortiCNAPP's fully computed attack-path risk graphs from `LW_APA_ATTACK_PATHS` — a broader, scored analysis distinct from the simpler Internet→Target reachability paths in `fetchExposurePaths()`. Used by the dashboard's Attack Paths panel, which applies a `path_score >= 80` filter client-side.
- **Returns:** an array of raw path rows (each carrying `METRICS.path_score` 0-100 and `METRICS.path_severity`), or `[]` on failure.
- **Gotcha:** the severity filtering is *not* done server-side here — this function just fetches and caches everything unfiltered.

### `fetchHighRiskVulns()` (line 681)
Fetches vulnerabilities with a CVE risk score of 9 or higher, at *any* severity level (including Medium/Low/Info), to power the Risk Findings "Host Exposure" category **and** the Internet Exposed Host panel (`_renderInternetHostExposedBeta`, Section 4). This is deliberately kept separate from `fetchVulns()`/`cache.vulns`, which stays Critical/High-severity-only and continues to drive the posture score, reports, and asset risk map unchanged.
- **Returns:** a flat array of vuln rows (paginated, capped at 5000 rows/page).
- **Gotchas:** the Lacework API rejects `expression:"gte"` with an HTTP 400 but accepts `expression:"ge"`. Unlike `fetchVulns()`, this function applies **no machine-status filter of its own** — `refreshData()` filters the raw result through `isMachineOffline()` before it's cached (see below), so don't assume `cache.highRiskVulns` is already Online/Launched-only if you're reading straight from this function's own return value elsewhere.

### `fetchVulns()` (line 716)
The main vulnerability fetcher: runs Critical and High severity queries against `Vulnerabilities/Hosts/search` in parallel with `fetchTrueExposure()`, then overwrites each row's exposure tags with the verified (not topological) exposure signal before applying client-side filters. This feeds the dashboard's vulnerability table, posture score (`calcRiskScore`), and reports — it's the single most consumed data source in the app. Before overwriting `machineTags.lw_InternetExposure`, it preserves Lacework's original tag as `machineTags.lw_InternetExposureRaw` — that field exists solely for the Internet Exposed Host panel (Section 4), which deliberately compares against the console's own raw signal rather than this app's verified one.
- **Returns:** `{ rows, fortiInventory, instanceIamProfile, getExposureEvidence }` — up to 500 filtered/sorted vuln rows plus data piggybacked out of `fetchTrueExposure()`.
- **Gotchas:** filtering happens entirely client-side — machine status must be Online/Launched (excludes Stopped/Terminated/Deallocated), and `cveRiskScore >= 8` is checked with a fallback chain (`cveRiskScore` → `riskScore` → `hostRiskScore`) deliberately *not* starting with `hostRiskScore`, since that broader host-composite metric can rate a host low even with a genuinely critical internet-exposed CVE present.

### `policyCloud(s)` (line 809)
A tiny string-matching helper that maps a policy/query ID string to its cloud provider (`aws`, `azure`, `gcp`, or a generic `cloud` fallback). Used by `fetchCompliance()` to label each compliance finding with its originating cloud.

### `policyCategoryTags(tags)` (line 819)
Extracts the `category`/`subCategory` labels from a policy's `tags` array (Lacework's `"domain:"`/`"subdomain:"` tag convention). Used to group compliance findings for the dashboard's category filters.

### `fetchCompliance()` (line 836)
Fetches the top Critical/High compliance policy definitions from `GET /Policies`, then executes each policy's own embedded LQL `queryText` (over a fixed 14-day window) to count violations, building a findings list for the "Critical Misconfigurations" panel and reports. This is one of the app's most rate-limit-sensitive fetchers since it can issue dozens of separate `Queries/execute` calls in one refresh cycle.
- **Returns:** an array of finding objects, sorted by violation count descending.
- **Gotchas:** capped at `COMPLIANCE_POLICY_CAP = 50` policies because Lacework's `Queries/execute` endpoint shares a single 480-requests/hour token bucket across compliance, secrets, secretsAll, and identities. Policies run in batches of 3 with a 1.5s gap between batches, and partial results are pushed to `cache` after every batch so the UI updates progressively.

### `fetchIdentities()` (line 924)
Fetches identity/entitlement data from `LW_CE_IDENTITIES`, enriches it with trust-policy data and reliable type/cloud classification from `LW_CE_LINKED_IDENTITIES`, then filters down to the highest-risk identities for the Identity & Access Risk view.
- **Returns:** up to 300 filtered/sorted identity rows, each annotated with `_trustPrincipals` and `_lqlType`.
- **Gotchas:** type is derived by regex-parsing `RELATION_TYPE` values like `AZURE_USER_TO_GROUP` rather than guessing from `PRINCIPAL_ID`/`NAME` patterns. Users, root accounts, and service accounts/principals are *always* included regardless of severity, while Roles are gated behind admin-flag/critical-severity/≥75%-unused-entitlements criteria. The 300-row cap exists because a lower cap previously let admin-flagged Roles fill every slot and starve out rarer admin IAM Users.

### `fetchGovernanceTargets()` (line 1114)
Builds the list of selectable "Governance Report" targets (a cloud account/subscription/project paired with a named compliance framework like CIS or SOC 2). Powers the Governance Reports tab's account/framework picker.
- **Returns:** a flat array of `{ cloud, label, primaryQueryId, secondaryQueryId }` target objects.

### `fetchSecretsAll()` (line 1154)
Fetches every discovered secret across hosts from `LW_HE_SECRETS_ALL`, in parallel with an `LW_HE_MACHINES` query used to identify stopped/terminated hosts, then filters out SSH host keys and secrets on machines that are powered off. Feeds the "All Secrets" panel.
- **Gotchas:** uses raw `request()` instead of the `post()` helper because it needs manual pagination. Stopped-host detection reads `LW_HE_MACHINES.TAGS`, which can appear either as an array of `{key, value}` pairs or as a plain object — both shapes are handled explicitly.

### `fetchSecrets()` (line 1245)
Fetches SSH private keys detected on hosts from `LW_HE_SECRETS_SSH_PRIVATE_KEYS`, filtered server-side to only overly-permissive keys. A lighter-weight, more targeted sibling of `fetchSecretsAll()`.
- **Gotcha:** `FILE_PERMISSIONS` is a numeric Unix mode *including file-type bits*, so the LQL filter is comparing against an encoded value, not a bare permission bitmask.

### `fetchPublicStorage()` (line 1289)
Detects genuinely publicly-accessible object storage (S3 buckets, Azure Blob containers, GCS buckets) by joining each cloud's storage inventory to the specific proof-of-exposure signal, then checking each cloud's own "master switch" (Block Public Access, `allowBlobPublicAccess`, `publicAccessPrevention`) that can neutralize that exposure regardless of the individual object's setting.
- **Gotchas:** runs its 8 queries in batches of 3 with 500ms gaps to avoid tripping the tenant's rate limit; a 429 on any one query silently reads as "no public storage" rather than "couldn't check," which is why `refreshData()` falls back to the prior cycle's result when a fresh result comes back empty.

### Identity-classification helpers (lines 1412–1463)
A cluster of small server-side predicate functions used together to score identity risk:
- **`isServiceAccount(r)`** — service account/service principal by name pattern or GCP suffix.
- **`isRoleType(r)`** — IAM/cloud role, excluding service accounts.
- **`isHighPermissive(r)`** — flags `ALLOWS_FULL_ADMIN`/`EXCESSIVE_PERMISSIONS` risk or critical/high severity.
- **`isNoMfa(r)`** — flags `PASSWORD_LOGIN_NO_MFA` or a falsy `MFA_ENABLED` field.
- **`unusedPctOf(r)`** — percentage of entitlements never used, `null` if no usable data.
- **`isOldAccessKey(r, thresholdDays)`** — any access key created 180+ days ago (default), checking six possible field-name casings defensively. Flagged in the code as unverified against live data — worth double-checking if access-key-age findings look suspiciously absent.
- **`isAdminNoMfaIdentity(r)`** — combines the above: not a service account, not a role, highly permissive, and no MFA — a genuine human admin without MFA.
- **`identityRiskScore(r)`** — 0-100 risk score: admin-no-MFA + (≥80% unused entitlements OR an old access key) → flat 80; otherwise the raw CIEM `METRICS.risk_score × 100`. Reused independently by `computeCspScores()` — note the client-side dashboard, mobile view, and report builders each keep their own duplicated copy of this same logic.

### `calcRiskScore(alerts, vulns, identities)` (line 1463) — server-side approximation
Computes a 0-100 score by taking the maximum `identityRiskScore()` across identities (60% weight), the maximum CVE risk score ×10 among vulns with `riskScore >= 8` (25% weight), and an alert-count bonus capped at 15 points. **This is only used for server-side console logging during `refreshData()`** — it is a cheaper approximation, not the number shown in the UI. The actual displayed posture score is `calcPostureScore()`, a client-side function (see Section 4) computed independently in the browser. Gotcha: this function reads `v.riskScore`, not `v.cveRiskScore` — a subtle inconsistency worth flagging since the two fields aren't guaranteed to be identical for a given row.

---

## 3. Orchestration & the Desktop Dashboard Scaffold `[SERVER]`

### `refreshData()` (line 1438)
This is the server-side "heartbeat" of the app — it runs on a timer and is responsible for calling every FortiCNAPP/Lacework API fetcher, then writing the results into the single in-memory `cache` object that `buildHtml()` (and the API routes) read from. Nothing in the UI ever hits the FortiCNAPP API directly; everything flows through this function into `cache`.

**Two-phase design:**
- **Phase 1 — fast parallel fetch:** `fetchAlerts()`, `fetchVulns()`, `fetchIdentities()`, `fetchSecrets()`, `fetchExposurePaths()`, `fetchAttackPaths()`, and `fetchHighRiskVulns()` are all fired at once via `Promise.allSettled(...)` — deliberately, so one fetcher failing (e.g. a 429) doesn't blow up the whole refresh; each result is unwrapped individually and falls back to an empty array with a recorded error instead of throwing. As soon as this batch settles, `cache` is immediately updated and `saveCacheToDisk()` is called.
- **Phase 2 — throttled compliance + secretsAll + publicStorage:** these three are kicked off together, but each publishes to `cache` the moment it individually resolves rather than waiting for all three. They're separated from Phase 1 because firing all ~10 fetchers simultaneously would burst past FortiCNAPP's per-tenant `Queries/execute` rate limit — `fetchPublicStorage()` alone issues 8 CFG queries.

**Gotchas:** On a rate-limited (429) empty result, `compliance` and `publicStorage` intentionally fall back to the *previous* cached value rather than showing "zero," so the UI doesn't flash to "nothing found" on a transient error. `highRiskVulns` is filtered through `isMachineOffline()` (excluding stopped/deallocated hosts, since `fetchHighRiskVulns()` doesn't do this itself) before it reuses the `getExposureEvidence` closure from `fetchVulns()` to re-tag exposure with the app's own verified-exposure definition — but unlike `cache.vulns`, each row's *original* Lacework tag is preserved first as `machineTags.lw_InternetExposureRaw`, since the Internet Exposed Host panel deliberately reads that raw value instead of the verified one (see Section 4).

### `buildHtml(_account, intervalSec)` (line 1557)
This single function returns the entire desktop dashboard as one giant template-literal string — the full HTML document, a large embedded `<style>` block, and an inline `<script>` block containing all client-side JavaScript (documented in Section 4). It is called once per HTTP request to the dashboard route, and its return value is sent directly as the response body.

**Why this unusual approach:** there's no build step, bundler, or npm frontend dependencies — the whole UI is hand-written HTML/CSS/JS concatenated into a JS string, using template-literal interpolation (e.g. `${intervalSec}`) to inject server-computed values straight into the client script at render time. This keeps the project a genuine "single file" Node app. The tradeoff: the function is very long and mixes three languages inside one JS string — editors won't syntax-highlight the embedded parts correctly, and a stray backtick or `${` inside the string can break the whole thing.

**Inputs/outputs:** `_account` (tenant name) and `intervalSec` (auto-refresh interval, injected into the client script as `const REFRESH=${intervalSec}`). Returns one large HTML string.

**Roughly what's in each part:**
- **CSS (~1597–1936):** color tokens, animations, and styling for the app shell.
- **HTML markup (~1938–2643):** sidebar nav, top bar, report header, KPI cards, the panel grid, and the Settings view.
- **Inline `<script>` (starts ~2645):** everything in Section 4 of this document.

---

## 4. Client-Side Dashboard JavaScript `[CLIENT]`

Everything in this section lives inside the `<script>` block that `buildHtml()` generates as part of its returned string (it closes at line 6192). **It runs in the browser, not in Node.js.** `refreshData()` and `buildHtml()` itself execute on the server when a request comes in or the refresh timer fires, but once that string is sent to the client and parsed, these functions execute in the browser's JS engine with access to `document`/`window`/`fetch`, and zero access to Node.js globals, the server's `cache` variable, or API credentials — any data they use was baked into the page at render time or fetched afterward via `fetch()` calls to the server's `/api/*` routes.

### Small formatting/DOM utilities
- **`fmtSec(s)`** (2648) — formats a seconds count into `"1h 5m"`/`"3m 20s"`/`"12s"`, used for the refresh countdown.
- **`setFooterInterval(sec)`** (2653) — writes that formatted interval into the footer.
- **`e(s)`** (2658) — HTML-escapes a string (`&`, `<`, `>`) — used everywhere dynamic strings are injected into `innerHTML`.
- **`tr(s, n)`** (2660) — truncates a string to `n` characters with an ellipsis.
- **`fmtDate(t)`** (2661) — converts a timestamp into a locale date+time string, e.g. `"Jul 29, 26 14:03"`.
- **`sev(s)`** (2666) — renders a colored severity badge (Critical/High/Medium/other).
- **`status(s)`** (2673) — renders a colored status badge (Open/In Progress/Closed).
- **`cloud(c)`** (2680) — renders a cloud-provider badge (AWS/Azure/GCP).
- **`strip(s)`** (2681) — returns a CSS class for a row's colored left border based on severity.
- **`pathHopLabel(node)`** (2684) — picks the best display label for one hop in a verified exposure path.
- **`exposurePathHopsStr(rec)`** (2687) — turns a path record's hops into an arrow-joined string, e.g. `"Internet → SG → EC2"`.
- **`shortenAlertDesc(d)`** (2690) — turns a noisy raw alert description into a short readable label (e.g. `"Crypto Mining Detected"`) via pattern matching, falling back to a cleaned/truncated string.
- **`setKpi(id, n)`** (2713) — writes a number into a KPI tile by element id.
- **`setBody(id, h)`** (2742) — sets a panel body's `innerHTML`; nearly every `render*` function ends by calling this.
- **`state(id, icon, msg)`** (2743) — renders a generic "empty/error state" block into a panel body.
- **`setCount(id, n, bad)`** (2744) — sets a panel's count badge and toggles its color (red if `n>0` and flagged "bad").

### `buildPie(d)` (2714)
Builds the animated Risk Findings donut chart on the Overview: computes the proportion of alerts/host-exposure/identities/compliance/secrets, sets each SVG segment's stroke properties (staggered via `requestAnimationFrame`), and updates the numeric labels. Runs every refresh cycle from `load()`.

### `renderAlerts(rows, err)` (2746)
Renders the Alerts panel table. Gotcha: the "🤖 Triage" button is rendered disabled/greyed-out by design — it's a placeholder that gets enabled once the AI pre-triage (see the AI Chat cluster below) finishes in the background, not a bug.

### `renderVulns(rows, err)` / `_renderVulns(rows, err)` (2770 / 2785)
`renderVulns` is an error-safe wrapper that catches any exception thrown while building the panel and shows it inline instead of crashing the rest of `load()`. `_renderVulns` is the real implementation behind the **Private Host Most Exposed** panel — one of the most complex functions in the file. It groups CVE rows (risk ≥ 9) by hostname, cross-references each host with correlated identities/compliance/secrets/CIEM credentials (via `buildAssetRiskMap`, below), and renders only the non-internet-exposed ("Private") hosts — the Internet-Exposed tab itself was removed (see the "Internet-Exposed tab/panel removed" inline comment); those hosts are tracked in the separate Internet Exposed Host panel instead. It also calls `iehbQualifyingHostSet(_ld)` (defined near `_renderInternetHostExposedBeta`, below) and excludes any host that qualifies there too, so the same host never shows up as both "Private" and "Internet Exposed" across the two tabs — the two panels use different exposure definitions (verified here, raw there) and can otherwise disagree on a given host. Contains several helper closures (`summaryStrip`, `arTierOf`, `exposurePathChips`) scoped only to this function.

### `ciemCategoryLabel(t)` (2774)
Maps a raw secret type (e.g. `aws_secret_access_key`) to a friendly chip label like "AWS Key" or "SSH Key."

### `renderCompliance(rows, err)` (3174)
Renders the Compliance panel table, with a "Details" button that opens the compliance drawer (`openComplianceDetails`, below).

### `computeEffectivePublicStorage(d)` (3203)
Computes the canonical list of publicly exposed storage findings, shared by both the Public Storage Exposure panel and the Exploit Simulation Layer's summary badge so the two numbers never disagree. Filters out a hardcoded list of known-stale findings (`STALE_STORAGE_FINDINGS`), then merges in buckets/containers discovered only via a Verified Exposure Path (marked `severity:'high'`, a weaker signal than a confirmed public policy/ACL). Gotcha: the stale-findings filter is a manual allowlist that needs to be edited by hand once FortiCNAPP re-scans clean data — a workaround, not a permanent fix.

### `renderPublicStorage(d)` (3250)
Renders the Public Storage Exposure panel, grouped by cloud, with a best-effort DSPM data-classification chip and a Verified Internet Path chip per row.

### FortiGate inventory tiles — `filterFortiInventory`/`renderFortiGateTilesUI`/`renderFortiGate` (3330, 3334, 3367)
Draws click-to-filter tiles counting each Fortinet appliance type found by the name/tag heuristic (`classifyFortiName`), plus a table of FortiGate-only Verified Internet Path records. Filtering re-renders instantly from cached state without re-fetching. Gotcha: the underlying `exposurePaths.fortigate` dataset actually covers *all* Fortinet virtual appliances, not just FortiGate specifically.

### Internet Accessible Ressources tiles — `exposedAssetTypeLabel`/`filterExposedAssets`/`renderExposedAssetsUI`/`renderExposedAssets` (3403–3450)
Same toggle-tile pattern as the FortiGate panel, but for *every* verified exposure path target type across the whole tenant except `fortigate` — the comprehensive superset panel covering hosts and storage. FortiGate/Fortinet-appliance targets are explicitly excluded (`renderExposedAssets` filters `t.type!=='fortigate'`) since they already have their own dedicated FortiGate tab; showing them in both was redundant. Panel renamed from "Internet Exposed Assets" to **"Internet Accessible Ressources"**.

### Attack Paths panel — `attackPathRiskScore`/`filterAttackPaths`/`renderAttackPathsUI`/`renderAttackPaths` (3463–3520)
Filters `d.attackPaths` down to records with a path risk score ≥ 80, sorts them highest-first, and renders severity-count tiles (CRITICAL→LOW) with the same toggle-filter pattern.

### `iehbQualifyingHostSet(d)` (near 3494, just above `_renderInternetHostExposedBeta`)
A small, pure/stateless helper: scans `d.highRiskVulns`, keeps rows whose `machineTags.lw_InternetExposureRaw` (falling back to `lw_InternetExposure`) is `'Yes'`, tracks each hostname's max `hostRiskScore`, and returns a lowercased-hostname lookup map for hosts scoring `>= 7`. Exists so `_renderVulns` (Private Host Most Exposed) and `_renderInternetHostExposedBeta` (Internet Exposed Host) can agree on the same qualifying-host set without one function depending on the other's render order or internal state.

### `renderInternetHostExposedBeta(d)` / `_renderInternetHostExposedBeta(d)` (line ~3517)
The **Internet Exposed Host** panel — kept deliberately separate from the posture score and every other panel, because it exists specifically to reproduce the FortiCNAPP console's own "Hosts" query rather than this app's usual (stricter) exposure methodology. Sources from `d.highRiskVulns` (any severity, `cveRiskScore >= 9` — broader than `d.vulns`'s Critical/High-only pool), and qualifies a host on **`hostRiskScore >= 7`** (Lacework's composite per-machine score) **and** `machineTags.lw_InternetExposureRaw === 'Yes'` — Lacework's *raw*, unverified exposure tag, not the app's stricter verified (open SG/NSG/FW-rule) signal used everywhere else. Reuses the correlated-risk logic from `_renderVulns`, and adds one enrichment: matching an EC2 instance's IAM instance-profile to an identity record (AWS only).
- **Gotchas:** the raw-vs-verified distinction is deliberate, not a bug — the two signals genuinely disagree for some hosts (e.g. a host reachable only via a *restricted* allowlisted-IP rule, `lw_RestrictedExternalAccess='Yes'`, is raw-tagged exposed but not verified-exposed). The instance-profile→identity match is name-based, not guaranteed 1:1.

### Identity classification & pruning — `rootEquivalent`/`identType`/`isAdminIdentity`/`pruneToAdmin`/`riskFindingIdentities`/`riskFindingHostExposure` (3763–3874)
- **`rootEquivalent(r)`** — detects AWS root, Azure Global Admin, or GCP Super Admin by name/ID pattern.
- **`identType(r)`** — classifies an identity into a human label (IAM Role, IAM User, Service Account, etc.) using root-equivalence first, then a reliable relationship type if present, then ARN/name pattern heuristics.
- **`isAdminIdentity(r)`** — one-line check for `ALLOWS_FULL_ADMIN`.
- **`pruneToAdmin(cloud, cloudRows)`** — the single shared rule for which identities are worth surfacing at all: root/root-equivalent (always kept), or Admin-flagged Users/Roles. Everything else is dropped. Shared between the Identity tab and the Risk Findings count so the two never disagree.
- **`riskFindingIdentities(identities)`** — narrows further to Critical-severity, non-root identities only — the exact count shown in the Risk Findings donut.
- **`riskFindingHostExposure(d)`** — a three-way intersection (high-risk CVE + internet-exposed in two independent data sources + risk ≥ 9.5) so the Risk Findings summary and the detailed tab never show conflicting host lists.

### `renderIdentities(rows, err)` (3883)
Renders the three cloud-specific Identity tabs (AWS/Azure/GCP): prunes to admin-only via `pruneToAdmin`, sorts (root-equivalents → no-MFA → severity → risk score), and renders a table with a type badge, privilege badge, severity badge, a row of risk-flag "dots" with hover tooltips, percent unused permissions, and copy-ARN/trust-lookup action buttons. Also builds a type-filter chip bar per cloud.

### `renderSecretsAll(rows, err)` (4080)
Renders the "All Secrets" panel: groups secrets by type (friendlier label where known), sorts groups largest-first, one sub-table per group.

### `copyText(el)` (4123)
Copies an element's `data-cp` attribute to the clipboard and briefly flips the button icon to a checkmark — the shared "copy" behavior behind every copy button on the page (delegated via a single document-level click listener rather than one per button, since there can be hundreds of rows).

### `buildAssetRiskMap(d)` (4135) `[CLIENT — mirrors a server-side twin]`
The shared correlation engine for **Correlated Risk Findings per Asset**: combines CVE/vuln risk scores, CIEM/generic secrets matched by hostname, and a flat critical-misconfiguration boost into a per-hostname risk map, normalized 0–100 relative to the riskiest host. Reused by both `_renderVulns` and `_renderInternetHostExposedBeta` so their risk scores and chips always agree.
- **Returns:** `{map, maxRisk, critMisc}`.
- **Gotcha:** there is a *server-side* function with the same job, `computeAssetRiskMap()` (Section 5) — used by the report builders, which can't execute browser JS. The two implementations are hand-kept in sync rather than shared, since this client copy lives inside a flat template-literal string with no `require()`.

### `renderAssetRisk(d)` (4177)
Re-derives a near-duplicate of `buildAssetRiskMap`'s ranking with extra power-state/exposure detection, but **most of this function is dead code**: an early `return;` at line 4286 (commented `// view removed from nav — skip all HTML rendering below`) means nothing past that point ever executes. In practice its only live job today is computing `_renderedAssetMap` so `openHostGraph()` has data to read. If you're trying to change what an "Asset Risk" view displays and nothing happens, this is why.

### `nav(name)` (4503)
The main section-switcher for the dashboard's left nav — hides all views, shows the one matching `name`, and updates the URL hash so a reload/deep-link lands on the right tab. Special-cases `'compliance'` to also trigger `loadGovernanceTargets()`.

### Governance Report modal helpers (4519–4624)
`populateGovAccountSelect`, `loadGovernanceTargets`, `populateGovFrameworkOptions`, `govReportUrl`, `openReportGenModal`, `closeReportGenModal`, `rptGenAccountChanged`, `runReportGenModal` — together power the "Generate Report" modal's cloud-account/framework picker: fetch `/api/governance/targets` once, wire two `<select>` elements together, and call `/api/governance/report` before opening `/report` in a new tab.

### Identity risk classification (client copy) (4636–4679)
`isServiceAccount`, `isRoleType`, `isHighPermissive`, `isNoMfa`, `unusedPctOf`, `isOldAccessKey`, `isAdminNoMfaIdentity`, `identityRiskScore` — a client-side re-implementation of the *same* logic documented server-side in Section 2. This is intentional duplication (the browser can't call the server's functions), but it means any tweak to the risk rules must be applied in both places to stay consistent.

### `calcPostureScore(d)` (4684) — **the number actually shown on the dashboard**
The formula behind the main "Cloud Security Posture Score" gauge (0–100, higher = better). Builds a flat list of per-finding risk scores — alerts (critical=80/high=60/medium=40), CVEs (`riskScore×10`, only if ≥8), compliance (flat 80), identities (via `identityRiskScore()`), secrets (flat 10) — and returns `100 − average(all risk scores)`. No findings at all → a perfect 100. `scoreColor(p)`/`scoreBand(p)` (4694–4695) turn that number into a color and a band label ("Review Only Required"/"Action Required"/"Immediate Action Required"). This is the number every gauge on the page ultimately reduces to, alongside its per-cloud sibling `calcCspScore`.

### `renderRiskFindings(d)` (4697)
Fills the "Risk Findings" table (Alerts/Host Exposure/Identities/Compliance/Secrets grouped with counts and per-row risk scores), reusing `calcPostureScore`'s category logic to color-code rows. Each group header links back into `nav()`.

### CSP (per-cloud) scoring — `cspOfAlert`/`cspOfIdentity`/`calcCspScore`/`cspBadgeColor` (4743–4785)
`cspOfAlert`/`cspOfIdentity` attribute a record to `aws`/`azure`/`gcp` by keyword/field matching. `calcCspScore(d, csp)` is the per-cloud gauge score: buckets that cloud's findings into Critical/High/Medium/Low, computes `penalty = 40×(C/total) + 30×(H/total) + 20×(M/total) + 10×(L/total)`, returns `100 − penalty` (or `null` if zero findings, meaning "no data," treated as 100 by callers). Using shares rather than raw counts means a cloud with far more inventory isn't penalized just for having more assets.

### `renderCspLab(d, csp)` (4787)
Renders the per-cloud tab of the Exploit Simulation Lab (the hex kill-chain diagram scoped to one CSP). Deliberately omits a "Critical Alerts" node — unlike the global panel — because `cspOfAlert()`'s keyword matching can't reliably attribute alerts to one cloud, and a false zero would be misleading.

### Tab switchers — `switchVTab`/`switchIdentTab`/`switchLabTab` (4827–4869)
Toggle between sub-tabs within a panel (Vulns: exposed/private; Identities: AWS/Azure/GCP, lazily loading trust data; Lab: Global vs. per-CSP).

### Kill-chain diagram presentation helpers (4874–4899)
`exposedHostsTooltip`, `exposedHostsSubLabel`, `renderExposedHostsCapRow` — build the hover text, in-diagram label, and caption row listing exposed hosts/IPs for the "Exposed Hosts" hex node, shared between the Global and per-CSP panels.

### `renderLab(d)` (4900)
Renders the Global tab of the Exploit Simulation Lab — the attacker → internet → [Identities/Alerts/Exposed Hosts/Compliance/Secrets] → "YOUR CLOUD" hex diagram, using `buildAssetRiskMap(d)` to find exposed hosts and `computeEffectivePublicStorage(d)` for the Public Storage badge.

### `closeHostGraph()` / `openHostGraph(hostName, resourceName)` (4946, 4951)
Powers the per-host "Attack Path" modal opened by clicking an exposed host anywhere in the dashboard. Checks `_renderedPrivMap` first to decide if this is a lateral attack on a private host (purple styling) vs. a genuine internet-facing host (looked up in `_renderedAssetMap`), assembles that host's risk factors, builds a kill-chain diagram, and — for hosts with a known public IP — fires an async GeoIP lookup. Gotcha: depends on `_renderedAssetMap`/`_renderedPrivMap` already being populated by an earlier `render*` call in the same `load()` cycle; calling it before the first data load completes does nothing.

### `hexKillChainSvg(spec)` (line 7426, called from four places in this section)
Draws the attacker → network → factor-hexagons → target SVG diagram at the visual core of the Exploit Simulation Layer. **Known subtle bug source:** it generates each diagram's internal gradient/filter IDs from a running counter (`hexKillChainSvg._seq`), not from the diagram's content. Because inactive tabs are hidden with CSS rather than removed from the DOM, multiple diagram instances can coexist on the page; if two diagrams ever computed the same ID (this happened when IDs were content-derived instead of counter-based, since every per-CSP tab has the same factor count), the browser resolves `url(#id)` against whichever matching element appears first in document order, silently corrupting the *other* diagram. Keep ID generation counter-based if you ever touch this function.

### `load()` (5070)
The dashboard's main "tick" function — fetches `/api/data`; if the server hasn't finished its own first fetch yet, shows a loading state and retries in 15s. Once real data arrives, it calls essentially every `render*` function in this document in sequence, then updates the "last fetched" timestamp and error banner. Runs once after `startupSequence()` and then on a recurring timer (`REFRESH` seconds).

### `startupSequence()` (5118)
Runs a scripted 10-second intro before the first real `load()` — cycles a random FortiGate "fun fact" card every 2 seconds, then calls `load()` for real and starts the recurring refresh interval.

### `updateRiskScore(p)` / `updateLadder(p)` (5147, 5157)
Animate the main circular gauge's arc/color/number, and highlight the matching rung ("urgent" <50, "attention" <90, "proactive" ≥90) in the risk-ladder illustration.

### `calcGlobalScoreFromCsp(d)` (5167)
Averages the three per-cloud scores (defaulting a missing cloud to 100) into the single number shown on the main gauge — the headline score is literally the mean of the three CSP gauges.

### `updateCspGauges(d)` (5172)
Fills in the three AWS/Azure/GCP gauge widgets (score/arc/color/band via `calcCspScore`) plus a best-effort account-alias label scanned from compliance findings, excluding raw numeric AWS account IDs so the label doesn't show a meaningless number.

### Login / visitor badge cluster — likely dead code (5231–5263)
`setCookie`, `getCookie`, `wireReportBtn(user)`, `showUserBadge(user)` are defined here but **have no callers anywhere in the file** — there is no `submitLogin()` function either; the real login page (`LOGIN_HTML`) is a plain server-rendered `<form action="/api/register">`. This whole cluster (plus the server's `/api/register` route) looks like an orphaned remnant of a previous registration-flow design — worth confirming with the team before relying on or removing it. `logout()` in the same area is the one function that *is* live (just `window.location.href='/'`).

### Admin settings — `unlockAdminSettings()` / `loadAdminSettings()` (5272, 5288)
`unlockAdminSettings` gates the hidden admin panel behind a hardcoded password (`'fortinetadmin'`) — a friction speed bump, not real security. `loadAdminSettings` fetches `/api/settings` and populates the refresh-interval/days-back dropdowns.

### FortiGate "fun fact" ticker (5309–5413)
`_fgLoadLiveFacts`, `_fgPickFact`, `_fgShowCard`, `_fgHideCard`, `_fgArrowCycle`, `_fgRunCycle`, `applyFactFreq`, `toggleFgVibe` — manage the rotating "cloud security fact" card (merging in live headlines from `/api/fg-facts` every 30 minutes) and persist the user's on/off + frequency preference to `localStorage`. Not security-relevant — a marketing/engagement widget.

### `applySettings()` / `applyDaysBack()` (5415, 5429)
POST the chosen refresh interval / assessment-window length to `/api/settings`.

### AI Investigation Chat cluster (5453–5697)
Powers the in-dashboard "Ask AI to triage this alert" chat, backed by `/api/ai/*`.
- `_aiMarkBtn`, `_preTriage`/`_preTriageAll` — proactively pre-fetch a canned triage answer for every visible alert in the background (staggered 2s apart) so it's ready by the time a user clicks.
- `_aiStartThread`, `_aiFetchRetry` — start a chat thread and a generic fetch-with-one-retry wrapper.
- **`openAiChat(alertId, alertName, severity)`** (5547) — opens the chat modal, kicks off (or reuses) a background thread-start promise.
- `_aiStartTimer` — the "(Ns)" elapsed-time counter shown while waiting.
- **`pickAiPrompt(type)`** (5569) — fires a canned prompt; uses the pre-triage cache if ready, otherwise shows a placeholder + rotating fact while waiting.
- `_aiAddMsg`, `_aiStreamMsg` — append a chat bubble (with thumbs-up/down feedback buttons) and fake a "typing" reveal effect (the response isn't actually streamed token-by-token from the server, just already-complete text revealed word by word).
- **`sendAiMessage()`** (5668) — sends a free-form follow-up question.
- `closeAiChat()` — closes the modal and clears state.

### Detail-modal click delegation (5700–5720)
A single delegated `click` listener routing clicks on various row buttons to the matching `open*Details()`/`loadTrustPrincipals()` function, avoiding one listener per row across potentially hundreds of rows.

### `loadTrustPrincipals(btn)` (5722)
For an IAM role, fetches `/api/identity-trust?pid=...` to find every principal allowed to assume it, renders the list, and calls `updateGraphEdges()` so the same data draws arrows on the Identity Correlation Graph.

### `renderIdentityGraph(rows)` (5747)
Draws the SVG Identity Correlation Graph (Users/Service Accounts on the left, Roles on the right, colored by risk score). Only draws nodes here — trust-relationship arrows are added incrementally by `updateGraphEdges` as each role's data loads. Gotcha: resets its node-position/trust-map state every call, so previously-loaded trust edges are wiped and won't reappear until the user re-triggers `loadTrustPrincipals` for each role again.

### `updateGraphEdges(rolePid, principals)` (5835)
Adds the curved arrows (and any new external-principal boxes) connecting users/services to roles they can assume, rebuilding the whole edges SVG group from accumulated state each time it's called. Gotcha: matching a trust principal string to a known node uses fuzzy suffix matching, so a principal ARN format that doesn't share a trailing path segment with a known node draws as a disconnected "external principal" box instead of linking to the real node.

### Small SVG/UI helpers (5891–5919)
`svgEsc` (HTML-escaping for SVG text — duplicated verbatim inside `renderIdentityGraph`), `closeMachPanel`/`closeGeoPanel`, and a delegated click listener routing "goto host card"/factor-node clicks to `openHostGraph`/`nav`/`closeHostGraph`.

### GeoIP panel — `openGeoPanel(ip, hostname)` / `renderGeo(body, d)` (5922, 5940)
Opens a modal, fetches `/api/geoip?ip=...` (cached client-side in `_geoCache`), and renders country/city/org/ASN/timezone as a simple key/value table.

### `openCveDetails(cveId)` (5979)
Opens the shared details modal in CVE mode: fetches `/api/cve?id=...` (backed server-side by `fetchCveDetails`) and renders both a FortiGuard summary and an NVD CVSS/description/references block.

### `openComplianceDetails(policyId)` (6030)
Opens the modal in compliance mode using **already-cached client data** (`_lastData.compliance`, no extra fetch) — finds the matching policy and renders its violating resources as a dynamic table with heuristically-chosen columns.

### `openIdentityDetails(principalId)` (6062)
Opens the modal in identity mode: fetches `/api/identity?principalId=...` and renders identity/risk/entitlement/access-key sections. Gotcha: always shows a hardcoded "MFA: NO MFA" line regardless of the identity's actual MFA status — a static label, not data-driven.

### `openMachineDetails(hostname)` (6131)
Opens the modal in machine mode: fetches `/api/machine?hostname=...` and renders a curated list of known tag keys (Instance ID, Instance Type, Cloud Provider, Zone, Account, etc.) plus any extra tags, capped at 20 extras.

---

## 5. Mobile View & Shared Report Helpers `[MIXED]`

### `MOBILE_HTML` (line 6214) `[CLIENT — served as a static string]`
A complete, standalone HTML page (its own `<style>` and `<script>`) served byte-for-byte at `GET /mobile`. Unlike the desktop dashboard, it isn't generated by a function call — it's a static constant built once at module load. It renders a compact "single scroll" experience: one posture-score gauge, a colored band label, and a short prioritized list of remediation steps linking back to the relevant desktop anchor (e.g. `/desktop#identities`). It polls `/api/data` every 60 seconds and recomputes its own copies of `calcScore(d)`, `identityRiskScore(r)`, and the identity-classification predicates, plus `buildSteps(d, p)` for the "next best actions" list.

**Gotcha (maintenance risk):** all of this scoring/rendering logic is **hand-duplicated** from the desktop dashboard's client-side code (Section 4), and in the case of `identityRiskScore`, from the server-side copy too. There are now three near-identical copies of "how risky is this identity" logic in different corners of the file, with no shared module (since `MOBILE_HTML` is a flat string with no `require()`). Changing the posture-score or identity-risk formula in one place and forgetting the others is a real, easy-to-make mistake here.

### `sanitizeCacheData(data)` (line 7118) `[SERVER]`
Takes a deep copy of the cache (identities, vulns, secrets, compliance, alerts, etc.) and deterministically replaces every real, sensitive identifier — hostnames, machine IDs, IAM ARNs, secret identifiers, resource IDs/ARNs, account IDs, IPs, emails — with a realistic-looking fake value. Scores, counts, and structure are left untouched, so the sanitized data still renders and scores exactly like the real one.

**Why it's deterministic:** uses a `seen` map keyed by `category + '|' + realValue`; the first occurrence of a real value gets the next counter-based fake value, and every later occurrence (even in a different field) maps to that same fake value — so a hostname appearing in both the vulns list and the secrets list stays consistent, and cross-references in the sanitized report still line up. Structured fields are swapped by field name directly; free-text fields (alert descriptions, trust-policy strings) go through a `scrubText()` regex pass for ARNs/account IDs/IPs/emails, plus a final substring-replace pass for any already-seen identifier embedded in prose.

**Used by:** `/report`, `/report2`, `/report3` when called with `?sanitize=1` — lets someone generate a shareable report (demo, screenshot, sales deck) with the real data's shape and scoring, without leaking a customer's actual infrastructure names or credentials.

### `groupVulnsByHost(vulns)` (line 7197) `[SERVER]`
Buckets a flat vuln-row list into one entry per host, resolving a hostname via a fallback chain (`machineTags.Hostname` → `evalCtx.hostname` → `mid` → `'Unknown Host'`), tracking `exposed`/`pubIp`/`maxRisk` per host. `maxRisk` uses `cveRiskScore` before falling back to `riskScore`, matching how `fetchVulns()` itself defines "CVE risk."
- **Returns:** `{ hosts, exposedCount, internalCount }`, sorted internet-exposed-first, then by descending risk — so reports always lead with the riskiest, most-exposed machine.

### `computeAssetRiskMap(vulns, secretsAll, compliance)` (line 7230) `[SERVER — twin of the client's buildAssetRiskMap]`
The server-side per-host "correlated risk" engine — an explicit server-side port of the client-only `buildAssetRiskMap()` (Section 4) so the three report builders can compute the same numbers without being able to run browser JS.

**The scoring formula, exactly as coded:**
1. **CVE/threat risk:** each matched vuln adds `min(100, riskScore × 10)` points.
2. **Secret risk (two tiers):** CIEM-sensitive secret types (SSH keys, cloud credentials, OAuth tokens) add **100 points** each; generic secrets add **50 points** each. Matched to a host via fuzzy hostname substring matching.
3. **Misconfiguration boost:** `miscBoost = min(60, criticalComplianceCount × 10)`, applied to every host that already has some risk (compliance findings aren't host-scoped in this dataset, so the boost is a flat account-wide addition, not attributed to one specific host).
4. **Normalization:** `normalizedScore = round(risk / maxRisk × 100)` — the riskiest host in the environment is always 100.

**Returns:** `{ map, maxRisk, critMisc }`. **Gotcha:** must be kept in sync by hand with the client's `buildAssetRiskMap()` — the same duplication risk as `MOBILE_HTML`.

### `computeCspScores(data)` (line 7310) `[SERVER — mirrors the client's calcGlobalScoreFromCsp/calcCspScore]`
Computes a 0-100 posture score per cloud provider plus a blended overall score, so the report's gauges match what the live dashboard would show. Attributes each alert/compliance/identity finding to a cloud (by keyword matching or explicit fields), buckets by severity, and computes `penalty = 40×(C/total) + 30×(H/total) + 20×(M/total) + 10×(L/total)` → `score = 100 − penalty` (rate-based, so a cloud with 200 findings and one with 2 findings in the same severity mix score identically). A cloud with zero findings gets `null` ("no data"), treated as 100 when averaging into the overall blended score.
- **Returns:** `{ cspScores, cspFindings, cspCounts, score, sBand, sColor }`.

---

## 6. Report Builders (PDF/HTML reports) `[SERVER]`

All four functions below read the same `cache` object and share the helpers from Section 5 (`groupVulnsByHost`, `computeAssetRiskMap`, `computeCspScores`) so their numbers always agree — they differ only in scope, filtering, and presentation.

### `buildReportHtml(data, meta)` (line 7572) — the original report, `GET /report`
The primary, customer-facing report. Saved to `rca.html`/`rca.pdf` (rendered via headless Chromium). Sections: cover with overall + per-cloud gauges, Critical Alerts, Critical Non-Compliance (grouped by resource type), Critical CVEs (risk ≥ 9, grouped by host/exposure), Identity Risk (human Cloud Users only, no MFA), Secrets Found, and a Recommended Next Steps summary. This is the narrowest, most conservative of the three — every filter is tuned tight so it reads as a clean, low-noise deliverable. No per-host diagrams, no IAM-role/service-account tables, no SSH-key findings.

### `buildReportHtml2(data, meta)` (line 8127) — the beta wider-scope report, `GET /report2`
Saved to `rca2.html`/`rca2.pdf`. Adds: full Risk Score per Cloud tables (showing the actual findings driving each gauge, via `cspFindings`/`cspCounts`), per-host risk diagrams for the top-2 riskiest assets (via `computeAssetRiskMap` + `hostRiskDiagramSvg`), IAM/RBAC Roles with high privilege + high unused entitlements (including trust-policy "who can assume this" data), Service Accounts, SSH Keys Too Open, and Secrets Found. By far the broadest/most detailed report — the only one covering roles, service accounts, trust data, and SSH hygiene. Explicitly labeled "Beta" in its own title/footer.

### `buildReportHtml3(data, meta)` (line 8487) — the newest "Cloud Overview Report," `GET /report3`
Saved to `rca3.html`/`rca3.pdf`. A condensed, chart-first report aimed at executives rather than practitioners: just 4 pages — cover (gauges), a single donut chart of risk-finding categories, five identity/secrets stat tiles (no supporting tables), and a "Top Risk Assets" list (internet-exposed hosts + publicly-accessible storage) with a 3-bullet next-steps block. The only report using `computeEffectivePublicStorage()` (public storage exposure) and the only one splitting CIEM-credential secrets from generic secrets as a distinct stat. Zero row-level finding tables anywhere — everything is a count, gauge, or donut. Its identity-classification helpers are intentionally re-duplicated rather than shared with `buildReportHtml2` (flagged in an inline comment: "report builders are independently maintained").

### `buildReportHtml4(data, meta)` (line 8826) — "Generate Report_BETA," the narrative assessment report, `GET /report4`
Saved to `rca4.html`/`rca4.pdf`. Structured as a narrative professional-services-style assessment rather than a dashboard-shaped export: **1. Scope and Objectives**, **2. Cloud Environment Overview** (lists only clouds actually detected in `computeCspScores()`'s output — this integration has no OCI data source, so OCI is never claimed even though the section title format was originally modeled on a spec that mentioned it), **3. Assessment Methodology** (states the live `dynamicDaysBack` window, not a hardcoded number), **4. Risk Findings Categories**, **5. Evidence and Affected Assets** (an inventory table over `computeAssetRiskMap()`'s top 15 hosts by `normalizedScore`), **6. Internet Exposed Resources** (4 subsections: hosts, public storage, admin-no-MFA, secrets-on-exposed-hosts), **7. Immediate and Long-Term Actions** (every bullet conditional on real findings computed above — no fabricated boilerplate).
- **Section 4 ("Risk Findings Categories") is 4 curated buckets, not a keyword classifier:** Identity & Access (identities with `ALLOWS_FULL_ADMIN` risk + no MFA, root accounts excluded via `isRootAccount()`, plus high-permission IAM/RBAC roles), Misconfiguration — Critical-severity compliance findings only, Secrets on Exposed Host, Internet Accessible Storage. An earlier iteration classified all alerts+compliance findings into 6 domains (Identity/Network/Storage/Logging/Encryption/Kubernetes) via keyword regex on title/description — that approach was deliberately replaced because it mixed low-signal generic findings in with the curated ones.
- **Section 6a (Internet-Exposed Hosts) renders each host as an expandable `<details>`/`<summary>` card** (collapsed by default) — clicking it reveals a per-finding table joined from the *raw* `vulns`/`secretsAll` arrays (not `computeAssetRiskMap`'s aggregated type-string-only lists), so each row shows the actual CVE `package current-version → fix-version` or the secret's absolute `FILE_PATH` on the host.
- Shares `computeCspScores`, `computeAssetRiskMap`, `computeEffectivePublicStorage`, `groupVulnsByHost`, `tocCardHtml`, and `REPORT_CSS` with the other three report builders — only the identity-classification helpers are re-duplicated locally, per the same "independently maintained" convention as `buildReportHtml2`/`buildReportHtml3`.

---

## 7. Request Routing & Startup `[SERVER]`

### `requestHandler(req, res)` (line 8730)
The raw `(req, res) => {...}` callback passed straight to Node's built-in `http.createServer()`/`https.createServer()`. There is no Express or router library — every route is matched by hand with `if (req.url === '/x')` or `req.url.startsWith('/y')` checks, top to bottom, until one branch handles the request and calls `res.end()`. This keeps the app dependency-free at the cost of a long if/else chain and a few sharp edges: prefix-matched routes (`/report`, `/report2`, `/report3`, `/report4`) must stay carefully ordered so the longer paths are checked first; query-string parsing style is inconsistent (manual string-splitting in older routes, `URLSearchParams` in newer ones); and every response manually spreads CORS headers since there's no shared middleware (CORS is wide open, `Access-Control-Allow-Origin: *`).

**Gotchas:** `OPTIONS` requests are answered `204` for CORS preflight before any route matching. `POST` handlers manually buffer the request body via `req.on('data'/'end')` + `JSON.parse` — no body-parsing middleware, so this pattern is duplicated in every POST handler. The `/report*` routes are side-effecting beyond returning HTML: they write `.html`/`.pdf` files to disk and shell out to headless Chromium in the background (fire-and-forget) while the HTML response itself returns immediately. `/` behaves differently by both User-Agent (mobile → redirect to `/mobile`) and an auth cookie (decides `LOGIN_HTML` vs. the full dashboard). Any unrecognized URL falls through to the full dashboard HTML (200, not 404) — an SPA-style catch-all so deep links never hard-fail.

#### Route table

| Method | Path | Description |
|---|---|---|
| `OPTIONS` | any | CORS preflight — always `204`. |
| `POST` | `/api/register` | Appends a lead-capture row to `contacts.csv`. |
| `GET` | `/api/settings` | Returns current `refreshIntervalSec`/`daysBack`. |
| `POST` | `/api/settings` | Updates `refreshIntervalSec` (6–48h) or `daysBack` (7/14/15/21/30) at runtime. |
| `POST` | `/api/ai/start` | Starts a FortiCNAPP AI Assistant thread for an alert. |
| `POST` | `/api/ai/message` | Sends a follow-up message in an existing AI thread. |
| `GET` | `/api/cve` (prefix) | CVE lookup via `fetchCveDetails()`. |
| `GET` | `/api/geoip` (prefix) | IP geolocation via ipinfo.io, cached. |
| `GET` | `/api/identity-trust` (prefix) | Trust-relationship principals for a given identity. |
| `GET` | `/api/identity` (prefix) | Single identity detail (`LW_CE_IDENTITIES`). |
| `GET` | `/api/machine` (prefix) | Single host/machine detail (`LW_HE_MACHINES`). |
| `GET` | `/api/governance/targets` (prefix) | Available governance report accounts/frameworks. |
| `GET` | `/api/governance/report` (prefix) | Runs/fetches a governance report; caches as `lastGovernanceReport`. |
| `POST` | `/api/ai/rate` | Records thumbs up/down on an AI response. |
| `GET` | `/api/fg-facts` | Rotating "did you know" facts for the footer ticker. |
| `GET` | `/api/data` | Full JSON `cache` snapshot. |
| `GET` | `/health` | Plain-text `OK` liveness check. |
| `GET` | `/mobile` | Mobile dashboard (`MOBILE_HTML`). |
| `GET` | `/desktop` | Forces the desktop dashboard regardless of UA. |
| `GET` | `/report4` (prefix) | Generates **Generate Report_BETA** — narrative assessment-style report → `rca4.html`/`rca4.pdf`. |
| `GET` | `/report3` (prefix) | Generates the Cloud Overview report → `rca3.html`/`rca3.pdf`. |
| `GET` | `/report2` (prefix) | Generates the beta wider-scope report → `rca2.html`/`rca2.pdf`. |
| `GET` | `/report` (prefix) | Generates the original report → `rca.html`/`rca.pdf`. |
| `POST` | `/api/login` | Logs a lead, then serves the dashboard directly (no redirect, to avoid self-signed-cert cookie issues). |
| `GET` | `/` (mobile UA) | 302 to `/mobile`. |
| `GET` | `/` (desktop) | `LOGIN_HTML` if no auth cookie, else the dashboard. |
| any unmatched | — | Falls through to the dashboard HTML (200), not a 404. |

### `startApp(listeningPort, protocol)` (line 9206)
Called from inside the `.listen()` callback once a server actually starts listening — never called to start listening itself. Prints a startup banner (mock vs. live mode, account, refresh interval) and kicks off the data pipeline.

- **Mock mode** (`MOCK_FILE` set): synchronously loads the mock JSON into `cache` and stops there — no live refresh timer, no IP resolution; the dashboard serves that static snapshot forever.
- **Live mode:** calls `loadCacheFromDisk()` first (so the dashboard isn't blank while the first live fetch, which can take minutes, runs), then `resolveReachableIP(LW_ACCOUNT)`, and in its `.finally()` — **regardless of whether IP resolution succeeded** — triggers the very first `refreshData()` and starts `startRefreshTimer()`. Also sets up a 24-hour timer to re-resolve the account's reachable IP independent of the data-refresh cycle.

**HTTP/TLS mode selection** (decided just before `startApp` is ever called, based on `TLS_CERT`/`TLS_KEY` env vars):
- **Both set → HTTPS mode:** reads the cert/key files synchronously (a read failure calls `process.exit(1)` immediately — no fallback to HTTP); serves `requestHandler` over HTTPS on `PORT_TLS` (default 8443); **also** spins up a second, separate plain-HTTP server on `PORT` whose only job is to 301-redirect every request to the HTTPS URL — it never calls `requestHandler`/`startApp` itself.
- **Otherwise → plain HTTP** on `PORT` (default 8888), the default when no cert/key is configured.

**Gotchas:** there's no auto-generated self-signed cert in this code — "self-signed mode" just means an operator points `TLS_CERT`/`TLS_KEY` at a cert they generated themselves; the code treats it identically to a CA-signed one. In TLS mode, two Node servers run concurrently on two ports, but `startApp` (and therefore the banner + `refreshData()` bootstrap) only ever runs once, from the HTTPS server's callback. A bad/missing cert path is a hard failure, not a graceful HTTP fallback.
