#!/usr/bin/env node
// Fortinet Rapid Cloud Assessment Powered by FortiCNAPP — Live Dashboard
// Usage:  node server.js   |   open http://localhost:8888
// No npm packages required.

'use strict';
const http  = require('http');
const https = require('https');
const dns   = require('dns');
const net   = require('net');
const fs    = require('fs');
const path  = require('path');

const CONTACTS_CSV = path.join(__dirname, 'contacts.csv');
if (!fs.existsSync(CONTACTS_CSV)) {
  fs.writeFileSync(CONTACTS_CSV, 'Timestamp,FirstName,LastName,Company,Handle\n');
}

// ── CONFIG ────────────────────────────────────────────────────────────────────
// Optional: LW_KEY_FILE=/path/to/keys.json — Lacework key JSON (keyId, secret, subAccount)
let _keyFileData = {};
try {
  const _kf = process.env.LW_KEY_FILE || '';
  if (_kf) _keyFileData = JSON.parse(fs.readFileSync(_kf, 'utf8'));
} catch(e) { console.warn('[keyfile] Could not read LW_KEY_FILE:', e.message); }

const LW_ACCOUNT    = process.env.LW_ACCOUNT    || 'partner-demo.lacework.net';
const LW_KEY_ID     = process.env.LW_KEY_ID     || _keyFileData.keyId    || 'YOUR_KEY_ID';
const LW_SECRET     = process.env.LW_SECRET     || _keyFileData.secret   || 'YOUR_SECRET_KEY';
const LW_SUBACCOUNT = process.env.LW_SUBACCOUNT || _keyFileData.subAccount || _keyFileData.sub_account || '';
const PORT       = Number(process.env.PORT)     || 8888;
const PORT_TLS   = Number(process.env.PORT_TLS) || 8443;
const TLS_CERT   = process.env.TLS_CERT || '';  // path to fullchain.pem
const TLS_KEY    = process.env.TLS_KEY  || '';  // path to privkey.pem
const INTERVAL   = 86400; // refresh interval (seconds) — 24 hrs
let dynamicInterval = INTERVAL;
let _refreshTimer = null;
function startRefreshTimer() {
  if (_refreshTimer) clearInterval(_refreshTimer);
  _refreshTimer = setInterval(() => refreshData().catch(e => console.error('[refresh]', e.message)), dynamicInterval * 1000);
}
const DAYS_BACK        = 15;   // look-back window default
const ALERT_DAYS_BACK  = 14;   // High Fidelity Alerts fixed window
let dynamicDaysBack = DAYS_BACK;
const MOCK_FILE  = process.env.MOCK_FILE  || '';   // set to mock_data.json to skip API calls
// ─────────────────────────────────────────────────────────────────────────────

let token       = null;
let tokenExpiry = 0;
// Last successfully-run Governance Report (account + named compliance framework, e.g.
// "CIS AWS Foundations Benchmark v1.4"), set by GET /api/governance/report. PDF report
// generation reuses this — if a framework was run interactively before generating the
// PDF, its Medium/High/Critical NonCompliant findings drive the Non-Compliance section
// instead of the ad-hoc Policies-based fallback.
let lastGovernanceReport = null;
let cache = {
  alerts: [], vulns: [], compliance: [], identities: [], publicStorage: [], fortiInventory: [], instanceIamProfile: {}, highRiskVulns: [],
  fetchedAt: null, errors: {}, account: LW_ACCOUNT, subAccount: LW_SUBACCOUNT,
  riskScore: 0, daysBack: DAYS_BACK,
  summary: { alerts: 0, vulns: 0, compliance: 0, identities: 0, publicStorage: 0 },
};

// ── Persistent cache — survives container restarts/redeploys ───────────────────
// /app/data is bind-mounted to a named Docker volume (see deploy.sh/deploy_PrivateCloud.sh),
// so it outlives both `docker restart` (which already preserves the container's own
// writable layer) and a full `docker rm`+recreate. On startup, loadCacheFromDisk() restores
// the last-known-good cache immediately so the dashboard shows real data right away instead
// of blank panels during the first refresh cycle (which can take minutes — compliance alone
// evaluates up to COMPLIANCE_POLICY_CAP policies in throttled batches, and highRiskVulns
// paginates ~15k rows). refreshData() still runs normally afterward and overwrites this with
// fresh data as each phase completes, same as before persistence existed.
const CACHE_FILE = path.join(__dirname, 'data', 'cache.json');
function loadCacheFromDisk() {
  try {
    const raw = fs.readFileSync(CACHE_FILE, 'utf8');
    const loaded = JSON.parse(raw);
    // Spread over the current default `cache` shape first, not the other way around — an
    // older cache.json from before a field was added (e.g. highRiskVulns) must not leave
    // that field undefined; the in-code default always wins for keys the file doesn't have.
    cache = { ...cache, ...loaded };
    console.log(`[cache] restored from disk (${CACHE_FILE}), last fetched ${loaded.fetchedAt || 'unknown'}`);
  } catch (e) {
    if (e.code !== 'ENOENT') console.log('[cache] failed to load from disk:', e.message);
  }
}
function saveCacheToDisk() {
  try {
    fs.mkdirSync(path.dirname(CACHE_FILE), { recursive: true });
    fs.writeFileSync(CACHE_FILE, JSON.stringify(cache));
  } catch (e) {
    console.log('[cache] failed to save to disk:', e.message);
  }
}

const geoIpCache = {}; // ip → ipinfo.io response, cached for container lifetime



// ── HTTP helpers ──────────────────────────────────────────────────────────────

let accountIP = null; // resolved + verified reachable IP for LW_ACCOUNT

function tcpReachable(ip, port) {
  return new Promise(resolve => {
    const sock = net.createConnection({ host: ip, port });
    sock.setTimeout(3000);
    sock.on('connect', () => { sock.destroy(); resolve(true); });
    sock.on('error',   () => resolve(false));
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
  });
}

async function resolveReachableIP(hostname) {
  const addrs = await new Promise(res => dns.resolve4(hostname, (e, a) => res(e ? [] : a)));
  for (const ip of addrs) {
    if (await tcpReachable(ip, 443)) {
      console.log(`[dns] ${hostname} → ${ip} (reachable, cached for container lifetime)`);
      return ip;
    }
    console.log(`[dns] ${hostname} → ${ip} unreachable, skipping`);
  }
  console.log(`[dns] ${hostname}: all IPs unreachable, falling back to system resolver`);
  return null;
}

function request(method, hostname, path, headers, body, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const resolvedIP = hostname === LW_ACCOUNT ? accountIP : null;
    const opts = {
      hostname, port: 443, path, method,
      ...(resolvedIP ? { lookup: (_h, o, cb) => (o && o.all) ? cb(null, [{ address: resolvedIP, family: 4 }]) : cb(null, resolvedIP, 4) } : {}),
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...headers,
      },
    };
    const req = https.request(opts, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString();
        let parsed = raw;
        try { parsed = JSON.parse(raw); } catch (_) {}
        resolve({ status: res.statusCode, body: parsed, raw, headers: res.headers });
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error(`${method} ${path} timed out`)); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ── External CVE lookup (NVD + FortiGuard) ───────────────────────────────────
async function fetchCveDetails(cveId) {
  const id = cveId.trim().toUpperCase();
  const result = { id, nvd: null, fg: null, error: null };

  // 1. NVD API — structured JSON, no auth
  try {
    const { status, body } = await request('GET', 'services.nvd.nist.gov',
      `/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`,
      { 'Accept': 'application/json', 'User-Agent': 'FortiCNAPP-RCA/1.0' }, null, 25000);
    if (status === 200 && body?.vulnerabilities?.length) {
      const cve = body.vulnerabilities[0].cve;
      const desc = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
      const m31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
      const m30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
      const m2  = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
      const cvss = m31 || m30 || m2;
      const cwes = (cve.weaknesses || []).flatMap(w => w.description.map(d => d.value)).filter(Boolean);
      const refs = (cve.references || []).slice(0, 5).map(r => r.url);
      result.nvd = {
        description: desc,
        cvssScore: cvss?.baseScore,
        cvssVersion: m31 ? '3.1' : m30 ? '3.0' : '2.0',
        cvssSeverity: cvss?.baseSeverity,
        cvssVector: cvss?.vectorString,
        cwes,
        published: cve.published,
        lastModified: cve.lastModified,
        references: refs,
      };
    }
  } catch (e) { result.nvdError = e.message.includes('timed out') ? 'NVD API unreachable from this server (timeout)' : e.message; }

  // 2. FortiGuard — fetch search page HTML, extract what we can
  try {
    const { status, raw } = await request('GET', 'www.fortiguard.com',
      `/threatintel-search?q=${encodeURIComponent(id)}`,
      { 'Accept': 'text/html', 'User-Agent': 'Mozilla/5.0 (compatible; FortiCNAPP-RCA)' }, null, 12000);
    if (status === 200 && typeof raw === 'string') {
      const descM = raw.match(/<meta\s+name="description"\s+content="([^"]{10,500})"/i);
      const scoreM = raw.match(/(?:cvss[^>]*>|score[^>]*>|<b>)\s*(\d+\.\d)\s*(?:<\/|\/10)/i);
      const titleM = raw.match(/<title>([^<]{5,120})<\/title>/i);
      result.fg = {
        title: titleM?.[1]?.trim() || null,
        metaDesc: descM?.[1]?.trim() || null,
        cvssHint: scoreM?.[1] || null,
        url: `https://www.fortiguard.com/threatintel-search?q=${encodeURIComponent(id)}`,
      };
    }
  } catch (e) { result.fgError = e.message; }

  return result;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

async function ensureToken() {
  if (token && Date.now() < tokenExpiry) return token;
  const { status, body } = await request(
    'POST', LW_ACCOUNT, '/api/v2/access/tokens',
    { 'X-LW-UAKS': LW_SECRET },
    { keyId: LW_KEY_ID, expiryTime: 3600 },
  );
  // Lacework returns 201 Created for token generation
  if (status !== 200 && status !== 201)
    throw new Error(`Auth HTTP ${status}: ${JSON.stringify(body).slice(0, 200)}`);
  const tok = body?.token ?? body?.data?.token;
  if (!tok) throw new Error(`No token in auth response: ${JSON.stringify(body).slice(0, 150)}`);
  token       = tok;
  tokenExpiry = Date.now() + 3400 * 1000;
  console.log('[auth] Token OK');
  return token;
}

// ── API helpers ───────────────────────────────────────────────────────────────

async function withRetry(fn, label, retries = 5) {
  for (let i = 0; i < retries; i++) {
    try {
      const result = await fn();
      if (result.status !== 429 && result.status < 500) return result;
      if (result.status === 429) {
        // Lacework: 480 requests/hour per-endpoint token bucket, shared across every
        // caller hitting that path (e.g. all Queries/execute traffic — compliance,
        // secrets, secretsAll, identities). RateLimit-Reset (seconds) tells us how long
        // until a token frees up; honor it instead of guessing, but cap it — a fresh
        // token is usually available well before the bucket's full hourly reset.
        const resetSec = parseInt(result.headers?.['ratelimit-reset'], 10);
        const waitMs = Number.isFinite(resetSec) ? Math.min(Math.max(resetSec, 1), 30) * 1000 : 3000 * (i + 1);
        console.log(`  [retry] ${label} got 429 (rate limited), waiting ${Math.round(waitMs/1000)}s, attempt ${i + 1}/${retries}`);
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      console.log(`  [retry] ${label} got ${result.status}, attempt ${i + 1}/${retries}`);
    } catch (e) {
      console.log(`  [retry] ${label} error: ${e.message}, attempt ${i + 1}/${retries}`);
      if (i === retries - 1 || e.message.includes('timed out')) throw e;
    }
    await new Promise(r => setTimeout(r, 2000 * (i + 1)));
  }
  return fn();
}

function subAccountHeaders(tok) {
  return {
    Authorization: `Bearer ${tok}`,
    ...(LW_SUBACCOUNT ? { 'Account-Name': LW_SUBACCOUNT } : {}),
  };
}

async function post(path, body, timeoutMs = 30000) {
  const tok = await ensureToken();
  const { status, body: resp } = await withRetry(
    () => request('POST', LW_ACCOUNT, `/api/v2/${path}`, subAccountHeaders(tok), body, timeoutMs),
    path,
  );
  if (status === 204) return [];
  if (status !== 200 && status !== 201)
    throw new Error(`POST ${path} → HTTP ${status}: ${JSON.stringify(resp).slice(0, 500)}`);
  return Array.isArray(resp?.data) ? resp.data : (Array.isArray(resp) ? resp : []);
}

async function get(path) {
  const tok = await ensureToken();
  const { status, body: resp } = await withRetry(
    () => request('GET', LW_ACCOUNT, `/api/v2/${path}`, subAccountHeaders(tok), null),
    path,
  );
  if (status === 204) return null;
  if (status !== 200 && status !== 201)
    throw new Error(`GET ${path} → HTTP ${status}: ${JSON.stringify(resp).slice(0, 200)}`);
  return resp;
}

async function postRaw(path, body, timeoutMs = 30000) {
  const tok = await ensureToken();
  const { status, body: resp } = await request('POST', LW_ACCOUNT, `/api/v2/${path}`, subAccountHeaders(tok), body, timeoutMs);
  return { status, resp };
}

async function putRaw(path, body, timeoutMs = 30000) {
  const tok = await ensureToken();
  const { status, body: resp } = await request('PUT', LW_ACCOUNT, `/api/v2/${path}`, subAccountHeaders(tok), body, timeoutMs);
  return { status, resp };
}


function timeFmt(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

function timeFilter(days) {
  const end   = new Date();
  const start = new Date(Date.now() - (days || dynamicDaysBack) * 86400000);
  // NOTE: Lacework v2 search uses singular "timeFilter" not "timeFilters"
  return { startTime: timeFmt(start), endTime: timeFmt(end) };
}

function timeArgs(days) {
  const tf = timeFilter(days);
  return [{ name: 'StartTimeRange', value: tf.startTime }, { name: 'EndTimeRange', value: tf.endTime }];
}

// ── 1. Alerts — POST /api/v2/Alerts/search ───────────────────────────────────

// Alerts API caps at 7 days per request — split into chunks if window > 7
function alertTimeWindows(daysOverride) {
  const total = daysOverride || dynamicDaysBack;
  const chunkDays = 7;
  const windows = [];
  for (let offset = 0; offset < total; offset += chunkDays) {
    const end   = new Date(Date.now() - offset * 86400000);
    const start = new Date(Date.now() - Math.min(offset + chunkDays, total) * 86400000);
    windows.push({ startTime: timeFmt(start), endTime: timeFmt(end) });
  }
  return windows;
}

async function fetchAlerts() {
  const windows = alertTimeWindows(ALERT_DAYS_BACK);
  const RETURNS = ['alertId', 'alertName', 'alertType', 'severity', 'status', 'startTime', 'endTime', 'derivedFields', 'alertInfo'];
  const batches = await Promise.all(windows.flatMap(tf => [
    post('Alerts/search', { timeFilter: tf, filters: [{ field: 'severity', expression: 'eq', value: 'Critical' }], returns: RETURNS, paging: { rows: 500 } }),
    post('Alerts/search', { timeFilter: tf, filters: [{ field: 'severity', expression: 'eq', value: 'High'     }], returns: RETURNS, paging: { rows: 500 } }),
    post('Alerts/search', { timeFilter: tf, filters: [{ field: 'severity', expression: 'eq', value: 'Medium'   }], returns: RETURNS, paging: { rows: 500 } }),
  ]));
  const rows = batches.flat();
  // High Fidelity filter: open/in-progress status + anomaly/composite categories only
  const CATS = new Set(['anomaly', 'composite']);
  const filtered = rows
    .filter(r => { const s = (r.status || '').toLowerCase(); return s === 'open' || s === 'in progress'; })
    .filter(r => { const c = (r.derivedFields?.category || '').toLowerCase(); return CATS.has(c); });
  console.log('[alerts] raw:',rows.length,'after hf filter:',filtered.length);
  return filtered
    .sort((a, b) => new Date(b.startTime || 0) - new Date(a.startTime || 0))
    .slice(0, 500);
}

// ── 2. Vulns — POST /api/v2/Vulnerabilities/Hosts/search ─────────────────────
// Field mapping (confirmed via API exploration):
//   machineTags.lw_InternetExposure = "Yes"  → internet-exposed filter (client-side)
//   cveRiskScore >= 8                         → CVE severity filter (client-side; API rejects it)
//   featureKey.version_installed              → installed package version
//   machineTags.Hostname                      → display hostname
// Server-side filters: status=Active, severity=Critical|High only.
//
// NOTE: filtering was originally on hostRiskScore (Lacework's composite host-risk metric)
// instead of cveRiskScore (the CVE's own CVSS-based severity). Confirmed via live data this
// hides real, internet-exposed hosts with critical CVEs: e.g. "my-blogs" had a traced
// internet→IGW→security-group→instance exposure path (LW_APA_EXPOSURE_PATHS) and a Critical
// CVE at cveRiskScore 9.74, but hostRiskScore 0.22 (Lacework's composite weighs in factors
// beyond CVE severity, e.g. asset-criticality tagging) — so it never appeared in this panel.

// ── True Internet Exposure — verified via actual security-group/NSG/firewall rules ──
// machineTags.lw_InternetExposure just reflects "this host sits on a network path that
// reaches the internet" (confirmed via LW_APA_EXPOSURE_PATHS) — it does NOT mean the
// attached security control actually permits inbound traffic. This checks the real rules:
//   AWS:   instance → SecurityGroups[].GroupId → IpPermissions[].IpRanges[].CidrIp
//   Azure: VM → NIC → networkSecurityGroup → securityRules[] source
//   GCP:   instance → tags.items[] → firewall targetTags match, sourceRanges
// Two tiers, not one binary flag:
//   'open'       — a wide-open wildcard rule (0.0.0.0/0, ::/0, "Internet", "Any", "*").
//                  Reachable by anyone — this is what counts as "Internet Exposed"
//                  everywhere (dashboard counts, Exploit Simulation Layer, Attack Path,
//                  reports).
//   'restricted' — an Allow rule scoped to a specific public/internet-routable IP or CIDR
//                  (e.g. an allowlisted partner or admin address). The host *does* accept
//                  inbound traffic from the internet, just from a narrow allowlist — real,
//                  but a materially smaller blast radius than wide-open. Surfaced as
//                  "Restricted External Access", not folded into the main Exposed tally.
// Only genuinely private/reserved sources (RFC1918, loopback, link-local, CGNAT,
// multicast/reserved) count as neither.
function isWildcardSource(cidr) {
  const s = String(cidr || '').trim().toLowerCase();
  return s === '*' || s === '0.0.0.0/0' || s === '::/0' || s === 'internet' || s === 'any';
}
function isPublicSource(cidr) {
  const s = String(cidr || '').trim().toLowerCase();
  if (!s) return false;
  if (isWildcardSource(s)) return true;
  const ip = s.split('/')[0];
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false; // not a plain IPv4/CIDR (e.g. a service tag or unrecognized IPv6) — not counted
  const a = parseInt(m[1], 10), b = parseInt(m[2], 10);
  if (a === 10) return false;                          // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return false;    // 172.16.0.0/12
  if (a === 192 && b === 168) return false;             // 192.168.0.0/16
  if (a === 127) return false;                          // loopback
  if (a === 169 && b === 254) return false;             // link-local
  if (a === 100 && b >= 64 && b <= 127) return false;    // CGNAT 100.64.0.0/10
  if (a === 0) return false;                            // "this network"
  if (a >= 224) return false;                            // multicast + reserved
  return true;
}
// ── Fortinet appliance presence — best-effort name/tag heuristic, NOT an authoritative
// type field (unlike LW_APA_EXPOSURE_PATHS' target:"type"="fortigate", which only exists
// for FortiGate — see fetchExposurePaths()). Scans the full compute inventory fetchTrueExposure()
// already pulls (every AWS/Azure/GCP instance, not just internet-exposed or vuln-scanned
// ones) for instance names/tags matching known Fortinet product naming conventions. 'other'
// must stay last — it's the catch-all for any "forti"-containing name not matched above.
const FORTI_PRODUCTS = [
  { key: 'fortigate',     label: 'FortiGate',     re: /forti\s*-?gate|(?:^|[^a-z])fgt(?:[^a-z]|$)/i },
  { key: 'fortimanager',  label: 'FortiManager',  re: /forti\s*-?manager|(?:^|[^a-z])f-?mg(?:[^a-z]|$)/i },
  { key: 'fortianalyzer', label: 'FortiAnalyzer', re: /forti\s*-?analyzer|(?:^|[^a-z])faz(?:[^a-z]|$)/i },
  { key: 'fortiadc',      label: 'FortiADC',      re: /forti\s*-?adc|(?:^|[^a-z])fad(?:[^a-z]|$)/i },
  { key: 'fortiweb',      label: 'FortiWeb',      re: /forti\s*-?web|(?:^|[^a-z])fweb(?:[^a-z]|$)/i },
  { key: 'fortimail',     label: 'FortiMail',     re: /forti\s*-?mail/i },
  { key: 'fortisandbox',  label: 'FortiSandbox',  re: /forti\s*-?sandbox/i },
  { key: 'fortitester',   label: 'FortiTester',   re: /forti\s*-?tester/i },
  { key: 'fortiddos',     label: 'FortiDDoS',     re: /forti\s*-?ddos/i },
  { key: 'other',         label: 'Other Fortinet',re: /forti/i },
];
function classifyFortiName(name) {
  if (!name) return null;
  for (const p of FORTI_PRODUCTS) { if (p.re.test(name)) return p; }
  return null;
}

async function fetchTrueExposure() {
  const [awsInstanceRows, awsSgRows, azureNicRows, azureNsgRows, gcpInstanceRows, gcpFwRows, azureVmRows] = await Promise.all([
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_AWS_EC2_INSTANCES } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_AWS_EC2_SECURITY_GROUPS } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_AZURE_NETWORK_NETWORKINTERFACES } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_AZURE_NETWORK_NETWORKSECURITYGROUPS } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_GCP_COMPUTE_INSTANCE } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_GCP_COMPUTE_FIREWALL } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
    post('Queries/execute', { query: { queryText: `{source { LW_CFG_AZURE_COMPUTE_VIRTUALMACHINES } return distinct {RESOURCE_ID, RESOURCE_CONFIG}}` }, arguments: timeArgs(7) }, 60000).catch(() => []),
  ]);

  // Azure VMs carry no "Name" tag the way AWS does — machineTags.Hostname for Azure is the
  // ARM resource name (e.g. "RJ-EMSONPREM"), which can differ from the actual OS computer
  // name Lacework's own console displays/searches by (e.g. "EMS-FranLab"). Map ARM resource
  // name (lowercase) → OS computer name so vuln rows can carry the console-matching name.
  const azureComputerNames = {};
  azureVmRows.forEach(v => {
    const cfg = v.RESOURCE_CONFIG || {};
    const name = cfg.extended?.instanceView?.computerName || cfg.osProfile?.computerName || '';
    if (name) azureComputerNames[(v.RESOURCE_ID || '').toLowerCase()] = name;
  });

  const portRangeStr = (from, to) => (from == null ? '*' : from === to ? String(from) : `${from}-${to}`);

  // AWS: SG has an inbound Allow rule from a public source (wildcard or a specific public
  // IP) → capture each matching rule as evidence, keyed by GroupId, so instances carrying
  // that SG can show exactly what's open and why.
  const awsWildcardSgRules = new Map(); // groupId → [{sgName, protocol, port, source}]
  for (const sg of awsSgRows) {
    const cfg = sg.RESOURCE_CONFIG || {};
    const perms = cfg.IpPermissions || [];
    const reasons = [];
    for (const p of perms) {
      (p.IpRanges || []).filter(r => isPublicSource(r.CidrIp)).forEach(r => reasons.push({
        control: 'security group', name: cfg.GroupName || sg.RESOURCE_ID,
        protocol: (p.IpProtocol === '-1' ? 'all' : (p.IpProtocol || '').toUpperCase()),
        port: portRangeStr(p.FromPort, p.ToPort), source: r.CidrIp,
        tier: isWildcardSource(r.CidrIp) ? 'open' : 'restricted',
      }));
      (p.Ipv6Ranges || []).filter(r => isPublicSource(r.CidrIpv6)).forEach(r => reasons.push({
        control: 'security group', name: cfg.GroupName || sg.RESOURCE_ID,
        protocol: (p.IpProtocol === '-1' ? 'all' : (p.IpProtocol || '').toUpperCase()),
        port: portRangeStr(p.FromPort, p.ToPort), source: r.CidrIpv6,
        tier: isWildcardSource(r.CidrIpv6) ? 'open' : 'restricted',
      }));
    }
    if (reasons.length) awsWildcardSgRules.set(sg.RESOURCE_ID, reasons);
  }
  const awsExposure = new Map(); // instanceId → [reasons]
  for (const inst of awsInstanceRows) {
    const sgs = (inst.RESOURCE_CONFIG && inst.RESOURCE_CONFIG.SecurityGroups) || [];
    const reasons = sgs.flatMap(g => awsWildcardSgRules.get(g.GroupId) || []);
    if (reasons.length) awsExposure.set(inst.RESOURCE_ID, reasons);
  }

  // Azure: NSG has an inbound Allow rule from a public source (wildcard or a specific
  // public IP, e.g. an allowlisted partner address) → capture each matching rule, keyed
  // by NSG name, so VMs behind that NSG (via their NIC) can show exactly what's open and why.
  const azureWildcardNsgRules = new Map(); // nsgName (lowercase) → [{name, protocol, port, source}]
  for (const nsg of azureNsgRows) {
    const rules = (nsg.RESOURCE_CONFIG && nsg.RESOURCE_CONFIG.securityRules) || [];
    const reasons = [];
    for (const r of rules) {
      const p = r.properties || r;
      if (p.direction !== 'Inbound' || p.access !== 'Allow') continue;
      const srcs = p.sourceAddressPrefix ? [p.sourceAddressPrefix] : (p.sourceAddressPrefixes || []);
      const wildcardSrc = srcs.find(isPublicSource);
      if (!wildcardSrc) continue;
      const ports = p.destinationPortRange ? [p.destinationPortRange] : (p.destinationPortRanges || ['*']);
      reasons.push({
        control: 'NSG rule', name: r.name || nsg.RESOURCE_ID,
        protocol: (p.protocol === '*' ? 'all' : (p.protocol || '')).toUpperCase(),
        port: ports.join(','), source: wildcardSrc,
        tier: isWildcardSource(wildcardSrc) ? 'open' : 'restricted',
      });
    }
    if (reasons.length) azureWildcardNsgRules.set((nsg.RESOURCE_ID || '').toLowerCase(), reasons);
  }
  const azureExposure = new Map(); // VM name (lowercase) → [reasons]
  for (const nic of azureNicRows) {
    const cfg = nic.RESOURCE_CONFIG || {};
    const vmId = cfg.virtualMachine && cfg.virtualMachine.id;
    const nsgId = cfg.networkSecurityGroup && cfg.networkSecurityGroup.id;
    if (!vmId || !nsgId) continue;
    const nsgName = (nsgId.split('/').pop() || '').toLowerCase();
    const reasons = azureWildcardNsgRules.get(nsgName);
    if (reasons && reasons.length) {
      const vmName = (vmId.split('/').pop() || '').toLowerCase();
      if (vmName) azureExposure.set(vmName, reasons);
    }
  }

  // GCP: firewall allows inbound from a public source (wildcard or a specific public IP)
  // → capture as evidence for any instance matching its targetTags (or ALL instances on
  // that network if targetTags is empty).
  const gcpWildcardFirewalls = [];
  for (const fw of gcpFwRows) {
    const cfg = fw.RESOURCE_CONFIG || {};
    if (cfg.direction && cfg.direction !== 'INGRESS') continue;
    if (cfg.disabled) continue;
    const ranges = cfg.sourceRanges || [];
    const allowed = Array.isArray(cfg.allowed) ? cfg.allowed : [];
    const wildcardRange = ranges.find(isPublicSource);
    if (allowed.length && wildcardRange) {
      gcpWildcardFirewalls.push({
        targetTags: cfg.targetTags || [],
        reasons: allowed.map(a => ({
          control: 'firewall rule', name: fw.RESOURCE_ID,
          protocol: (a.IPProtocol || '').toUpperCase(), port: (a.ports || ['all']).join(','), source: wildcardRange,
          tier: isWildcardSource(wildcardRange) ? 'open' : 'restricted',
        })),
      });
    }
  }
  const gcpExposure = new Map(); // instance name (lowercase) → [reasons]
  for (const inst of gcpInstanceRows) {
    const cfg = inst.RESOURCE_CONFIG || {};
    const instTags = (cfg.tags && cfg.tags.items) || [];
    const reasons = gcpWildcardFirewalls
      .filter(fw => fw.targetTags.length === 0 || fw.targetTags.some(t => instTags.includes(t)))
      .flatMap(fw => fw.reasons);
    if (reasons.length) gcpExposure.set((inst.RESOURCE_ID || '').toLowerCase(), reasons);
  }

  console.log(`  [true-exposure] AWS instances w/ public-source SG: ${awsExposure.size}  Azure VMs w/ public-source NSG: ${azureExposure.size}  GCP instances w/ public-source FW: ${gcpExposure.size}`);

  // Returns full exposure evidence for a vuln row's host: a permissive security-group/
  // NSG/firewall rule is necessary but NOT sufficient — the host also needs an actual
  // public IP for that rule to route anywhere. A wildcard-open SG on an instance with no
  // public IP (machineTags.ExternalIp empty) is unreachable regardless.
  // `exposed` = has an 'open' (wildcard) rule — the real "Internet Exposed" signal.
  // `restricted` = has only 'restricted' (specific-public-IP) rules — real but narrower
  // blast radius; surfaced separately, not folded into the main Exposed tally.
  const getExposureEvidence = function(machineTags) {
    const mt = machineTags && typeof machineTags === 'object' && !Array.isArray(machineTags) ? machineTags : {};
    const publicIp = String(mt.ExternalIp || '').trim();
    if (!publicIp) return { exposed: false, restricted: false, publicIp: '', reasons: [] };
    const instanceId = mt.InstanceId || '';
    const hostname = (mt.Hostname || mt.Name || '').toLowerCase();
    const reasons = (instanceId.startsWith('i-') && awsExposure.get(instanceId))
      || (hostname && azureExposure.get(hostname))
      || (hostname && gcpExposure.get(hostname))
      || [];
    const exposed = reasons.some(r => r.tier === 'open');
    return { exposed, restricted: !exposed && reasons.length > 0, publicIp, reasons };
  };

  // Fortinet appliance presence scan — see FORTI_PRODUCTS comment above. Reuses the full
  // instance inventory already fetched above (no extra API calls).
  const fortiInventory = [];
  awsInstanceRows.forEach(inst => {
    const cfg = inst.RESOURCE_CONFIG || {};
    const tags = Array.isArray(cfg.Tags) ? cfg.Tags : [];
    const name = (tags.find(t => t.Key === 'Name') || {}).Value || inst.RESOURCE_ID || '';
    const match = classifyFortiName(name);
    if (match) fortiInventory.push({ cloud: 'aws', product: match.key, label: match.label, name, resourceId: inst.RESOURCE_ID || '' });
  });
  azureVmRows.forEach(vm => {
    const cfg = vm.RESOURCE_CONFIG || {};
    const name = cfg.extended?.instanceView?.computerName || cfg.osProfile?.computerName || vm.RESOURCE_ID || '';
    const match = classifyFortiName(name) || classifyFortiName(vm.RESOURCE_ID || '');
    if (match) fortiInventory.push({ cloud: 'azure', product: match.key, label: match.label, name, resourceId: vm.RESOURCE_ID || '' });
  });
  gcpInstanceRows.forEach(inst => {
    const cfg = inst.RESOURCE_CONFIG || {};
    const name = inst.RESOURCE_ID || cfg.name || '';
    const match = classifyFortiName(name);
    if (match) fortiInventory.push({ cloud: 'gcp', product: match.key, label: match.label, name, resourceId: inst.RESOURCE_ID || '' });
  });
  console.log(`  [forti-inventory] appliances matched by name/tag heuristic: ${fortiInventory.length}`);

  // AWS instance → attached IAM instance-profile ARN, for the "Internet Exposed Host"
  // tab's host→IAM-role linkage. AWS-only for now — Azure/GCP would need managed-identity/
  // service-account data this app doesn't currently fetch. Instance profile name is matched
  // to an IAM role by NAME against `identities` at render time (profile and role share the
  // same name by convention when created via console/typical IaC, but this is a heuristic,
  // not a guaranteed 1:1 — an instance profile is technically a separate resource wrapping a role).
  const instanceIamProfile = {};
  awsInstanceRows.forEach(inst => {
    const arn = inst.RESOURCE_CONFIG && inst.RESOURCE_CONFIG.IamInstanceProfile && inst.RESOURCE_CONFIG.IamInstanceProfile.Arn;
    if (!arn || !inst.RESOURCE_ID) return;
    const profileName = arn.split('/').pop() || '';
    instanceIamProfile[inst.RESOURCE_ID] = { arn, profileName };
  });

  return { getExposureEvidence, azureComputerNames, fortiInventory, instanceIamProfile };
}

// ── Verified Exposure Paths — LW_APA_EXPOSURE_PATHS (Attack Path Analysis) ──────
// Lacework's own graph-traced Internet→Target paths (Internet → Gateway → Security
// Group/NSG → target resource) for the resource types the dashboard already enriches
// with CVE/machine detail or public-storage findings: S3 buckets, EC2 instances, Azure
// VMs, Azure Blob storage. Purely additive — does NOT feed fetchTrueExposure's SG/NSG/
// FW-rule detection, dashboard counts, posture score, or reports. Matched onto existing
// panel rows client-side and rendered as a "Verified Path" chip alongside the existing
// evidence. azureBlob's target type traces the storage account's blob SERVICE, not
// individual containers — 0 rows in this tenant as of writing, kept for when data appears.
async function fetchExposurePaths() {
  const RETURN = 'RECORD_CREATED_TIME, PATH_ID, PROVIDER_TYPE, DOMAIN_ID, METRICS, PATH, target';
  const SOURCE = 'LW_APA_EXPOSURE_PATHS a, array_to_rows(a.TARGETS) as (target)';
  function q(targetType) {
    const queryText = `{ source { ${SOURCE} } FILTER { target:"type" = "${targetType}" } return distinct { ${RETURN} } }`;
    return post('Queries/execute', { query: { queryText }, arguments: timeArgs(dynamicDaysBack) }, 60000)
      .catch(e => { console.log(`  [exposure-paths] ${targetType} ERR:`, e.message.slice(0, 150)); return []; });
  }
  // Unfiltered — every traced Internet→Target path regardless of target type, TARGETS left
  // as its raw (unflattened) array rather than array_to_rows-exploded like the per-type
  // queries above. Powers the "Internet Accessible Ressources" tab, a comprehensive superset of
  // the type-specific panels (Host Internet Exposure, Public Storage Exposure, FortiGate).
  function qAll() {
    const queryText = `{ source { LW_APA_EXPOSURE_PATHS } return distinct { RECORD_CREATED_TIME, PATH_ID, PROVIDER_TYPE, DOMAIN_ID, METRICS, PATH, TARGETS } }`;
    return post('Queries/execute', { query: { queryText }, arguments: timeArgs(dynamicDaysBack) }, 60000)
      .catch(e => { console.log('  [exposure-paths] all ERR:', e.message.slice(0, 150)); return []; });
  }
  const [s3, ec2, azureVm, azureBlob, fortigate, all] = await Promise.all([
    q('s3:bucket'),
    q('ec2:instance'),
    q('microsoft.compute/virtualmachines'),
    q('microsoft.storage/storageaccounts/blobservices'),
    q('fortigate'),
    qAll(),
  ]);
  console.log(`  [exposure-paths] s3:${s3.length} ec2:${ec2.length} azureVm:${azureVm.length} azureBlob:${azureBlob.length} fortigate:${fortigate.length} all:${all.length}`);
  return { s3, ec2, azureVm, azureBlob, fortigate, all };
}

// ── Attack Paths — LW_APA_ATTACK_PATHS (Attack Path Analysis) ──────────────────
// Full computed attack-path graphs, distinct from LW_APA_EXPOSURE_PATHS above (that table is
// Internet→Target reachability only; this one is FortiCNAPP's broader attack-path risk
// scoring). Each record's METRICS carries METRICS.path_score (0-100) + METRICS.path_severity —
// confirmed against a live tenant. Fetched/cached unfiltered here; renderAttackPaths() applies
// the path_score >= 80 filter client-side (same pattern as the rest of exposurePaths).
async function fetchAttackPaths() {
  const queryText = `{ source { LW_APA_ATTACK_PATHS } return distinct { RECORD_CREATED_TIME, PATH_ID, PROVIDER_TYPE, DOMAIN_ID, METRICS, PATH, TARGETS } }`;
  const rows = await post('Queries/execute', { query: { queryText }, arguments: timeArgs(dynamicDaysBack) }, 60000)
    .catch(e => { console.log('  [attack-paths] ERR:', e.message.slice(0, 150)); return []; });
  console.log(`  [attack-paths] total:${rows.length}${rows[0] ? ' sample METRICS: ' + JSON.stringify(rows[0].METRICS) : ' (no rows)'}`);
  return rows;
}

// ── High-risk vulnerabilities — cveRiskScore >= 9, ANY severity ────────────────
// Powers Risk Findings' "Host Exposure" category specifically (filtered further to
// internet-exposed hosts client-side) — deliberately separate from fetchVulns()/cache.vulns
// below, which stays Critical/High-severity-only and continues to drive posture score,
// reports, the asset risk map, and every other existing consumer unchanged.
// Confirmed live: the API rejects expression:"gte" (400 "Invalid format in request body")
// but accepts expression:"ge" — matches the FortiCNAPP console's own "Risk score >= 9"
// query-builder clause, which is NOT severity-gated (can return Medium/Low/Info CVEs with
// a high risk score that Critical/High-only queries never see at all).
async function fetchHighRiskVulns() {
  const tok = await ensureToken();
  let allRows = [];
  let path = 'Vulnerabilities/Hosts/search';
  let body = {
    timeFilter: timeFilter(7),
    filters: [
      { field: 'status', expression: 'eq', value: 'Active' },
      { field: 'cveRiskScore', expression: 'ge', value: 9 },
    ],
    returns: ['vulnId', 'severity', 'hostRiskScore', 'cveRiskScore', 'riskScore', 'featureKey', 'fixInfo', 'evalCtx', 'machineTags', 'mid', 'startTime'],
    paging: { rows: 5000 },
  };
  let pageNum = 0;
  while (true) {
    pageNum++;
    try {
      const { status, resp } = pageNum === 1
        ? await postRaw(path, body, 60000)
        : { status: 200, resp: await get(path) };
      if (status !== 200) { console.log(`  [high-risk-vulns] page ${pageNum} → HTTP ${status}`); break; }
      const rows = Array.isArray(resp?.data) ? resp.data : [];
      allRows.push(...rows);
      const nextUrl = resp?.paging?.urls?.nextPage;
      if (!nextUrl) break;
      path = new URL(nextUrl).pathname.replace(/^\/api\/v2\//, '');
    } catch (e) {
      console.log(`  [high-risk-vulns] page ${pageNum} ERR:`, e.message.slice(0, 150));
      break;
    }
  }
  console.log(`  [high-risk-vulns] total:${allRows.length} (cveRiskScore >= 9, any severity)`);
  return allRows;
}

// Shared "Machine status in (Online, Launched)" check — module-scope so both fetchVulns()
// and refreshData()'s highRiskVulns correction can apply the same exclusion. Without it,
// stopped/deallocated hosts leak into any dataset that skips this (confirmed live:
// fetchHighRiskVulns() itself doesn't filter by machine status at all).
const OFFLINE_RE = /stopped|terminated|deallocat|stopping|shutting|offline/i;
function isMachineOffline(mt) {
  const mtObj = mt && typeof mt === 'object' && !Array.isArray(mt) ? mt : null;
  const mtArr = Array.isArray(mt) ? mt : null;
  const state = mtObj
    ? (mtObj.State || mtObj.PowerState || mtObj.status || '')
    : (mtArr?.find(t => /^state$/i.test(t.key))?.value || '');
  return !!(state && OFFLINE_RE.test(state));
}

async function fetchVulns() {
  function vulnQuery(sev) {
    return post('Vulnerabilities/Hosts/search', {
      timeFilter: timeFilter(7),
      filters: [
        { field: 'severity', expression: 'eq', value: sev      },
        { field: 'status',   expression: 'eq', value: 'Active' },
      ],
      returns: [
        'vulnId', 'severity', 'hostRiskScore', 'cveRiskScore', 'riskScore',
        'featureKey', 'fixInfo', 'evalCtx', 'machineTags', 'mid',
        'hostRiskInfo', 'startTime',
      ],
      paging: { rows: 5000 },
    }, 60000);
  }

  const [crits, highs, trueExposure] = await Promise.all([
    vulnQuery('Critical').catch(e => { console.log('  [vulns] Critical fetch failed:', e.message); return []; }),
    vulnQuery('High').catch(e     => { console.log('  [vulns] High fetch failed:', e.message); return []; }),
    fetchTrueExposure().catch(e   => { console.log('  [true-exposure] fetch failed:', e.message); return { getExposureEvidence: () => ({ exposed: false, restricted: false, publicIp: '', reasons: [] }), azureComputerNames: {}, fortiInventory: [], instanceIamProfile: {} }; }),
  ]);
  const { getExposureEvidence, azureComputerNames, fortiInventory, instanceIamProfile } = trueExposure;

  const rows = [...crits, ...highs];

  // Overwrite machineTags.lw_InternetExposure with the verified value (real wide-open
  // wildcard security-group/NSG/firewall rule), not Lacework's topological "sits on a path
  // to the internet" tag — every downstream consumer already reads this field, so this
  // replaces exposure classification everywhere without touching each call site
  // individually. lw_RestrictedExternalAccess is the separate, lower-severity signal for
  // hosts reachable only from a specific allowlisted public IP (not wide open) — real
  // exposure, but not folded into "Internet Exposed" counts/Attack Path/report tallies.
  // r._exposureEvidence carries the actual justification (rule/port/source) per row.
  for (const r of rows) {
    const mt = r.machineTags;
    if (mt && typeof mt === 'object' && !Array.isArray(mt)) {
      const ev = getExposureEvidence(mt);
      // Preserve Lacework's own raw tag before overwriting it — the "Internet Exposed
      // Host" panel deliberately compares against the FortiCNAPP console's own field
      // (see _renderInternetHostExposedBeta), which can disagree with our stricter
      // verified signal below.
      mt.lw_InternetExposureRaw = mt.lw_InternetExposure;
      mt.lw_InternetExposure = ev.exposed ? 'Yes' : 'No';
      mt.lw_RestrictedExternalAccess = ev.restricted ? 'Yes' : 'No';
      r._exposureEvidence = ev;
      // Normalize "Resource Name" across clouds so the dashboard shows the same identifier
      // FortiCNAPP's own console does. AWS already carries this natively (machineTags.Name,
      // the EC2 Name tag). Azure has no equivalent — machineTags.Hostname is the ARM resource
      // name, which can differ from the OS computer name Lacework's console searches/displays
      // by (e.g. ARM name "RJ-EMSONPREM" vs OS computer name "EMS-FranLab").
      if (!mt.Name && mt.Hostname) {
        const cn = azureComputerNames[mt.Hostname.toLowerCase()];
        if (cn) mt.Name = cn;
      }
    }
  }

  // Client-side filters (API does not support these as server-side expressions):
  //   Hosts > Machine status in (Online, Launched)  — exclude stopped/terminated hosts
  //   cveRiskScore >= 8                              — CVE severity threshold
  //   machineTags.lw_InternetExposure === "Yes"      — primary internet exposure check
  //   Fallback: hostRiskInfo.host_risk_factors_breakdown.internet_reachability !== "None"
  const filtered = rows.filter(r => {
    // Machine status: Online or Launched (exclude Stopped/Terminated/Deallocated)
    if (isMachineOffline(r.machineTags)) return false;

    // CVE severity score >= 8 (fallback: riskScore → hostRiskScore as impact proxy).
    // Deliberately NOT hostRiskScore first — that's Lacework's broader host-composite
    // metric, which can rate a host low even with a genuinely critical, internet-exposed
    // CVE present (see note above fetchVulns).
    const cs = parseFloat(r.cveRiskScore ?? r.riskScore ?? r.hostRiskScore ?? 0);
    if (cs < 8) return false;

    return true;
  });

  console.log(`  [vulns] raw crit:${crits.length} hi:${highs.length} → cveRisk>=8: ${filtered.length}`);
  const vulnRows = filtered
    .sort((a, b) => parseFloat(b.cveRiskScore ?? b.hostRiskScore ?? 0) - parseFloat(a.cveRiskScore ?? a.hostRiskScore ?? 0))
    .slice(0, 500);
  // fetchTrueExposure() already pulls the full compute inventory needed for the Fortinet
  // appliance presence scan (see FORTI_PRODUCTS) — piggyback its result out through here
  // rather than re-running those CFG queries a second time from refreshData(). Same for
  // getExposureEvidence — refreshData() reuses it to verify-exposure-correct
  // fetchHighRiskVulns()'s rows too, instead of a second full CFG re-fetch.
  return { rows: vulnRows, fortiInventory, instanceIamProfile, getExposureEvidence };
}

// ── 3. Top Critical Non-Compliance ───────────────────────────────────────────
// Policies API returns LQL queryText per policy. Execute the top Critical
function policyCloud(s) {
  const u = (s || '').toUpperCase();
  if (u.includes('AWS')) return 'aws';
  if (u.includes('AZURE') || u.includes('AZ_')) return 'azure';
  if (u.includes('GCP') || u.includes('GOOGLE')) return 'gcp';
  return 'cloud';
}

// Policy tags encode category/subcategory as "domain:<X>" / "subdomain:<X>" (see
// Lacework Policies API tags examples, e.g. "domain:AWS", "subdomain:Configuration").
function policyCategoryTags(tags) {
  const arr = Array.isArray(tags) ? tags : [];
  const find = prefix => { const t = arr.find(x => (x||'').toLowerCase().startsWith(prefix)); return t ? t.slice(prefix.length) : ''; };
  return { category: find('domain:'), subCategory: find('subdomain:') };
}

// Cap on how many compliance policies one refresh cycle evaluates. Lacework's
// Queries/execute endpoint shares one 480-requests/hour token bucket across every
// caller — compliance, secrets, secretsAll, and identities. Evaluating all
// (sometimes 250+) enabled Critical/High policies in a single burst can by itself
// consume over half that hourly budget, and every restart/redeploy/crash re-runs the
// full burst — stacking multiple runs into the same rolling hour reliably exhausts
// the bucket and starts failing every other feature that shares it (confirmed live:
// secrets + secretsAll both started throwing HTTP 429 after a handful of restarts).
// Critical-first sort means the highest-severity policies are always evaluated first.
const COMPLIANCE_POLICY_CAP = 50;

async function fetchCompliance() {
  // Step 1 — get enabled Critical/High compliance policy definitions, capped and
  // sorted Critical-first (see COMPLIANCE_POLICY_CAP above for why the cap exists).
  let policies = [];
  try {
    const resp = await get('Policies');
    const all  = Array.isArray(resp?.data) ? resp.data : [];
    const sevOk = s => ['critical','high'].includes((s||'').toLowerCase());
    policies = all.filter(p =>
      p.policyType === 'Compliance' && sevOk(p.severity) &&
      p.enabled !== false && p.queryText,
    )
    .sort((a, b) => {
      const rank = s => s?.toLowerCase() === 'critical' ? 0 : 1;
      return rank(a.severity) - rank(b.severity);
    })
    .slice(0, COMPLIANCE_POLICY_CAP);
    console.log(`  [compliance] ${all.filter(p=>p.policyType==='Compliance').length} total compliance policies, evaluating ${policies.length} critical/high (capped at ${COMPLIANCE_POLICY_CAP})`);
  } catch (e) {
    console.log(`  [compliance/Policies] ${e.message.slice(0,120)}`);
    return [];
  }

  // Step 2 — run policy queries in parallel batches of 3 (avoids rate-limit, ~3× faster than
  // sequential). Fixed 14-day ("last 2 weeks") window regardless of the global dynamicDaysBack
  // assessment-window setting — Critical Misconfigurations is always assessed on its own clock.
  const findings = [];
  const tf2 = timeFilter(14);
  const BATCH = 3;

  async function runPolicy(p) {
    try {
      const rows = await post('Queries/execute', {
        query: { queryText: p.queryText },
        arguments: [
          { name: 'StartTimeRange', value: tf2.startTime },
          { name: 'EndTimeRange',   value: tf2.endTime   },
        ],
      }, 60000);
      console.log(`  [compliance] ${p.policyId} → ${rows.length} rows`);
      if (rows.length) {
        const { category, subCategory } = policyCategoryTags(p.tags);
        return {
          alertId:     p.policyId,
          cloud:       policyCloud(p.queryId || p.policyId),
          title:       p.title || p.policyId,
          description: p.description || '—',
          severity:    (p.severity || 'critical').charAt(0).toUpperCase() + (p.severity || 'critical').slice(1).toLowerCase(),
          category,
          subCategory,
          violations:  rows.length,
          // Full resource detail, not just a preview — bounded only as a payload-size
          // safety ceiling, not a "top N" business cap.
          resources:   rows.slice(0, 1000),
        };
      }
    } catch (e) {
      // 429s are already retried with backoff inside post()/withRetry() — reaching here on
      // a 429 means the bucket stayed exhausted through every retry, not a one-off blip.
      console.log(`  [compliance] ${p.policyId} ERR: ${e.message.slice(0,200)}`);
    }
    return null;
  }

  for (let i = 0; i < policies.length; i += BATCH) {
    const batch = policies.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(runPolicy));
    results.forEach(r => r && findings.push(r));
    // Push partial results to cache so client sees them on next poll
    if (findings.length) {
      cache = { ...cache, compliance: findings.slice().sort((a, b) => b.violations - a.violations) };
    }
    if (i + BATCH < policies.length) {
      // Evaluating every enabled Critical/High policy (not a capped top-15) can mean 100+
      // requests against Lacework's shared 480/hour Queries/execute bucket, on top of
      // secretsAll/secrets/identities traffic hitting the same bucket — a larger gap here
      // spreads that load out so a single refresh cycle doesn't threaten the hourly budget.
      await new Promise(r => setTimeout(r, 1500));
    }
  }

  console.log(`  [compliance] ${findings.length} policies with violations`);
  return findings.sort((a, b) => b.violations - a.violations);
}

// ── 4. Identities — POST /api/v2/Queries/execute (LQL) ───────────────────────
// LW_CE_IDENTITIES — main identity data, with optional TRUST_POLICY enrichment

async function fetchIdentities() {
  const tf = timeFilter(7); // hard-cap at 7 days

  const mainQuery = `{
    source { LW_CE_IDENTITIES }
    return distinct {
      PRINCIPAL_ID,
      PROVIDER_TYPE,
      NAME,
      LAST_USED_TIME,
      CREATED_TIME,
      METRICS,
      ACCESS_KEYS,
      ENTITLEMENT_COUNTS
    }
  }`;

  // Try to also fetch TRUST_POLICY for role→principal correlation
  const trustQuery = `{
    source { LW_CE_IDENTITIES }
    return distinct {
      PRINCIPAL_ID,
      TRUST_POLICY
    }
  }`;

  // LW_CE_LINKED_IDENTITIES has no free-text PRINCIPAL_TYPE field, but its RELATION_TYPE
  // values are prefixed with the real identity type (e.g. AZURE_USER_TO_GROUP,
  // AWS_ROLE_TO_ROLE, GCP_GOOGLE_ACCOUNT_TO_GROUP, AZURE_SERVICE_ACCOUNT_TO_GROUP) — a
  // reliable, LQL-verified type signal, unlike guessing from PRINCIPAL_ID/NAME string
  // patterns (which misses Azure AD / GCP Workspace users whose ID is a bare email).
  const linkedQuery = `{
    source { LW_CE_LINKED_IDENTITIES }
    return distinct {
      PRINCIPAL_ID,
      RELATION_TYPE,
      LINKED_PRINCIPAL_ID,
      LINKED_NAME
    }
  }`;

  const [rows, trustRows, linkedRows] = await Promise.all([
    post('Queries/execute', {
      query: { queryText: mainQuery },
      arguments: [{ name: 'StartTimeRange', value: tf.startTime }, { name: 'EndTimeRange', value: tf.endTime }],
    }, 60000).catch(() => []),
    post('Queries/execute', {
      query: { queryText: trustQuery },
      arguments: [{ name: 'StartTimeRange', value: tf.startTime }, { name: 'EndTimeRange', value: tf.endTime }],
    }, 60000).catch(() => []),
    post('Queries/execute', {
      query: { queryText: linkedQuery },
      arguments: [{ name: 'StartTimeRange', value: tf.startTime }, { name: 'EndTimeRange', value: tf.endTime }],
    }, 60000).catch(() => []),
  ]);

  // Build trust map: PRINCIPAL_ID → TRUST_POLICY
  const trustMap = {};
  for (const t of trustRows) {
    if (t.PRINCIPAL_ID && t.TRUST_POLICY) trustMap[t.PRINCIPAL_ID] = t.TRUST_POLICY;
  }

  // Build LQL-verified type map: PRINCIPAL_ID → { cloud: AWS|AZURE|GCP, type: USER | ROLE | GOOGLE_ACCOUNT | SERVICE_ACCOUNT | INSTANCE_PROFILE | GROUP | ... }
  // Cloud is kept alongside type — RELATION_TYPE's own prefix (e.g. AZURE_USER_TO_GROUP)
  // was previously discarded, so an Azure user linked via that relation collapsed to the
  // same bare 'USER' type as an AWS IAM user and got labeled identically downstream.
  const lqlTypeMap = {};
  for (const l of linkedRows) {
    if (!l.PRINCIPAL_ID || lqlTypeMap[l.PRINCIPAL_ID]) continue;
    const m = /^(AWS|AZURE|GCP)_(.+?)_TO_/.exec(l.RELATION_TYPE || '');
    if (m) lqlTypeMap[l.PRINCIPAL_ID] = { cloud: m[1], type: m[2] };
  }

  console.log(`  [identities] total: ${rows.length}  trust policies: ${Object.keys(trustMap).length}  LQL-typed: ${Object.keys(lqlTypeMap).length}`);
  if (rows.length) console.log(`  [identities] sample: ${JSON.stringify(rows[0]).slice(0, 200)}`);

  // Filter criteria (any match qualifies):
  //   1. Risk severity = Critical
  //   2. Unused permissions >= 75%
  //   3. Full Admin flag (always include)
  // Identity type: limit to AWS/Azure/GCP role, user, service account (skip generic/unknown)
  const CLOUD_ROLE_TYPES = new Set(['aws','azure','gcp','google']);
  const filtered = rows
    .filter(r => {
      const risks  = r.METRICS?.risks ?? [];
      const sev    = (r.METRICS?.risk_severity || '').toLowerCase();
      const unused = r.ENTITLEMENT_COUNTS?.entitlements_unused_count ?? null;
      const total  = r.ENTITLEMENT_COUNTS?.entitlements_total_count  ?? null;
      const highUnused = unused !== null && total !== null && total > 0 && (unused / total) >= 0.75;
      const isCritical = sev === 'critical';

      // Identity type must be a cloud role/user/service (not a bare generic entry)
      const pid = (r.PRINCIPAL_ID || '').toLowerCase();
      const pt  = (r.PROVIDER_TYPE || '').toLowerCase();
      const nm  = (r.NAME || '').toLowerCase();
      const isTypedIdentity =
        pid.includes(':role/') || pid.includes(':user/') ||
        pid.includes('serviceaccount') || pid.includes('.iam.gserviceaccount.com') ||
        pid.includes(':root') || nm === 'root' ||
        pt.includes('serviceprincipal') || pt.includes('aad') ||
        CLOUD_ROLE_TYPES.has(pt.split('_')[0]);
      if (!isTypedIdentity) return false;

      // Users, Root accounts, and Service Accounts/Principals are always included
      // regardless of severity, so the Identity & Access Risk view can show the full
      // Critical/High/Medium/Low picture for cloud users. Roles stay gated behind
      // admin/critical/high-unused — there are far more of them, and only the
      // highest-risk ones are actionable at that volume.
      const isRole = pid.includes(':role/') || pid.includes(':assumed-role/');
      if (!isRole) return true;

      return risks.includes('ALLOWS_FULL_ADMIN') || isCritical || highUnused;
    })
    .sort((a, b) => {
      // Sort: Full Admin first, then by risk_score desc
      const aAdmin = (a.METRICS?.risks ?? []).includes('ALLOWS_FULL_ADMIN') ? 0 : 1;
      const bAdmin = (b.METRICS?.risks ?? []).includes('ALLOWS_FULL_ADMIN') ? 0 : 1;
      if (aAdmin !== bAdmin) return aAdmin - bAdmin;
      return (b.METRICS?.risk_score || 0) - (a.METRICS?.risk_score || 0);
    })
    // Was capped at 50 — in role-heavy AWS orgs, admin-flagged roles alone can fill every
    // slot (Full Admin sorted first) and starve out rarer-but-real risks like admin IAM
    // Users entirely before they reach the client. Raised well above typical pre-filtered
    // volume so long-tail identity types (Users among many Roles) aren't silently dropped.
    .slice(0, 300);

  // Parse TRUST_POLICY (from trustMap) into trust principals for the Correlated tab
  filtered.forEach(r => {
    const principals = [];
    try {
      const raw = trustMap[r.PRINCIPAL_ID];
      if (raw) {
        const tp = typeof raw === 'string' ? JSON.parse(raw) : raw;
        const stmts = tp?.Statement || tp?.statement || [];
        for (const stmt of stmts) {
          const p = stmt?.Principal || stmt?.principal;
          if (!p) continue;
          if (typeof p === 'string') { principals.push({ type: 'AWS', principal: p }); continue; }
          for (const [k, v] of Object.entries(p)) {
            const vals = Array.isArray(v) ? v : [v];
            vals.forEach(vv => principals.push({ type: k, principal: vv }));
          }
        }
      }
      // Also surface lateral movement principals from METRICS if available
      const lateral = r.METRICS?.lateral_movement_principals || [];
      lateral.forEach(lp => principals.push({ type: 'Lateral', principal: lp }));
    } catch (_) {}
    r._trustPrincipals = principals;
    r._lqlType = lqlTypeMap[r.PRINCIPAL_ID] || null;
  });

  return filtered;
}

// ── Governance Reports — GET /api/v2/CloudAccounts + /api/v2/Reports ─────────
// Lets the UI pick a named compliance framework ("Governance Report") and run it
// against a specific configured cloud account, via Lacework's Reports API.
// NOTE: only AWS_CIS_14 / AZURE_CIS_1_5 / GCP_CIS13 are confirmed exact reportType
// values from the API spec; the rest follow Lacework's documented naming convention
// but a wrong/unsupported value will simply surface as an API error to the caller.
const GOVERNANCE_REPORT_TYPES = {
  aws: [
    { value: 'AWS_CIS_14',        label: 'CIS AWS Foundations Benchmark v1.4' },
    { value: 'AWS_CIS_S3',        label: 'CIS AWS Foundations — S3 Only' },
    { value: 'AWS_SOC_2',         label: 'SOC 2' },
    { value: 'AWS_HIPAA',         label: 'HIPAA' },
    { value: 'AWS_PCI_DSS_3.2.1', label: 'PCI DSS 3.2.1' },
    { value: 'AWS_ISO_27001:2013',label: 'ISO 27001:2013' },
    { value: 'AWS_NIST_CSF',      label: 'NIST CSF' },
    { value: 'NIST_800-53_Rev4',  label: 'NIST 800-53 Rev4' },
    { value: 'NIST_800-171_Rev2', label: 'NIST 800-171 Rev2' },
    { value: 'AWS_CMMC_1.02',     label: 'CMMC 1.02' },
  ],
  azure: [
    { value: 'AZURE_CIS_1_5',       label: 'CIS Azure Foundations Benchmark v1.5' },
    { value: 'AZURE_SOC_2',         label: 'SOC 2' },
    { value: 'AZURE_PCI_DSS_3.2.1', label: 'PCI DSS 3.2.1' },
    { value: 'AZURE_ISO_27001:2013',label: 'ISO 27001:2013' },
    { value: 'AZURE_NIST_CSF',      label: 'NIST CSF' },
  ],
  gcp: [
    { value: 'GCP_CIS13',         label: 'CIS GCP Foundations Benchmark v1.3' },
    { value: 'GCP_SOC_2',         label: 'SOC 2' },
    { value: 'GCP_PCI_DSS_3.2.1', label: 'PCI DSS 3.2.1' },
    { value: 'GCP_ISO_27001:2013',label: 'ISO 27001:2013' },
    { value: 'GCP_HIPAA',         label: 'HIPAA' },
  ],
};

async function fetchGovernanceTargets() {
  let accounts = [];
  try { accounts = (await get('CloudAccounts'))?.data || []; } catch (e) { console.error('[governance] CloudAccounts fetch failed:', e.message); }

  const perAccount = await Promise.all(accounts.filter(a => a.enabled).map(async (a) => {
    const d = a.data || {};
    if (a.type === 'AwsCfg' && d.awsAccountId) {
      return [{ cloud: 'aws', label: `AWS ${d.awsAccountId} — ${a.name}`, primaryQueryId: d.awsAccountId, secondaryQueryId: '' }];
    }
    if (a.type === 'AzureCfg' && d.tenantId) {
      let subs = [];
      try {
        const subResp = await get(`Configs/AzureSubscriptions?tenantId=${encodeURIComponent(d.tenantId)}`);
        subs = (subResp?.data || []).flatMap(t => t.subscriptions || []);
      } catch (e) { console.error('[governance] AzureSubscriptions fetch failed:', e.message); }
      return subs.length
        ? subs.map(sub => ({ cloud: 'azure', label: `Azure ${sub} — ${a.name}`, primaryQueryId: d.tenantId, secondaryQueryId: sub }))
        : [{ cloud: 'azure', label: `Azure tenant ${d.tenantId} — ${a.name}`, primaryQueryId: d.tenantId, secondaryQueryId: '' }];
    }
    if (a.type === 'GcpCfg' && d.id) {
      if (d.idType === 'ORGANIZATION') {
        let projs = [];
        try {
          const projResp = await get(`Configs/GcpProjects?orgId=${encodeURIComponent(d.id)}`);
          projs = (projResp?.data || []).flatMap(o => o.projects || []);
        } catch (e) { console.error('[governance] GcpProjects fetch failed:', e.message); }
        return projs.length
          ? projs.map(p => ({ cloud: 'gcp', label: `GCP ${p} — ${a.name}`, primaryQueryId: p, secondaryQueryId: p }))
          : [{ cloud: 'gcp', label: `GCP org ${d.id} — ${a.name}`, primaryQueryId: d.id, secondaryQueryId: d.id }];
      }
      return [{ cloud: 'gcp', label: `GCP ${d.id} — ${a.name}`, primaryQueryId: d.id, secondaryQueryId: d.id }];
    }
    return [];
  }));
  return perAccount.flat();
}

// ── 5. Secrets All — POST /api/v2/Queries/execute (LQL) ──────────────────────
// LW_HE_SECRETS_ALL dataset — all discovered secrets across hosts

async function fetchSecretsAll() {
  const tf = timeFilter(7); // hard-cap at 7 days — larger windows time out
  const tok = await ensureToken();
  const timeArgs = [
    { name: 'StartTimeRange', value: tf.startTime },
    { name: 'EndTimeRange',   value: tf.endTime   },
  ];

  // Run secrets fetch + machine state query in parallel
  const secretsQueryText = `{source { LW_HE_SECRETS_ALL } return {RECORD_CREATED_TIME, MID, HOSTNAME, FILE_PATH, SECRET_TYPE, SECRET_METADATA}}`;
  const machQueryText    = `{source { LW_HE_MACHINES } return { MID, HOSTNAME, TAGS }}`;

  // withRetry() (not a bare request() call) so a 429 here gets the same RateLimit-Reset-aware
  // backoff as every other Queries/execute caller, instead of throwing on the first hit — this
  // fetcher needs the raw {status, body} shape for pagination, so it can't go through post().
  const [r1resp, machResp] = await Promise.all([
    withRetry(() => request('POST', LW_ACCOUNT, '/api/v2/Queries/execute',
      subAccountHeaders(tok),
      { query: { queryText: secretsQueryText }, arguments: timeArgs }, 60000), 'Queries/execute (secretsAll)'),
    withRetry(() => request('POST', LW_ACCOUNT, '/api/v2/Queries/execute',
      subAccountHeaders(tok),
      { query: { queryText: machQueryText }, arguments: timeArgs }, 60000), 'Queries/execute (machines)')
      .catch(() => ({ status: 0, body: null })),
  ]);

  if (r1resp.status !== 200 && r1resp.status !== 201)
    throw new Error(`Queries/execute → HTTP ${r1resp.status}`);

  const all = [];
  if (Array.isArray(r1resp.body?.data)) all.push(...r1resp.body.data);

  // Follow secrets pages
  let nextUrl = r1resp.body?.paging?.urls?.nextPage || null;
  while (nextUrl) {
    const u = new URL(nextUrl);
    const { status: sN, body: rN } = await withRetry(() => request(
      'GET', LW_ACCOUNT, u.pathname + u.search,
      { Authorization: `Bearer ${tok}` }, null,
    ), 'Queries/execute (secretsAll page)');
    if (sN !== 200) break;
    if (Array.isArray(rN?.data)) all.push(...rN.data);
    nextUrl = rN?.paging?.urls?.nextPage || null;
  }

  // Build stopped-host sets from LW_HE_MACHINES TAGS
  const STOPPED_STATES = new Set(['stopped','terminated','deallocated','stopping',
    'shutting-down','powered_off','off','poweroff','deallocating']);
  const stoppedMIDs   = new Set();
  const stoppedHosts  = new Set();
  (machResp.body?.data || []).forEach(m => {
    const tags = m.TAGS;
    let ps = '';
    if (Array.isArray(tags)) {
      const t = tags.find(t => (t.key || '').toLowerCase() === 'powerstate');
      ps = (t?.value || '').toLowerCase();
    } else if (tags && typeof tags === 'object') {
      ps = String(tags.powerState || tags.PowerState || '').toLowerCase();
    }
    if (STOPPED_STATES.has(ps)) {
      if (m.MID)      stoppedMIDs.add(String(m.MID));
      if (m.HOSTNAME) stoppedHosts.add(m.HOSTNAME);
    }
  });

  let filtered = all.filter(r => {
    const path = (r.FILE_PATH || '');
    const meta = (typeof r.SECRET_METADATA === 'object' && r.SECRET_METADATA) ? r.SECRET_METADATA : {};
    const p = meta.file_permissions;
    if (/etc\/ssh\/ssh_host_/i.test(path)) return false;
    if (p !== undefined && p !== null) return (p & 0o377) !== 0;
    return true;
  });

  // Exclude secrets whose host is explicitly stopped/terminated
  const beforeStop = filtered.length;
  if (stoppedMIDs.size || stoppedHosts.size) {
    filtered = filtered.filter(r => {
      if (r.MID      && stoppedMIDs.has(String(r.MID)))  return false;
      if (r.HOSTNAME && stoppedHosts.has(r.HOSTNAME))     return false;
      return true;
    });
  }
  console.log(`  [secrets-ssh] total permissive (>chmod 400): ${all.length}`);
  console.log(`  [secrets-all] total: ${all.length}, after exclusions: ${filtered.length}` +
    (beforeStop - filtered.length ? ` (${beforeStop - filtered.length} on stopped hosts removed)` : ''));
  return filtered;
}

// ── 6. Secrets SSH Keys — POST /api/v2/Queries/execute (LQL) ─────────────────
// LW_HE_SECRETS_SSH_PRIVATE_KEYS dataset — SSH private keys detected on hosts

async function fetchSecrets() {
  const tf = timeFilter(7); // hard-cap at 7 days
  // FILE_PERMISSIONS is a top-level Number (Unix mode including file type bits).
  // Regular file + chmod 400 = 0o100400 = 33024.
  // Filter: > 33024 means at least one permission bit beyond owner-read is set.
  // Also fetch rows where FILE_PERMISSIONS is NULL (include — unknown is risky).
  const queryText = `{source { LW_HE_SECRETS_SSH_PRIVATE_KEYS } filter { FILE_PERMISSIONS > 33024 } return {HOSTNAME, FILE_PATH, SSH_KEY_TYPE, FILE_PERMISSIONS}}`;
  const rows = await post('Queries/execute', {
    query: { queryText },
    arguments: [
      { name: 'StartTimeRange', value: tf.startTime },
      { name: 'EndTimeRange',   value: tf.endTime   },
    ],
  }, 60000);
  console.log(`  [secrets-ssh] total permissive (>chmod 400): ${rows.length}`);
  return rows;
}

// ── Public Storage Exposure — object storage only (S3 / Azure Blob containers / GCS
// buckets), never block storage (EBS/Managed Disks/Persistent Disks are out of scope).
// Each cloud is fetched directly from its own CFG resource inventory + the specific
// signal that actually proves public exposure — not inferred from generic compliance
// policy titles, which only surfaces whatever cloud happens to have a Critical/High
// policy loaded that week:
//   AWS   — LW_CFG_AWS_S3 (bucket inventory) joined to GET_BUCKET_POLICY_STATUS.IsPublic
//           and GET_BUCKET_ACL grants to the AllUsers/AuthenticatedUsers group URIs, gated
//           by GET_PUBLIC_ACCESS_BLOCK (IgnorePublicAcls/RestrictPublicBuckets can neutralize
//           an otherwise-public policy/ACL).
//   Azure — LW_CFG_AZURE_STORAGE_STORAGEACCOUNTS_BLOBSERVICES_CONTAINERS.publicAccess,
//           checked per-container ('Blob'/'Container' = public, 'None' = private), gated
//           by the parent storage account's allowBlobPublicAccess (LW_CFG_AZURE_STORAGE_
//           STORAGEACCOUNTS) — Azure denies public access account-wide when that's Disabled
//           regardless of what an individual container's own setting says.
//   GCP   — LW_CFG_GCP_STORAGE_BUCKET joined to its _IAMPOLICY bindings for the
//           allUsers/allAuthenticatedUsers special members, gated by the bucket's own
//           iamConfiguration.publicAccessPrevention ('enforced' blocks public IAM/ACL grants
//           outright).
//
// 8 queries run in small batches (not all at once) with short gaps between batches, same
// self-throttling pattern fetchCompliance() uses — otherwise this alone can push a refresh
// cycle over Lacework's per-account rate limit alongside the other concurrent Phase-1
// fetchers, and a 429 on any one of these silently reads as "no public storage" instead of
// "couldn't check" (refreshData() falls back to the prior cycle's result when that happens
// — see the publicStorage retention comment there).
async function fetchPublicStorage() {
  const tf = timeArgs(7);
  async function q(source, fields) {
    try {
      return await post('Queries/execute', {
        query: { queryText: `{source { ${source} } return distinct { ${fields} }}` },
        arguments: tf,
      }, 60000);
    } catch (e) {
      console.log(`  [public-storage] ${source} ERR: ${e.message.slice(0, 100)}`);
      return [];
    }
  }
  const specs = [
    ['LW_CFG_AWS_S3', 'RESOURCE_ID, ACCOUNT_ID, ACCOUNT_ALIAS, RESOURCE_REGION, ARN, RESOURCE_CONFIG'],
    ['LW_CFG_AWS_S3_GET_BUCKET_POLICY_STATUS', 'RESOURCE_ID, RESOURCE_CONFIG'],
    ['LW_CFG_AWS_S3_GET_BUCKET_ACL', 'RESOURCE_ID, RESOURCE_CONFIG'],
    ['LW_CFG_AWS_S3_GET_PUBLIC_ACCESS_BLOCK', 'RESOURCE_ID, RESOURCE_CONFIG'],
    ['LW_CFG_AZURE_STORAGE_STORAGEACCOUNTS_BLOBSERVICES_CONTAINERS', 'RESOURCE_ID, SUBSCRIPTION_ID, URN, RESOURCE_CONFIG'],
    ['LW_CFG_AZURE_STORAGE_STORAGEACCOUNTS', 'RESOURCE_ID, RESOURCE_CONFIG'],
    ['LW_CFG_GCP_STORAGE_BUCKET', 'RESOURCE_ID, PROJECT_ID, RESOURCE_REGION, RESOURCE_CONFIG'],
    ['LW_CFG_GCP_STORAGE_BUCKET_IAMPOLICY', 'RESOURCE_ID, RESOURCE_CONFIG'],
  ];
  const BATCH = 3;
  const results = [];
  for (let i = 0; i < specs.length; i += BATCH) {
    const batch = specs.slice(i, i + BATCH);
    results.push(...await Promise.all(batch.map(([source, fields]) => q(source, fields))));
    if (i + BATCH < specs.length) await new Promise(r => setTimeout(r, 500));
  }
  const [s3Buckets, s3PolicyStatus, s3Acl, s3PublicAccessBlock, azContainers, azStorageAccounts, gcpBuckets, gcpIamPolicy] = results;

  // ── AWS S3 ── A bucket's own Block Public Access settings can neutralize an otherwise-
  // public policy/ACL: IgnorePublicAcls makes S3 disregard public ACL grants entirely, and
  // RestrictPublicBuckets strips external (non-AWS-service) access from a public bucket
  // policy. So a bucket only counts as actually public if the relevant block flag is NOT
  // set — a bucket with IsPublic=true but RestrictPublicBuckets=true is not exposed.
  const s3BlockMap = {};
  s3PublicAccessBlock.forEach(r => {
    const cfg = r.RESOURCE_CONFIG?.PublicAccessBlockConfiguration || {};
    s3BlockMap[r.RESOURCE_ID] = { ignoreAcls: cfg.IgnorePublicAcls === true, restrictBuckets: cfg.RestrictPublicBuckets === true };
  });
  const s3PublicReasons = {}; // RESOURCE_ID → ['Public Policy'|'Public ACL', ...]
  function markS3Public(id, reason) {
    if (!s3PublicReasons[id]) s3PublicReasons[id] = [];
    s3PublicReasons[id].push(reason);
  }
  s3PolicyStatus.forEach(r => {
    const isPublicPolicy = r.RESOURCE_CONFIG?.PolicyStatus?.IsPublic === true;
    const restricted = s3BlockMap[r.RESOURCE_ID]?.restrictBuckets;
    if (isPublicPolicy && !restricted) markS3Public(r.RESOURCE_ID, 'Public Policy');
  });
  s3Acl.forEach(r => {
    const grants = r.RESOURCE_CONFIG?.Grants || [];
    const isPublicGrant = grants.some(g => /AllUsers|AuthenticatedUsers/.test(g?.Grantee?.URI || ''));
    const ignored = s3BlockMap[r.RESOURCE_ID]?.ignoreAcls;
    if (isPublicGrant && !ignored) markS3Public(r.RESOURCE_ID, 'Public ACL');
  });
  const awsPublic = s3Buckets.filter(b => s3PublicReasons[b.RESOURCE_ID]).map(b => ({
    cloud: 'aws',
    name: b.RESOURCE_ID,
    account: b.ACCOUNT_ALIAS || b.ACCOUNT_ID || '—',
    region: b.RESOURCE_REGION || '—',
    resourceType: 'S3 Bucket (' + s3PublicReasons[b.RESOURCE_ID].join(' + ') + ')',
    urn: b.ARN || b.RESOURCE_ID,
  }));

  // ── Azure Blob Containers ── A container's own publicAccess setting is gated by its
  // parent storage account's allowBlobPublicAccess: when that account-level switch is
  // Disabled, Azure denies public access to every container underneath it regardless of
  // what the individual container's publicAccess property says — same relationship as
  // S3's Block Public Access overriding a bucket's own policy/ACL above.
  const azAllowPublicMap = {}; // storage account name (lowercased) → allowBlobPublicAccess
  azStorageAccounts.forEach(a => { azAllowPublicMap[(a.RESOURCE_ID || '').toLowerCase()] = a.RESOURCE_CONFIG?.allowBlobPublicAccess; });
  const azurePublic = azContainers.filter(c => {
    const pa = c.RESOURCE_CONFIG?.publicAccess;
    if (!pa || pa === 'None') return false;
    const acctMatch = /storageaccounts\/([^/]+)\//i.exec(c.URN || '');
    const acctName = acctMatch ? acctMatch[1].toLowerCase() : null;
    // Missing account row (join miss) defaults to "not blocked" — Azure's own account
    // default is allowBlobPublicAccess=true unless explicitly disabled.
    return acctName ? azAllowPublicMap[acctName] !== false : true;
  }).map(c => {
    const acctMatch = /storageaccounts\/([^/]+)\//i.exec(c.URN || '');
    return {
      cloud: 'azure',
      name: c.RESOURCE_ID,
      account: acctMatch ? acctMatch[1] : (c.SUBSCRIPTION_ID || '—'),
      region: '—',
      resourceType: 'Blob Container (' + c.RESOURCE_CONFIG.publicAccess + ')',
      urn: c.URN || c.RESOURCE_ID,
    };
  });

  // ── GCP Cloud Storage ── Public Access Prevention (publicAccessPrevention: 'enforced')
  // is GCP's equivalent master switch — when enforced, GCP blocks anonymous/public access
  // via IAM or ACL even if an allUsers/allAuthenticatedUsers binding exists on the bucket.
  const gcpPapByBucket = {};
  gcpBuckets.forEach(b => { gcpPapByBucket[b.RESOURCE_ID] = b.RESOURCE_CONFIG?.iamConfiguration?.publicAccessPrevention; });
  const gcpPublicIds = new Set();
  gcpIamPolicy.forEach(p => {
    const bindings = p.RESOURCE_CONFIG?.bindings || [];
    const isPublicMember = bindings.some(b => (b.members || []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers'));
    const papEnforced = gcpPapByBucket[p.RESOURCE_ID] === 'enforced';
    if (isPublicMember && !papEnforced) gcpPublicIds.add(p.RESOURCE_ID);
  });
  const gcpPublic = gcpBuckets.filter(b => gcpPublicIds.has(b.RESOURCE_ID)).map(b => ({
    cloud: 'gcp',
    name: (b.RESOURCE_ID || '').replace('//storage.googleapis.com/', ''),
    account: b.PROJECT_ID || '—',
    region: b.RESOURCE_REGION || '—',
    resourceType: 'Cloud Storage Bucket',
    urn: b.RESOURCE_ID,
  }));

  const findings = [...awsPublic, ...azurePublic, ...gcpPublic];
  console.log(`  [public-storage] aws:${awsPublic.length} azure:${azurePublic.length} gcp:${gcpPublic.length}`);
  return findings;
}

// ── Identity risk classification — shared by calcRiskScore() and computeCspScores(), the
// only two server-side (Node) scoring functions; the client dashboard, mobile view, and both
// report builders each keep their own duplicated copy (no shared JS runtime across those). ──
function isServiceAccount(r) {
  const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase(), p=(r.PROVIDER_TYPE||'').toLowerCase();
  return pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||p.includes('serviceprincipal')||p.includes('aad');
}
function isRoleType(r) {
  const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase();
  return (pid.includes(':role/')||pid.includes(':assumed-role/')||nm.includes('role')) && !isServiceAccount(r);
}
function isHighPermissive(r) {
  const risks = (r.METRICS && r.METRICS.risks) || [];
  const sev = (r.METRICS && r.METRICS.risk_severity || '').toLowerCase();
  return risks.includes('ALLOWS_FULL_ADMIN') || risks.includes('EXCESSIVE_PERMISSIONS') || sev === 'critical' || sev === 'high';
}
function isNoMfa(r) {
  const risks = (r.METRICS && r.METRICS.risks) || [];
  return risks.includes('PASSWORD_LOGIN_NO_MFA') || !r.MFA_ENABLED;
}
function unusedPctOf(r) {
  const ec = r.ENTITLEMENT_COUNTS || {};
  const unusedCnt = ec.entitlements_unused_count, totalCnt = ec.entitlements_total_count || ec.entitlements_count;
  return ec.entitlements_unused_percentage != null ? ec.entitlements_unused_percentage
    : (unusedCnt != null && totalCnt ? (unusedCnt/totalCnt)*100 : null);
}
// Access-key age — verified against a live tenant snapshot (AWS/Azure/GCP all agree on
// shape): ACCESS_KEYS is an OBJECT keyed by access_key_id, not an array, and each key's
// creation date is `created_time` — not the create_date/CreateDate casings this function
// originally guessed at (written with no live data available to confirm against; see
// docs/superpowers/specs/2026-07-28-risk-findings-weighting-design.md). Only active keys
// count — an already-disabled key isn't a live rotation risk.
function accessKeyList(r) {
  const raw = r.ACCESS_KEYS;
  if (!raw || typeof raw !== 'object') return [];
  return Array.isArray(raw) ? raw : Object.values(raw);
}
function isOldAccessKey(r, thresholdDays) {
  thresholdDays = thresholdDays || 180;
  return accessKeyList(r).some(k => {
    if (!k || typeof k !== 'object' || k.active === false) return false;
    const created = k.created_time || k.create_date || k.CREATE_DATE || k.createDate || k.CreateDate || k.created_at || k.CREATED_AT;
    if (!created) return false;
    const ageDays = (Date.now() - new Date(created).getTime()) / 86400000;
    return Number.isFinite(ageDays) && ageDays >= thresholdDays;
  });
}
// Oldest active key's age in days, for display — null if no active keys with a known date.
function oldestActiveKeyAgeDays(r) {
  const ages = accessKeyList(r)
    .filter(k => k && typeof k === 'object' && k.active !== false)
    .map(k => {
      const created = k.created_time || k.create_date || k.CREATE_DATE || k.createDate || k.CreateDate || k.created_at || k.CREATED_AT;
      if (!created) return null;
      const d = (Date.now() - new Date(created).getTime()) / 86400000;
      return Number.isFinite(d) ? d : null;
    })
    .filter(d => d !== null);
  return ages.length ? Math.max(...ages) : null;
}
function isAdminNoMfaIdentity(r) {
  return !isServiceAccount(r) && !isRoleType(r) && isHighPermissive(r) && isNoMfa(r);
}
// Admin + No-MFA + (unused entitlements ≥80% OR an access key ≥180d old) → flat 80 (same
// tier as a Critical alert). Otherwise falls back to the raw FortiCNAPP CIEM risk_score.
function identityRiskScore(r) {
  const qualifies = isAdminNoMfaIdentity(r) && ((unusedPctOf(r) ?? 0) >= 80 || isOldAccessKey(r));
  return qualifies ? 80 : Math.min(100, (r.METRICS?.risk_score || 0) * 100);
}

// ── Main refresh ──────────────────────────────────────────────────────────────

function calcRiskScore(alerts, vulns, identities) {
  const topIdent = identities.reduce((m, i) => Math.max(m, identityRiskScore(i)), 0);
  const topCve   = vulns.reduce((m, v) => { const rs = parseFloat(v.riskScore || 0); return rs >= 8 ? Math.max(m, rs * 10) : m; }, 0);
  const alertPts = Math.min(alerts.length * 3, 15);
  return Math.min(100, Math.round(topIdent * 0.60 + topCve * 0.25 + alertPts));
}

// Reports read from the background-refreshed `cache` rather than querying live on every
// request (the full refreshData() cycle can take minutes due to rate-limit-driven
// compliance throttling — see COMPLIANCE_POLICY_CAP notes above). That's intentional and
// fast for the common case. But if the scheduled refresh cycle has stalled or crashed
// (confirmed live: report sections lagging behind real cloud state), a report could
// silently serve data far older than the configured refresh interval with no indication
// anything was wrong. This is a safety net, not a live-per-request fetch: only refreshes
// when the cache is stale beyond the configured interval (+10% grace), so normal report
// generation still just reads the cache as before.
async function ensureFreshCache() {
  if (!cache.fetchedAt) return;
  const ageMs = Date.now() - new Date(cache.fetchedAt).getTime();
  const maxAgeMs = dynamicInterval * 1000 * 1.1;
  if (ageMs <= maxAgeMs) return;
  console.log(`[report] cache is ${Math.round(ageMs/60000)}min old (limit ${Math.round(maxAgeMs/60000)}min) — refreshing before generating report`);
  try { await refreshData(); }
  catch (e) { console.error('[report] pre-generation refresh failed, serving existing cache:', e.message); }
}

async function refreshData() {
  console.log(`\n[${new Date().toISOString()}] Refreshing…`);
  const errors = {};

  // Phase 1: fast parallel fetch — update cache immediately so UI is responsive.
  // fetchPublicStorage() deliberately is NOT in this batch — its 8 CFG queries would double
  // the concurrent Queries/execute burst at the exact moment this fires, which is enough by
  // itself to trip this tenant's rate limit before compliance even gets a turn. It runs in
  // Phase 2 instead, after Phase 1's fetchers have already completed and freed up quota.
  const [a, v, i, s, ep, ap, hrv] = await Promise.allSettled([
    fetchAlerts(),
    fetchVulns(),
    fetchIdentities(),
    fetchSecrets(),
    fetchExposurePaths(),
    fetchAttackPaths(),
    fetchHighRiskVulns(),
  ]);

  function unwrap(res, key) {
    if (res.status === 'fulfilled') return res.value;
    errors[key] = res.reason?.message ?? String(res.reason);
    console.error(`  [${key}] ERROR: ${errors[key]}`);
    return [];
  }

  const alerts       = unwrap(a,  'alerts');
  const vulnsResult   = unwrap(v,  'vulns');
  const vulns         = Array.isArray(vulnsResult) ? vulnsResult : (vulnsResult.rows || []);
  const fortiInventory = Array.isArray(vulnsResult) ? [] : (vulnsResult.fortiInventory || []);
  const instanceIamProfile = Array.isArray(vulnsResult) ? {} : (vulnsResult.instanceIamProfile || {});
  const getExposureEvidence = Array.isArray(vulnsResult) ? null : vulnsResult.getExposureEvidence;
  const identities    = unwrap(i,  'identities');
  const secrets      = unwrap(s,  'secrets');
  const exposurePaths = ep.status === 'fulfilled' ? ep.value : (unwrap(ep, 'exposurePaths'), { s3: [], ec2: [], azureVm: [], azureBlob: [], fortigate: [], all: [] });
  const attackPaths   = unwrap(ap, 'attackPaths');
  // fetchHighRiskVulns() itself applies no machine-status filter (unlike fetchVulns()) —
  // exclude stopped/deallocated/terminated hosts here so every consumer of cache.highRiskVulns
  // (including the Internet Exposed Host panel) sees only Online/Launched machines, matching
  // the FortiCNAPP console's own "Machine status in (Online, Launched)" filter.
  const highRiskVulnsRaw = unwrap(hrv, 'highRiskVulns').filter(r => !isMachineOffline(r.machineTags));
  // Apply the same verified-exposure correction fetchVulns() applies to cache.vulns — reuses
  // the getExposureEvidence closure fetchVulns() already computed rather than re-running the
  // CFG queries a second time. Without this, highRiskVulns would use Lacework's raw
  // topological "internet exposed" tag instead of the actually-verified (open SG/NSG/FW rule
  // + public IP) signal the rest of the app relies on — a second, inconsistent definition.
  if (getExposureEvidence) {
    for (const r of highRiskVulnsRaw) {
      const mt = r.machineTags;
      if (mt && typeof mt === 'object' && !Array.isArray(mt)) {
        const evd = getExposureEvidence(mt);
        // Preserve Lacework's own raw tag — see matching comment in fetchVulns().
        mt.lw_InternetExposureRaw = mt.lw_InternetExposure;
        mt.lw_InternetExposure = evd.exposed ? 'Yes' : 'No';
        mt.lw_RestrictedExternalAccess = evd.restricted ? 'Yes' : 'No';
        r._exposureEvidence = evd;
      }
    }
  }

  // Publish fast data right away; compliance + secretsAll + publicStorage update the cache
  // as each becomes ready
  cache = {
    ...cache,
    alerts, vulns, identities, secrets, exposurePaths, attackPaths, fortiInventory, instanceIamProfile,
    highRiskVulns: highRiskVulnsRaw,
    fetchedAt: new Date().toISOString(),
    errors,
    account: LW_ACCOUNT,
    daysBack: dynamicDaysBack,
    riskScore: calcRiskScore(alerts, vulns, identities),
    summary: { alerts: alerts.length, vulns: vulns.length, compliance: cache.compliance?.length ?? 0, identities: identities.length, secrets: secrets.length, secretsAll: cache.secretsAll?.length ?? 0, publicStorage: cache.publicStorage?.length ?? 0 },
  };
  saveCacheToDisk(); // Phase 1 result — saved now so a restart mid-Phase-2 still keeps this

  // Phase 2: compliance + secretsAll + publicStorage run concurrently, each publishing to
  // cache the moment IT resolves — not gated behind all three settling together. They used
  // to run sequentially (compliance fully finishing before secretsAll started) to avoid
  // rate-limit contention, but compliance now evaluates every enabled Critical/High policy
  // instead of a capped top-15 and can take several minutes; secretsAll (usually much
  // faster) would otherwise sit unpublished behind it the whole time. Compliance already
  // self-throttles internally (batches of 3, 500ms gaps between batches) and publicStorage
  // does the same (batches of 3, see fetchPublicStorage()), so running secretsAll's single
  // query alongside them is a small, acceptable increase in concurrent Queries/execute calls.
  const compliancePromise = fetchCompliance()
    .then(v => ({ status: 'fulfilled', value: v }))
    .catch(e => ({ status: 'rejected', reason: e }))
    .then(res => {
      const freshComp = unwrap(res, 'compliance');
      // Retain last good compliance result when rate-limited (429 → empty list)
      const compliance = freshComp.length > 0 ? freshComp : (cache.compliance ?? []);
      cache = { ...cache, compliance, summary: { ...cache.summary, compliance: compliance.length } };
      return compliance;
    });

  const secretsAllPromise = fetchSecretsAll()
    .then(v => ({ status: 'fulfilled', value: v }))
    .catch(e => ({ status: 'rejected', reason: e }))
    .then(res => {
      const secretsAll = unwrap(res, 'secretsAll');
      cache = { ...cache, secretsAll, summary: { ...cache.summary, secretsAll: secretsAll.length } };
      return secretsAll;
    });

  // fetchPublicStorage()'s per-query catch (see there) turns a rate-limited query into an
  // empty result rather than a thrown error, so an empty result here can mean either
  // "genuinely nothing public" or "got rate-limited mid-fetch". Retaining the prior cycle's
  // result on empty — same guard compliance uses above — avoids the panel flashing to
  // "nothing found" on a transient 429.
  const publicStoragePromise = fetchPublicStorage()
    .then(v => ({ status: 'fulfilled', value: v }))
    .catch(e => ({ status: 'rejected', reason: e }))
    .then(res => {
      const freshPublicStorage = unwrap(res, 'publicStorage');
      const publicStorage = freshPublicStorage.length > 0 ? freshPublicStorage : (cache.publicStorage ?? []);
      cache = { ...cache, publicStorage, summary: { ...cache.summary, publicStorage: publicStorage.length } };
      return publicStorage;
    });

  const [compliance, secretsAll, publicStorage] = await Promise.all([compliancePromise, secretsAllPromise, publicStoragePromise]);

  console.log(`[done] alerts:${alerts.length} vulns:${vulns.length} compliance:${compliance.length} identities:${identities.length} secretsAll:${secretsAll.length} publicStorage:${publicStorage.length}`);
  if (Object.keys(errors).length) console.log('[errors]', errors);
  saveCacheToDisk(); // Full cache including Phase 2 (compliance/secretsAll/publicStorage)
}

// ── Dashboard HTML ────────────────────────────────────────────────────────────

function buildHtml(_account, intervalSec) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiCNAPP · Rapid Cloud Assessment</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  /* ── Console palette ── */
  --bg:#f3f4f6;--surface:#ffffff;--card:#f9fafb;--card2:#f3f4f6;
  --border:#e5e7eb;--border2:#d1d5db;
  --text:#111827;--sub:#374151;--muted:#6b7280;
  --accent:#da291c;--accent-l:#c42418;--accent-dim:rgba(218,41,28,.07);
  /* risk — desaturated, GitHub-scale */
  --cr:#b91c1c;--cr-bg:#fef2f2;--cr-bd:#fca5a5;
  --hi:#c2410c;--hi-bg:#fff7ed;--hi-bd:#fdba74;
  --me:#92400e;--me-bg:#fffbeb;--me-bd:#fcd34d;
  --ok:#166534;--ok-bg:#f0fdf4;--ok-bd:#86efac;
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Inter',BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;line-height:1.5;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

/* ── Animations ── */
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes step1-flash{0%,100%{box-shadow:0 0 0 0 rgba(185,28,28,.6)}50%{box-shadow:0 0 0 14px rgba(185,28,28,0)}}
@keyframes snake-flow{to{stroke-dashoffset:-26}}
@keyframes path-flow{to{stroke-dashoffset:-20}}
@keyframes fg-arrow{0%,100%{transform:translateX(0)}50%{transform:translateX(4px)}}

/* ── App shell ── */
.app-layout{display:flex;min-height:100vh}
.main{flex:1;min-width:0}

/* ── Sidebar ── */
.sidebar{width:210px;background:#0d1117;flex-shrink:0;position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column;border-right:1px solid #21262d}
.sb-brand{padding:14px 14px 12px;border-bottom:1px solid #21262d}
.sb-logo{display:none}
.sb-name{font-size:12px;font-weight:600;color:#c9d1d9;letter-spacing:-.1px}
.sb-sect{padding:14px 14px 4px;font-size:9px;font-weight:700;letter-spacing:.12em;color:#30363d;text-transform:uppercase}
.sb-item{display:flex;align-items:flex-start;gap:8px;padding:7px 12px;margin:1px 6px;border-radius:5px;cursor:pointer;color:#8b949e;font-size:12px;font-weight:400;transition:background .1s,color .1s;user-select:none;white-space:normal;line-height:1.35}
.sb-item:hover{background:#161b22;color:#c9d1d9}
.sb-item.active{background:#21262d;color:#f0f6fc;font-weight:600;border-left:2px solid var(--accent);padding-left:10px}
.sb-item svg{width:14px;height:14px;margin-top:1px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0;opacity:.7}
.sb-item.active svg{opacity:1}
.sb-sep{margin:6px 12px;border:none;border-top:1px solid #21262d}
.sb-spacer{flex:1}

/* ── Top bar ── */
.top-bar{display:flex;align-items:center;justify-content:flex-end;padding:6px 20px;background:var(--surface);border-bottom:1px solid var(--border);gap:12px;position:sticky;top:0;z-index:100}
.tb-user{display:flex;align-items:center;gap:8px}
.tb-avatar{width:28px;height:28px;border-radius:4px;background:var(--accent);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.tb-name{font-size:12px;font-weight:600;color:var(--text);line-height:1.2}
.tb-role-lbl{font-size:10px;color:var(--muted);line-height:1.2}
.tb-badge{font-size:9px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;background:var(--me-bg);color:var(--me);border:1px solid var(--me-bd);border-radius:3px;padding:1px 6px}

/* ── Views ── */
.view{display:none}.view.active{display:block}

/* ── Report header ── */
.rpt-header{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 24px}
.rpt-top{display:grid;grid-template-columns:1fr auto 1fr;align-items:center}
.rpt-brand{display:flex;align-items:center;gap:12px}
.logo{width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.logo svg{width:20px;height:20px;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.rpt-title{font-size:15px;font-weight:700;color:var(--text)}
.rpt-sub{font-size:10px;color:var(--accent);text-transform:uppercase;letter-spacing:.1em;margin-top:1px}
.rpt-meta{text-align:right;font-size:11px;color:var(--muted);line-height:1.8;justify-self:end}
.rpt-meta b{color:var(--sub)}
.live-row{display:flex;align-items:center;gap:5px;font-size:11px;color:var(--muted);justify-content:flex-end}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--muted)}
.live-dot.ok{background:#238636;animation:blink 2.5s ease-in-out infinite}
.live-dot.err{background:var(--cr)}

/* ── Posture score ── */
.rs-block{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:8px 32px;border-left:1px solid var(--border);border-right:1px solid var(--border)}
.rs-label{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:4px}
.rs-num{font-size:44px;font-weight:800;line-height:1;letter-spacing:-2px;color:var(--text);font-variant-numeric:tabular-nums;transition:color .4s}
.mountain{display:flex;align-items:flex-end;gap:4px;height:24px;margin:6px 0 4px}
.mt-bar{width:12px;border-radius:2px 2px 0 0;background:var(--border2);transition:background .4s}
.mt-bar.lit{background:currentColor}
.mt-1{height:6px}.mt-2{height:12px}.mt-3{height:18px}.mt-4{height:24px}
.rs-band{font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;transition:color .4s}

/* ── KPI bar ── */
.kpi-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-bottom:1px solid var(--border)}
.kpi{background:var(--surface);padding:14px 20px;position:relative;overflow:hidden;cursor:default;border-right:1px solid var(--border)}
.kpi:last-child{border-right:none}
.kpi::before{content:'';position:absolute;left:0;top:0;bottom:0;width:2px}
.kpi.red::before{background:var(--cr)}
.kpi.orange::before{background:var(--hi)}
.kpi.yellow::before{background:var(--me)}
.kpi.teal::before{background:var(--accent)}
.kpi-label{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin-bottom:5px}
.kpi-val{font-size:28px;font-weight:800;line-height:1;letter-spacing:-1px;color:var(--text);font-variant-numeric:tabular-nums}
.kpi.red .kpi-val{color:var(--cr)}
.kpi.orange .kpi-val{color:var(--hi)}
.kpi.yellow .kpi-val{color:var(--me)}
.kpi.teal .kpi-val{color:var(--accent)}
.kpi-desc{font-size:10px;color:var(--muted);margin-top:4px}

/* ── Error notice ── */
.err-notice{background:var(--cr-bg);border-bottom:1px solid var(--cr-bd);padding:6px 24px;font-size:11px;color:var(--cr);display:none}
.err-notice.show{display:block}

/* ── Section layout (overview grid) ── */
.sections{display:grid;grid-template-columns:repeat(2,1fr);gap:0;border-top:1px solid var(--border)}
@media(max-width:1000px){.sections{grid-template-columns:1fr}}
.section{border-right:1px solid var(--border);border-bottom:1px solid var(--border);background:var(--surface)}
.section:nth-child(even){border-right:none}

/* ── Section header ── */
.sec-hdr{display:flex;align-items:center;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border);background:var(--card)}
.sec-icon{width:26px;height:26px;border-radius:5px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0}
.si-red{background:var(--cr-bg);border:1px solid var(--cr-bd)}
.si-orange{background:var(--hi-bg);border:1px solid var(--hi-bd)}
.si-yellow{background:var(--me-bg);border:1px solid var(--me-bd)}
.si-teal{background:var(--accent-dim);border:1px solid rgba(218,41,28,.2)}
.sec-title{font-size:12px;font-weight:600;color:var(--text)}
.sec-desc{font-size:10px;color:var(--muted);margin-top:1px}
.sec-count{margin-left:auto;font-size:10px;font-weight:700;padding:2px 8px;border-radius:3px;border:1px solid var(--border);font-variant-numeric:tabular-nums}
.sec-count.bad{color:var(--cr);background:var(--cr-bg);border-color:var(--cr-bd)}
.sec-count.ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}

/* ── Data table ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:11.5px}
thead{position:sticky;top:0;z-index:2}
thead th{text-align:left;padding:5px 10px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);background:var(--card);border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .08s}
tbody tr:hover{background:var(--card)}
tbody tr:last-child{border-bottom:none}
td{padding:5px 10px;vertical-align:middle;color:var(--sub)}
td.p{color:var(--text);font-weight:500;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.desc{color:var(--sub);max-width:420px;white-space:normal;word-break:break-word;line-height:1.45}
td.m{font-family:'SFMono-Regular',Consolas,monospace;font-size:10px;color:var(--muted);white-space:nowrap}
td.r{text-align:right;padding-right:10px;white-space:nowrap;width:1%}
td.desc{font-size:11px;max-width:520px;padding-top:6px;padding-bottom:6px}

/* ── Badges ── */
.b{display:inline-flex;align-items:center;gap:3px;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;white-space:nowrap;border:1px solid transparent}
/* Risk flag tooltip */
.rf-dot{position:relative;display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;font-size:7px;font-weight:800;cursor:default;flex-shrink:0}
.rf-dot .rf-tip{display:none;position:absolute;top:calc(100% + 6px);left:50%;transform:translateX(-50%);background:#1e293b;color:#f8fafc;border-radius:6px;padding:7px 10px;font-size:11px;font-weight:400;white-space:normal;width:220px;box-shadow:0 4px 16px rgba(0,0,0,.25);z-index:9999;pointer-events:none;line-height:1.45}
.rf-dot .rf-tip strong{font-weight:700;display:block;margin-bottom:2px;font-size:11.5px}
.rf-dot .rf-tip::before{content:'';position:absolute;bottom:100%;left:50%;transform:translateX(-50%);border:5px solid transparent;border-bottom-color:#1e293b}
.rf-dot:hover .rf-tip{display:block}
.b::before{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}
.b-cr{color:var(--cr);background:var(--cr-bg);border-color:var(--cr-bd)}
.b-hi{color:var(--hi);background:var(--hi-bg);border-color:var(--hi-bd)}
.b-me{color:var(--me);background:var(--me-bg);border-color:var(--me-bd)}
.b-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}
.b-nt{color:var(--muted);background:var(--card);border-color:var(--border)}
.risk-score{font-size:12px;font-weight:700;color:var(--cr);font-variant-numeric:tabular-nums}
.tag-admin{font-size:9px;font-weight:700;color:var(--cr);border:1px solid var(--cr-bd);padding:1px 5px;border-radius:3px}
.tag-nomfa{font-size:9px;font-weight:700;color:var(--hi);border:1px solid var(--hi-bd);padding:1px 5px;border-radius:3px}

/* ── Row severity strip ── */
.strip-cr td:first-child{border-left:2px solid var(--cr)}
.strip-hi td:first-child{border-left:2px solid var(--hi)}
.strip-me td:first-child{border-left:2px solid var(--me)}

/* ── State / spinner ── */
.state{display:flex;flex-direction:column;align-items:center;gap:8px;padding:36px 24px;color:var(--muted);font-size:12px;text-align:center}
.state-icon{font-size:22px;opacity:.3}
.spinner{width:18px;height:18px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}

/* ── Links / copy button ── */
.rf-link{color:var(--sub);text-decoration:none;font-weight:500}
.rf-link:hover{color:var(--accent);text-decoration:underline}
.cp-btn{display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border:none;background:transparent;color:var(--border2);cursor:pointer;border-radius:2px;padding:0;margin-left:4px;vertical-align:middle;flex-shrink:0;transition:color .1s}
.ar-exposed-row{cursor:pointer;transition:background .12s}
.ar-exposed-row:hover{background:#fff1f2}
.cp-btn:hover{color:var(--accent)}
.cp-btn.ok{color:var(--ok)}

/* ── Dashboard pie / overview ── */
.pie-section{display:flex;flex-direction:column;align-items:center;gap:12px;padding:16px 28px 14px;background:var(--surface);border-bottom:1px solid var(--border)}
.pie-donut{flex-shrink:0;display:flex;justify-content:center}
.pie-legend{display:grid;grid-template-columns:repeat(4,1fr);width:100%;max-width:860px;background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.pi-row{display:flex;flex-direction:column;gap:4px;padding:16px 18px;cursor:pointer;transition:background .1s;border-right:1px solid var(--border)}
.pi-row:last-child{border-right:none}
.pi-row:hover{background:var(--card)}
.pi-topbar{height:2px;border-radius:1px;margin-bottom:4px}
.pi-cnt{font-size:36px;font-weight:800;line-height:1;letter-spacing:-2px;font-variant-numeric:tabular-nums}
.pi-name{font-size:12px;font-weight:600;color:var(--sub);line-height:1.3;margin-top:3px}
.pi-desc{font-size:10px;color:var(--muted);line-height:1.45}
.dash-kpis{display:none}
.dk-val{font-size:36px;font-weight:800;line-height:1;letter-spacing:-2px}
.dk-red .dk-val{color:var(--cr)}.dk-orange .dk-val{color:var(--hi)}.dk-amber .dk-val{color:var(--me)}.dk-purple .dk-val{color:#7c3aed}

/* ── Section view header ── */
.view-hdr{padding:12px 20px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border);background:var(--surface)}
.vh-icon{display:none}
.vh-text{flex:1}
.vh-title{font-size:13px;font-weight:700;color:var(--text);text-transform:uppercase;letter-spacing:.04em}
.vh-sub{font-size:10px;color:var(--muted);margin-top:1px}
.vh-badge{font-size:11px;font-weight:700;padding:2px 10px;border-radius:3px;white-space:nowrap;font-variant-numeric:tabular-nums;border:1px solid var(--border);background:var(--card);color:var(--sub)}
/* section accents — left border only, no background wash */
.vha-red{border-left:3px solid var(--cr)}.vha-red .vh-title{color:var(--cr)}.vha-red .vh-badge{color:var(--cr);border-color:var(--cr-bd);background:var(--cr-bg)}
.vha-orange{border-left:3px solid var(--hi)}.vha-orange .vh-title{color:var(--hi)}.vha-orange .vh-badge{color:var(--hi);border-color:var(--hi-bd);background:var(--hi-bg)}
.vha-amber{border-left:3px solid var(--me)}.vha-amber .vh-title{color:var(--me)}.vha-amber .vh-badge{color:var(--me);border-color:var(--me-bd);background:var(--me-bg)}
.vha-purple{border-left:3px solid #7c3aed}.vha-purple .vh-title{color:#6d28d9}.vha-purple .vh-badge{color:#6d28d9;border-color:#c4b5fd;background:#f5f3ff}

/* ── Misc ── */
.agent-tip{font-size:10px;color:var(--accent);cursor:default;border-bottom:1px dashed var(--accent);padding-bottom:1px}
.footer{text-align:center;padding:12px;font-size:10px;color:var(--muted);border-top:1px solid var(--border)}
.sec-hdr.dark{background:var(--surface);border-bottom:1px solid var(--border)}

/* ── Risk Findings view ── */
.rf-posture{display:flex;align-items:center;gap:24px;padding:16px 24px;background:var(--surface);border-bottom:1px solid var(--border)}
.rf-pos-num{font-size:52px;font-weight:800;line-height:1;letter-spacing:-2px;font-variant-numeric:tabular-nums;transition:color .4s}
.rf-pos-meta{display:flex;flex-direction:column;gap:2px}
.rf-pos-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:var(--muted)}
.rf-pos-band{font-size:14px;font-weight:700;letter-spacing:.04em;transition:color .4s}
.rf-pos-sub{font-size:10px;color:var(--muted)}
.rf-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-bottom:1px solid var(--border)}
.rf-kpi{background:var(--surface);padding:11px 16px;border-right:1px solid var(--border)}
.rf-kpi:last-child{border-right:none}
.rf-kpi-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:4px}
.rf-kpi-val{font-size:22px;font-weight:800;line-height:1;letter-spacing:-1px;color:var(--text);font-variant-numeric:tabular-nums}
.rf-kpi-sub{font-size:10px;color:var(--muted);margin-top:2px}
.rf-body{padding:14px 18px}

/* ── Journey / Snake maps ── */
.jmap-outer{padding:14px 14px 10px;display:flex;justify-content:center}
.jmap-svg{width:100%;max-width:1000px;overflow:visible}
.cjmap-outer{padding:14px 14px 10px;display:flex;justify-content:center}
.cjmap-svg{width:100%;max-width:750px;overflow:visible}

/* ── Report button + modal ── */
.rpt-btn{display:flex;align-items:center;gap:7px;margin:8px 8px 0;padding:9px 12px;border-radius:5px;cursor:pointer;background:var(--accent);color:#fff;font-size:11px;font-weight:700;letter-spacing:.04em;border:none;width:calc(100% - 16px);transition:background .1s}
.rpt-btn:hover{background:var(--accent-l)}
.rpt-btn svg{width:13px;height:13px;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal-box{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:24px 24px 18px;width:380px;max-width:92vw;box-shadow:0 16px 48px rgba(0,0,0,.18)}
.modal-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:4px}
.modal-sub{font-size:11px;color:var(--muted);margin-bottom:18px}
.modal-field{margin-bottom:12px}
.modal-label{font-size:10px;font-weight:700;color:var(--sub);letter-spacing:.06em;text-transform:uppercase;margin-bottom:4px}
.modal-input{width:100%;background:var(--card);border:1px solid var(--border);border-radius:5px;padding:8px 10px;color:var(--text);font-size:12px;font-family:inherit;outline:none;transition:border-color .1s}
.modal-input:focus{border-color:var(--accent)}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
.modal-btn{padding:7px 16px;border-radius:5px;font-size:12px;font-weight:600;cursor:pointer;border:1px solid var(--border);font-family:inherit;transition:background .1s}
.modal-btn.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
.modal-btn.primary:hover{background:var(--accent-l)}
.modal-btn.primary:disabled{opacity:.5;cursor:not-allowed}
.modal-btn.ghost{background:transparent;color:var(--sub)}
.modal-btn.ghost:hover{background:var(--card)}
.modal-status{text-align:center;padding:14px 0 4px;font-size:11px;color:var(--muted);line-height:1.7;min-height:44px}
.modal-dl{display:flex;flex-direction:column;gap:6px;margin-top:10px}
.modal-dl a{display:flex;align-items:center;gap:7px;padding:8px 12px;background:var(--card);border:1px solid var(--border);border-radius:5px;color:var(--sub);text-decoration:none;font-size:11px;font-weight:600;transition:background .1s}
.modal-dl a:hover{background:var(--card2)}
.modal-dl a svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round}

/* ── Login ── */
.login-overlay{position:fixed;inset:0;z-index:2000;background:#0d1117;display:flex;align-items:center;justify-content:center}
.login-box{width:380px;max-width:92vw;background:var(--surface);border:1px solid var(--border2);border-radius:8px;padding:28px 28px 22px;box-shadow:0 0 0 1px #21262d}
.login-logo{display:flex;align-items:center;gap:10px;margin-bottom:22px}
.login-logo-name{font-size:12px;font-weight:600;color:var(--sub);letter-spacing:.02em}
.login-title{font-size:18px;font-weight:700;color:var(--text);margin-bottom:4px}
.login-sub{font-size:11px;color:var(--muted);margin-bottom:20px}
.login-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.login-field{display:flex;flex-direction:column;gap:4px;margin-bottom:10px}
.login-label{font-size:9px;font-weight:700;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}
.login-input{background:var(--card);border:1px solid var(--border);border-radius:5px;padding:8px 10px;color:var(--text);font-size:12px;font-family:inherit;outline:none;transition:border-color .1s}
.login-input:focus{border-color:var(--accent)}
.login-select{appearance:none;background:var(--card);border:1px solid var(--border);border-radius:5px;padding:8px 24px 8px 10px;color:var(--text);font-size:12px;font-family:inherit;outline:none;width:100%;cursor:pointer;transition:border-color .1s}
.login-select:focus{border-color:var(--accent)}
.login-btn{width:100%;margin-top:6px;padding:10px;border-radius:5px;background:var(--accent);color:#fff;font-size:12px;font-weight:700;border:none;cursor:pointer;letter-spacing:.04em;transition:background .1s}
.login-btn:hover{background:var(--accent-l)}
.login-err{font-size:11px;color:var(--cr);margin-top:6px;min-height:16px;text-align:center}

/* ── Tabs (lab / identities) ── */
.lab-tabs-bar{display:flex;gap:0;padding:0 20px;border-bottom:1px solid var(--border);background:var(--card);flex-wrap:wrap}
.lab-tab{padding:8px 16px;border:none;border-bottom:2px solid transparent;background:transparent;font-size:11px;font-weight:600;color:var(--muted);cursor:pointer;transition:color .1s,border-color .1s;letter-spacing:.02em;margin-bottom:-1px}
.lab-tab:hover{color:var(--text)}
.lab-tab.active{color:var(--text);border-bottom-color:var(--accent)}
.lab-tab[data-csp=aws].active{color:#e8891a;border-bottom-color:#e8891a}
.lab-tab[data-csp=azure].active{color:#0078D4;border-bottom-color:#0078D4}
.lab-tab[data-csp=gcp].active{color:#4285F4;border-bottom-color:#4285F4}

/* ── AI overlay ── */
.ai-overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:2000;display:flex;align-items:center;justify-content:center;padding:16px}
.ai-panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;width:540px;max-width:100%;height:72vh;max-height:680px;display:flex;flex-direction:column;box-shadow:0 20px 60px rgba(0,0,0,.3);overflow:hidden}
.ai-hdr{padding:12px 16px 10px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-shrink:0;background:var(--card)}
.ai-hdr-left{display:flex;flex-direction:column;gap:1px;min-width:0}
.ai-hdr-tag{font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--accent)}
.ai-hdr-title{font-size:12px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ai-hdr-sub{font-size:10px;color:var(--muted)}
.ai-close{width:26px;height:26px;border-radius:4px;border:1px solid var(--border);background:var(--card);font-size:14px;line-height:1;color:var(--muted);cursor:pointer;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:background .1s}
.ai-close:hover{background:var(--card2);color:var(--text)}
.ai-body{flex:1;overflow-y:auto;padding:12px 16px;display:flex;flex-direction:column;gap:8px}
.ai-msg{max-width:85%;padding:8px 12px;border-radius:6px;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.ai-msg.user{align-self:flex-end;background:var(--accent);color:#fff}
.ai-msg.assistant{align-self:flex-start;background:var(--card);color:var(--text);border:1px solid var(--border)}
.ai-msg.thinking{align-self:flex-start;background:transparent;color:var(--muted);font-style:italic;border:1px dashed var(--border)}
.ai-inv-btn.ai-ready{background:#166534!important;}
.ai-msg.fact{align-self:center;background:var(--card);border:1px solid var(--border);border-radius:6px;color:var(--sub);font-size:11px;font-style:italic;padding:7px 12px;max-width:90%;text-align:center}
.ai-msg.fact::before{content:"Did you know?  ";font-style:normal;font-weight:700;color:var(--accent)}
.ai-feedback{display:flex;align-items:center;gap:5px;align-self:flex-start;margin-top:-4px;margin-left:2px}
.ai-fb-btn{background:none;border:1px solid var(--border);border-radius:4px;padding:2px 6px;font-size:12px;cursor:pointer;line-height:1;color:var(--muted);transition:background .1s}
.ai-fb-btn:hover{background:var(--card)}
.ai-fb-btn.voted{border-color:var(--ok-bd);background:var(--ok-bg);color:var(--ok)}
.ai-fb-btn.voted-neg{border-color:var(--cr-bd);background:var(--cr-bg);color:var(--cr)}
.ai-fb-note{font-size:10px;color:var(--muted);margin-left:2px}
.fg-arrow{display:inline-block;animation:fg-arrow 0.9s ease-in-out infinite;color:var(--accent);font-style:normal;margin-right:3px;font-size:12px}
#fg-inline{width:100%;max-width:clamp(340px,52vw,600px);margin-top:14px;margin-right:4.5%;opacity:0;transform:translateY(10px);transition:opacity .4s,transform .4s;pointer-events:none;position:relative}
#fg-inline.show{opacity:1;transform:translateY(0);pointer-events:auto}
.fg-bubble{background:var(--surface);border:1px solid var(--accent);border-top:3px solid var(--accent);border-radius:6px;padding:14px 18px 12px;box-shadow:0 4px 20px rgba(218,41,28,.1);position:relative}
.fg-bubble-header{display:flex;align-items:center;gap:7px;margin-bottom:8px}
.fg-bubble-icon{width:24px;height:24px;border-radius:4px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:12px;flex-shrink:0}
.fg-bubble-label{font-size:9px;font-weight:700;letter-spacing:.1em;color:var(--accent);text-transform:uppercase}
.fg-bubble-src{font-size:9px;color:var(--muted);margin-left:auto}
.fg-bubble-fact{font-size:12px;font-weight:500;color:var(--text);line-height:1.65;padding-left:2px}
.ai-footer{padding:8px 12px;border-top:1px solid var(--border);display:flex;gap:7px;flex-shrink:0;background:var(--card)}
.ai-input{flex:1;padding:8px 10px;border:1px solid var(--border);border-radius:5px;font-size:12px;outline:none;color:var(--text);background:var(--surface);transition:border-color .1s}
.ai-input:focus{border-color:var(--accent)}
.ai-send{padding:8px 14px;background:var(--accent);color:#fff;border:none;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;white-space:nowrap;transition:background .1s}
.ai-send:hover{background:var(--accent-l)}
.ai-send:disabled{opacity:.45;cursor:not-allowed}
.ai-prompt-row{display:flex;gap:8px;width:100%}
.ai-prompt-btn{flex:1;padding:9px 6px;border:1px solid var(--border);border-radius:5px;background:var(--card);color:var(--sub);font-size:11px;font-weight:600;cursor:pointer;transition:background .1s,border-color .1s}
.ai-prompt-btn:hover{border-color:var(--accent);color:var(--accent)}
.ai-prompt-btn:disabled{opacity:.4;cursor:not-allowed}

/* ── Machine details panel ── */
.mach-overlay{position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:2000;display:flex;align-items:flex-end;justify-content:flex-end}
.mach-panel{background:var(--surface);border-left:1px solid var(--border);width:460px;max-width:100vw;height:100vh;display:flex;flex-direction:column;overflow:hidden}
.mach-hdr{padding:14px 16px 10px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;gap:8px;flex-shrink:0;background:var(--card)}
.mach-hdr-icon{width:32px;height:32px;border-radius:5px;background:var(--card2);display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;border:1px solid var(--border)}
.mach-title{font-size:12px;font-weight:700;color:var(--text);word-break:break-all}
.mach-sub{font-size:10px;color:var(--muted);margin-top:1px}
.mach-body{flex:1;overflow-y:auto;overflow-x:hidden;padding:12px 16px;display:flex;flex-direction:column;gap:10px;-webkit-overflow-scrolling:touch}
.mach-section{background:var(--card);border:1px solid var(--border);border-radius:5px;overflow:hidden}
.mach-section-title{font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:5px 10px;background:var(--card2);border-bottom:1px solid var(--border)}
.mach-row{display:flex;align-items:baseline;gap:8px;padding:4px 10px;border-bottom:1px solid var(--border)}
.mach-row:last-child{border-bottom:none}
.mach-key{font-size:10px;font-weight:600;color:var(--muted);min-width:110px;flex-shrink:0}
.mach-val{font-size:11px;color:var(--text);word-break:break-all;font-family:'SFMono-Regular',Consolas,monospace}
</style>
</head>
<body>


<div class="app-layout">

<!-- Sidebar -->
<div class="sidebar">
  <div class="sb-brand" style="flex-direction:column;align-items:flex-start;gap:3px;padding:14px 16px">
    <div style="display:flex;align-items:center;gap:0">
      <span style="font-size:20px;font-weight:500;color:#fff;letter-spacing:.04em;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;line-height:1">F</span>
      <svg viewBox="0 0 100 100" width="17" height="17" style="margin:0 1px;vertical-align:middle">
        <rect x="5"  y="5"  width="39" height="28" rx="9" fill="#c93428"/>
        <rect x="56" y="5"  width="39" height="28" rx="9" fill="#c93428"/>
        <rect x="5"  y="41" width="39" height="18" rx="5" fill="#c93428"/>
        <rect x="56" y="41" width="39" height="18" rx="5" fill="#c93428"/>
        <rect x="5"  y="67" width="39" height="28" rx="9" fill="#c93428"/>
        <rect x="56" y="67" width="39" height="28" rx="9" fill="#c93428"/>
      </svg>
      <span style="font-size:20px;font-weight:500;color:#fff;letter-spacing:.04em;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;line-height:1">RTINET</span>
    </div>
    <div style="font-size:9px;font-weight:600;color:#6b7280;letter-spacing:.08em;text-transform:uppercase;margin-left:1px">Rapid Cloud Assessment</div>
    <div style="font-size:8px;font-weight:500;color:#DA291C;letter-spacing:.06em;text-transform:uppercase;margin-left:1px">Powered by FortiCNAPP</div>
  </div>
  <div class="sb-sect">Dashboard</div>
  <div class="sb-item active" id="nav-overview" onclick="nav('overview')">
    <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
    CSPM Score
  </div>
  <div class="sb-item" id="nav-csp-scores" onclick="nav('csp-scores')">
    <svg viewBox="0 0 24 24"><path d="M21.21 15.89A9 9 0 1 1 8.11 2.79"/><path d="M22 12A10 10 0 0 0 12 2v10z"/></svg>
    CSPM Score per CSP
  </div>
  <div class="sb-item" id="nav-lab" onclick="nav('lab')">
    <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
    Exploit Simulation Layer
  </div>
  <div class="sb-sect">Threat Center</div>
  <div class="sb-item" id="nav-alerts" onclick="nav('alerts')">
    <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    High Fidelity Alerts
  </div>
  <div class="sb-sect">Risk Findings</div>
  <div class="sb-item" id="nav-risk" onclick="nav('risk')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r=".5" fill="currentColor"/></svg>
    Risk Findings Inventory
  </div>
  <div class="sb-item" id="nav-attack-paths" onclick="nav('attack-paths')">
    <svg viewBox="0 0 24 24"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M8.5 8.5l7 7"/><path d="M18 6l-6 6"/></svg>
    Attack Paths
  </div>
  <div class="sb-item" id="nav-identities" onclick="nav('identities')">
    <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
    Identities
  </div>
  <div class="sb-item" id="nav-secrets-all" onclick="nav('secrets-all')">
    <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    Secrets
  </div>
  <div class="sb-item" id="nav-compliance" onclick="nav('compliance')">
    <svg viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
    Critical Misconfigurations
  </div>
  <div class="sb-item" id="nav-exposed-assets" onclick="nav('exposed-assets')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
    Internet Accessible Ressources
  </div>
  <div class="sb-item" id="nav-iehb" onclick="nav('iehb')">
    <svg viewBox="0 0 24 24"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M12 8v4"/><circle cx="12" cy="15" r=".5" fill="currentColor"/></svg>
    Internet Exposed Host
  </div>
  <div class="sb-item" id="nav-vulns" onclick="nav('vulns')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    Private Host Most Exposed
  </div>
  <div class="sb-item" id="nav-storage" onclick="nav('storage')">
    <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
    Public Storage Exposure
  </div>
  <div class="sb-item" id="nav-fortigate" onclick="nav('fortigate')">
    <svg viewBox="0 0 24 24"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/><path d="M9 12l2 2 4-4"/></svg>
    FortiGate
  </div>
  <div class="sb-sect">Operational Guidance</div>
  <div class="sb-item" id="nav-admin-settings" onclick="nav('admin-settings')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    Admin Settings
  </div>
  <!-- Generate Report button (was "Generate Report 2 Beta" — now the only report button) -->
  <div style="padding:0 0 6px">
    <a id="rpt2-btn-link" href="/report2" target="_blank" class="rpt-btn" style="display:flex;text-decoration:none">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      Generate Cloud Security Report
    </a>
  </div>
  <!-- Sidebar meta -->
  <div style="padding:12px 14px;border-top:1px solid #1f2937;margin-top:auto">
    <span id="kpi-a" style="display:none"></span><span id="kpi-v" style="display:none"></span><span id="kpi-i" style="display:none"></span><span id="kpi-c" style="display:none"></span>
    <div style="font-size:10px;color:#6b7280;line-height:1.8;text-align:center;margin-bottom:8px">
      <div><b id="acct-lbl" style="color:#9ca3af">Customer Name</b></div>
      <div>Last refresh: <b id="fetched-at" style="color:#9ca3af">—</b></div>
      <div style="display:flex;align-items:center;justify-content:center;gap:5px"><div class="live-dot" id="live-dot"></div><span id="countdown">Initializing…</span></div>
    </div>

  </div>
</div>

<!-- Main content -->
<div class="main">

<div class="top-bar" id="top-bar" style="display:none">
  <div class="tb-user">
    <div>
      <div class="tb-name" id="tb-name">—</div>
      <div class="tb-role-lbl" id="tb-role">—</div>
    </div>
    <div class="tb-avatar" id="tb-avatar">?</div>
    <span class="tb-badge" id="tb-admin-badge" style="display:none">Admin</span>
  </div>
  <button onclick="logout()" style="margin-left:8px;padding:5px 12px;font-size:11px;font-weight:600;color:#64748b;background:transparent;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;letter-spacing:.03em" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">Sign out</button>
</div>

<div class="err-notice" id="err-bar"></div>

<!-- ═══ View: Dashboard ═══ -->
<div class="view active" id="view-overview">
  <div style="display:flex;flex-direction:column;align-items:center;justify-content:flex-start;padding:20px 24px 16px;gap:0">

    <!-- Title -->
    <div style="font-size:16px;font-weight:800;letter-spacing:.2em;text-transform:uppercase;color:#DA291C;margin-bottom:12px">Cloud Security Risk Score</div>
    <div style="font-size:9.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#64748b;text-align:center;max-width:560px;margin-bottom:10px;line-height:1.5"><span style="color:#15803d;font-weight:800">Accelerating Risk Reduction</span> while strengthening cloud security posture, improving configuration hygiene &amp; enhancing runtime threat detection</div>

    <!-- Centering wrapper: responsive — fills available space up to a comfortable max -->
    <div style="width:100%;max-width:clamp(480px,58vw,740px);display:flex;flex-direction:column;align-items:center">
    <!-- Band boundaries at score 30/60/80 (Foundational/Managed/Advanced/Optimized) -->
    <svg id="gauge-svg" viewBox="-118 -46 636 364" style="display:block;width:100%;overflow:visible">
      <defs>
        <linearGradient id="band-grad" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">
          <stop offset="0%"     stop-color="#ef4444"/>
          <stop offset="20.6%"  stop-color="#ef4444"/>
          <stop offset="20.6%"  stop-color="#f59e0b"/>
          <stop offset="65.45%" stop-color="#f59e0b"/>
          <stop offset="65.45%" stop-color="#22c55e"/>
          <stop offset="90.45%" stop-color="#22c55e"/>
          <stop offset="90.45%" stop-color="#3b82f6"/>
          <stop offset="100%"   stop-color="#3b82f6"/>
        </linearGradient>
        <filter id="gauge-glow"><feDropShadow dx="0" dy="2" stdDeviation="6" flood-color="rgba(0,0,0,.12)"/></filter>
        <filter id="bub-glow"><feDropShadow dx="0" dy="2" stdDeviation="5" flood-color="rgba(0,0,0,.15)"/></filter>
        <path id="lp" d="M 2,205 A 198,198 0 0,1 398,205"/>
      </defs>

      <!-- Outer shadow ring -->
      <path fill="none" stroke="#f0f4f8" stroke-width="42" stroke-linecap="round"
            d="M 25,205 A 175,175 0 0,1 375,205"/>
      <!-- Grey background track -->
      <path fill="none" stroke="#e2e8f0" stroke-width="32" stroke-linecap="round"
            d="M 25,205 A 175,175 0 0,1 375,205"/>
      <!-- Coloured fill arc -->
      <path id="gauge-arc" fill="none" stroke="url(#band-grad)" stroke-width="32" stroke-linecap="round"
            stroke-dasharray="0 550" d="M 25,205 A 175,175 0 0,1 375,205"
            filter="url(#gauge-glow)" style="transition:stroke-dasharray 1.2s cubic-bezier(.22,1,.36,1)"/>
      <!-- Band divider ticks at score 30 / 60 / 80 -->
      <line x1="86" y1="48" x2="108" y2="79"   stroke="white" stroke-width="3.5" stroke-linecap="round"/>
      <line x1="260" y1="20" x2="248" y2="57"  stroke="white" stroke-width="3.5" stroke-linecap="round"/>
      <line x1="357" y1="91" x2="326" y2="113" stroke="white" stroke-width="3.5" stroke-linecap="round"/>
      <!-- Band labels removed — legend row below carries the labels -->
      <!-- Score number -->
      <text id="gauge-score" x="200" y="172" text-anchor="middle" font-size="58" font-weight="900"
            letter-spacing="-3" font-family="-apple-system,BlinkMacSystemFont,sans-serif" fill="#94a3b8">—</text>

      <!-- Objective tagline — anchored at x=200 (gauge arc center) -->
      <text x="200" y="238" text-anchor="middle" font-size="9.5" font-weight="600"
            letter-spacing=".08em" font-family="-apple-system,BlinkMacSystemFont,sans-serif"
            fill="#64748b" text-transform="uppercase">
        <tspan>THE HIGHER THE SCORE, THE MORE MATURE YOUR CLOUD SECURITY POSTURE</tspan>
      </text>

      <!-- ── Maturity legend — primary label only (no negative wording); hovering a chip
           reveals the executive interpretation via its native <title> tooltip. Replaces the
           old per-band callout bubbles with hand-tuned tail-triangle geometry, which doesn't
           scale cleanly to a 4th band. The active band (matching the current score) is
           highlighted; the others stay dimmed. ── -->
      <g id="gauge-legend" font-family="-apple-system,BlinkMacSystemFont,sans-serif">
        <g id="bubble-foundational" opacity="0.35" style="transition:opacity .4s,filter .4s">
          <title>Foundational (0–30) — Security controls are immature; significant exposure and remediation priorities exist</title>
          <rect x="-58" y="252" width="120" height="32" rx="16" fill="#fef2f2" stroke="#ef4444" stroke-width="1.3"/>
          <circle cx="-40" cy="268" r="5.5" fill="#ef4444"/>
          <text x="-28" y="272" font-size="11" font-weight="800" fill="#b91c1c" font-family="-apple-system,sans-serif">Foundational</text>
        </g>
        <g id="bubble-managed" opacity="0.35" style="transition:opacity .4s,filter .4s">
          <title>Managed (31–60) — Core controls are established, but security gaps and optimization opportunities remain</title>
          <rect x="74" y="252" width="120" height="32" rx="16" fill="#fffbeb" stroke="#f59e0b" stroke-width="1.3"/>
          <circle cx="92" cy="268" r="5.5" fill="#f59e0b"/>
          <text x="104" y="272" font-size="11" font-weight="800" fill="#b45309" font-family="-apple-system,sans-serif">Managed</text>
        </g>
        <g id="bubble-advanced" opacity="0.35" style="transition:opacity .4s,filter .4s">
          <title>Advanced (61–80) — Security posture is strong with effective controls and manageable residual risk</title>
          <rect x="206" y="252" width="120" height="32" rx="16" fill="#f0fdf4" stroke="#22c55e" stroke-width="1.3"/>
          <circle cx="224" cy="268" r="5.5" fill="#22c55e"/>
          <text x="236" y="272" font-size="11" font-weight="800" fill="#15803d" font-family="-apple-system,sans-serif">Advanced</text>
        </g>
        <g id="bubble-optimized" opacity="0.35" style="transition:opacity .4s,filter .4s">
          <title>Optimized (81–100) — Mature cloud security posture with proactive risk management and continuous improvement</title>
          <rect x="338" y="252" width="120" height="32" rx="16" fill="#eff6ff" stroke="#3b82f6" stroke-width="1.3"/>
          <circle cx="356" cy="268" r="5.5" fill="#3b82f6"/>
          <text x="368" y="272" font-size="11" font-weight="800" fill="#1d4ed8" font-family="-apple-system,sans-serif">Optimized</text>
        </g>
      </g>
    </svg>

    </div><!-- /gauge-wrapper -->

    <!-- Fact bubble -->
    <div id="fg-inline">
      <div class="fg-bubble">
        <div class="fg-bubble-header">
          <div class="fg-bubble-icon">☁️</div>
          <span class="fg-bubble-label">Fortinet Cloud Security Report 2026</span>
          <span class="fg-bubble-src" id="fg-inline-src">fortinet.com</span>
        </div>
        <div class="fg-bubble-fact" id="fg-inline-fact"></div>
      </div>
    </div>

    <!-- hidden ov-* elements so JS updates don't error -->
    <span id="ov-a" style="display:none"></span>
    <span id="ov-v" style="display:none"></span>
    <span id="ov-i" style="display:none"></span>
    <span id="ov-c" style="display:none"></span>

  </div>
  <div class="footer">Fortinet Rapid Cloud Assessment Powered by FortiCNAPP &nbsp;·&nbsp; Auto-refresh every <span id="footer-interval">—</span> &nbsp;·&nbsp; <span id="countdown">—</span> &nbsp;·&nbsp; <span id="footer-time"></span></div>
</div><!-- /view-overview -->

<!-- ═══ View: CSPM Score per CSP ═══ -->
<div class="view" id="view-csp-scores">
  <div style="display:flex;flex-direction:column;align-items:center;justify-content:flex-start;padding:28px 24px 24px;gap:0">
    <div style="font-size:16px;font-weight:800;letter-spacing:.2em;text-transform:uppercase;color:#DA291C;margin-bottom:4px">Cloud Security Posture — per Cloud Provider</div>
    <div style="font-size:10px;color:#94a3b8;letter-spacing:.06em;text-transform:uppercase;margin-bottom:32px">Individual CSPM scores for AWS · Azure · GCP</div>
    <div style="display:flex;justify-content:center;gap:40px;width:100%;flex-wrap:wrap">

      <!-- AWS -->
      <div style="display:flex;flex-direction:column;align-items:center;gap:4px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:18px 20px 14px;box-shadow:0 1px 4px rgba(0,0,0,.06)">
        <!-- Org + Sub Account above gauge -->
        <div style="display:flex;flex-direction:column;align-items:center;gap:2px;margin-bottom:6px;width:100%">
          <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8">FortiCNAPP Tenant</div>
          <div id="csp-org-aws" style="font-size:13px;font-weight:800;color:#0f172a;letter-spacing:.01em">—</div>
          <div style="font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-top:4px">FortiCNAPP Account</div>
          <div id="csp-sub-aws" style="font-size:11px;font-weight:600;color:#475569;font-family:ui-monospace,monospace;word-break:break-all;text-align:center">—</div>
        </div>
        <span id="csp-label-aws" style="display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:900;letter-spacing:.1em;padding:5px 14px;border-radius:6px;color:#232F3E;background:#FF9900">
          <svg viewBox="0 0 80 48" height="18" xmlns="http://www.w3.org/2000/svg"><path fill="#FF9900" d="M22.5 29.4c-5.4 2.8-8.3 1-9.9 0-.3-.2-.4 0-.3.3.6 1.7 2.5 4.4 6.1 4.4 3.6 0 6.6-2.3 7.1-2.7.5-.4.1-.6-.3-.4-1.4.6-2.5.7-2.7.4zm3.2-1.3c-.2-.2-1.2-.3-2.1-.1-.9.2-2.3.8-2.2 1.1 0 .1.1.1.4 0l.9-.2c1.1-.2 2.4-.1 2.8.4.3.4-.1 1.3-.2 1.5-.1.2 0 .3.2.1 1.4-1.3 1.4-2.5.2-2.8z"/><path fill="#FF9900" d="M34.4 21.1c0-.5 0-1-.1-1.4-.4-2.2-1.6-3.2-3.4-3.2-1.2 0-2.3.5-2.9 1.7-.3.5-.4 1.1-.4 1.8 0 1.9.9 3 2.3 3.4.5.1 1 .2 1.6.2.7 0 1.4-.1 2.1-.4.5-.2.8-.6.8-.9v-1.2zm-3.2 1.5c-.8 0-1.4-.5-1.6-1.3-.1-.3-.1-.6-.1-.9 0-.5.1-.9.3-1.2.3-.5.7-.7 1.3-.7.9 0 1.5.6 1.7 1.7.1.3.1.6.1.9 0 .3 0 .5-.1.7-.2.5-.8.8-1.6.8zM41 23.2c-1 0-1.9-.3-2.6-.6l-.3-.1v-.5c0-.2.1-.2.2-.2h.2c.7.3 1.5.6 2.3.6.9 0 1.4-.4 1.4-.9 0-.4-.3-.7-.9-.9l-1.3-.4c-.8-.3-1.5-.9-1.5-2 0-1.1.9-2 2.4-2 .8 0 1.6.2 2.1.5l.3.2v.5c0 .2-.1.2-.2.2-.1 0-.1 0-.2-.1-.5-.2-1.1-.4-1.8-.4-.8 0-1.2.3-1.2.8 0 .3.2.6.8.8l1.3.4c1 .3 1.7.9 1.7 2 0 1.2-1 2.1-2.7 2.1zm6.2-.1h-.8c-.1 0-.2 0-.2-.1L43.8 17h.8c.1 0 .2.1.2.2l1 3.8.2.8.2-.8 1.1-3.8c0-.1.1-.2.2-.2h.6c.1 0 .2.1.2.2l1.1 3.8.2.8.2-.8 1-3.8c0-.1.1-.2.2-.2h.8l-1.6 6-.1.1h-.8c-.1 0-.2-.1-.2-.2l-1.1-3.9-.2-.9-.2.9-1.1 3.9c0 .1-.1.2-.3.2zm8.5 0h-1.1c-.1 0-.2-.1-.2-.2V17h1.1c.1 0 .2.1.2.2v6z"/></svg>
          AWS
        </span>
        <svg viewBox="-25 -20 300 155" style="width:clamp(200px,28vw,340px);overflow:visible">
          <path fill="none" stroke="#f0f4f8" stroke-width="18" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>
          <path fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>
          <path id="csp-arc-aws" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"
                stroke-dasharray="0 314" d="M 25,120 A 100,100 0 0,1 225,120"
                style="transition:stroke-dasharray 1.2s cubic-bezier(.22,1,.36,1)"/>
          <text id="csp-score-aws" x="125" y="100" text-anchor="middle" font-size="38" font-weight="900"
                font-family="-apple-system,BlinkMacSystemFont,sans-serif" fill="#94a3b8">—</text>
          <text id="csp-band-aws" x="125" y="117" text-anchor="middle" font-size="10" font-weight="700"
                font-family="-apple-system,sans-serif" fill="#94a3b8" letter-spacing=".05em"></text>
          <text x="25"  y="135" text-anchor="middle" font-size="11" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">0</text>
          <text x="225" y="135" text-anchor="middle" font-size="11" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">100</text>
        </svg>
      </div>

      <!-- Azure -->
      <div style="display:flex;flex-direction:column;align-items:center;gap:4px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:18px 20px 14px;box-shadow:0 1px 4px rgba(0,0,0,.06)">
        <!-- Org + Sub Account above gauge -->
        <div style="display:flex;flex-direction:column;align-items:center;gap:2px;margin-bottom:6px;width:100%">
          <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8">FortiCNAPP Tenant</div>
          <div id="csp-org-azure" style="font-size:13px;font-weight:800;color:#0f172a;letter-spacing:.01em">—</div>
          <div style="font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-top:4px">FortiCNAPP Account</div>
          <div id="csp-sub-azure" style="font-size:11px;font-weight:600;color:#475569;font-family:ui-monospace,monospace;word-break:break-all;text-align:center">—</div>
        </div>
        <span id="csp-label-azure" style="display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:900;letter-spacing:.1em;padding:5px 14px;border-radius:6px;color:#fff;background:#0078D4">
          <svg viewBox="0 0 59 48" height="18" xmlns="http://www.w3.org/2000/svg"><path fill="#fff" d="M33.3 3.6L18.6 40.8H6.3L17.7 20l-6.8-3.9L33.3 3.6zM35.2 5.1l14.5 35.7H37.4L31.6 26l-5.6-10.9 9.2-10zM0 44h59v2H0z"/></svg>
          Azure
        </span>
        <svg viewBox="-25 -20 300 155" style="width:clamp(200px,28vw,340px);overflow:visible">
          <path fill="none" stroke="#f0f4f8" stroke-width="18" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>
          <path fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>
          <path id="csp-arc-azure" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"
                stroke-dasharray="0 314" d="M 25,120 A 100,100 0 0,1 225,120"
                style="transition:stroke-dasharray 1.2s cubic-bezier(.22,1,.36,1)"/>
          <text id="csp-score-azure" x="125" y="100" text-anchor="middle" font-size="38" font-weight="900"
                font-family="-apple-system,BlinkMacSystemFont,sans-serif" fill="#94a3b8">—</text>
          <text id="csp-band-azure" x="125" y="117" text-anchor="middle" font-size="10" font-weight="700"
                font-family="-apple-system,sans-serif" fill="#94a3b8" letter-spacing=".05em"></text>
          <text x="25"  y="135" text-anchor="middle" font-size="11" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">0</text>
          <text x="225" y="135" text-anchor="middle" font-size="11" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">100</text>
        </svg>
      </div>

      <!-- GCP -->
      <div style="display:flex;flex-direction:column;align-items:center;gap:4px;background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:18px 20px 14px;box-shadow:0 1px 4px rgba(0,0,0,.06)">
        <!-- Org + Sub Account above gauge -->
        <div style="display:flex;flex-direction:column;align-items:center;gap:2px;margin-bottom:6px;width:100%">
          <div style="font-size:10px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#94a3b8">FortiCNAPP Tenant</div>
          <div id="csp-org-gcp" style="font-size:13px;font-weight:800;color:#0f172a;letter-spacing:.01em">—</div>
          <div style="font-size:10px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-top:4px">FortiCNAPP Account</div>
          <div id="csp-sub-gcp" style="font-size:11px;font-weight:600;color:#475569;font-family:ui-monospace,monospace;word-break:break-all;text-align:center">—</div>
        </div>
        <span id="csp-label-gcp" style="display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:900;letter-spacing:.1em;padding:5px 14px;border-radius:6px;color:#fff;background:#4285F4">
          <svg viewBox="0 0 48 48" height="18" xmlns="http://www.w3.org/2000/svg"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.3 9 3.4l6.7-6.7C35.7 2.4 30.2 0 24 0 14.7 0 6.7 5.4 2.9 13.3l7.8 6C12.5 13.4 17.8 9.5 24 9.5z"/><path fill="#4285F4" d="M46.9 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h12.9c-.6 3-2.3 5.5-4.8 7.2l7.5 5.8c4.4-4 7.3-10 7.3-17z"/><path fill="#FBBC05" d="M10.7 28.7A14.6 14.6 0 0 1 9.5 24c0-1.6.3-3.2.8-4.7l-7.8-6A24 24 0 0 0 0 24c0 3.9.9 7.5 2.5 10.7l8.2-6z"/><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.5-5.8c-2 1.4-4.6 2.3-7.7 2.3-6.2 0-11.5-4.2-13.4-9.8l-8.2 6C6.7 42.6 14.7 48 24 48z"/></svg>
          GCP
        </span>
        <svg viewBox="-25 -20 300 155" style="width:clamp(200px,28vw,340px);overflow:visible">
          <path fill="none" stroke="#f0f4f8" stroke-width="18" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>
          <path fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>
          <path id="csp-arc-gcp" fill="none" stroke="#e2e8f0" stroke-width="14" stroke-linecap="round"
                stroke-dasharray="0 314" d="M 25,120 A 100,100 0 0,1 225,120"
                style="transition:stroke-dasharray 1.2s cubic-bezier(.22,1,.36,1)"/>
          <text id="csp-score-gcp" x="125" y="100" text-anchor="middle" font-size="38" font-weight="900"
                font-family="-apple-system,BlinkMacSystemFont,sans-serif" fill="#94a3b8">—</text>
          <text id="csp-band-gcp" x="125" y="117" text-anchor="middle" font-size="10" font-weight="700"
                font-family="-apple-system,sans-serif" fill="#94a3b8" letter-spacing=".05em"></text>
          <text x="25"  y="135" text-anchor="middle" font-size="11" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">0</text>
          <text x="225" y="135" text-anchor="middle" font-size="11" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">100</text>
        </svg>
      </div>

    </div>
  </div>
  <div class="footer">Fortinet Rapid Cloud Assessment Powered by FortiCNAPP &nbsp;·&nbsp; Auto-refresh every <span class="footer-interval-ref">—</span> &nbsp;·&nbsp; <span id="footer-time-csp"></span></div>
</div><!-- /view-csp-scores -->

<!-- ═══ View: Critical Alerts ═══ -->
<div class="view" id="view-alerts">
  <div class="view-hdr vha-red">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">High Fidelity Alerts</div>
      <div class="vh-sub" id="sub-alerts">Active threats &amp; policy violations · last ${ALERT_DAYS_BACK} days</div>
    </div>
    <span class="vh-badge" id="cnt-a">—</span>
  </div>
  <div id="body-a"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Vulnerabilities ═══ -->
<div class="view" id="view-vulns">
  <div class="view-hdr vha-orange">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Private Host Most Exposed</div>
      <div class="vh-sub">Private hosts · CVE risk ≥ 9 · Unpatched · Correlated Secrets, Identities &amp; Misconfigs &nbsp;<a class="agent-tip" href="https://docs.fortinet.com/document/forticnapp/latest/administration-guide/903770/agent-based-workload-security" target="_blank" style="text-decoration:none" title="Enable the FortiCNAPP agent for deeper in-memory &amp; runtime vulnerability detection">Agent available ↗</a></div>
    </div>
    <span class="vh-badge" id="cnt-v">—</span>
  </div>
  <div id="body-v"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Compliance ═══ -->
<div class="view" id="view-compliance">
  <div class="view-hdr vha-amber">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Critical Misconfigurations</div>
      <div class="vh-sub">NonCompliant · Critical severity · sorted by violations</div>
    </div>
    <span class="vh-badge" id="cnt-c">—</span>
  </div>
  <div id="body-c"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Identities ═══ -->
<div class="view" id="view-identities">
  <div class="view-hdr vha-purple">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Identity &amp; Access Risk</div>
      <div class="vh-sub">High-permissive identities · no-MFA admins · role assignments</div>
    </div>
    <span class="vh-badge" id="cnt-i">—</span>
  </div>
  <div class="lab-tabs-bar">
    <button class="lab-tab active" id="itab-aws" onclick="switchIdentTab('aws')">AWS</button>
    <button class="lab-tab" id="itab-azure" onclick="switchIdentTab('azure')">Azure</button>
    <button class="lab-tab" id="itab-gcp" onclick="switchIdentTab('gcp')">GCP</button>
  </div>
  <div id="ibody-aws" style="padding:0 20px"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
  <div id="ibody-azure" style="display:none;padding:0 20px"></div>
  <div id="ibody-gcp" style="display:none;padding:0 20px"></div>
  <!-- keep legacy id so existing KPI wiring still works -->
  <div id="body-i" style="display:none"></div>
</div>

<!-- ═══ View: Secrets ═══ -->
<div class="view" id="view-secrets-all">
  <div class="view-hdr vha-purple">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Secrets Found</div>
      <div class="vh-sub">All secrets &amp; credentials detected on hosts</div>
    </div>
    <span class="vh-badge" id="cnt-sa">—</span>
  </div>
  <div id="body-sa"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Public Storage Exposure ═══ -->
<div class="view" id="view-storage">
  <div class="view-hdr vha-orange">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Public Storage Exposure</div>
      <div class="vh-sub">S3 / Blob / Cloud Storage with public access, across AWS, Azure &amp; GCP</div>
    </div>
    <span class="vh-badge" id="cnt-storage">—</span>
  </div>
  <div id="body-storage"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: FortiGate ═══ -->
<div class="view" id="view-fortigate">
  <div class="view-hdr vha-orange">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">FortiGateVM</div>
      <div class="vh-sub">Fortinet appliance presence across the cloud environment — product mix (name/tag match) &amp; verified internet-exposed Fortinet appliances (Attack Path Analysis)</div>
    </div>
    <span class="vh-badge" id="cnt-fortigate">—</span>
  </div>
  <div id="fortigate-tiles" style="display:flex;gap:12px;flex-wrap:wrap;padding:16px 20px 4px"></div>
  <div id="body-fortigate-inventory" style="padding:0 20px"></div>
  <div style="padding:8px 20px 4px;font-size:11px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em">Verified Internet-Exposed Fortinet Appliances (Attack Path Analysis)</div>
  <div id="body-fortigate"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Internet Accessible Ressources ═══ -->
<div class="view" id="view-exposed-assets">
  <div class="view-hdr vha-orange">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Internet Accessible Ressources</div>
      <div class="vh-sub">Every asset with a verified Internet&rarr;Target path (FortiCNAPP Attack Path Analysis) — all types, comprehensive superset of Host/Storage exposure</div>
    </div>
    <span class="vh-badge" id="cnt-exposed-assets">—</span>
  </div>
  <div id="exposed-assets-tiles" style="display:flex;gap:12px;flex-wrap:wrap;padding:16px 20px 4px"></div>
  <div id="body-exposed-assets"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Internet Exposed Host ═══ -->
<div class="view" id="view-iehb">
  <div class="view-hdr vha-orange">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Internet Exposed Host</div>
      <div class="vh-sub">Matches the FortiCNAPP console's own Hosts query: Host Risk Score &ge; 7 &middot; Internet exposed = True &middot; Machine status Online/Launched &middot; has a Vulnerable-status observation &middot; enriched with Critical misconfigurations, secrets, and high-permission attached IAM roles (AWS only)</div>
    </div>
    <span class="vh-badge" id="cnt-iehb">—</span>
  </div>
  <div style="padding:10px 20px 0;font-size:10.5px;color:#94a3b8">Filter: Machine status Launched/Online &middot; Vulnerability status Active &middot; Internet Exposed = True (FortiCNAPP's own raw tag — not this app's stricter verified SG/NSG/FW-rule signal used elsewhere) &middot; Host Risk Score &ge; 7. This is a beta comparison view — not wired into the posture score or other panels.</div>
  <div id="body-iehb"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Attack Paths ═══ -->
<div class="view" id="view-attack-paths">
  <div class="view-hdr vha-orange">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Attack Paths</div>
      <div class="vh-sub">FortiCNAPP Attack Path Analysis — computed multi-hop attack paths, risk score 80+</div>
    </div>
    <span class="vh-badge" id="cnt-attack-paths">—</span>
  </div>
  <div id="attack-paths-tiles" style="display:flex;gap:12px;flex-wrap:wrap;padding:16px 20px 4px"></div>
  <div id="body-attack-paths"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Asset Risk ═══ -->
<div class="view" id="view-asset-risk">
  <div class="view-hdr">
    <div class="vh-text">
      <div class="vh-title">Correlated Risk per Asset</div>
      <div class="vh-sub">Hosts ranked by combined CVE · Secrets · CIEM · Misconfig risk score</div>
    </div>
    <span class="vh-badge" id="cnt-ar">—</span>
  </div>
  <div id="body-ar"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- Per-Host Attack Path modal -->
<div id="host-graph-overlay" style="display:none;position:fixed;inset:0;z-index:3100;background:rgba(0,0,0,.6);align-items:flex-start;justify-content:center;overflow-y:auto;padding:40px 16px">
  <div style="background:#fff;border-radius:14px;width:min(920px,96vw);box-shadow:0 24px 60px rgba(0,0,0,.35);overflow:hidden;margin:auto">
    <div id="host-graph-hdr" style="background:linear-gradient(135deg,#7f1d1d,#b91c1c);padding:16px 22px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:14px;font-weight:800;color:#fff;letter-spacing:.04em" id="host-graph-title">Attack Path</div>
        <div style="font-size:11px;color:#fca5a5;margin-top:2px">Exploit Simulation · Internet-Exposed Host</div>
      </div>
      <button onclick="closeHostGraph()" style="background:rgba(255,255,255,.15);border:none;border-radius:8px;color:#fff;font-size:18px;width:32px;height:32px;cursor:pointer;line-height:1">&#x2715;</button>
    </div>
    <div id="host-graph-body" style="padding:0"></div>
  </div>
</div>

<!-- Generate Report — Cloud Account + Compliance Framework prompt -->
<div id="rptgen-overlay" style="display:none;position:fixed;inset:0;z-index:3200;background:rgba(0,0,0,.55);align-items:center;justify-content:center">
  <div style="background:#fff;border-radius:14px;width:min(460px,96vw);box-shadow:0 24px 60px rgba(0,0,0,.3);overflow:hidden">
    <div style="background:linear-gradient(135deg,#0f172a,#334155);padding:18px 22px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:15px;font-weight:800;color:#fff">Generate Report</div>
        <div style="font-size:11px;color:#cbd5e1;margin-top:2px">Scope the Compliance section to one cloud account &amp; framework</div>
      </div>
      <button onclick="closeReportGenModal()" style="background:rgba(255,255,255,.15);border:none;border-radius:8px;color:#fff;font-size:18px;width:32px;height:32px;cursor:pointer;line-height:1">&#x2715;</button>
    </div>
    <div style="padding:20px 22px;display:flex;flex-direction:column;gap:12px">
      <div style="display:flex;flex-direction:column;gap:3px">
        <span style="font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#64748b">1. Cloud Account</span>
        <select id="rptgen-account-select" style="padding:8px 10px;border:1px solid #cbd5e1;border-radius:6px;font-size:12.5px;font-weight:600;color:#0f172a;background:#fff;cursor:pointer;outline:none" onchange="rptGenAccountChanged()" onmousedown="loadGovernanceTargets()">
          <option value="">Loading cloud accounts…</option>
        </select>
      </div>
      <div style="display:flex;flex-direction:column;gap:3px">
        <span style="font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#64748b">2. Compliance Framework (CIS / HIPAA / NIST / SOC 2 / PCI…)</span>
        <select id="rptgen-framework-select" style="padding:8px 10px;border:1px solid #cbd5e1;border-radius:6px;font-size:12.5px;font-weight:600;color:#0f172a;background:#fff;cursor:pointer;outline:none">
          <option value="">Select account first…</option>
        </select>
      </div>
      <div id="rptgen-status" style="font-size:11px;color:#b91c1c;min-height:14px"></div>
      <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:4px">
        <a id="rptgen-skip" href="/report" target="_blank" onclick="closeReportGenModal()" style="font-size:11px;color:#94a3b8;text-decoration:none;align-self:center;margin-right:auto">Skip — use default compliance scan</a>
        <button id="rptgen-go-btn" onclick="runReportGenModal()" disabled style="padding:8px 18px;border:none;border-radius:6px;font-size:12px;font-weight:700;color:#fff;background:#0f172a;cursor:pointer;opacity:.5">Generate Report</button>
      </div>
    </div>
  </div>
</div>

<!-- GeoIP detail panel -->
<div id="geo-overlay" style="display:none;position:fixed;inset:0;z-index:3000;background:rgba(0,0,0,.55);align-items:center;justify-content:center">
  <div style="background:#fff;border-radius:14px;width:min(480px,96vw);box-shadow:0 24px 60px rgba(0,0,0,.3);overflow:hidden">
    <div style="background:linear-gradient(135deg,#0369a1,#0ea5e9);padding:18px 22px;display:flex;align-items:center;justify-content:space-between">
      <div>
        <div style="font-size:15px;font-weight:800;color:#fff" id="geo-title">GeoIP Lookup</div>
        <div style="font-size:11px;color:#bae6fd;margin-top:2px" id="geo-sub">Powered by ipinfo.io</div>
      </div>
      <button onclick="closeGeoPanel()" style="background:rgba(255,255,255,.15);border:none;border-radius:8px;color:#fff;font-size:18px;width:32px;height:32px;cursor:pointer;line-height:1">✕</button>
    </div>
    <div id="geo-body" style="padding:20px 22px;font-size:13px;min-height:80px"></div>
  </div>
</div>

<!-- ═══ View: Risk Findings ═══ -->
<div class="view" id="view-risk">
  <div style="text-align:center;padding:18px 24px 14px;background:var(--surface);border-bottom:1px solid var(--border)">
    <div style="font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:12px">Critical Risk Findings</div>
    <svg viewBox="0 0 160 160" width="160" height="160" style="display:block;margin:0 auto;overflow:visible">
      <circle cx="80" cy="80" r="58" fill="none" stroke="var(--border)" stroke-width="16"/>
      <g transform="rotate(-90,80,80)" opacity=".9">
        <circle id="rf-pseg-a" cx="80" cy="80" r="58" fill="none" stroke="#ef4444" stroke-width="16" stroke-linecap="butt" stroke-dasharray="0 364.4" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-v" cx="80" cy="80" r="58" fill="none" stroke="#f97316" stroke-width="16" stroke-linecap="butt" stroke-dasharray="0 364.4" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-i" cx="80" cy="80" r="58" fill="none" stroke="#8b5cf6" stroke-width="16" stroke-linecap="butt" stroke-dasharray="0 364.4" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-c" cx="80" cy="80" r="58" fill="none" stroke="#f59e0b" stroke-width="16" stroke-linecap="butt" stroke-dasharray="0 364.4" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-s" cx="80" cy="80" r="58" fill="none" stroke="#0ea5e9" stroke-width="16" stroke-linecap="butt" stroke-dasharray="0 364.4" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
      </g>
      <text id="rf-pie-total" x="80" y="75" text-anchor="middle" dominant-baseline="middle" fill="var(--text)" font-size="28" font-weight="800" font-family="inherit" letter-spacing="-1">—</text>
      <text x="80" y="93" text-anchor="middle" fill="var(--muted)" font-size="7" font-weight="700" letter-spacing=".1em">CRITICAL RISK</text>
      <text x="80" y="103" text-anchor="middle" fill="var(--muted)" font-size="7" font-weight="700" letter-spacing=".1em">FINDINGS</text>
    </svg>
    <div style="display:flex;gap:16px;justify-content:center;margin-top:12px;flex-wrap:wrap;font-size:10.5px">
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('alerts')"><div style="width:8px;height:8px;border-radius:50%;background:#ef4444"></div><span style="color:var(--muted)">Alerts</span><b id="rf-n-a" style="margin-left:2px;color:var(--sub);font-weight:600">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('vulns')"><div style="width:8px;height:8px;border-radius:50%;background:#f97316"></div><span style="color:var(--muted)">Exposure</span><b id="rf-n-v" style="margin-left:2px;color:var(--sub);font-weight:600">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('identities')"><div style="width:8px;height:8px;border-radius:50%;background:#8b5cf6"></div><span style="color:var(--muted)">Identities</span><b id="rf-n-i" style="margin-left:2px;color:var(--sub);font-weight:600">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('compliance')"><div style="width:8px;height:8px;border-radius:50%;background:#f59e0b"></div><span style="color:var(--muted)">Misconfigurations</span><b id="rf-n-c" style="margin-left:2px;color:var(--sub);font-weight:600">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('secrets-all')"><div style="width:8px;height:8px;border-radius:50%;background:#0ea5e9"></div><span style="color:var(--muted)">Secrets</span><b id="rf-n-s" style="margin-left:2px;color:var(--sub);font-weight:600">—</b></div>
    </div>
  </div>
  <!-- hidden KPI value holders still updated by JS for internal use -->
  <span id="rf-k-a" style="display:none"></span><span id="rf-k-v" style="display:none"></span><span id="rf-k-c" style="display:none"></span><span id="rf-k-i" style="display:none"></span><span id="rf-k-s" style="display:none"></span>
  <div class="rf-body">
    <div id="rf-table"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
  </div>
</div>

<!-- ═══ View: Exploit Simulation Layer ═══ -->
<div class="view" id="view-lab">
  <div class="view-hdr">
    <div class="vh-text">
      <div class="vh-title">Exploit Simulation Layer</div>
      <div class="vh-sub">Posture: <b id="lab-score">—</b> &nbsp;·&nbsp; <span id="lab-band-txt">—</span> &nbsp;·&nbsp; Fix findings to advance toward Optimized</div>
    </div>
    <div id="lab-storage-badge" onclick="nav('storage')" style="display:none;cursor:pointer;align-items:center;gap:7px;font-size:11px;font-weight:700;color:#fff;background:#b91c1c;border-radius:7px;padding:6px 13px" title="Public object storage — click to view">
      🗄️ <span id="lab-storage-cnt">0</span> Public Storage Resource<span id="lab-storage-plural">s</span> Exposed
    </div>
  </div>

  <!-- ── Lab tab bar: Global | AWS | Azure | GCP ── -->
  <div class="lab-tabs-bar">
    <button class="lab-tab active" id="labtab-global" onclick="switchLabTab('global')">Global</button>
    <button class="lab-tab" id="labtab-aws" data-csp="aws" onclick="switchLabTab('aws')">AWS</button>
    <button class="lab-tab" id="labtab-azure" data-csp="azure" onclick="switchLabTab('azure')">Azure</button>
    <button class="lab-tab" id="labtab-gcp" data-csp="gcp" onclick="switchLabTab('gcp')">GCP</button>
  </div>

  <!-- Global — Exploit Simulation Layer (Deep Space hex diagram, rendered by renderLab()) -->
  <div id="lab-global-panel">
  <div class="jmap-outer" id="lab-global-diagram"></div>
  <div id="jnd3-ip-row" style="display:none;padding:2px 24px 14px;font-size:11px;color:#7c2d12;text-align:center"></div>
  </div><!-- /lab-global-panel -->

  <!-- ── Per-CSP diagram (Deep Space hex diagram, re-rendered per active tab by renderCspLab()) ── -->
  <div id="lab-csp-panel" style="display:none">
    <!-- CSP header row -->
    <div style="padding:14px 24px 0;display:flex;align-items:center;gap:10px">
      <span id="clab-csp-badge" style="font-size:10px;font-weight:900;letter-spacing:.14em;text-transform:uppercase;padding:3px 12px;border-radius:5px;color:#fff;background:#94a3b8">—</span>
      <span style="font-size:11px;color:var(--sub)">Posture: <b id="clab-score" style="color:#94a3b8">—</b> &nbsp;·&nbsp; <span id="clab-band-txt">—</span> &nbsp;·&nbsp; Fix findings to advance toward Optimized</span>
    </div>
    <div class="cjmap-outer" id="lab-csp-diagram"></div>
    <div id="cjnd3-ip-row" style="display:none;padding:2px 24px 14px;font-size:11px;color:#7c2d12;text-align:center"></div>
  </div>

</div>

<div class="view" id="view-admin-settings">
  <div class="view-hdr">
    <div class="vh-text">
      <div class="vh-title">Admin Settings</div>
      <div class="vh-sub">Configure dashboard behaviour</div>
    </div>
  </div>

  <div id="admin-settings-lock" style="padding:60px 20px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px">
    <div style="width:52px;height:52px;border-radius:50%;background:#f1f5f9;display:flex;align-items:center;justify-content:center">
      <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="#64748b" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    </div>
    <div style="font-size:13px;font-weight:700;color:#0f172a">Admin Settings is locked</div>
    <div style="font-size:11px;color:#64748b;max-width:280px;text-align:center">Enter the admin password to view and change dashboard settings.</div>
    <div style="display:flex;align-items:center;gap:10px;margin-top:6px">
      <input type="password" id="admin-settings-pwd" placeholder="Password" autocomplete="off" onkeydown="if(event.key==='Enter')unlockAdminSettings()" style="padding:8px 12px;border:1px solid #cbd5e1;border-radius:7px;font-size:13px;color:#0f172a;background:#f8fafc;outline:none;width:180px">
      <button onclick="unlockAdminSettings()" style="padding:8px 18px;background:#DA291C;color:#fff;border:none;border-radius:7px;font-size:13px;font-weight:700;cursor:pointer">Unlock</button>
    </div>
    <div id="admin-settings-pwd-err" style="font-size:11px;color:#ef4444;font-weight:600;display:none">Incorrect password</div>
  </div>

  <div id="admin-settings-content" style="display:none;padding:24px 20px;max-width:520px">
    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:22px 24px;margin-bottom:16px">
      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:4px">Data Refresh Interval</div>
      <div style="font-size:11px;color:#64748b;margin-bottom:14px">How often the server re-fetches data from FortiCNAPP. Min 6 h · Max 48 h.</div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <select id="settings-refresh-select" style="padding:8px 12px;border:1px solid #cbd5e1;border-radius:7px;font-size:13px;font-weight:600;color:#0f172a;background:#f8fafc;cursor:pointer;outline:none">
          <option value="21600">6 hours</option>
          <option value="43200">12 hours</option>
          <option value="86400" selected>24 hours (default)</option>
          <option value="172800">48 hours</option>
        </select>
        <button onclick="applySettings()" style="padding:8px 18px;background:#DA291C;color:#fff;border:none;border-radius:7px;font-size:13px;font-weight:700;cursor:pointer">Apply</button>
        <span id="settings-saved" style="font-size:12px;color:#22c55e;font-weight:700;opacity:0;transition:opacity .4s">✓ Saved</span>
      </div>
      <div style="margin-top:14px;padding:10px 14px;background:#f1f5f9;border-radius:7px;font-size:11px;color:#475569">
        Current server interval: <b id="settings-cur-interval">—</b>
      </div>
    </div>
    <div style="font-size:10px;color:#94a3b8;padding:0 4px">Changes take effect immediately on the server. The browser page reloads at the same cadence.</div>

    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:22px 24px;margin-top:16px">
      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:4px">Cloud Security Facts</div>
      <div style="font-size:11px;color:#64748b;margin-bottom:14px">Rotating Fortinet 2026 Cloud Report &amp; blog facts shown under the main gauge. Adjust how often a new fact appears.</div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;font-weight:600;color:#0f172a">
          <input type="checkbox" id="settings-vibe-toggle" checked onchange="toggleFgVibe(this.checked)" style="width:16px;height:16px;accent-color:#DA291C;cursor:pointer">
          Enable Cloud Security Facts
        </label>
      </div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <span style="font-size:12px;font-weight:600;color:#374151">Frequency:</span>
        <select id="settings-fact-freq" style="padding:7px 12px;border:1px solid #cbd5e1;border-radius:7px;font-size:13px;font-weight:600;color:#0f172a;background:#f8fafc;cursor:pointer;outline:none" onchange="applyFactFreq(this.value)">
          <option value="30">Every 30 seconds (default)</option>
          <option value="60">Every 1 minute</option>
          <option value="120">Every 2 minutes</option>
          <option value="300">Every 5 minutes</option>
          <option value="600">Every 10 minutes</option>
          <option value="1800">Every 30 minutes</option>
          <option value="3600">Every 60 minutes</option>
        </select>
        <span id="settings-fact-saved" style="font-size:12px;color:#22c55e;font-weight:700;opacity:0;transition:opacity .4s">✓ Saved</span>
      </div>
    </div>

    <div style="background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:22px 24px;margin-top:16px">
      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:4px">Assessment Window</div>
      <div style="font-size:11px;color:#64748b;margin-bottom:14px">Sliding look-back period used for all API queries (alerts, CVEs, identities, secrets, compliance).</div>
      <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
        <select id="settings-days-select" style="padding:8px 12px;border:1px solid #cbd5e1;border-radius:7px;font-size:13px;font-weight:600;color:#0f172a;background:#f8fafc;cursor:pointer;outline:none">
          <option value="7">7 days</option>
          <option value="14">14 days</option>
          <option value="15">15 days (default)</option>
          <option value="21">21 days</option>
          <option value="30">30 days</option>
        </select>
        <button onclick="applyDaysBack()" style="padding:8px 18px;background:#DA291C;color:#fff;border:none;border-radius:7px;font-size:13px;font-weight:700;cursor:pointer">Apply</button>
        <span id="settings-days-saved" style="font-size:12px;color:#22c55e;font-weight:700;opacity:0;transition:opacity .4s">✓ Saved</span>
      </div>
      <div style="margin-top:14px;padding:10px 14px;background:#f1f5f9;border-radius:7px;font-size:11px;color:#475569">
        Current window: <b id="settings-cur-days">—</b> · Takes effect on next data refresh
      </div>
    </div>

  </div>
</div>

</div><!-- /main -->
</div><!-- /app-layout -->

<script>
const REFRESH=${intervalSec};
let cd=10,_isStartup=true;
function fmtSec(s){
  if(s>=3600){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h+'h'+(m>0?' '+m+'m':'');}
  if(s>=60){const m=Math.floor(s/60),ss=s%60;return m+'m'+(ss>0?' '+ss+'s':'');}
  return s+'s';
}
function setFooterInterval(sec){
  const fi=document.getElementById('footer-interval');
  if(fi)fi.textContent=fmtSec(sec);
}

const e=s=>String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
${hexKillChainSvg.toString()}
const tr=(s,n)=>{s=String(s||'');return s.length>n?s.slice(0,n)+'\\u2026':s||'\\u2014'};
function fmtDate(t){
  if(!t)return'\\u2014';
  try{const d=new Date(t);return d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'2-digit'})+' '+d.toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit',hour12:false});}
  catch{return String(t).slice(0,16)}
}
function sev(s){
  const l=(s||'').toLowerCase();
  if(l==='critical')return'<span class="b b-cr">Critical</span>';
  if(l==='high')return'<span class="b b-hi">High</span>';
  if(l==='medium')return'<span class="b b-me">Medium</span>';
  return'<span class="b b-nt">'+e(s||'\\u2014')+'</span>';
}
function status(s){
  const l=(s||'').toLowerCase();
  if(l==='open')return'<span class="b b-cr">Open</span>';
  if(l==='in_progress')return'<span class="b b-hi">In Progress</span>';
  if(l==='closed')return'<span class="b b-ok">Closed</span>';
  return'<span class="b b-nt">'+e(s||'\\u2014')+'</span>';
}
function cloud(c){const m={aws:'b-ok',azure:'b-hi',gcp:'b-cr'};return'<span class="b '+(m[c]||'b-nt')+'">'+(c||'').toUpperCase()+'</span>';}
function strip(s){return(s||'').toLowerCase()==='critical'?'strip-cr':'strip-hi';}
// Verified Exposure Path (LW_APA_EXPOSURE_PATHS) hop label — shared by the Host Internet
// Exposure panel and the Public Storage Exposure panel.
function pathHopLabel(node){
  return(node&&(node.displayName||(node.key&&(node.key.id||node.key.arn))||node.type))||'?';
}
function exposurePathHopsStr(rec){
  return(rec.PATH||[]).map(function(hopArr){return(hopArr||[]).map(pathHopLabel).join('/');}).map(e).join(' &rarr; ');
}
function shortenAlertDesc(d){
  if(!d)return'—';
  const t=d.toLowerCase();
  // Strip IPs, ports, domains, hashes before pattern matching
  const clean=d.replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b/g,'').replace(/\b[a-f0-9]{32,}\b/gi,'').replace(/\s{2,}/g,' ').trim();
  if(/crypto.?min|mining/i.test(t))              return'Crypto Mining Detected';
  if(/bad.?ip|malicious.?ip|known.?bad/i.test(t))return'Bad External Communication';
  if(/brute.?force|password.?spray|credential.?stuff/i.test(t)) return'Brute Force / Credential Attack';
  if(/data.?exfil|exfiltrat/i.test(t))           return'Data Exfiltration Risk';
  if(/dns.?tunnel|dns.?exfil/i.test(t))          return'DNS Tunneling Detected';
  if(/lateral.?mov/i.test(t))                    return'Lateral Movement';
  if(/privilege.?escal|priv.?esc/i.test(t))       return'Privilege Escalation';
  if(/command.?and.?control|c2|c&c/i.test(t))    return'C2 Communication';
  if(/port.?scan|network.?scan/i.test(t))         return'Port / Network Scan';
  if(/ransomware/i.test(t))                       return'Ransomware Activity';
  if(/reverse.?shell|shell.?spawn|remote.?shell/i.test(t)) return'Reverse Shell Activity';
  if(/anomal.*login|unusual.*login|suspicious.*login/i.test(t)) return'Suspicious Login Activity';
  if(/new.*admin|admin.*creat|iam.*escalat/i.test(t)) return'Privileged Account Change';
  if(/unauthorized.*api|api.*abuse/i.test(t))     return'Unauthorized API Access';
  if(/tor\b|vpn.?exit|proxy/i.test(t))            return'Anonymised External Communication';
  // Fallback: strip specifics and truncate
  return clean.length>50?clean.slice(0,48)+'…':clean||d.slice(0,50);
}
function setKpi(id,n){const el=document.getElementById(id);if(el)el.textContent=n;}
function buildPie(d){
  var segs=[
    {id:'rf-pseg-a',key:'a',n:(d.alerts||[]).length},
    {id:'rf-pseg-v',key:'v',n:riskFindingHostExposure(d).length},
    {id:'rf-pseg-i',key:'i',n:riskFindingIdentities(d.identities).length},
    {id:'rf-pseg-c',key:'c',n:(d.compliance||[]).length},
    {id:'rf-pseg-s',key:'s',n:(d.secretsAll||[]).length},
  ];
  var total=segs.reduce(function(s,c){return s+c.n;},0);
  var C=364.4,GAP=5;
  var active=segs.filter(function(s){return s.n>0;}).length||1;
  var usable=C-GAP*active;
  var cum=0;
  segs.forEach(function(seg){
    var el=document.getElementById(seg.id);
    var len=total===0?0:(seg.n/total)*usable;
    (function(e,l,o){
      requestAnimationFrame(function(){
        if(e){e.setAttribute('stroke-dasharray',l.toFixed(1)+' '+(C-l).toFixed(1));e.setAttribute('stroke-dashoffset',(-o).toFixed(1));}
      });
    })(el,len,cum);
    var nl=document.getElementById('rf-n-'+seg.key);
    if(nl)nl.textContent=seg.n||'0';
    if(seg.n>0)cum+=len+GAP;
  });
  var rft=document.getElementById('rf-pie-total');
  if(rft)rft.textContent=total||'0';
}
function setBody(id,h){const el=document.getElementById(id);if(el)el.innerHTML=h;}
function state(id,icon,msg){setBody(id,'<div class="state"><span class="state-icon">'+icon+'</span><span>'+e(msg)+'</span></div>');}
function setCount(id,n,bad){const el=document.getElementById(id);if(!el)return;el.textContent=n;el.className='sec-count '+(n>0&&bad?'bad':'ok');}

function renderAlerts(rows,err){
  if(err){state('body-a','',err);return}
  setKpi('kpi-a',rows.length);setCount('cnt-a',rows.length,true);
  if(!rows.length){state('body-a','','No open critical alerts');return}
  const baseA='https://'+(_lastData?.account||'');
  setBody('body-a','<div class="tbl-wrap"><table><thead><tr><th>Alert ID</th><th>Alert</th><th>Description</th><th>Status</th><th>Time</th><th></th></tr></thead><tbody>'
    +rows.map(r=>{
      const rawDesc=(r.alertInfo?.description||r.alertType||'').replace(/\s+/g,' ').trim();
      const desc=shortenAlertDesc(rawDesc);
      const href=baseA;
      const aid=e(String(r.alertId||''));
      return'<tr class="'+strip('critical')+'">'
        +'<td class="m"><a class="rf-link" href="'+e(href)+'" target="_blank">'+e(r.alertId||'\\u2014')+'</a><button class="cp-btn" data-cp="'+aid+'">'+cpIcon+'</button></td>'
        +'<td class="p"><a class="rf-link" href="'+e(href)+'" target="_blank">'+e(r.alertName||'—')+'</a></td>'
        +'<td style="white-space:nowrap"><button class="ai-inv-btn" data-aid="'+aid+'" data-aname="'+e(r.alertName||'')+'" data-asev="'+e(r.severity||'')+'" '
          +'style="display:inline-flex;align-items:center;gap:4px;padding:3px 9px;font-size:10px;font-weight:700;background:#94a3b8;color:#fff;border:none;border-radius:6px;cursor:not-allowed;white-space:nowrap;opacity:.7" '
          +'disabled title="AI triage preparing…">🤖 Triage</button></td>'
        +'<td class="desc">'+e(desc||'—')+'</td>'
        +'<td>'+status(r.status)+'</td>'
        +'<td class="m">'+fmtDate(r.startTime)+'</td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function renderVulns(rows,err){
  try{_renderVulns(rows,err);}catch(ex){state('body-v','','Host Internet Exposure render error: '+ex.message+' ('+ex.stack+')');console.error('[renderVulns]',ex);}
}
// Friendly category label for a raw SECRET_TYPE (e.g. "aws_secret_access_key" → "AWS Key").
function ciemCategoryLabel(t){
  var tl=(t||'').toLowerCase();
  if(tl.indexOf('ssh')>=0)return'SSH Key';
  if(tl.indexOf('aws')>=0)return'AWS Key';
  if(tl.indexOf('gcp')>=0||tl.indexOf('google')>=0)return'GCP Key';
  if(tl.indexOf('azure')>=0)return'Azure Key';
  if(tl.indexOf('oauth')>=0||tl.indexOf('token')>=0)return'OAuth Token';
  if(tl.indexOf('rsa')>=0||tl.indexOf('ecdsa')>=0||tl.indexOf('ed25519')>=0)return'Private Key';
  return t||'Credential';
}

function _renderVulns(rows,err){
  if(err){state('body-v','',err);return;}
  // Panel threshold raised to CVE risk ≥ 9 (tighter than the server's own ≥ 8 base fetch) —
  // filtered client-side since 9 is a strict subset of the already-fetched ≥8 data, same
  // scoped-filter pattern as the Beta tab's own ≥9 gate (no separate fetch needed).
  rows=(rows||[]).filter(function(r){return parseFloat(r.cveRiskScore??r.riskScore??r.hostRiskScore??0)>=9;});
  setKpi('kpi-v',rows.length);setCount('cnt-v',rows.length,true);
  if(!rows.length){state('body-v','','≥ 9 risk score · internet-exposed · unpatched — no results');return;}

  // ── Pull correlated data from global cache ─────────────────────────────────
  var _ld=_lastData||{};
  var _corIdents=(_ld.identities)||[];
  var _critIdents=_corIdents.filter(function(id){var s=(id.METRICS&&id.METRICS.risk_severity||'').toLowerCase();return s==='critical'||s==='high';});
  var _critCompl=((_ld.compliance)||[]).filter(function(c){return(c.severity||'').toLowerCase()==='critical';});
  // Build per-host correlated asset risk map
  var _arm=buildAssetRiskMap(_ld);
  var _arMap=_arm.map;
  var _arMaxRisk=_arm.maxRisk;
  var _arCritMisc=_arm.critMisc;
  // Tier helper
  function arTierOf(score,exposed){
    if(score>=75)return exposed?{l:'CRITICAL',c:'#b91c1c',bd:'#fca5a5'}:{l:'MEDIUM',c:'#92400e',bd:'#fcd34d'};
    if(score>=50)return exposed?{l:'HIGH',c:'#c2410c',bd:'#fdba74'}:{l:'LOW',c:'#4b5563',bd:'#d1d5db'};
    if(score>=30)return{l:'MEDIUM',c:'#92400e',bd:'#fcd34d'};
    return{l:'LOW',c:'#4b5563',bd:'#d1d5db'};
  }

  // ── Group by hostname ──────────────────────────────────────────────────────
  var hostMap={};
  rows.forEach(function(r){
    var mt2=r.machineTags;
    var h=(mt2&&typeof mt2==='object'&&!Array.isArray(mt2)&&mt2.Hostname)||
          (r.evalCtx&&r.evalCtx.hostname)||r.mid||'?';
    if(!hostMap[h]){
      var mt=r.machineTags;
      var pubIp='';
      if(mt&&typeof mt==='object'&&!Array.isArray(mt)){
        pubIp=mt.ExternalIp||mt.PublicIp||mt.publicIp||'';
      } else if(Array.isArray(mt)){
        var pt=mt.find(function(t){return/external.?ip|public.?ip/i.test(t.key||'');});
        if(pt)pubIp=pt.value||'';
      }
      var cloudRaw=(mt&&typeof mt==='object'&&!Array.isArray(mt)&&mt.VmProvider)||'';
      var cloud=cloudRaw?cloudRaw.toLowerCase():'';
      if(cloud==='google')cloud='gcp';
      var mt2Obj=(mt2&&typeof mt2==='object'&&!Array.isArray(mt2))?mt2:null;
      var instanceId=(mt&&typeof mt==='object'&&!Array.isArray(mt)&&mt.InstanceId)||'';
      var resourceName=(mt&&typeof mt==='object'&&!Array.isArray(mt)&&mt.Name)||'';
      hostMap[h]={name:h,pubIp:pubIp,cloud:cloud,instanceId:instanceId,resourceName:resourceName,
        reach:(mt2Obj&&mt2Obj.lw_InternetExposure==='Yes'?'Internet Exposed':null)||'',
        restricted:!!(mt2Obj&&mt2Obj.lw_RestrictedExternalAccess==='Yes'),
        vulns:[],maxRisk:0,crit:0,high:0,fixable:0,
        exposureEvidence:r._exposureEvidence||null};
    }
    var host=hostMap[h];
    var rs=parseFloat(r.hostRiskScore||r.riskScore||0);
    if(rs>host.maxRisk)host.maxRisk=rs;
    var sv=(r.severity||'').toLowerCase();
    if(sv==='critical')host.crit++;
    else if(sv==='high')host.high++;
    var hasFix=r.fixInfo&&(r.fixInfo.fix_available===true||String(r.fixInfo.fix_available)==='1');
    if(hasFix)host.fixable++;
    host.vulns.push(r);
  });

  var allHosts=Object.values(hostMap).sort(function(a,b){return b.maxRisk-a.maxRisk;});

  // Internet-exposed hosts come from vulns data (all have CVE risk ≥ 9)
  var inetHosts=allHosts.filter(function(h){return h.reach==='Internet Exposed';});

  // Private hosts: all non-internet-exposed hosts with CVE risk ≥ 9 · Unpatched (same
  // base set as the Internet Exposed tab), enriched with correlated Secrets from secretsAll —
  // NOT gated on secrets being present, so hosts with only CVE risk still show up.
  var _CIEM_TYPES=['SSH_PRIVATE_KEY','SSH_PRIVATE_KEYS','RSA','ECDSA','ED25519',
    'AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY','AWS_CREDENTIALS','AWS_SECRET',
    'GOOGLE_OAUTH_TOKEN','GCP_SERVICE_ACCOUNT','AZURE_CLIENT_SECRET','AZURE_SAS_TOKEN'];
  var _privMap={};
  var _exposedHostSet={};
  var _iehbSet=iehbQualifyingHostSet(_ld);
  allHosts.forEach(function(h){
    // Also exclude any host that qualifies for the Internet Exposed Host panel (raw
    // exposure tag, not this panel's verified one — see iehbQualifyingHostSet) so the same
    // host never shows up as both "Private" and "Internet Exposed" across the two tabs.
    if(h.reach==='Internet Exposed'||_iehbSet[h.name.toLowerCase()]){_exposedHostSet[h.name.toLowerCase()]=true;return;}
    _privMap[h.name.toLowerCase()]={name:h.name,cloud:h.cloud||'',restricted:!!h.restricted,
      instanceId:h.instanceId||'',resourceName:h.resourceName||'',pubIp:h.pubIp||'',
      ciemSecrets:[],genericSecrets:[],vulns:h.vulns||[],maxRisk:h.maxRisk||0,crit:h.crit||0,high:h.high||0};
  });
  // Correlate secrets onto matching hosts (and surface secret-only hosts with no CVE >= 8 too).
  // Must also skip hosts already known Internet Exposed above -- otherwise a host with no
  // qualifying CVE (so never evaluated against reach) but with a secretsAll entry would
  // get created here and misclassified as private in the Attack Path graph.
  (_ld.secretsAll||[]).forEach(function(s){
    var hn=s.HOSTNAME||'';
    if(!hn)return;
    var hnl=hn.toLowerCase();
    if(_exposedHostSet[hnl])return;
    if(!_privMap[hnl])_privMap[hnl]={name:hn,ciemSecrets:[],genericSecrets:[],vulns:[],maxRisk:0,crit:0,high:0};
    var t=(s.SECRET_TYPE||'').toUpperCase();
    if(_CIEM_TYPES.indexOf(t)>=0)_privMap[hnl].ciemSecrets.push(s.SECRET_TYPE||t);
    else _privMap[hnl].genericSecrets.push(s.SECRET_TYPE||t);
  });

  var privHosts=Object.values(_privMap)
    .sort(function(a,b){return(b.ciemSecrets.length*2+b.genericSecrets.length+b.maxRisk)-(a.ciemSecrets.length*2+a.genericSecrets.length+a.maxRisk);});

  function summaryStrip(hostArr,rowsArr,label){
    var tc=rowsArr.filter(function(r){return(r.severity||'').toLowerCase()==='critical';}).length;
    var th=rowsArr.filter(function(r){return(r.severity||'').toLowerCase()==='high';}).length;
    var tf=rowsArr.filter(function(r){return r.fixInfo&&(r.fixInfo.fix_available===true||String(r.fixInfo.fix_available)==='1');}).length;
    return'<div style="display:flex;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center">'
      +'<span style="font-size:11px;font-weight:700;color:var(--text)">'+hostArr.length+' Hosts</span>'
      +'<span style="font-size:11px;color:var(--muted)">&middot; '+rowsArr.length+' CVEs</span>'
      +(tc?'<span class="b b-cr">'+tc+' Critical</span>':'')
      +(th?'<span class="b b-hi">'+th+' High</span>':'')
      +(tf?'<span class="b b-ok">'+tf+' fixable</span>':'')
      +'<span style="margin-left:auto;font-size:9px;color:var(--muted)">'+label+'</span>'
    +'</div>';
  }

  // Internet-Exposed tab/panel removed — internet-exposed hosts are still tracked
  // elsewhere (Internet Exposed Host tab, Risk Findings' Host Exposure category via
  // riskFindingHostExposure()); this panel now shows only Private Hosts, no tab switcher.
  var html='';

  // ── Private Hosts panel ────────────────────────────────────────────────────
  // Card format matches the Internet Exposed Host tab's asset-card design
  // (newHostInterExposure.png reference) — two-column card: Asset Details + Cloud Context
  // on the left, Security Findings + Actions on the right, "View all findings" expansion
  // below with correlated risk strip, non-compliance violations, and the full CVE table.
  html+='<div id="vpanel-priv">';
  if(!privHosts.length){
    html+='<div class="state">No private hosts with CVE risk ≥ 9 or exposed Secrets found</div>';
  }else{
    var privCap=50;
    html+='<div style="display:flex;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center">'
      +'<span style="font-size:11px;font-weight:700;color:var(--text)">'+privHosts.length+' Private Hosts</span>'
      +'<span style="font-size:11px;color:var(--muted)">&middot; CVE Risk ≥ 9 &amp; Exposed Secrets</span>'
      +(_arCritMisc?'<span class="b b-hi" style="font-size:9px">'+_arCritMisc+' Critical Misconfigs</span>':'')
      +(_critIdents.length?'<span class="b" style="font-size:9px;background:#ede9fe;color:#7c3aed;border:1px solid #ddd6fe">'+_critIdents.length+' Privileged Identities</span>':'')
      +'<span style="margin-left:auto;font-size:9px;color:var(--muted)">Private &middot; Correlated Secrets · Identities &amp; Misconfigs</span>'
    +'</div>'
    +(privHosts.length>privCap?'<div style="font-size:10px;color:var(--muted);padding:6px 16px;background:var(--surface);border-bottom:1px solid var(--border)">Showing top '+privCap+' of '+privHosts.length+' hosts by risk</div>':'');

    // Non-compliance violations matched to host, same JSON-substring approach as the Beta tab
    var _compMatchPriv={};
    privHosts.forEach(function(h){_compMatchPriv[h.name.toLowerCase()]=[];});
    ((_ld.compliance)||[]).forEach(function(c){
      if(!Array.isArray(c.resources)||!c.resources.length)return;
      var resJson=JSON.stringify(c.resources).toLowerCase();
      Object.keys(_compMatchPriv).forEach(function(hn){if(resJson.indexOf(hn)>=0)_compMatchPriv[hn].push(c);});
    });

    // High-permission attached IAM role (AWS only), same heuristic as the Beta tab
    var _instanceIamProfile=_ld.instanceIamProfile||{};
    function isHighPermissivePriv(r){
      var risks=(r.METRICS&&r.METRICS.risks)||[];
      var sev=((r.METRICS&&r.METRICS.risk_severity)||'').toLowerCase();
      return risks.indexOf('ALLOWS_FULL_ADMIN')!==-1||risks.indexOf('EXCESSIVE_PERMISSIONS')!==-1||sev==='critical'||sev==='high';
    }
    privHosts.forEach(function(h){
      h.iamRole=null;
      var profile=h.instanceId&&_instanceIamProfile[h.instanceId];
      if(!profile)return;
      var match=_corIdents.find(function(r){
        var pid=(r.PRINCIPAL_ID||'').toLowerCase(),nm=(r.NAME||'').toLowerCase(),pn=profile.profileName.toLowerCase();
        return nm===pn||pid.split('/').pop()===pn;
      });
      h.iamRole=match?{name:match.NAME||profile.profileName,highPermissive:isHighPermissivePriv(match)}:{name:profile.profileName,highPermissive:null};
    });

    function detailRowPriv(label,val){
      if(!val||val==='—')return'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:11px"><span style="color:#94a3b8">'+e(label)+'</span><span style="color:#cbd5e1">—</span></div>';
      return'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:11px">'
        +'<span style="color:#94a3b8">'+e(label)+'</span>'
        +'<span style="display:flex;align-items:center;gap:4px;font-family:monospace;font-weight:600;color:#1e293b;text-align:right;word-break:break-all">'+e(val)+'<button class="cp-btn" data-cp="'+e(val)+'" style="flex-shrink:0">'+cpIcon+'</button></span>'
      +'</div>';
    }
    function contextChipPriv(label,val){
      return'<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:6px 8px;font-size:10px;min-width:0">'
        +'<div style="color:#94a3b8;font-weight:600;text-transform:uppercase;letter-spacing:.03em;font-size:8.5px;margin-bottom:2px">'+e(label)+'</div>'
        +'<div style="color:#1e293b;font-weight:600;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+e(val)+'">'+e(val)+'</div>'
      +'</div>';
    }
    var sevStylePriv={CRITICAL:{c:'#b91c1c',bg:'#fef2f2',bd:'#fecaca'},HIGH:{c:'#c2410c',bg:'#fff7ed',bd:'#fdba74'}};
    function findingCardPriv(f){
      var s=sevStylePriv[f.sev]||sevStylePriv.HIGH;
      return'<div style="display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border:1px solid '+s.bd+';border-left:3px solid '+s.c+';background:'+s.bg+';border-radius:6px;margin-bottom:6px">'
        +'<span style="color:'+s.c+';font-size:13px;line-height:1.3">&#9888;</span>'
        +'<div style="min-width:0;flex:1">'
          +'<div style="font-size:11px;font-weight:700;color:#1e293b;word-break:break-word">'+e(f.title)+'</div>'
          +'<div style="margin-top:2px"><span style="font-size:8.5px;font-weight:800;color:'+s.c+';background:#fff;border:1px solid '+s.bd+';border-radius:3px;padding:0 5px">'+f.sev+'</span> <span style="font-size:9.5px;color:#94a3b8">&middot; '+e(f.cat)+'</span></div>'
        +'</div>'
      +'</div>';
    }

    privHosts.slice(0,privCap).forEach(function(host,pidx){
      var bodyId='priv-cve-body-'+pidx;
      var n=host.vulns.length;
      var hasCiem=host.ciemSecrets.length>0;
      var arEntry=_arMap[host.name];
      var arScore=arEntry?arEntry.normalizedScore:0;
      var arTier=arTierOf(arScore,false);
      function arChipPriv(label,col,bd){return'<span style="font-size:9px;font-weight:600;color:'+col+';border:1px solid '+bd+';border-radius:3px;padding:1px 6px;white-space:nowrap">'+label+'</span>';}

      var cloudFullName={aws:'Amazon Web Services',azure:'Microsoft Azure',gcp:'Google Cloud Platform'}[host.cloud]||'Cloud Provider';
      var cloudIconColor=cspBadgeColor(host.cloud);
      var primaryLabel=host.resourceName||host.name;
      var rawTags=(host.vulns[0]&&host.vulns[0].machineTags)||{};
      var zone=rawTags.Zone||'—';
      var netLabel=host.cloud==='azure'?'VNet':'VPC';
      var netVal=rawTags.VpcId||'—';
      var acctLabel=host.cloud==='azure'?'Subscription':(host.cloud==='gcp'?'Project':'Subnet');
      var acctVal=host.cloud==='azure'?(rawTags.SubscriptionName||rawTags.SubscriptionId||'—'):(rawTags.SubnetId||rawTags.ProjectId||'—');

      var findings=[];
      if(hasCiem)findings.push({title:host.ciemSecrets.length+' exposed CIEM credential'+(host.ciemSecrets.length!==1?'s':'')+' on this host',sev:'CRITICAL',cat:'Credential Exposure'});
      if(host.genericSecrets.length)findings.push({title:host.genericSecrets.length+' exposed secret'+(host.genericSecrets.length!==1?'s':'')+' on this host',sev:'HIGH',cat:'Credential Exposure'});
      if(host.iamRole&&host.iamRole.highPermissive===true)findings.push({title:'Attached IAM role ('+host.iamRole.name+') grants high-permission access',sev:'HIGH',cat:'Identity & Access'});
      host.vulns.slice().sort(function(a,b){return(parseFloat(b.cveRiskScore||b.riskScore||0))-(parseFloat(a.cveRiskScore||a.riskScore||0));}).slice(0,3).forEach(function(r){
        var rs=parseFloat(r.cveRiskScore||r.riskScore||0);
        findings.push({title:(r.vulnId||r.cveId||'CVE')+' — '+((r.featureKey&&r.featureKey.name)||'package')+' (risk '+rs.toFixed(1)+')',sev:rs>=9.5?'CRITICAL':'HIGH',cat:'Vulnerability Management'});
      });
      var findingsShown=findings.slice(0,4);

      html+='<div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:16px;background:#fff">'
        +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:0">'
          +'<div style="padding:18px;border-right:1px solid #e2e8f0">'
            +'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">'
              +'<div style="width:42px;height:42px;border-radius:9px;background:'+cloudIconColor+';display:flex;align-items:center;justify-content:center;flex-shrink:0"><span style="color:#fff;font-weight:900;font-size:11px;letter-spacing:.02em">'+e((host.cloud||'').toUpperCase()||'?')+'</span></div>'
              +'<div style="min-width:0">'
                +'<div style="font-size:15px;font-weight:800;color:#0f172a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e(primaryLabel)+'</div>'
                +'<div style="font-size:10.5px;color:#94a3b8">'+e(cloudFullName)+'</div>'
              +'</div>'
            +'</div>'
            +(host.restricted
              ?'<span style="display:inline-flex;align-items:center;gap:4px;font-size:9.5px;font-weight:800;letter-spacing:.05em;color:#0369a1;background:#f0f9ff;border:1px solid #bae6fd;border-radius:20px;padding:3px 10px" title="Reachable from a specific allowlisted public IP, not wide open">RESTRICTED EXTERNAL ACCESS</span>'
              :'<span style="display:inline-flex;align-items:center;gap:4px;font-size:9.5px;font-weight:800;letter-spacing:.05em;color:#374151;background:#f3f4f6;border:1px solid #e5e7eb;border-radius:20px;padding:3px 10px">PRIVATE &middot; NOT INTERNET EXPOSED</span>')
            +'<div style="margin-top:16px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-bottom:2px">Asset Details</div>'
            +detailRowPriv('Hostname',host.name)
            +detailRowPriv('Resource ID',host.instanceId)
            +'<div style="margin-top:14px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-bottom:6px">Cloud Context</div>'
            +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">'
              +contextChipPriv('Zone',zone)+contextChipPriv(netLabel,netVal)
              +contextChipPriv(acctLabel,acctVal)
              +contextChipPriv('IAM Role',host.iamRole?host.iamRole.name:'None attached')
            +'</div>'
          +'</div>'
          +'<div style="padding:18px">'
            +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
              +'<div style="display:flex;align-items:center;gap:8px">'
                +'<span style="font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#374151">Security Findings</span>'
                +'<span style="font-size:10px;font-weight:800;color:#fff;background:#DA291C;border-radius:10px;padding:1px 8px;min-width:16px;text-align:center">'+findings.length+'</span>'
              +'</div>'
              +'<button class="toggle-host-cve" data-body="'+bodyId+'" data-n="'+n+'" style="font-size:10px;font-weight:700;color:#DA291C;background:none;border:none;cursor:pointer;padding:0">View all findings &rsaquo;</button>'
            +'</div>'
            +(findingsShown.length?findingsShown.map(findingCardPriv).join(''):'<div style="font-size:11px;color:#94a3b8">No specific findings enriched — see full CVE list below.</div>')
            +(findings.length>findingsShown.length?'<div style="font-size:10px;color:#94a3b8;margin-top:2px">+'+(findings.length-findingsShown.length)+' more in full list</div>':'')
            +'<div style="margin-top:14px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-bottom:8px">Actions</div>'
            +'<div style="display:flex;gap:8px;flex-wrap:wrap">'
              +'<button class="goto-host-card-btn" data-hostname="'+e(host.name)+'" data-resourcename="'+e(host.resourceName||'')+'" style="font-size:11px;font-weight:700;color:#fff;background:#DA291C;border:none;border-radius:6px;padding:7px 14px;cursor:pointer">&#9651; Exploit Graph</button>'
              +'<button class="mach-inv-btn" data-hostname="'+e(host.name)+'" style="font-size:11px;font-weight:700;color:#374151;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:7px 14px;cursor:pointer">Machine Details</button>'
            +'</div>'
          +'</div>'
        +'</div>'
        +'<div id="'+bodyId+'" style="display:none;padding:16px 18px;border-top:1px solid #e2e8f0;background:#fafafa">'
        +'<div style="font-size:9px;color:var(--muted);margin-bottom:6px">'+n+' CVE'+(n!==1?'s':'')+' &middot; private host</div>'
        +(arScore
          ?'<div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;padding:6px 0;border-bottom:1px solid var(--border);margin-bottom:8px">'
            +'<span style="font-size:9px;color:var(--muted)">Correlated risk</span>'
            +'<span style="font-size:15px;font-weight:800;color:'+arTier.c+';font-variant-numeric:tabular-nums;line-height:1">'+arScore+'</span>'
            +'<span style="font-size:8px;font-weight:700;color:'+arTier.c+';border:1px solid '+arTier.bd+';border-radius:3px;padding:1px 5px">'+arTier.l+'</span>'
            +'<div style="flex:0 0 70px;height:3px;background:#e5e7eb;border-radius:2px"><div style="height:3px;border-radius:2px;background:'+arTier.c+';width:'+arScore+'%"></div></div>'
            +(arEntry&&arEntry.ciemSecrets.length?arChipPriv('CIEM \xb7 '+arEntry.ciemSecrets.length,'#b91c1c','#fca5a5'):'')
            +(arEntry&&arEntry.genericSecrets.length?arChipPriv('SEC \xb7 '+arEntry.genericSecrets.length,'#92400e','#fcd34d'):'')
            +(_arCritMisc?arChipPriv('MISCONF \xb7 '+_arCritMisc,'#4b5563','#d1d5db'):'')
          +'</div>':'')
        +(function(){
          var matched=_compMatchPriv[host.name.toLowerCase()]||[];
          if(!matched.length)return'';
          return'<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px">'
            +'<div style="font-size:9px;font-weight:800;letter-spacing:.07em;color:#b45309;margin-bottom:6px">NON-COMPLIANCE VIOLATIONS ON THIS HOST <span style="font-weight:400;color:var(--muted)">('+matched.length+')</span></div>'
            +matched.map(function(c){
              var cl=e(c.cloud||''),sev=(c.severity||'').toLowerCase();
              return'<div style="padding:6px 0;border-bottom:1px solid var(--border)">'
                +'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">'
                  +'<span style="font-size:10.5px;font-weight:600;color:var(--text)">'+e(c.title||c.alertId||'')+'</span>'
                  +'<span style="display:flex;gap:4px;flex-shrink:0">'+(cl?'<span class="b b-nt" style="font-size:8px">'+cl.toUpperCase()+'</span>':'')+'<span class="b '+(sev==='critical'?'b-cr':'b-hi')+'" style="font-size:8px">'+(c.severity||'')+'</span></span>'
                +'</div>'
              +'</div>';
            }).join('')
          +'</div>';
        })()
        +(n?'<div class="tbl-wrap"><table style="font-size:11px">'
          +'<thead><tr><th style="width:160px">CVE / Vuln ID</th><th style="width:52px">CVE Risk</th><th>Package · Installed version</th><th>OS / Namespace</th><th>Fix version</th><th></th></tr></thead><tbody>'
          +host.vulns.map(function(r){
            var fix=r.fixInfo&&(r.fixInfo.fix_available===true||String(r.fixInfo.fix_available)==='1');
            var fixVer=(r.fixInfo&&r.fixInfo.fixed_version)||'';
            var cveId=e(r.vulnId||r.cveId||'');
            var svcol=(r.severity||'').toLowerCase()==='critical'?'#b91c1c':'#c2410c';
            return'<tr>'
              +'<td style="white-space:nowrap"><span style="font-family:monospace;font-size:10.5px;font-weight:700;color:'+svcol+'">'+e(r.vulnId||r.cveId||'—')+'</span><button class="cp-btn" data-cp="'+cveId+'" style="margin-left:3px">'+cpIcon+'</button></td>'
              +'<td class="r"><span class="risk-score">'+parseFloat(r.cveRiskScore||r.hostRiskScore||r.riskScore||0).toFixed(1)+'</span></td>'
              +'<td style="font-size:10.5px">'+e(r.featureKey&&r.featureKey.name||'—')+(r.featureKey&&r.featureKey.version_installed?'<br><span style="font-size:9px;color:var(--muted)">'+e(r.featureKey.version_installed)+'</span>':'')+'</td>'
              +'<td style="font-size:10px;color:var(--muted)">'+e(r.featureKey&&r.featureKey.namespace||'—')+'</td>'
              +'<td>'+(fix?'<span class="b b-ok" title="'+e(fixVer)+'">'+e(tr(fixVer,16)||'Fix ✓')+'</span>':'<span class="b b-nt">No fix</span>')+'</td>'
              +'<td style="white-space:nowrap"><button class="cve-det-btn" data-cve="'+cveId+'" style="font-size:9px;padding:1px 6px;border-radius:3px;border:none;cursor:pointer;background:#f97316;color:#fff;font-weight:700;margin-right:3px">Details</button><button class="cp-btn" data-cp="'+cveId+'" title="Copy CVE ID">'+cpIcon+'</button></td>'
            +'</tr>';
          }).join('')
          +'</tbody></table></div>'
          :'<div style="font-size:10px;color:var(--muted)">No CVEs on this host — flagged via correlated secrets only.</div>')
        +'</div>'
      +'</div>';
    });
  }
  html+='</div>'; // closes vpanel-priv

  _renderedPrivMap=_privMap;
  setBody('body-v',html);
}

function renderCompliance(rows,err){
  if(err){state('body-c','',err);return}
  setKpi('kpi-c',rows.length);setCount('cnt-c',rows.length,true);
  if(!rows.length){state('body-c','','No critical compliance violations');return}
  const baseC='https://'+(_lastData?.account||'');
  setBody('body-c','<div class="tbl-wrap"><table><thead><tr><th style="width:9%">Policy ID</th><th style="width:6%">Cloud</th><th style="width:14%">Title</th><th style="width:8%">Category</th><th style="width:9%">Subcategory</th><th style="width:34%">Description</th><th style="width:7%">Severity</th><th style="width:7%">Resource Count</th><th style="width:6%"></th></tr></thead><tbody>'
    +rows.map(r=>'<tr class="'+strip(r.severity)+'">'
      +'<td class="m"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(r.alertId||'—')+'</a><button class="cp-btn" data-cp="'+e(r.alertId||'')+'">'+cpIcon+'</button></td>'
      +'<td>'+cloud(r.cloud)+'</td>'
      +'<td class="desc" style="max-width:none"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(r.title||'—')+'</a></td>'
      +'<td>'+e(r.category||'—')+'</td>'
      +'<td>'+e(r.subCategory||'—')+'</td>'
      +'<td class="desc" style="white-space:pre-line;max-width:none">'+e(r.description||'—')+'</td>'
      +'<td>'+sev(r.severity)+'</td>'
      +'<td class="r">'+e(r.violations||0)+'</td>'
      +'<td><button class="comp-det-btn" data-pid="'+e(r.alertId||'')+'" style="font-size:10px;padding:2px 9px;border-radius:5px;border:none;cursor:pointer;background:#f59e0b;color:#fff;font-weight:700" title="Non-compliant resources">Details</button></td>'
    +'</tr>').join('')+'</tbody></table></div>');
}

// ── Public Storage Exposure — object storage only (S3 buckets, Azure Blob containers,
// GCS buckets — never block storage) fetched directly server-side (fetchPublicStorage())
// from each cloud's own CFG inventory + its specific public-access proof (S3 bucket policy
// status/ACL, Azure per-container publicAccess, GCS bucket IAM policy grants) — see the
// comment on fetchPublicStorage() for why this isn't inferred from compliance policy titles.
// "Content" still cross-references whatever DSPM data-classification fields a compliance
// finding's resource row happens to carry for the same bucket/container name, best-effort.
// Effective Public Storage Exposure findings — shared by the Public Storage Exposure panel
// and the Exploit Simulation Layer's "N Public Storage Resources Exposed" badge, so both
// always agree on the same count.
function computeEffectivePublicStorage(d){
  // Known-stale CSPM snapshot entries: resources FortiCNAPP's last scan captured as public
  // but that no longer exist in the live cloud account (confirmed 2026-07-27 — Azure
  // returns ResourceNotFound, not a public-access-denied error, for this container). Not a
  // detection-logic bug; the fix is a fresh FortiCNAPP Azure CSPM re-scan. This list should
  // shrink to empty once that happens — remove entries here as they're confirmed stale, or
  // drop this filter entirely once verified clean.
  var STALE_STORAGE_FINDINGS=['juiceshopswagger'];
  var findings=((d&&d.publicStorage)||[]).filter(function(f){return STALE_STORAGE_FINDINGS.indexOf(f.name)===-1;});

  // ── Verified Exposure Paths (LW_APA_EXPOSURE_PATHS, s3:bucket + Azure Blob) — buckets/
  // containers aren't hosts, so no CVE/machine enrichment applies, just the traced
  // Internet→Target route. A bucket already found via policy/ACL analysis gets the path
  // cross-linked onto its existing row (kept at 'critical' — the policy/ACL check proved
  // actual public access). A bucket found ONLY via a traced path is added as its own row
  // at 'high' — a real network-reachable route was confirmed, but not that the bucket
  // policy itself grants public access, so it's a weaker signal than the policy/ACL
  // findings above and is labeled distinctly. Azure Blob's target type traces the storage
  // account's blob SERVICE, not individual containers, so its displayName may match a
  // storage account name rather than a specific container.
  var epByBucket={};
  [['s3','S3 Bucket'],['azureBlob','Azure Blob Storage']].forEach(function(src){
    ((d&&d.exposurePaths&&d.exposurePaths[src[0]])||[]).forEach(function(r){
      var nm=r.TARGET&&r.TARGET.displayName;
      if(!nm)return;
      r._resourceLabel=src[1];
      (epByBucket[nm]=epByBucket[nm]||[]).push(r);
    });
  });
  var existingNames={};
  findings.forEach(function(f){f.severity=f.severity||'critical';existingNames[f.name]=true;});
  Object.keys(epByBucket).forEach(function(nm){
    if(existingNames[nm])return;
    var rec=epByBucket[nm][0];
    findings.push({
      cloud:(rec.PROVIDER_TYPE||'aws').toLowerCase(),
      name:nm,
      account:rec.DOMAIN_ID||'—',
      region:'—',
      resourceType:rec._resourceLabel+' (Verified Internet Path)',
      severity:'high',
      urn:(rec.TARGET&&rec.TARGET.key&&(rec.TARGET.key.arn||rec.TARGET.key.id))||nm,
    });
  });
  return {findings, epByBucket};
}

function renderPublicStorage(d){
  var _eff=computeEffectivePublicStorage(d);
  var findings=_eff.findings;
  var epByBucket=_eff.epByBucket;

  if(!findings.length){setCount('cnt-storage',0,true);state('body-storage','','No public object storage exposure found (S3 buckets, Azure Blob containers, GCS buckets)');return}

  var CONTENT_KEYS=['DATA_CATEGORIES','SENSITIVE_DATA_TYPES','DATA_CLASSIFICATION','DATA_CLASSIFICATIONS','SENSITIVITY','PII_TYPES','CONTENT_TYPES','CLASSIFICATION','DATA_TYPES'];
  function pick(row,keys){for(var i=0;i<keys.length;i++){if(row&&row[keys[i]]!=null&&row[keys[i]]!=='')return row[keys[i]];}return null;}
  var dspmByName={};
  ((d&&d.compliance)||[]).forEach(function(f){
    (Array.isArray(f.resources)?f.resources:[]).forEach(function(row){
      var nm=row&&(row.URN||row.RESOURCE_ID||row.RESOURCE_KEY||row.BUCKET_NAME||row.NAME);
      var v=nm&&pick(row,CONTENT_KEYS);
      if(nm&&v!=null)dspmByName[nm]=v;
    });
  });
  function contentHtml(name){
    var v=dspmByName[name];
    if(v==null)return'<span style="color:#94a3b8;font-size:10.5px">No data classification available</span>';
    var vals=Array.isArray(v)?v:[v];
    return vals.map(function(x){return'<span class="b b-hi" style="margin:1px">'+e(String(x))+'</span>';}).join(' ');
  }

  function verifiedPathCell(name){
    var recs=epByBucket[name];
    if(!recs||!recs.length)return'<span style="color:#94a3b8;font-size:10.5px">&mdash;</span>';
    return'<span style="font-size:9px;font-family:monospace;font-weight:600;color:#15803d;background:#f0fdf4;border:1px solid #86efac;border-radius:3px;padding:1px 6px" title="Verified via FortiCNAPP Attack Path Analysis">'
      +exposurePathHopsStr(recs[0])
    +'</span>';
  }

  var groups={aws:[],azure:[],gcp:[]};
  findings.forEach(function(f){
    var c=(f.cloud||'').toLowerCase();
    if(!groups[c])groups[c]=[];
    groups[c].push(f);
  });

  setCount('cnt-storage',findings.length,true);

  var order=['aws','azure','gcp'];
  var html=order.filter(function(c){return groups[c]&&groups[c].length;}).map(function(c){
    var items=groups[c];
    var rowsHtml=items.map(function(f){
      return'<tr>'
        +'<td class="p" style="font-family:monospace;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+e(String(f.urn||f.name))+'">'+e(String(f.name))+'</td>'
        +'<td class="p">'+e(String(f.account||'—'))+'</td>'
        +'<td class="p">'+e(String(f.region||'—'))+'</td>'
        +'<td class="desc">'+e(f.resourceType||'—')+'</td>'
        +'<td>'+sev(f.severity||'critical')+'</td>'
        +'<td>'+contentHtml(f.name)+'</td>'
        +'<td>'+verifiedPathCell(f.name)+'</td>'
      +'</tr>';
    }).join('');
    return'<div style="padding:6px 0 8px;margin-top:16px;font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#111827;border-bottom:2px solid #11182733;margin-bottom:4px">'+cloud(c)+' <span style="font-weight:400;color:#9ca3af">('+items.length+' resource'+(items.length===1?'':'s')+')</span></div>'
      +'<div class="tbl-wrap"><table><thead><tr><th>Bucket / Container</th><th>Account / Project</th><th>Region</th><th>Resource Type</th><th>Severity</th><th>Content — Data Classification (DSPM)</th><th>Verified Internet Path</th></tr></thead><tbody>'+rowsHtml+'</tbody></table></div>';
  }).join('');

  setBody('body-storage',html);
}

// ── FortiGateVM — two independent signals, purely additive (no effect on posture score,
// alerts, or any other panel):
//  1. fortiInventory — best-effort name/tag heuristic scan of the FULL compute inventory
//     (see FORTI_PRODUCTS server-side), tenant-wide presence across all Fortinet product
//     lines, not just FortiGate and not just internet-exposed. Powers the tiles below.
//  2. exposurePaths.fortigate — LW_APA_EXPOSURE_PATHS records, FortiGate ONLY (the only
//     product this table classifies with its own type), each a verified Internet→VM path.
// Tiles are click-to-filter against fortiInventory itself (their own source data) — the
// Attack-Path-verified table below stays separate/unfiltered since it's a different
// dataset (FortiGate-only, path-verified) with no per-product breakdown to filter by.
// NOTE: onclick args use &apos; (HTML entity), NOT backslash-escaped quotes — this whole
// script is embedded inside buildHtml()'s own outer template literal, which consumes one
// level of backslash-escaping before the browser ever sees it, silently corrupting any
// \' sequence and breaking the ENTIRE inline <script> block's syntax (not just this
// function). &apos; sidesteps that entirely. See existing switchVTab(&apos;inet&apos;) for
// the established precedent — don't reintroduce \' here.
var _fortiInventory=[];
var _fortiInventoryFilter=null;
function filterFortiInventory(label){
  _fortiInventoryFilter=(_fortiInventoryFilter===label)?null:label;
  renderFortiGateTilesUI();
}
function renderFortiGateTilesUI(){
  var inv=_fortiInventory;
  var el=document.getElementById('fortigate-tiles');
  var invEl=document.getElementById('body-fortigate-inventory');
  if(!el)return;
  if(!inv.length){
    el.innerHTML='<div class="state"><span>No Fortinet appliances matched by name/tag across the scanned compute inventory</span></div>';
    if(invEl)invEl.innerHTML='';
    return;
  }
  var counts={};
  inv.forEach(function(r){counts[r.label]=(counts[r.label]||0)+1;});
  var order=Object.keys(counts).sort(function(a,b){return counts[b]-counts[a];});
  if(_fortiInventoryFilter&&order.indexOf(_fortiInventoryFilter)===-1)_fortiInventoryFilter=null;
  el.innerHTML=order.map(function(label){
    var active=label===_fortiInventoryFilter;
    return'<div onclick="filterFortiInventory(&apos;'+label+'&apos;)" title="Click to filter — click again to clear" style="cursor:pointer;flex:1;min-width:130px;background:#fff;border:2px solid '+(active?'#DA291C':'#e2e8f0')+';border-radius:10px;padding:16px;text-align:center;transition:border-color .15s">'
      +'<div style="font-size:30px;font-weight:900;color:#DA291C">'+counts[label]+'</div>'
      +'<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-top:4px">'+e(label)+'</div>'
    +'</div>';
  }).join('')
  +'<div style="flex-basis:100%;font-size:10px;color:#94a3b8;margin-top:6px">Best-effort name/tag match against the scanned compute inventory — not an authoritative device-type field.</div>';
  var shown=_fortiInventoryFilter?inv.filter(function(r){return r.label===_fortiInventoryFilter;}):[];
  if(!invEl)return;
  if(!shown.length){invEl.innerHTML='';return}
  var rowsHtml=shown.map(function(r){
    return'<tr><td>'+cloud(r.cloud)+'</td><td class="p">'+e(r.label)+'</td>'
      +'<td class="p" style="font-family:monospace">'+e(r.name||'—')+'</td>'
      +'<td class="p" style="font-family:monospace">'+e(r.resourceId||'—')+'</td></tr>';
  }).join('');
  invEl.innerHTML='<div style="padding:8px 0;font-size:11px;color:#64748b">Filtered to <b>'+e(_fortiInventoryFilter)+'</b> — <a href="#" onclick="event.preventDefault();filterFortiInventory(&apos;'+_fortiInventoryFilter+'&apos;)" style="color:#DA291C;font-weight:700">clear filter</a></div>'
    +'<div class="tbl-wrap"><table><thead><tr><th>Cloud</th><th>Product</th><th>Name</th><th>Resource ID</th></tr></thead><tbody>'+rowsHtml+'</tbody></table></div>';
}
function renderFortiGate(d){
  _fortiInventory=((d&&d.fortiInventory)||[]);
  renderFortiGateTilesUI();
  var rows=((d&&d.exposurePaths&&d.exposurePaths.fortigate)||[]);
  if(!rows.length){setCount('cnt-fortigate',_fortiInventory.length,false);state('body-fortigate','','No FortiGate VMs detected via FortiCNAPP Attack Path Analysis');return}
  setCount('cnt-fortigate',_fortiInventory.length,false);
  var rowsHtml=rows.map(function(r){
    var t=r.TARGET||{};
    var name=(t.tags&&t.tags.Name)||t.displayName||(t.key&&(t.key.id||t.key.arn))||'—';
    var hopN=r.METRICS&&r.METRICS.path_length;
    return'<tr>'
      +'<td>'+cloud((r.PROVIDER_TYPE||'').toLowerCase())+'</td>'
      +'<td class="p">'+e(String(r.DOMAIN_ID||'—'))+'</td>'
      +'<td class="p" style="font-family:monospace">'+e(String(name))+'</td>'
      +'<td><span style="font-size:9px;font-family:monospace;font-weight:600;color:#15803d;background:#f0fdf4;border:1px solid #86efac;border-radius:3px;padding:1px 6px" title="Verified via FortiCNAPP Attack Path Analysis">'+exposurePathHopsStr(r)+(hopN?' &nbsp;('+hopN+' hops)':'')+'</span></td>'
      +'<td class="m">'+fmtDate(r.RECORD_CREATED_TIME)+'</td>'
    +'</tr>';
  }).join('');
  setBody('body-fortigate','<div class="tbl-wrap"><table><thead><tr><th>Cloud</th><th>Domain / Account</th><th>Target</th><th>Verified Internet Path</th><th>First Seen</th></tr></thead><tbody>'+rowsHtml+'</tbody></table></div>');
}

// ── Internet Accessible Ressources — unfiltered LW_APA_EXPOSURE_PATHS, every target type except
// 'fortigate' (that type has its own dedicated FortiGate panel — see renderFortiGate()),
// TARGETS left as its raw array (one path record can carry more than one target).
// Comprehensive superset of the type-specific panels (Host Internet Exposure, Public
// Storage Exposure) — purely additive, no effect on posture score or any other panel.
var EXPOSED_ASSET_TYPE_LABELS={
  's3:bucket':'S3 Bucket','ec2:instance':'EC2 Instance',
  'microsoft.compute/virtualmachines':'Azure VM',
  'microsoft.storage/storageaccounts/blobservices':'Azure Blob Storage',
};
function exposedAssetTypeLabel(t){return EXPOSED_ASSET_TYPE_LABELS[t]||t||'Unknown';}
// Flattened {rec,target} rows from the last render — kept so tile clicks can re-filter the
// table instantly without touching cached API data or re-fetching.
var _exposedAssetsRows=[];
var _exposedAssetsFilter=null; // active tile label, or null for "all"
function filterExposedAssets(label){
  _exposedAssetsFilter=(_exposedAssetsFilter===label)?null:label; // click active tile again to clear
  renderExposedAssetsUI();
}
function renderExposedAssetsUI(){
  var rows=_exposedAssetsRows;
  var tilesEl=document.getElementById('exposed-assets-tiles');
  if(!rows.length){
    setCount('cnt-exposed-assets',0,false);
    if(tilesEl)tilesEl.innerHTML='';
    state('body-exposed-assets','','No internet-exposed assets detected via FortiCNAPP Attack Path Analysis');
    return;
  }
  var counts={};
  rows.forEach(function(x){var lbl=exposedAssetTypeLabel(x.target&&x.target.type);counts[lbl]=(counts[lbl]||0)+1;});
  var order=Object.keys(counts).sort(function(a,b){return counts[b]-counts[a];});
  if(_exposedAssetsFilter&&order.indexOf(_exposedAssetsFilter)===-1)_exposedAssetsFilter=null; // stale filter (data refreshed)
  var shown=_exposedAssetsFilter?rows.filter(function(x){return exposedAssetTypeLabel(x.target&&x.target.type)===_exposedAssetsFilter;}):rows;
  setCount('cnt-exposed-assets',shown.length,true);
  if(tilesEl)tilesEl.innerHTML=order.map(function(label){
    var active=label===_exposedAssetsFilter;
    return'<div onclick="filterExposedAssets(&apos;'+label+'&apos;)" title="Click to filter — click again to clear" style="cursor:pointer;flex:1;min-width:130px;background:#fff;border:2px solid '+(active?'#DA291C':'#e2e8f0')+';border-radius:10px;padding:16px;text-align:center;transition:border-color .15s">'
      +'<div style="font-size:30px;font-weight:900;color:#DA291C">'+counts[label]+'</div>'
      +'<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-top:4px">'+e(label)+'</div>'
    +'</div>';
  }).join('');
  var rowsHtml=shown.map(function(x){
    var r=x.rec,t=x.target||{};
    var name=(t.tags&&t.tags.Name)||t.displayName||(t.key&&(t.key.id||t.key.arn))||'—';
    var hopN=r.METRICS&&r.METRICS.path_length;
    return'<tr>'
      +'<td>'+cloud((r.PROVIDER_TYPE||'').toLowerCase())+'</td>'
      +'<td class="p">'+e(String(r.DOMAIN_ID||'—'))+'</td>'
      +'<td class="p">'+e(exposedAssetTypeLabel(t.type))+'</td>'
      +'<td class="p" style="font-family:monospace">'+e(String(name))+'</td>'
      +'<td><span style="font-size:9px;font-family:monospace;font-weight:600;color:#15803d;background:#f0fdf4;border:1px solid #86efac;border-radius:3px;padding:1px 6px" title="Verified via FortiCNAPP Attack Path Analysis">'+exposurePathHopsStr(r)+(hopN?' &nbsp;('+hopN+' hops)':'')+'</span></td>'
      +'<td class="m">'+fmtDate(r.RECORD_CREATED_TIME)+'</td>'
    +'</tr>';
  }).join('');
  var filterNote=_exposedAssetsFilter?'<div style="padding:8px 4px;font-size:11px;color:#64748b">Filtered to <b>'+e(_exposedAssetsFilter)+'</b> — <a href="#" onclick="event.preventDefault();filterExposedAssets(&apos;'+_exposedAssetsFilter+'&apos;)" style="color:#DA291C;font-weight:700">clear filter</a></div>':'';
  setBody('body-exposed-assets',filterNote+'<div class="tbl-wrap"><table><thead><tr><th>Cloud</th><th>Domain / Account</th><th>Type</th><th>Target</th><th>Verified Internet Path</th><th>First Seen</th></tr></thead><tbody>'+rowsHtml+'</tbody></table></div>');
}
function renderExposedAssets(d){
  var records=((d&&d.exposurePaths&&d.exposurePaths.all)||[]);
  var rows=[];
  records.forEach(function(r){
    (r.TARGETS||[]).forEach(function(t){if(t.type!=='fortigate')rows.push({rec:r,target:t});});
  });
  _exposedAssetsRows=rows;
  renderExposedAssetsUI();
}

// ── Attack Paths — LW_APA_ATTACK_PATHS ──────────────────────────────────────────
// Confirmed against a live tenant: METRICS.path_score (0-100) + METRICS.path_severity
// ("LOW"/"MEDIUM"/"HIGH"/"CRITICAL" presumably). Filtered to path_score >= 80.
function attackPathRiskScore(rec){
  var v=rec&&rec.METRICS&&rec.METRICS.path_score;
  return typeof v==='number'?v:null;
}
var _attackPathRecords=[];
var _attackPathFilter=null;
function filterAttackPaths(label){
  _attackPathFilter=(_attackPathFilter===label)?null:label;
  renderAttackPathsUI();
}
function renderAttackPathsUI(){
  var records=_attackPathRecords;
  var tilesEl=document.getElementById('attack-paths-tiles');
  if(!records.length){
    setCount('cnt-attack-paths',0,false);
    if(tilesEl)tilesEl.innerHTML='';
    state('body-attack-paths','','No attack paths with risk score ≥ 80');
    return;
  }
  var counts={};
  records.forEach(function(r){var sev=(r.METRICS&&r.METRICS.path_severity)||'Unknown';counts[sev]=(counts[sev]||0)+1;});
  var sevOrder=['CRITICAL','HIGH','MEDIUM','LOW'];
  var order=Object.keys(counts).sort(function(a,b){
    var ai=sevOrder.indexOf(a),bi=sevOrder.indexOf(b);
    if(ai===-1&&bi===-1)return counts[b]-counts[a];
    if(ai===-1)return 1; if(bi===-1)return -1;
    return ai-bi;
  });
  if(_attackPathFilter&&order.indexOf(_attackPathFilter)===-1)_attackPathFilter=null;
  var sevColor={CRITICAL:'#DA291C',HIGH:'#CC4A1A',MEDIUM:'#B7770D',LOW:'#2C5280'};
  if(tilesEl)tilesEl.innerHTML=order.map(function(label){
    var active=label===_attackPathFilter;
    var col=sevColor[label]||'#64748b';
    return'<div onclick="filterAttackPaths(&apos;'+label+'&apos;)" title="Click to filter — click again to clear" style="cursor:pointer;flex:1;min-width:130px;background:#fff;border:2px solid '+(active?col:'#e2e8f0')+';border-radius:10px;padding:16px;text-align:center;transition:border-color .15s">'
      +'<div style="font-size:30px;font-weight:900;color:'+col+'">'+counts[label]+'</div>'
      +'<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.04em;margin-top:4px">'+e(label)+'</div>'
    +'</div>';
  }).join('');
  var shown=_attackPathFilter?records.filter(function(r){return((r.METRICS&&r.METRICS.path_severity)||'Unknown')===_attackPathFilter;}):records;
  setCount('cnt-attack-paths',shown.length,true);
  var rowsHtml=shown.map(function(r){
    var targets=(r.TARGETS||[]).map(function(t){return(t.tags&&t.tags.Name)||t.displayName||(t.key&&(t.key.id||t.key.arn))||t.type||'—';});
    var hopN=r.METRICS&&r.METRICS.path_length;
    var rs=attackPathRiskScore(r);
    var sevLabel=(r.METRICS&&r.METRICS.path_severity)||'';
    return'<tr>'
      +'<td>'+cloud((r.PROVIDER_TYPE||'').toLowerCase())+'</td>'
      +'<td class="p">'+e(String(r.DOMAIN_ID||'—'))+'</td>'
      +'<td class="p" style="font-family:monospace">'+e(targets.join(', ')||'—')+'</td>'
      +'<td class="p"><b>'+e(String(rs))+'</b>'+(sevLabel?' <span style="font-size:9px;font-weight:700;color:#b91c1c">'+e(sevLabel)+'</span>':'')+'</td>'
      +'<td><span style="font-size:9px;font-family:monospace;font-weight:600;color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:3px;padding:1px 6px" title="FortiCNAPP Attack Path Analysis">'+exposurePathHopsStr(r)+(hopN?' &nbsp;('+hopN+' hops)':'')+'</span></td>'
      +'<td class="m">'+fmtDate(r.RECORD_CREATED_TIME)+'</td>'
    +'</tr>';
  }).join('');
  var filterNote=_attackPathFilter?'<div style="padding:8px 4px;font-size:11px;color:#64748b">Filtered to <b>'+e(_attackPathFilter)+'</b> — <a href="#" onclick="event.preventDefault();filterAttackPaths(&apos;'+_attackPathFilter+'&apos;)" style="color:#DA291C;font-weight:700">clear filter</a></div>':'';
  setBody('body-attack-paths',filterNote+'<div class="tbl-wrap"><table><thead><tr><th>Cloud</th><th>Domain / Account</th><th>Targets</th><th>Risk Score</th><th>Path</th><th>First Seen</th></tr></thead><tbody>'+rowsHtml+'</tbody></table></div>');
}
function renderAttackPaths(d){
  var all=((d&&d.attackPaths)||[]);
  _attackPathRecords=all.filter(function(r){var rs=attackPathRiskScore(r);return rs!=null&&rs>=80;})
    .sort(function(a,b){return(attackPathRiskScore(b)||0)-(attackPathRiskScore(a)||0);});
  renderAttackPathsUI();
}

// ── Internet Exposed Host ────────────────────────────────────────────────────
// Test methodology for comparison against the existing panels — NOT wired into posture
// score, alerts, or any other panel. Filter: verified internet-exposed hosts only, CVE risk
// score >= 9 (hard cutoff, no partial credit below), enriched with Critical misconfigs,
// secrets, and high-permission attached IAM role (AWS instance-profile name matched to a
// role identity by name — a heuristic, not a guaranteed 1:1; Azure/GCP not implemented,
// no managed-identity/service-account linkage data is fetched for those clouds yet).
// Shared with _renderVulns() (Private Host Most Exposed) so the same host never appears in
// both panels at once. Pure/stateless — recomputes the "Internet Exposed Host" qualifying
// set (Host Risk Score >= 7 + Lacework's raw, unverified Internet Exposed tag — see the
// methodology note in _renderInternetHostExposedBeta below) fresh each call, independent of
// render order. Returns a lowercased-hostname lookup map, not an array.
function iehbQualifyingHostSet(d){
  var scores={};
  ((d&&d.highRiskVulns)||[]).forEach(function(r){
    var mt=r.machineTags;
    var mtObj=(mt&&typeof mt==='object'&&!Array.isArray(mt))?mt:null;
    if(!mtObj)return;
    var exposedRaw=mtObj.lw_InternetExposureRaw!=null?mtObj.lw_InternetExposureRaw:mtObj.lw_InternetExposure;
    if(exposedRaw!=='Yes')return;
    var h=mtObj.Hostname||(r.evalCtx&&r.evalCtx.hostname)||r.mid||'';
    if(!h)return;
    var hl=h.toLowerCase();
    var hrs=parseFloat(r.hostRiskScore??0);
    if(!(hl in scores)||hrs>scores[hl])scores[hl]=hrs;
  });
  var set={};
  Object.keys(scores).forEach(function(hl){if(scores[hl]>=7)set[hl]=true;});
  return set;
}
function renderInternetHostExposedBeta(d){
  try{_renderInternetHostExposedBeta(d);}catch(ex){state('body-iehb','','Internet Exposed Host render error: '+ex.message);console.error('[renderInternetHostExposedBeta]',ex);}
}
function _renderInternetHostExposedBeta(d){
  d=d||{};
  // highRiskVulns (cveRiskScore>=9, ANY severity — see fetchHighRiskVulns) is used instead
  // of the narrower d.vulns (Critical/High severity + cveRiskScore>=8 only — see
  // fetchVulns), because a host can carry a cveRiskScore>=9 finding that Lacework itself
  // doesn't label Critical/High, which d.vulns would silently drop before it ever reaches
  // this panel.
  var vulns=d.highRiskVulns||[];
  var instanceIamProfile=d.instanceIamProfile||{};

  // ── Matches the FortiCNAPP console's own "Hosts" query exactly:
  //   Hosts > Risk score >= 7             — host.hostRiskScore (Lacework's composite
  //                                          per-machine score), NOT the per-CVE score
  //   Vulnerability observation > status is Vulnerable — guaranteed by fetchVulns()/
  //                                          fetchHighRiskVulns() (status:'Active' filter
  //                                          server-side)
  //   Hosts > Machine status in (Online, Launched)      — guaranteed by fetchVulns()'s
  //                                          own OFFLINE_RE exclusion
  //   Hosts > Internet exposed is True    — mtObj.lw_InternetExposureRaw, Lacework's own
  //                                          raw/topological tag, deliberately NOT the
  //                                          app's stricter verified (SG/NSG/FW-rule)
  //                                          signal used everywhere else — this panel
  //                                          exists specifically to compare against the
  //                                          console's own methodology, and the two can
  //                                          disagree (a host can be raw-tagged exposed
  //                                          without an open wildcard rule we can verify).
  // Same per-host grouping shape as the Private Host Most Exposed panel (_renderVulns).
  var hostMap={};
  vulns.forEach(function(r){
    var mt=r.machineTags;
    var mtObj=(mt&&typeof mt==='object'&&!Array.isArray(mt))?mt:null;
    var exposedRaw=mtObj?(mtObj.lw_InternetExposureRaw!=null?mtObj.lw_InternetExposureRaw:mtObj.lw_InternetExposure):null;
    if(!mtObj||exposedRaw!=='Yes')return;
    var h=mtObj.Hostname||(r.evalCtx&&r.evalCtx.hostname)||r.mid||'?';
    if(!hostMap[h]){
      var cloudRaw=mtObj.VmProvider||'';
      var cloud=cloudRaw?cloudRaw.toLowerCase():'';
      if(cloud==='google')cloud='gcp';
      hostMap[h]={name:h,pubIp:mtObj.ExternalIp||mtObj.PublicIp||mtObj.publicIp||'',cloud:cloud,
        instanceId:mtObj.InstanceId||'',resourceName:mtObj.Name||'',
        vulns:[],maxRisk:0,hostRiskScore:0,crit:0,exposureEvidence:r._exposureEvidence||null};
    }
    var host=hostMap[h];
    var rs=parseFloat(r.cveRiskScore??r.riskScore??0);
    if(rs>host.maxRisk)host.maxRisk=rs;
    var hrs=parseFloat(r.hostRiskScore??0);
    if(hrs>host.hostRiskScore)host.hostRiskScore=hrs;
    if((r.severity||'').toLowerCase()==='critical')host.crit++;
    host.vulns.push(r);
  });
  var hosts=Object.values(hostMap).filter(function(h){return h.hostRiskScore>=7;}).sort(function(a,b){return b.hostRiskScore-a.hostRiskScore;});

  if(!hosts.length){setCount('cnt-iehb',0,false);state('body-iehb','','No internet-exposed hosts with a Host Risk Score ≥ 7 were found');return}
  setCount('cnt-iehb',hosts.length,true);

  // ── Same correlated-risk map + Verified Path lookup the Host Internet Exposure panel
  // uses, reused as-is so the two panels agree on secrets/misconfig/CIEM numbers ──
  var _arm=buildAssetRiskMap(d);
  var _arMap=_arm.map, _arCritMisc=_arm.critMisc;
  function arTierOf(score,exposed){
    if(score>=75)return exposed?{l:'CRITICAL',c:'#b91c1c',bd:'#fca5a5'}:{l:'MEDIUM',c:'#92400e',bd:'#fcd34d'};
    if(score>=50)return exposed?{l:'HIGH',c:'#c2410c',bd:'#fdba74'}:{l:'LOW',c:'#4b5563',bd:'#d1d5db'};
    if(score>=30)return{l:'MEDIUM',c:'#92400e',bd:'#fcd34d'};
    return{l:'LOW',c:'#4b5563',bd:'#d1d5db'};
  }
  var _epRaw=d.exposurePaths||{};
  var _epByInstance={};
  (_epRaw.ec2||[]).forEach(function(r){var id=r.TARGET&&r.TARGET.key&&r.TARGET.key.id;if(!id)return;(_epByInstance[id]=_epByInstance[id]||[]).push(r);});
  var _epByAzureVm={};
  (_epRaw.azureVm||[]).forEach(function(r){var nm=r.TARGET&&r.TARGET.displayName;if(!nm)return;var k=nm.toLowerCase();(_epByAzureVm[k]=_epByAzureVm[k]||[]).push(r);});
  function exposurePathChips(epRecs){
    if(!epRecs||!epRecs.length)return'';
    var shown=epRecs.slice(0,2).map(function(rec){
      var hopN=rec.METRICS&&rec.METRICS.path_length;
      return'<span style="font-size:9px;font-family:monospace;font-weight:600;color:#15803d;background:#f0fdf4;border:1px solid #86efac;border-radius:3px;padding:1px 6px" title="Verified via FortiCNAPP Attack Path Analysis">'
        +'<b>Verified Path</b> &nbsp;'+exposurePathHopsStr(rec)+(hopN?' &nbsp;('+hopN+' hops)':'')+'</span>';
    }).join('');
    var more=epRecs.length>2?'<span style="font-size:9px;color:var(--muted)">+'+(epRecs.length-2)+' more</span>':'';
    return shown+more;
  }

  // ── Non-Compliance violations matched to host, same JSON-substring approach as the
  // Host Internet Exposure panel ──
  var _compMatch={};
  hosts.forEach(function(h){_compMatch[h.name.toLowerCase()]=[];});
  (d.compliance||[]).forEach(function(c){
    if(!Array.isArray(c.resources)||!c.resources.length)return;
    var resJson=JSON.stringify(c.resources).toLowerCase();
    Object.keys(_compMatch).forEach(function(hn){if(resJson.indexOf(hn)>=0)_compMatch[hn].push(c);});
  });

  // ── High-permission attached IAM role (AWS only — new, not part of the existing panel).
  // Instance-profile name matched to a role identity by name; heuristic, not guaranteed 1:1. ──
  function isHighPermissive(r){
    var risks=(r.METRICS&&r.METRICS.risks)||[];
    var sev=((r.METRICS&&r.METRICS.risk_severity)||'').toLowerCase();
    return risks.indexOf('ALLOWS_FULL_ADMIN')!==-1||risks.indexOf('EXCESSIVE_PERMISSIONS')!==-1||sev==='critical'||sev==='high';
  }
  var identities=d.identities||[];
  hosts.forEach(function(h){
    h.iamRole=null;
    var profile=h.instanceId&&instanceIamProfile[h.instanceId];
    if(!profile)return;
    var match=identities.find(function(r){
      var pid=(r.PRINCIPAL_ID||'').toLowerCase(),nm=(r.NAME||'').toLowerCase(),pn=profile.profileName.toLowerCase();
      return nm===pn||pid.split('/').pop()===pn;
    });
    h.iamRole=match?{name:match.NAME||profile.profileName,highPermissive:isHighPermissive(match)}:{name:profile.profileName,highPermissive:null};
  });

  var html=summaryStripBeta(hosts);

  hosts.forEach(function(host,idx){
    var bodyId='iehb-cve-body-'+idx;
    var n=host.vulns.length;
    var arEntry=_arMap[host.name];
    var arScore=arEntry?arEntry.normalizedScore:0;
    var arTier=arTierOf(arScore,true);
    function arChip(label,col,bd){return'<span style="font-size:9px;font-weight:600;color:'+col+';border:1px solid '+bd+';border-radius:3px;padding:1px 6px;white-space:nowrap">'+label+'</span>';}
    var hasCiemInet=!!(arEntry&&arEntry.ciemSecrets&&arEntry.ciemSecrets.length);

    var ev=host.exposureEvidence;
    var expBadges='';
    if(host.pubIp)expBadges+='<span style="font-size:9px;font-family:monospace;font-weight:700;color:#0369a1;background:#f0f9ff;border:1px solid #bae6fd;border-radius:3px;padding:1px 6px">Public IP '+e(host.pubIp)+'</span>';
    if(ev&&ev.reasons&&ev.reasons.length){
      var seenCtrl={};
      expBadges+=ev.reasons.filter(function(r){var k=r.control+'|'+r.name;if(seenCtrl[k])return false;seenCtrl[k]=1;return true;}).map(function(r){
        var ctrlLabel=r.control==='security group'?'SG':r.control==='NSG rule'?'NSG':'FW';
        return'<span title="'+e(r.protocol+' '+r.port+' from '+r.source)+'" style="font-size:9px;font-weight:600;color:#7c2d12;background:#fff7ed;border:1px solid #fdba74;border-radius:3px;padding:1px 6px;font-family:monospace">'+e(ctrlLabel+': '+r.name)+'</span>';
      }).join('');
    }
    var cloudTagInet=host.cloud?'<span style="font-size:8px;font-weight:800;letter-spacing:.04em;color:#fff;background:'+cspBadgeColor(host.cloud)+';border-radius:3px;padding:1px 6px;vertical-align:middle;margin-left:6px">'+e(host.cloud.toUpperCase())+'</span>':'';
    var epMatch=(host.instanceId&&_epByInstance[host.instanceId])||_epByAzureVm[host.name.toLowerCase()]||null;
    var epChips=exposurePathChips(epMatch);
    // Resource Name (e.g. "my-blogs") leads as the primary identifier when available — much
    // easier to identify at a glance than the raw hostname; hostname moves to the subtitle line.
    var primaryLabel=host.resourceName||host.name;
    var idNameLine=(host.resourceName?'<span style="font-size:9px;font-family:monospace;color:var(--muted)">Hostname <b style="color:var(--text)">'+e(host.name)+'</b></span>':'')
      +(host.instanceId?'<span style="font-size:9px;font-family:monospace;color:var(--muted)">Resource ID <b style="color:var(--text)">'+e(host.instanceId)+'</b></span>':'');
    var iamBadge=host.iamRole
      ?(host.iamRole.highPermissive===true
        ?'<span style="font-size:9px;font-weight:700;color:#fff;background:#DA291C;border-radius:3px;padding:1px 6px" title="'+e(host.iamRole.name)+'">High-Perm IAM Role</span>'
        :host.iamRole.highPermissive===false
          ?'<span style="font-size:9px;font-weight:600;color:#15803d;background:#f0fdf4;border:1px solid #86efac;border-radius:3px;padding:1px 6px" title="'+e(host.iamRole.name)+'">IAM Role (not high-perm)</span>'
          :'<span style="font-size:9px;color:var(--muted)" title="Instance profile: '+e(host.iamRole.name)+'">IAM role unresolved</span>')
      :'';

    // ── Asset-detail card layout (per newHostInterExposure.png reference) — left panel:
    // asset identity + details + cloud context; right panel: security-findings summary +
    // actions. The full CVE table stays as the "View all findings" expansion below,
    // reusing the existing toggle-host-cve/bodyId collapsible rather than rebuilding it.
    var cloudFullName={aws:'Amazon Web Services',azure:'Microsoft Azure',gcp:'Google Cloud Platform'}[host.cloud]||'Cloud Provider';
    var cloudIconColor=cspBadgeColor(host.cloud);
    // Confirmed live field names per cloud — Azure carries no SubnetId/ResourceGroup in
    // machineTags at all (only AWS does), and VpcId is actually populated for Azure too
    // (the VNet name, e.g. "DMZ-VNET") — so label/value must be paired per-cloud, not
    // via a generic fallback chain that would show an Azure VNet under an "AWS Subnet" label.
    var rawTags=(host.vulns[0]&&host.vulns[0].machineTags)||{};
    var zone=rawTags.Zone||'—';
    var netLabel=host.cloud==='azure'?'VNet':'VPC';
    var netVal=rawTags.VpcId||'—';
    var acctLabel=host.cloud==='azure'?'Subscription':(host.cloud==='gcp'?'Project':'Subnet');
    var acctVal=host.cloud==='azure'?(rawTags.SubscriptionName||rawTags.SubscriptionId||'—'):(rawTags.SubnetId||rawTags.ProjectId||'—');

    function detailRow(label,val){
      if(!val||val==='—')return'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:11px"><span style="color:#94a3b8">'+e(label)+'</span><span style="color:#cbd5e1">—</span></div>';
      return'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #f1f5f9;font-size:11px">'
        +'<span style="color:#94a3b8">'+e(label)+'</span>'
        +'<span style="display:flex;align-items:center;gap:4px;font-family:monospace;font-weight:600;color:#1e293b;text-align:right;word-break:break-all">'+e(val)+'<button class="cp-btn" data-cp="'+e(val)+'" style="flex-shrink:0">'+cpIcon+'</button></span>'
      +'</div>';
    }
    function contextChip(label,val){
      return'<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:6px 8px;font-size:10px;min-width:0">'
        +'<div style="color:#94a3b8;font-weight:600;text-transform:uppercase;letter-spacing:.03em;font-size:8.5px;margin-bottom:2px">'+e(label)+'</div>'
        +'<div style="color:#1e293b;font-weight:600;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+e(val)+'">'+e(val)+'</div>'
      +'</div>';
    }

    // Findings list — same signals as the badge row before, reframed as finding cards.
    var findings=[];
    if(ev&&ev.reasons&&ev.reasons.length){
      var seenCtrl2={};
      ev.reasons.filter(function(r){var k=r.control+'|'+r.name;if(seenCtrl2[k])return false;seenCtrl2[k]=1;return true;}).forEach(function(r){
        findings.push({title:'Security group allows '+(r.protocol||'traffic')+' '+(r.port||'')+' from '+(r.source||'public internet'),sev:'CRITICAL',cat:'Network Exposure'});
      });
    }
    if(host.pubIp)findings.push({title:'Instance has a public IP address ('+host.pubIp+')',sev:'CRITICAL',cat:'Network Exposure'});
    if(hasCiemInet)findings.push({title:arEntry.ciemSecrets.length+' exposed CIEM credential'+(arEntry.ciemSecrets.length!==1?'s':'')+' on this host',sev:'CRITICAL',cat:'Credential Exposure'});
    if(arEntry&&arEntry.genericSecrets&&arEntry.genericSecrets.length)findings.push({title:arEntry.genericSecrets.length+' exposed secret'+(arEntry.genericSecrets.length!==1?'s':'')+' on this host',sev:'HIGH',cat:'Credential Exposure'});
    if(host.iamRole&&host.iamRole.highPermissive===true)findings.push({title:'Attached IAM role ('+host.iamRole.name+') grants high-permission access',sev:'HIGH',cat:'Identity & Access'});
    host.vulns.slice().sort(function(a,b){return(parseFloat(b.cveRiskScore||b.riskScore||0))-(parseFloat(a.cveRiskScore||a.riskScore||0));}).slice(0,3).forEach(function(r){
      var rs=parseFloat(r.cveRiskScore||r.riskScore||0);
      findings.push({title:(r.vulnId||r.cveId||'CVE')+' — '+((r.featureKey&&r.featureKey.name)||'package')+' (risk '+rs.toFixed(1)+')',sev:rs>=9.5?'CRITICAL':'HIGH',cat:'Vulnerability Management'});
    });
    var findingsShown=findings.slice(0,4);
    var sevStyle={CRITICAL:{c:'#b91c1c',bg:'#fef2f2',bd:'#fecaca'},HIGH:{c:'#c2410c',bg:'#fff7ed',bd:'#fdba74'}};
    function findingCard(f){
      var s=sevStyle[f.sev]||sevStyle.HIGH;
      return'<div style="display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border:1px solid '+s.bd+';border-left:3px solid '+s.c+';background:'+s.bg+';border-radius:6px;margin-bottom:6px">'
        +'<span style="color:'+s.c+';font-size:13px;line-height:1.3">&#9888;</span>'
        +'<div style="min-width:0;flex:1">'
          +'<div style="font-size:11px;font-weight:700;color:#1e293b;word-break:break-word">'+e(f.title)+'</div>'
          +'<div style="margin-top:2px"><span style="font-size:8.5px;font-weight:800;color:'+s.c+';background:#fff;border:1px solid '+s.bd+';border-radius:3px;padding:0 5px">'+f.sev+'</span> <span style="font-size:9.5px;color:#94a3b8">&middot; '+e(f.cat)+'</span></div>'
        +'</div>'
      +'</div>';
    }

    html+='<div style="border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;margin-bottom:16px;background:#fff">'
      +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:0">'
        // ── LEFT: asset panel ──
        +'<div style="padding:18px;border-right:1px solid #e2e8f0">'
          +'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">'
            +'<div style="width:42px;height:42px;border-radius:9px;background:'+cloudIconColor+';display:flex;align-items:center;justify-content:center;flex-shrink:0"><span style="color:#fff;font-weight:900;font-size:11px;letter-spacing:.02em">'+e((host.cloud||'').toUpperCase()||'?')+'</span></div>'
            +'<div style="min-width:0">'
              +'<div style="font-size:15px;font-weight:800;color:#0f172a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+e(primaryLabel)+'</div>'
              +'<div style="font-size:10.5px;color:#94a3b8">'+e(cloudFullName)+'</div>'
            +'</div>'
          +'</div>'
          +'<span style="display:inline-flex;align-items:center;gap:4px;font-size:9.5px;font-weight:800;letter-spacing:.05em;color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:20px;padding:3px 10px">&#9888; INTERNET EXPOSED</span>'
          +' <span style="display:inline-flex;align-items:center;gap:4px;font-size:9.5px;font-weight:800;letter-spacing:.05em;color:#92400e;background:#fffbeb;border:1px solid #fcd34d;border-radius:20px;padding:3px 10px">Host Risk Score '+host.hostRiskScore.toFixed(1)+'</span>'
          +(epChips?'<div style="margin-top:8px">'+epChips+'</div>':'')
          +'<div style="margin-top:16px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-bottom:2px">Asset Details</div>'
          +detailRow('Hostname',host.name)
          +detailRow('Resource ID',host.instanceId)
          +detailRow('Public IP',host.pubIp)
          +'<div style="margin-top:14px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-bottom:6px">Cloud Context</div>'
          +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">'
            +contextChip('Zone',zone)+contextChip(netLabel,netVal)
            +contextChip(acctLabel,acctVal)
            +contextChip('IAM Role',host.iamRole?host.iamRole.name:'None attached')
          +'</div>'
        +'</div>'
        // ── RIGHT: findings + actions panel ──
        +'<div style="padding:18px">'
          +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'
            +'<div style="display:flex;align-items:center;gap:8px">'
              +'<span style="font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#374151">Security Findings</span>'
              +'<span style="font-size:10px;font-weight:800;color:#fff;background:#DA291C;border-radius:10px;padding:1px 8px;min-width:16px;text-align:center">'+findings.length+'</span>'
            +'</div>'
            +'<button class="toggle-host-cve" data-body="'+bodyId+'" data-n="'+n+'" style="font-size:10px;font-weight:700;color:#DA291C;background:none;border:none;cursor:pointer;padding:0">View all findings &rsaquo;</button>'
          +'</div>'
          +(findingsShown.length?findingsShown.map(findingCard).join(''):'<div style="font-size:11px;color:#94a3b8">No specific findings enriched — see full CVE list below.</div>')
          +(findings.length>findingsShown.length?'<div style="font-size:10px;color:#94a3b8;margin-top:2px">+'+(findings.length-findingsShown.length)+' more in full list</div>':'')
          +'<div style="margin-top:14px;font-size:9.5px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;color:#94a3b8;margin-bottom:8px">Actions</div>'
          +'<div style="display:flex;gap:8px;flex-wrap:wrap">'
            +'<button class="goto-host-card-btn" data-hostname="'+e(host.name)+'" data-resourcename="'+e(host.resourceName||'')+'" style="font-size:11px;font-weight:700;color:#fff;background:#DA291C;border:none;border-radius:6px;padding:7px 14px;cursor:pointer">&#9651; Investigate</button>'
            +'<button class="mach-inv-btn" data-hostname="'+e(host.name)+'" style="font-size:11px;font-weight:700;color:#374151;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:7px 14px;cursor:pointer">Machine Details</button>'
          +'</div>'
        +'</div>'
      +'</div>'
      +'<div id="'+bodyId+'" style="display:none;padding:16px 18px;border-top:1px solid #e2e8f0;background:#fafafa">'
      +'<div style="font-size:9px;color:var(--muted);margin-bottom:6px">'+n+' CVE'+(n!==1?'s':'')+' &middot; internet-exposed &middot; Host Risk Score '+host.hostRiskScore.toFixed(1)+'</div>'
      +(arScore
        ?'<div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;padding:6px 0;border-bottom:1px solid var(--border);margin-bottom:8px">'
          +'<span style="font-size:9px;color:var(--muted)">Correlated risk</span>'
          +'<span style="font-size:15px;font-weight:800;color:'+arTier.c+';font-variant-numeric:tabular-nums;line-height:1">'+arScore+'</span>'
          +'<span style="font-size:8px;font-weight:700;color:'+arTier.c+';border:1px solid '+arTier.bd+';border-radius:3px;padding:1px 5px">'+arTier.l+'</span>'
          +'<div style="flex:0 0 70px;height:3px;background:#e5e7eb;border-radius:2px"><div style="height:3px;border-radius:2px;background:'+arTier.c+';width:'+arScore+'%"></div></div>'
          +(arEntry&&arEntry.ciemSecrets.length?arChip('CIEM \xb7 '+arEntry.ciemSecrets.length,'#b91c1c','#fca5a5'):'')
          +(arEntry&&arEntry.genericSecrets.length?arChip('SEC \xb7 '+arEntry.genericSecrets.length,'#92400e','#fcd34d'):'')
          +(_arCritMisc?arChip('MISCONF \xb7 '+_arCritMisc,'#4b5563','#d1d5db'):'')
        +'</div>':'')
      +(function(){
        var matched=_compMatch[host.name.toLowerCase()]||[];
        if(!matched.length)return'';
        return'<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px">'
          +'<div style="font-size:9px;font-weight:800;letter-spacing:.07em;color:#b45309;margin-bottom:6px">NON-COMPLIANCE VIOLATIONS ON THIS HOST <span style="font-weight:400;color:var(--muted)">('+matched.length+')</span></div>'
          +matched.map(function(c){
            var cl=e(c.cloud||''),sev=(c.severity||'').toLowerCase();
            return'<div style="padding:6px 0;border-bottom:1px solid var(--border)">'
              +'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">'
                +'<span style="font-size:10.5px;font-weight:600;color:var(--text)">'+e(c.title||c.alertId||'')+'</span>'
                +'<span style="display:flex;gap:4px;flex-shrink:0">'+(cl?'<span class="b b-nt" style="font-size:8px">'+cl.toUpperCase()+'</span>':'')+'<span class="b '+(sev==='critical'?'b-cr':'b-hi')+'" style="font-size:8px">'+(c.severity||'')+'</span></span>'
              +'</div>'
            +'</div>';
          }).join('')
        +'</div>';
      })()
      +'<div class="tbl-wrap"><table style="font-size:11px">'
        +'<thead><tr><th style="width:160px">CVE / Vuln ID</th><th style="width:52px">CVE Risk</th><th>Package · Installed version</th><th>OS / Namespace</th><th>Fix version</th><th></th></tr></thead><tbody>'
        +host.vulns.map(function(r){
          var fix=r.fixInfo&&(r.fixInfo.fix_available===true||String(r.fixInfo.fix_available)==='1');
          var fixVer=(r.fixInfo&&r.fixInfo.fixed_version)||'';
          var cveId=e(r.vulnId||r.cveId||'');
          var svcol=(r.severity||'').toLowerCase()==='critical'?'#b91c1c':'#c2410c';
          return'<tr>'
            +'<td style="white-space:nowrap"><span style="font-family:monospace;font-size:10.5px;font-weight:700;color:'+svcol+'">'+e(r.vulnId||r.cveId||'—')+'</span><button class="cp-btn" data-cp="'+cveId+'" style="margin-left:3px">'+cpIcon+'</button></td>'
            +'<td class="r"><span class="risk-score">'+parseFloat(r.cveRiskScore||r.hostRiskScore||r.riskScore||0).toFixed(1)+'</span></td>'
            +'<td style="font-size:10.5px">'+e(r.featureKey&&r.featureKey.name||'—')+(r.featureKey&&r.featureKey.version_installed?'<br><span style="font-size:9px;color:var(--muted)">'+e(r.featureKey.version_installed)+'</span>':'')+'</td>'
            +'<td style="font-size:10px;color:var(--muted)">'+e(r.featureKey&&r.featureKey.namespace||'—')+'</td>'
            +'<td>'+(fix?'<span class="b b-ok" title="'+e(fixVer)+'">'+e(tr(fixVer,16)||'Fix ✓')+'</span>':'<span class="b b-nt">No fix</span>')+'</td>'
            +'<td style="white-space:nowrap"><button class="cve-det-btn" data-cve="'+cveId+'" style="font-size:9px;padding:1px 6px;border-radius:3px;border:none;cursor:pointer;background:#f97316;color:#fff;font-weight:700;margin-right:3px">Details</button><button class="cp-btn" data-cp="'+cveId+'" title="Copy CVE ID">'+cpIcon+'</button></td>'
          +'</tr>';
        }).join('')
        +'</tbody></table></div>'
      +'</div>'
    +'</div>';
  });

  setBody('body-iehb',html);
}
function summaryStripBeta(hosts){
  var rowsArr=[];hosts.forEach(function(h){rowsArr=rowsArr.concat(h.vulns);});
  var tc=rowsArr.filter(function(r){return(r.severity||'').toLowerCase()==='critical';}).length;
  var th=rowsArr.filter(function(r){return(r.severity||'').toLowerCase()==='high';}).length;
  var tf=rowsArr.filter(function(r){return r.fixInfo&&(r.fixInfo.fix_available===true||String(r.fixInfo.fix_available)==='1');}).length;
  return'<div style="display:flex;gap:8px;padding:10px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center">'
    +'<span style="font-size:11px;font-weight:700;color:var(--text)">'+hosts.length+' Hosts</span>'
    +'<span style="font-size:11px;color:var(--muted)">&middot; '+rowsArr.length+' CVEs</span>'
    +(tc?'<span class="b b-cr">'+tc+' Critical</span>':'')
    +(th?'<span class="b b-hi">'+th+' High</span>':'')
    +(tf?'<span class="b b-ok">'+tf+' fixable</span>':'')
    +'<span style="margin-left:auto;font-size:9px;color:var(--muted)">Internet-exposed &middot; Host Risk Score ≥ 7 &middot; enriched with IAM role (AWS)</span>'
  +'</div>';
}

// ── Identity classification — global so both the Identity tab (renderIdentities) and the
// Risk Findings identities count (buildPie/renderRiskFindings) apply the exact same rule
// instead of two independently-maintained copies drifting apart. ──
// Cross-cloud "root-equivalent" detector — AWS has a literal root account; Azure/GCP
// don't, so the tenant-wide Global Administrator (Entra ID) / Workspace Super Admin
// (GCP) directory roles are the closest analogues (unrestricted control, no per-resource scoping).
// LW_CE_IDENTITIES has no dedicated "assigned role name" field for Azure/GCP, so this
// matches on NAME/PRINCIPAL_ID text the same way the existing AWS root check does.
function rootEquivalent(r){
  const pid=(r.PRINCIPAL_ID||'').toLowerCase();
  const nm=(r.NAME||'').toLowerCase();
  if(pid.includes(':root')||nm==='root')return{label:'AWS Root Account',color:'#dc2626',bg:'#fef2f2',border:'#fecaca'};
  if(nm.includes('global admin')||nm.includes('globaladmin')||pid.includes('globaladmin'))
    return{label:'Azure Global Administrator',color:'#dc2626',bg:'#fef2f2',border:'#fecaca'};
  if(nm.includes('super admin')||nm.includes('superadmin')||pid.includes('superadmin'))
    return{label:'GCP Workspace Super Admin',color:'#dc2626',bg:'#fef2f2',border:'#fecaca'};
  return null;
}
function identType(r){
  const pid=(r.PRINCIPAL_ID||'').toLowerCase();
  const nm=(r.NAME||'').toLowerCase();
  const pt=(r.PROVIDER_TYPE||'').toLowerCase();
  const rootEq=rootEquivalent(r);
  if(rootEq)return rootEq;
  // Real LQL-verified type from LW_CE_LINKED_IDENTITIES.RELATION_TYPE (server-attached
  // as r._lqlType) takes priority over string-pattern guessing below — it's classified
  // data straight from the source, not an ARN/name heuristic. Only covers identities
  // that appear in a linked-identity relationship (e.g. group membership, role chaining);
  // falls through to the heuristics for identities with no such relationship.
  const lqlType=r._lqlType; // {cloud:'AWS'|'AZURE'|'GCP', type:'USER'|'ROLE'|...} or null
  // NOTE: INSTANCE_PROFILE is deliberately NOT mapped to IAM Role here — an ARN-based
  // check further below reliably classifies actual instance profiles as their own
  // 'Instance Profile' type; folding them into 'IAM Role' here would hide them from
  // anything that filters on that distinct type (e.g. the EC2 Instance Profile tab).
  if(lqlType&&lqlType.type==='ROLE')return{label:'IAM Role',color:'#0369a1',bg:'#f0f9ff',border:'#bae6fd'};
  if(lqlType&&lqlType.type==='USER'){
    // Cloud is carried alongside type specifically so an Azure user linked via
    // AZURE_USER_TO_GROUP isn't collapsed into the same bare 'USER' bucket as an
    // AWS IAM user (RELATION_TYPE's own prefix used to be discarded — see lqlTypeMap).
    if(lqlType.cloud==='AZURE')return{label:'Azure User',color:'#0078D4',bg:'#eff6ff',border:'#bfdbfe'};
    if(lqlType.cloud==='GCP')return{label:'User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
    return{label:'IAM User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
  }
  if(lqlType&&lqlType.type==='GOOGLE_ACCOUNT')return{label:'User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
  if(lqlType&&lqlType.type==='SERVICE_ACCOUNT')return lqlType.cloud==='AZURE'
    ?{label:'Azure Service Principal',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'}
    :{label:'Service Account',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'};

  if(pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com'))return{label:'Service Account',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'};
  if(pid.includes(':assumed-role/')||pid.includes('/sts:'))return{label:'Assumed Role',color:'#b45309',bg:'#fffbeb',border:'#fde68a'};
  if(pid.includes(':group/'))return{label:'IAM Group',color:'#be185d',bg:'#fdf2f8',border:'#fbcfe8'};
  if(pid.includes(':instance-profile/'))return{label:'Instance Profile',color:'#0e7490',bg:'#ecfeff',border:'#a5f3fc'};
  // Azure/GCP identities are classified from PROVIDER_TYPE before the AWS-style ARN/name
  // heuristics below — those heuristics (":user/", "user" in name, "role" in name) are
  // AWS-shaped and otherwise misfire on Azure/GCP records whose NAME or PRINCIPAL_ID
  // happens to contain those substrings, mislabeling them as generic AWS types.
  if(pt==='azure'||pt==='gcp'){
    // Azure AD / GCP Workspace human users have PROVIDER_TYPE just 'azure'/'gcp' (no
    // serviceprincipal/aad marker) and no AWS-style ARN — but their PRINCIPAL_ID is an
    // email/UPN (e.g. user@tenant.onmicrosoft.com, user#EXT#@tenant.onmicrosoft.com,
    // user@workspace-domain.com). Any gserviceaccount.com address already matched the
    // Service Account check above, so an '@' here means a real person, not a service.
    if(pid.includes('@'))return pt==='azure'
      ?{label:'Azure User',color:'#0078D4',bg:'#eff6ff',border:'#bfdbfe'}
      :{label:'User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
    // Azure Service Principals / App Registrations (e.g. automation identities like
    // "lacework_security_audit", "azure-cli-*", FortiGate/FortiManager service accounts)
    // have a bare GUID PRINCIPAL_ID with no email — distinct from human Azure AD users,
    // whose ID always contains '@'. No linked-identity relationship is recorded for most
    // of them either (no group membership), so this is the last-resort signal.
    if(pt==='azure'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(pid))
      return{label:'Azure Service Principal',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'};
  }
  if(pid.includes(':role/')||nm.includes('role'))return{label:'IAM Role',color:'#0369a1',bg:'#f0f9ff',border:'#bae6fd'};
  if(pid.includes(':user/')||nm.includes('user'))return{label:'IAM User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
  if(pt.includes('serviceprincipal')||pt.includes('aad'))return{label:'Azure Service Principal',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'};
  if(pt.includes('user'))return{label:'User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
  return{label:'Identity',color:'#475569',bg:'#f8fafc',border:'#e2e8f0'};
}
// ── Admin-only pruning — one uniform rule across all three cloud tabs, and the basis
// for the Risk Findings "Identities" count too. Keep only: (User-type AND Admin) OR
// (IAM-Role-type AND Admin) OR Root/root-equivalent. Everything else — Service Accounts,
// Service Principals, Instance Profiles, Groups, Assumed Roles — is dropped entirely,
// admin or not. Root-equivalents (Global Administrator / Workspace Super Admin) always
// survive even without the explicit ALLOWS_FULL_ADMIN flag — they're inherently the
// top-privilege bucket by definition.
var USER_TYPE_LABELS=['IAM User','Azure User','User'];
var ROLE_TYPE_LABELS=['IAM Role'];
function isAdminIdentity(r){return((r.METRICS&&r.METRICS.risks)||[]).includes('ALLOWS_FULL_ADMIN');}
function pruneToAdmin(cloud,cloudRows){
  return cloudRows.filter(function(r){
    if(rootEquivalent(r))return true;
    if(!isAdminIdentity(r))return false;
    var t=identType(r).label;
    return USER_TYPE_LABELS.indexOf(t)!==-1||ROLE_TYPE_LABELS.indexOf(t)!==-1;
  });
}
// Identities count shown in Risk Findings (donut + inventory table) — same Admin-only
// pruning as the Identity tab, further narrowed to risk_severity Critical only, so the
// number here always matches what a reader would find by opening the Identity tab. Root/
// root-equivalent accounts are explicitly excluded here (never included), even though
// pruneToAdmin() itself always keeps them for the Identity tab — this list is meant to
// surface actionable Admin-privilege User/Role findings, not the account root(s) themselves.
function riskFindingIdentities(identities){
  return pruneToAdmin('all',identities||[]).filter(function(r){
    if(rootEquivalent(r))return false;
    return((r.METRICS&&r.METRICS.risk_severity)||'').toLowerCase()==='critical';
  });
}
// Host Exposure count/list shown in Risk Findings (Overview "Exposure" tile, inventory
// badge, and inventory table row) — single source of truth so all three can't drift apart
// the way they did when only the inventory table's items list got fixed. Sourced from
// highRiskVulns (server-side cveRiskScore>=9, ANY severity — see fetchHighRiskVulns()),
// restricted to hosts that also appear as internet-exposed in the Host Internet Exposure
// tab itself (cache.vulns, Critical/High only) — keeps this list and that tab in agreement
// instead of highRiskVulns' broader any-severity scan surfacing hosts the tab has no entry
// for at all. Threshold is >=9.5, not >=9 (fetchHighRiskVulns()'s own server-side floor) —
// raised per explicit request, kept as a client-side filter on top of the >=9 fetch rather
// than re-querying, since >=9.5 is a strict subset.
function riskFindingHostExposure(d){
  const tabExposedHosts=new Set((d.vulns||[]).filter(r=>{const mt=r.machineTags;const mtObj=(mt&&typeof mt==='object'&&!Array.isArray(mt))?mt:null;return mtObj&&mtObj.lw_InternetExposure==='Yes';}).map(r=>{const mt=r.machineTags;return mt&&mt.Hostname;}).filter(Boolean));
  // >=9.95 rather than the raw 0–10 scale's true max (10) — cveRiskScore in practice never
  // reaches exactly 10 (observed max ~9.98); this is the cutoff where the displayed
  // Math.round(cveRiskScore*10) risk score reads 100, matching what "risk score = 100" means
  // to a reader of the table rather than the underlying float.
  return(d.highRiskVulns||[]).filter(r=>{
    const mt=r.machineTags;
    const mtObj=(mt&&typeof mt==='object'&&!Array.isArray(mt))?mt:null;
    return mtObj&&mtObj.lw_InternetExposure==='Yes'&&tabExposedHosts.has(mtObj.Hostname)&&parseFloat(r.cveRiskScore??r.riskScore??0)>=9.95;
  });
}

function renderIdentities(rows,err){
  const setTab=function(id,html){var el=document.getElementById(id);if(el)el.innerHTML=html;};
  if(err){
    setTab('ibody-aws','<div class="state">'+err+'</div>');
    setTab('ibody-azure','<div class="state">'+err+'</div>');
    setTab('ibody-gcp','<div class="state">'+err+'</div>');
    return;
  }
  setKpi('kpi-i',rows.length);setCount('cnt-i',rows.length,true);
  if(!rows.length){
    const msg='<div class="state">No high-permissive identities found</div>';
    setTab('ibody-aws',msg);setTab('ibody-azure',msg);setTab('ibody-gcp',msg);return;
  }

  function shortName(r){
    const pid=r.PRINCIPAL_ID||'';
    const arnMatch=pid.match(/arn:[^:]+:[^:]+::[^:]*:(?:role|user|group|policy)\\/(.+)/i);
    if(arnMatch)return arnMatch[1];
    const gcpMatch=pid.match(/^([^@]+)@([^.]+)/);
    if(gcpMatch)return gcpMatch[1]+' @ '+gcpMatch[2];
    const azureMatch=pid.match(/\\/([^\\/]+)$/);
    if(azureMatch)return azureMatch[1];
    return r.NAME||pid;
  }

  // ── Risk flag dot definitions — fixed order, shown as circles per row ───────
  var RISK_DEFS=[
    {key:'ALLOWS_FULL_ADMIN',            abbr:'FA',  col:'#b91c1c', title:'Full Admin',              def:'This identity has full administrative access to the entire cloud environment. A single credential compromise gives an attacker unrestricted control over all resources.'},
    {key:'ALLOWS_PRIVILEGE_ESCALATION',  abbr:'PE',  col:'#b91c1c', title:'Privilege Escalation',    def:'This identity can elevate its own permissions or create/modify other identities. An attacker can use it to gain admin-level access from a lower-privilege entry point.'},
    {key:'PASSWORD_LOGIN_NO_MFA',        abbr:'MFA', col:'#c2410c', title:'No MFA',                  def:'Password-based login with no multi-factor authentication. If credentials are phished or leaked, the account can be taken over with no additional barrier.'},
    {key:'EXCESSIVE_PERMISSIONS',        abbr:'EP',  col:'#92400e', title:'Excessive Permissions',   def:'This identity has been granted significantly more permissions than it actually uses. Violates least-privilege — excess rights increase blast radius if compromised.'},
    {key:'CROSS_ACCOUNT_ACCESS',         abbr:'XA',  col:'#7c3aed', title:'Cross-Account Access',    def:'This identity can assume roles or access resources in other cloud accounts. Compromise of this identity could enable lateral movement across your entire organization.'},
    {key:'HAS_CONSOLE_ACCESS',           abbr:'CON', col:'#0369a1', title:'Console Access',          def:'This identity can log in to the cloud management console interactively. Service accounts and machine identities rarely need console access — a human-facing attack surface.'},
    {key:'UNUSED_PERMISSION_90_DAYS',    abbr:'UP',  col:'#4b5563', title:'Unused Permissions 90d',  def:'Permissions granted to this identity have not been used in the past 90 days. Stale permissions represent unnecessary risk — they should be removed per least-privilege.'},
    {key:'UNUSED_ACCESS_KEY_90_DAYS',    abbr:'UK',  col:'#4b5563', title:'Unused Access Key 90d',   def:'An access key (API credential) associated with this identity has not been used in 90+ days. Unused keys should be rotated or revoked to reduce the attack surface.'},
  ];

  function riskDots(risks){
    var rSet={};risks.forEach(function(k){rSet[k]=1;});
    return RISK_DEFS.map(function(d){
      var on=rSet[d.key];
      var bg=on?d.col:'#f3f4f6';var fg=on?'#fff':'#9ca3af';var bd=on?d.col:'#e5e7eb';
      return'<span class="rf-dot" style="background:'+bg+';color:'+fg+';border:1px solid '+bd+';letter-spacing:0">'+d.abbr
        +'<span class="rf-tip"><strong>'+(on?'● ':'○ ')+d.title+'</strong>'+e(d.def)+'</span>'
      +'</span>';
    }).join('');
  }

  function sevBadge(sev){
    var s=(sev||'').toLowerCase();
    if(s==='critical')return'<span class="b b-cr">Critical</span>';
    if(s==='high')return'<span class="b b-hi">High</span>';
    if(s==='medium')return'<span class="b b-me">Medium</span>';
    if(s)return'<span class="b b-nt">'+e(sev)+'</span>';
    return'<span class="b b-nt">—</span>';
  }

  function privBadge(risks){
    var isAdmin=risks.includes('ALLOWS_FULL_ADMIN');
    var noMfa=risks.includes('PASSWORD_LOGIN_NO_MFA')||risks.includes('AWS_ROOT_USER_PASSWORD_LOGIN_NO_MFA');
    if(isAdmin&&noMfa)return'<span style="font-size:10px;font-weight:800;background:#7f1d1d;color:#fff;border-radius:3px;padding:2px 8px;white-space:nowrap">&#9888; ADMIN + NO MFA</span>';
    if(isAdmin)return'<span style="font-size:10px;font-weight:700;background:#fef2f2;color:#b91c1c;border:1px solid #fecaca;border-radius:3px;padding:1px 7px;white-space:nowrap">&#9888; Admin</span>';
    if(risks.includes('ALLOWS_PRIVILEGE_ESCALATION')||risks.includes('EXCESSIVE_PERMISSIONS'))return'<span style="font-size:10px;font-weight:700;background:#fffbeb;color:#b45309;border:1px solid #fde68a;border-radius:3px;padding:1px 7px;white-space:nowrap">Elevated</span>';
    return'<span style="font-size:10px;color:#9ca3af">Standard</span>';
  }
  function identRow(r,idx){
    var risks=(r.METRICS&&r.METRICS.risks)?r.METRICS.risks:[];
    var sev=(r.METRICS&&r.METRICS.risk_severity)||'';
    var unused=(r.ENTITLEMENT_COUNTS&&r.ENTITLEMENT_COUNTS.entitlements_unused_count!=null)?r.ENTITLEMENT_COUNTS.entitlements_unused_count:null;
    var total=(r.ENTITLEMENT_COUNTS&&r.ENTITLEMENT_COUNTS.entitlements_total_count!=null)?r.ENTITLEMENT_COUNTS.entitlements_total_count:null;
    var unusedPct=(unused!==null&&total!==null&&total>0)?Math.min(100,Math.round(unused/total*100)):null;
    var unusedStr=(unusedPct!==null)?(unusedPct+'% unused'):'—';
    var unusedRaw=(unused!==null&&total!==null)?(unused+' / '+total+' unused'):'—';
    var unusedCol=unusedPct!==null?(unusedPct>=80?'#b91c1c':unusedPct>=50?'#c2410c':'#374151'):'#374151';
    var sName=shortName(r);
    var type=identType(r);
    var pid=r.PRINCIPAL_ID||'';
    var keys=Array.isArray(r.ACCESS_KEYS)?r.ACCESS_KEYS:[];
    var activeKeys=keys.filter(function(k){return(k.active||k.status||'').toString().toLowerCase()==='true'||k.active===true;});
    var lastUsed=r.LAST_USED_TIME?fmtDate(r.LAST_USED_TIME):'Never';
    return'<tr data-itype="'+e(type.label)+'">'
      +'<td style="font-size:11px;font-weight:500;color:#9ca3af;font-variant-numeric:tabular-nums;padding-right:4px;width:32px">'+(idx+1)+'</td>'
      +'<td style="max-width:320px">'
        +'<div style="font-weight:600;font-size:12.5px;color:#111827;word-break:break-word;line-height:1.4">'+e(sName)+'</div>'
        +(pid&&pid!==sName?'<div style="font-size:9px;color:#9ca3af;font-family:monospace;word-break:break-all;margin-top:1px;line-height:1.3">'+e(pid)+'</div>':'')
        +'<div style="font-size:10px;color:#6b7280;margin-top:2px">Last used: '+e(lastUsed)+(activeKeys.length?' &middot; '+activeKeys.length+' active key'+(activeKeys.length>1?'s':''):'')+'</div>'
      +'</td>'
      +'<td style="white-space:nowrap">'
        +'<span style="font-size:10px;font-weight:600;background:'+type.bg+';color:'+type.color+';border:1px solid '+type.border+';border-radius:3px;padding:1px 7px">'+e(type.label)+'</span>'
      +'</td>'
      +'<td>'+privBadge(risks)+'</td>'
      +'<td>'+sevBadge(sev)+'</td>'
      +'<td><div style="display:flex;gap:3px;align-items:center;flex-wrap:nowrap">'+riskDots(risks)+'</div></td>'
      +'<td style="font-size:11.5px;font-weight:600;color:'+unusedCol+';font-variant-numeric:tabular-nums;white-space:nowrap" title="'+unusedRaw+'">'+unusedStr+'</td>'
      +'<td style="white-space:nowrap">'
        +'<button class="cp-btn" data-cp="'+e(pid)+'" title="Copy ARN">'+cpIcon+'</button>'
        +'<button class="load-trust-btn" data-pid="'+e(pid)+'" title="Show which principals (accounts, services, users) are trusted to assume this role — lateral movement risk" style="font-size:9px;padding:1px 6px;border-radius:3px;border:1px solid #e5e7eb;background:#f9fafb;color:#374151;cursor:pointer;font-weight:600;margin-left:3px">Who can assume?</button>'
      +'</td>'
    +'</tr>';
  }

  function identTable(tableRows){
    if(!tableRows.length)return'<div class="state">No identities found</div>';
    return'<div class="tbl-wrap"><table>'
      +'<thead><tr>'
        +'<th style="width:32px">#</th>'
        +'<th>Identity name</th>'
        +'<th>Identity type</th>'
        +'<th>Privilege</th>'
        +'<th>Risk severity</th>'
        +'<th>Risk flags <span style="font-size:8px;font-weight:400;opacity:.6">FA PE MFA EP XA CON UP UK</span></th>'
        +'<th title="Percentage of granted permissions never used">Unused %</th>'
        +'<th></th>'
      +'</tr></thead>'
      +'<tbody>'+tableRows.map(identRow).join('')+'</tbody>'
    +'</table></div>';
  }

  var SEV_RANK={critical:0,high:1,medium:2,low:3};
  // Preferred display order for identity-type filter chips — root-equivalents first,
  // then humans, then machine identities, roughly Critical→Low blast-radius order.
  var TYPE_ORDER=['AWS Root Account','Azure Global Administrator','GCP Workspace Super Admin',
    'IAM User','Azure User','User','IAM Group','Azure Service Principal','Service Principal','Service Account','IAM Role','Assumed Role','Instance Profile','Identity'];

  // ── Identity-type filter chip bar — lets the user narrow a cloud tab down to one
  // identity type (IAM Role, IAM User, Service Account, ...) instead of the tab always
  // showing every type at once. Chips are built from whatever types are actually present
  // in this cloud's data; "All" (default) shows everything, matching the tab's full set.
  function typeFilterBarHtml(cloud,cloudRows){
    var typeMeta={};
    cloudRows.forEach(function(r){
      var t=identType(r);
      if(!typeMeta[t.label])typeMeta[t.label]={count:0,color:t.color,bg:t.bg,border:t.border};
      typeMeta[t.label].count++;
    });
    var typeLabels=Object.keys(typeMeta).sort(function(a,b){
      var ia=TYPE_ORDER.indexOf(a); ia=ia===-1?TYPE_ORDER.length:ia;
      var ib=TYPE_ORDER.indexOf(b); ib=ib===-1?TYPE_ORDER.length:ib;
      return ia-ib;
    });
    return '<div class="itype-filter" data-cloud="'+cloud+'" style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;padding:10px 0 4px">'
      +'<span style="font-size:9px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#9ca3af;margin-right:2px">Filter by identity type:</span>'
      +'<button class="itype-chip" data-itype-filter="all" '
        +'style="font-size:10.5px;font-weight:700;padding:3px 10px;border-radius:12px;border:1px solid #0f172a;background:#0f172a;color:#fff;cursor:pointer;opacity:1;box-shadow:0 0 0 2px #0f172a55">All ('+cloudRows.length+')</button>'
      +typeLabels.map(function(t){
        var m=typeMeta[t];
        return '<button class="itype-chip" data-itype-filter="'+e(t)+'" '
          +'style="font-size:10.5px;font-weight:600;padding:3px 10px;border-radius:12px;border:1px solid '+m.border+';background:'+m.bg+';color:'+m.color+';cursor:pointer;opacity:.62">'+e(t)+' ('+m.count+')</button>';
      }).join('')
    +'</div>';
  }

  function cloudGroupHtml(cloud,label){
    var cloudRows=pruneToAdmin(cloud,rows.filter(function(r){return cspOfIdentity(r)===cloud;})).sort(function(a,b){
      // Root accounts first, then no-MFA identities, then Critical→High→Medium→Low, then risk score.
      var aRoot=rootEquivalent(a)?0:1, bRoot=rootEquivalent(b)?0:1;
      if(aRoot!==bRoot)return aRoot-bRoot;
      var risksA=(a.METRICS&&a.METRICS.risks)||[], risksB=(b.METRICS&&b.METRICS.risks)||[];
      var aNoMfa=risksA.includes('PASSWORD_LOGIN_NO_MFA')?0:1, bNoMfa=risksB.includes('PASSWORD_LOGIN_NO_MFA')?0:1;
      if(aNoMfa!==bNoMfa)return aNoMfa-bNoMfa;
      var aSev=SEV_RANK[((a.METRICS&&a.METRICS.risk_severity)||'').toLowerCase()];
      var bSev=SEV_RANK[((b.METRICS&&b.METRICS.risk_severity)||'').toLowerCase()];
      aSev=aSev==null?4:aSev; bSev=bSev==null?4:bSev;
      if(aSev!==bSev)return aSev-bSev;
      return((b.METRICS&&b.METRICS.risk_score)||0)-((a.METRICS&&a.METRICS.risk_score)||0);
    });
    var pruneNote='showing Admin-privilege Users, IAM Roles &amp; Root only';
    var hdr='<div style="padding:6px 0 8px;margin-top:16px;font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#111827;border-bottom:2px solid #11182733;margin-bottom:4px">'+e(label)+' <span style="font-weight:400;color:#9ca3af">('+cloudRows.length+') &middot; '+pruneNote+'</span></div>';
    return hdr+(cloudRows.length?(typeFilterBarHtml(cloud,cloudRows)+identTable(cloudRows)):'<div class="state">No '+e(label)+' found</div>');
  }

  setTab('ibody-aws',   cloudGroupHtml('aws','AWS — Identities'));
  setTab('ibody-azure', cloudGroupHtml('azure','Azure — Identities'));
  setTab('ibody-gcp',   cloudGroupHtml('gcp','GCP — Identities'));
}

// Toggle the identity-type filter within a CSP tab: "all" shows every row, otherwise
// only rows whose identType() label (stamped as data-itype on each <tr>) matches.
// Delegated (not inline onclick) since chip HTML is regenerated on every data refresh.
document.addEventListener('click',function(ev){
  var btn=ev.target.closest('.itype-chip');
  if(!btn)return;
  var bar=btn.closest('.itype-filter');
  if(!bar)return;
  var cloud=bar.getAttribute('data-cloud');
  var type=btn.getAttribute('data-itype-filter');
  Array.prototype.forEach.call(bar.querySelectorAll('.itype-chip'),function(c){
    c.style.opacity='.62';c.style.boxShadow='none';
  });
  btn.style.opacity='1';btn.style.boxShadow='0 0 0 2px #0f172a55';
  var body=document.getElementById('ibody-'+cloud);
  if(!body)return;
  Array.prototype.forEach.call(body.querySelectorAll('tbody tr[data-itype]'),function(tr){
    tr.style.display=(type==='all'||tr.getAttribute('data-itype')===type)?'':'none';
  });
});

function renderSecretsAll(rows,err){
  const el=document.getElementById('t-sa');if(el)el.textContent=rows?rows.length:'—';
  setCount('cnt-sa',rows?rows.length:0,true);
  if(err){state('body-sa','',err);return}
  if(!rows||!rows.length){state('body-sa','','No secrets detected');return}
  // Group by SECRET_TYPE — plain listing of every secret found, no DAC/permission framing.
  const groups={};
  rows.forEach(r=>{
    const cat=r.SECRET_TYPE||'Unknown';
    if(!groups[cat])groups[cat]=[];
    groups[cat].push(r);
  });
  const SECRET_TYPE_LABELS={'SSH_PRIVATE_KEY':'SSH Private Key','SSH_PRIVATE_KEYS':'SSH Private Key','RSA':'SSH Private Key (RSA)','ECDSA':'SSH Private Key (ECDSA)','ED25519':'SSH Private Key (ED25519)','AWS_SECRET_ACCESS_KEY':'AWS Secret Access Key','AWS_ACCESS_KEY':'AWS Secret Access Key','AWS_CREDENTIALS':'AWS Credentials','AWS_SECRET':'AWS Secret Access Key'};
  const displayCat=cat=>SECRET_TYPE_LABELS[cat]||SECRET_TYPE_LABELS[cat.toUpperCase()]||cat;
  const sortedGroups=Object.entries(groups).sort((a,b)=>b[1].length-a[1].length);
  const renderGroup=([cat,items])=>{
    const hdrColor='#0ea5e9',hdrBg='#f0f9ff';
    const rowsHtml=items.map(r=>{
      const inContainer=r.IS_IN_CONTAINER===true||r.IS_IN_CONTAINER==='true'||r.IS_IN_CONTAINER===1;
      const containerLabel=inContainer?'<span class="b b-hi" title="'+e(r.CONTAINER_KEY||'')+'">'+e(r.CONTAINER_KEY?r.CONTAINER_KEY.slice(0,16):'Container')+'</span>':'<span style="color:#94a3b8">—</span>';
      const detectedAt=r.RECORD_CREATED_TIME?fmtDate(r.RECORD_CREATED_TIME):r.BATCH_END_TIME?fmtDate(r.BATCH_END_TIME):'—';
      return'<tr>'
        +'<td class="p">'+e(r.HOSTNAME||'—')+'<button class="cp-btn" data-cp="'+e(r.HOSTNAME||'')+'">'+cpIcon+'</button></td>'
        +'<td>'+containerLabel+'</td>'
        +'<td class="p"><code style="font-size:11px">'+e(r.FILE_PATH||'—')+'</code><button class="cp-btn" data-cp="'+e(r.FILE_PATH||'')+'">'+cpIcon+'</button></td>'
        +'<td class="m">'+detectedAt+'</td>'
        +'</tr>';
    }).join('');
    return'<div style="margin-bottom:18px">'
      +'<div style="display:flex;align-items:center;gap:8px;padding:7px 12px;background:'+hdrBg+';border-left:4px solid '+hdrColor+';border-radius:0 6px 6px 0;margin-bottom:4px">'
        +'<span style="font-weight:700;font-size:13px;color:'+hdrColor+'">'+e(displayCat(cat))+'</span>'
        +'<span style="background:'+hdrColor+';color:#fff;border-radius:10px;font-size:11px;font-weight:700;padding:1px 8px">'+items.length+'</span>'
      +'</div>'
      +'<div class="tbl-wrap"><table><thead><tr><th>Hostname</th><th>Container</th><th>File Path</th><th>Detected</th></tr></thead><tbody>'
        +rowsHtml
      +'</tbody></table></div>'
    +'</div>';
  };
  setBody('body-sa','<div>'+sortedGroups.map(renderGroup).join('')+'</div>');
}


const cpIcon='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
function copyText(el){
  const t=el.dataset.cp||'';
  navigator.clipboard.writeText(t).then(()=>{
    el.classList.add('ok');
    el.innerHTML='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg>';
    setTimeout(()=>{el.classList.remove('ok');el.innerHTML=cpIcon;},1500);
  }).catch(()=>{});
}
document.addEventListener('click',function(ev){if(ev.target.closest('.cp-btn'))copyText(ev.target.closest('.cp-btn'));});

// Shared helper — builds per-host correlated risk map from all data sources.
// Keys vulns by machineTags.Hostname (matches _renderVulns grouping).
function buildAssetRiskMap(d){
  var map={};
  var CIEM_T=['SSH_PRIVATE_KEY','SSH_PRIVATE_KEYS','RSA','ECDSA','ED25519',
    'AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY','AWS_CREDENTIALS','AWS_SECRET',
    'GOOGLE_OAUTH_TOKEN','GCP_SERVICE_ACCOUNT','AZURE_CLIENT_SECRET','AZURE_SAS_TOKEN'];
  var CIEM_SET={};CIEM_T.forEach(function(t){CIEM_SET[t]=true;});
  (d.vulns||[]).forEach(function(r){
    var mt=r.machineTags;
    var mtObj=(mt&&typeof mt==='object'&&!Array.isArray(mt))?mt:null;
    var host=(mtObj&&mtObj.Hostname)||(r.evalCtx&&r.evalCtx.hostname)||r.mid||'';
    if(!host)return;
    if(!map[host])map[host]={name:host,vulns:[],ciemSecrets:[],genericSecrets:[],risk:0,ciem:0,secretRisk:0,threatRisk:0,miscRisk:0,internetExposed:false,publicIP:null,cloud:''};
    var w=Math.min(100,parseFloat(r.riskScore||0)*10);
    map[host].vulns.push({id:r.vulnId||'',score:parseFloat(r.riskScore||0),w:w});
    map[host].threatRisk+=w;map[host].risk+=w;
    if(mtObj&&mtObj.lw_InternetExposure==='Yes')map[host].internetExposed=true;
    if(!map[host].publicIP){var pip=(mtObj&&(mtObj.ExternalIp||mtObj.PublicIpAddress||mtObj.public_ip||mtObj.externalIp))||null;if(pip)map[host].publicIP=pip;}
    if(!map[host].cloud){var cr=(mtObj&&mtObj.VmProvider)||'';var cl=cr?cr.toLowerCase():'';if(cl==='google')cl='gcp';if(cl)map[host].cloud=cl;}
  });
  (d.secretsAll||[]).forEach(function(r){
    var sh=(r.HOSTNAME||'').toLowerCase();
    if(!sh)return;
    var matchKey=null;
    var keys=Object.keys(map);
    for(var ki=0;ki<keys.length;ki++){
      var kl=keys[ki].toLowerCase();
      if(kl===sh||sh.indexOf(kl)===0||kl.indexOf(sh.split('.')[0])===0){matchKey=keys[ki];break;}
    }
    if(!matchKey)return;
    var t=(r.SECRET_TYPE||'').toUpperCase();
    if(CIEM_SET[t]){map[matchKey].ciemSecrets.push(r.SECRET_TYPE);map[matchKey].ciem+=100;map[matchKey].risk+=100;}
    else{map[matchKey].genericSecrets.push(r.SECRET_TYPE);map[matchKey].secretRisk+=50;map[matchKey].risk+=50;}
  });
  var critMisc=(d.compliance||[]).filter(function(c){return(c.severity||'').toLowerCase()==='critical';}).length;
  var miscBoost=Math.min(60,critMisc*10);
  if(miscBoost>0){var akeys=Object.keys(map);for(var ai=0;ai<akeys.length;ai++){var a=map[akeys[ai]];if(a.risk>0){a.miscRisk=miscBoost;a.risk+=miscBoost;}}}
  var allA=Object.values(map);
  var maxRisk=allA.reduce(function(mx,a){return Math.max(mx,a.risk);},1);
  allA.forEach(function(a){a.normalizedScore=Math.round(a.risk/maxRisk*100);});
  return{map:map,maxRisk:maxRisk,critMisc:critMisc};
}

function renderAssetRisk(d){
  const map={};
  const get=(host,mid)=>{
    const key=host||mid||'unknown';
    if(!map[key])map[key]={name:host||mid||'unknown',mid:mid||'',vulns:[],ciemSecrets:[],genericSecrets:[],risk:0,ciem:0,secretRisk:0,threatRisk:0,powerState:null,publicIP:null,internetExposed:undefined};
    return map[key];
  };
  const getPowerState=r=>{
    const tags=r.evalCtx?.machineTags;
    if(!Array.isArray(tags))return null;
    const t=tags.find(t=>(t.key||'').toLowerCase()==='powerstate');
    return t?(t.value||'').toLowerCase():null;
  };
  // Scan machineTags for public IP / internet-exposure indicators
  // Returns { exposed: bool|null, ip: string|null }
  const getNetInfo=r=>{
    const IP_RE=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    // Primary: top-level machineTags object (actual Lacework API format)
    const mt=r.machineTags;
    if(mt&&typeof mt==='object'&&!Array.isArray(mt)){
      const lwExp=mt.lw_InternetExposure;
      const ip=mt.ExternalIp||mt.PublicIpAddress||mt.public_ip||mt.externalIp||null;
      if(lwExp!==undefined)return{exposed:lwExp==='Yes',ip:ip||null};
      if(ip&&IP_RE.test(ip))return{exposed:true,ip};
    }
    // Fallback: evalCtx.machineTags array format (some cloud providers)
    const tags=r.evalCtx?.machineTags;
    const INET_KEY=/public.?ip|external.?ip|internet.?exp|public.?dns|public.?host/i;
    let ip=null;
    for(const f of['externalIp','publicIp','public_ip','externalIP','publicIP']){
      const v=(r.evalCtx?.[f]||'').trim();
      if(IP_RE.test(v)){ip=v;break;}
    }
    if(Array.isArray(tags)){
      for(const t of tags){
        const k=t.key||'';const v=(t.value||'').trim();
        if(INET_KEY.test(k)){
          if(!v||v==='false'||v==='no'||v==='none'||v==='N/A'||v==='null')return{exposed:false,ip:null};
          if(IP_RE.test(v))ip=v;
          return{exposed:true,ip};
        }
      }
    }
    return{exposed:ip?true:null,ip};
  };

  // Factor 3 — CVE Host Exposure (per host, Medium weight: riskScore×10)
  (d.vulns||[]).forEach(r=>{
    const host=r.evalCtx?.hostname||r.machineTags?.Hostname||r.evalCtx?.mid||r.mid||'';
    if(!host)return;
    const w=Math.min(100,parseFloat(r.riskScore||0)*10);
    const a=get(host,r.evalCtx?.mid||'');
    a.vulns.push({id:r.vulnId||'',score:r.riskScore,w});
    a.threatRisk+=w;
    a.risk+=w;
    const ps=getPowerState(r);
    if(ps&&a.powerState!=='running')a.powerState=ps;
    const ni=getNetInfo(r);
    if(ni.exposed===true)a.internetExposed=true;
    else if(ni.exposed===false&&a.internetExposed===undefined)a.internetExposed=false;
    if(ni.ip&&!a.publicIP)a.publicIP=ni.ip;
  });

  // Factor 1 — CIEM High-Perm (Critical, +100) via privileged credential proxy
  // Factor 2 — Secrets (High, +50 each)
  const HIGH_PERM_TYPES=new Set(['SSH_PRIVATE_KEY','SSH_PRIVATE_KEYS','RSA','ECDSA','ED25519',
    'AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY','AWS_CREDENTIALS','AWS_SECRET',
    'GOOGLE_OAUTH_TOKEN','GCP_SERVICE_ACCOUNT','AZURE_CLIENT_SECRET','AZURE_SAS_TOKEN']);
  (d.secretsAll||[]).forEach(r=>{
    const host=r.HOSTNAME||r.MID||'';
    if(!host)return;
    const a=get(host,r.MID||'');
    const t=(r.SECRET_TYPE||'').toUpperCase();
    if(HIGH_PERM_TYPES.has(t)){
      a.ciemSecrets.push(r.SECRET_TYPE||t);
      a.ciem+=100;
      a.risk+=100;
    } else {
      a.genericSecrets.push(r.SECRET_TYPE||t);
      a.secretRisk+=50;
      a.risk+=50;
    }
  });

  // Factor 4 — Critical Misconfiguration (account-wide, Low weight)
  // Compliance has no per-host data — applied as flat boost to all at-risk assets
  const critMisconfig=(d.compliance||[]).filter(r=>(r.severity||'').toLowerCase()==='critical').length;
  const miscBoost=Math.min(60,critMisconfig*10);
  if(miscBoost>0){
    Object.values(map).forEach(a=>{if(a.risk>0){a.miscRisk=miscBoost;a.risk+=miscBoost;}});
  }

  // Filter: running or unknown power state, rank by raw risk
  const all=Object.values(map).filter(a=>a.risk>0&&(a.powerState===null||a.powerState==='running')).sort((a,b)=>b.risk-a.risk);
  const maxRisk=all[0]?.risk||1;
  const sorted=all.filter(a=>Math.round(a.risk/maxRisk*100)>20);

  const el=document.getElementById('cnt-ar');if(el)el.textContent=sorted.length||'0';
  const labAction=document.getElementById('lab-asset-action');
  if(labAction)labAction.style.display=sorted.length?'flex':'none';
  const nd0=document.getElementById('jnd0-cnt');
  if(nd0)nd0.textContent=sorted.length||'0';
  const circle=document.getElementById('jnd0-circle');
  if(circle){
    if(sorted.length>0){circle.style.animation='step1-flash 2.5s ease-in-out infinite';}
    else{circle.style.animation='';circle.style.boxShadow='0 6px 24px rgba(239,68,68,.38)';}
  }
  // Store for openHostGraph — same map, same keys, same critMisconfig
  _renderedAssetMap={map:map,maxRisk:maxRisk,critMisc:critMisconfig};
  return; // view removed from nav — skip all HTML rendering below

  // Tier definitions (console palette)
  const TIERS={
    CRITICAL:{label:'CRITICAL',col:'#b91c1c',bd:'#fca5a5'},
    HIGH:    {label:'HIGH',    col:'#c2410c',bd:'#fdba74'},
    MEDIUM:  {label:'MEDIUM',  col:'#92400e',bd:'#fcd34d'},
    LOW:     {label:'LOW',     col:'#4b5563',bd:'#d1d5db'},
  };
  const tierOf=(score,internetExposed)=>{
    const ex=internetExposed===true;
    if(score>=75)return ex?TIERS.CRITICAL:TIERS.MEDIUM;
    if(score>=50)return ex?TIERS.HIGH:TIERS.LOW;
    if(score>=30)return TIERS.MEDIUM;
    return TIERS.LOW;
  };

  // Build ranked list with tier assignments
  const ranked=sorted.map(function(a,i){
    const score=Math.round(a.risk/maxRisk*100);
    return{a:a,i:i,score:score,t:tierOf(score,a.internetExposed)};
  });

  // Tier summary counts
  const tierCounts={CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  ranked.forEach(function(r){tierCounts[r.t.label]++;});

  // Factor chip — minimal outline only
  const chip=function(label,col,bd){
    return'<span style="font-size:9px;font-weight:700;color:'+col+';border:1px solid '+bd+';border-radius:3px;padding:1px 6px;white-space:nowrap;letter-spacing:.04em">'+label+'</span>';
  };

  // Compact inline score bar
  const bar=function(score,col){
    return'<div style="height:3px;background:#e5e7eb;border-radius:2px;width:100%;margin-top:4px">'
      +'<div style="height:3px;border-radius:2px;background:'+col+';width:'+score+'%;transition:width .5s ease"></div>'
    +'</div>';
  };

  // Summary strip
  let html='<div style="display:flex;align-items:center;gap:12px;padding:8px 16px;border-bottom:1px solid #e5e7eb;font-size:10px;font-weight:600;color:#6b7280;flex-wrap:wrap">'
    +'<span style="font-weight:700;color:#111827">'+sorted.length+' asset'+(sorted.length!==1?'s':'')+' ranked</span>';
  ['CRITICAL','HIGH','MEDIUM','LOW'].forEach(function(lbl){
    if(!tierCounts[lbl])return;
    var col=TIERS[lbl].col;
    html+='<span style="color:'+col+'">&#9679; '+lbl+': '+tierCounts[lbl]+'</span>';
  });
  html+='<span style="margin-left:auto;font-size:9px;font-weight:400;color:#9ca3af">Scores normalized 0–100 · internet exposure adjusts tier</span>'
    +'</div>';

  // Column header
  html+='<div style="display:grid;grid-template-columns:28px 1fr 80px;align-items:center;gap:0;padding:4px 16px 4px 16px;border-bottom:1px solid #e5e7eb;font-size:9px;font-weight:700;letter-spacing:.08em;color:#9ca3af;text-transform:uppercase">'
    +'<div></div>'
    +'<div>Host</div>'
    +'<div style="text-align:right">Score</div>'
  +'</div>';

  // Asset rows
  ranked.forEach(function(row){
    var a=row.a;var i=row.i;var score=row.score;var t=row.t;
    var avgCve=a.vulns.length?(a.vulns.reduce(function(s,v){return s+parseFloat(v.score||0);},0)/a.vulns.length).toFixed(1):'';

    // Factor chips
    var chips='';
    if(a.ciemSecrets.length)chips+=chip('CIEM \xb7 '+a.ciemSecrets.length,t.col===TIERS.CRITICAL.col?'#b91c1c':'#b91c1c','#fca5a5');
    if(a.genericSecrets.length)chips+=chip('SEC \xb7 '+a.genericSecrets.length,'#92400e','#fcd34d');
    if(a.vulns.length)chips+=chip('CVE \xb7 '+a.vulns.length+(avgCve?' avg '+avgCve:''),'#c2410c','#fdba74');
    if(a.miscRisk)chips+=chip('MISCONF \xb7 '+critMisconfig,'#4b5563','#d1d5db');

    // Internet badge
    var inetHtml='';
    if(a.internetExposed===true){
      inetHtml='<span style="font-size:9px;font-weight:700;color:#b91c1c;border:1px solid #fca5a5;border-radius:3px;padding:1px 5px;white-space:nowrap">INTERNET'+(a.publicIP?' \xb7 '+e(a.publicIP):'')+'</span>';
    }

    var isExposed=a.internetExposed===true;
    var rowCls=isExposed?'ar-host-row ar-exposed-row':'ar-host-row';

    html+='<div class="'+rowCls+'" data-hostname="'+e(a.name)+'" style="display:grid;grid-template-columns:28px 1fr 80px;align-items:start;gap:0;padding:8px 16px;border-bottom:1px solid #f3f4f6">'
      // Rank
      +'<div style="font-size:11px;font-weight:700;color:#9ca3af;font-variant-numeric:tabular-nums;padding-top:2px;border-left:2px solid '+t.col+';padding-left:6px">'+(i+1)+'</div>'

      // Host + factors
      +'<div style="min-width:0;padding-right:12px">'
        +'<div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:4px">'
          +(isExposed
            ?'<span style="font-family:SFMono-Regular,Consolas,monospace;font-size:11.5px;font-weight:700;color:#b91c1c;word-break:break-all;text-decoration:underline;text-underline-offset:2px">'+e(a.name)+'</span>'
            +'<span style="font-size:9px;font-weight:700;color:'+t.col+';letter-spacing:.08em;text-transform:uppercase">'+t.label+'</span>'
            +inetHtml
            +'<button class="goto-host-card-btn" data-hostname="'+e(a.name)+'" style="font-size:9px;font-weight:700;color:#b91c1c;background:#fee2e2;border:none;border-radius:3px;padding:2px 7px;letter-spacing:.04em;cursor:pointer">&#9650; Exploit Graph</button>'
            :'<span style="font-family:SFMono-Regular,Consolas,monospace;font-size:11.5px;font-weight:600;color:#111827;word-break:break-all">'+e(a.name)+'</span>'
            +'<span style="font-size:9px;font-weight:700;color:'+t.col+';letter-spacing:.08em;text-transform:uppercase">'+t.label+'</span>'
          )
        +'</div>'
        +(a.mid&&a.mid!==a.name?'<div style="font-size:10px;color:#9ca3af;font-family:monospace;margin-bottom:4px">'+e(a.mid)+'</div>':'')
        +'<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap">'
          +chips
          +'<span style="margin-left:auto;display:flex;gap:4px;align-items:center" onclick="event.stopPropagation()">'
            +'<button class="mach-inv-btn" data-hostname="'+e(a.name)+'" style="font-size:9px;padding:1px 7px;border-radius:3px;border:1px solid #d1d5db;cursor:pointer;background:#f9fafb;color:#374151;font-weight:600">Details</button>'
            +(a.publicIP?'<button class="geo-btn" data-ip="'+e(a.publicIP)+'" data-host="'+e(a.name)+'" style="font-size:9px;padding:1px 7px;border-radius:3px;border:1px solid #bfdbfe;cursor:pointer;background:#eff6ff;color:#1d4ed8;font-weight:600">GeoIP</button>':'')
            +(isExposed?'<button class="goto-host-card-btn" data-hostname="'+e(a.name)+'" style="font-size:9px;padding:1px 7px;border-radius:3px;border:1px solid #fca5a5;cursor:pointer;background:#fff1f2;color:#b91c1c;font-weight:600">&#9651; Exploit Graph</button>':'')
            +'<button class="cp-btn" data-cp="'+e(a.name)+'" title="Copy">'+cpIcon+'</button>'
          +'</span>'
        +'</div>'
      +'</div>'

      // Score
      +'<div style="text-align:right">'
        +'<span style="font-size:20px;font-weight:800;color:'+t.col+';font-variant-numeric:tabular-nums;line-height:1">'+score+'</span>'
        +bar(score,t.col)
      +'</div>'
    +'</div>';
  });

  html+='<div style="padding:8px 16px;font-size:9px;color:#9ca3af">CIEM &amp; Misconfig are account-wide · CVEs &amp; Secrets are per-host</div>';

  // ── Per-exposed-host Exploit Simulation graphs ──────────────────────────────
  var exposedRanked=ranked.filter(function(r){return r.a.internetExposed===true;});
  if(exposedRanked.length){
    var TCOL={CRITICAL:'#b91c1c',HIGH:'#c2410c',MEDIUM:'#92400e',LOW:'#4b5563'};
    var TBD ={CRITICAL:'#fca5a5',HIGH:'#fdba74',MEDIUM:'#fcd34d',LOW:'#d1d5db'};
    var TBG ={CRITICAL:'#fff7f7',HIGH:'#fff7ed',MEDIUM:'#fffbeb',LOW:'#f9fafb'};

    html+='<div style="margin:16px 0 0;border-top:2px solid #fca5a5">'
      +'<div style="padding:10px 16px 0;font-size:10px;font-weight:800;letter-spacing:.14em;color:#b91c1c;text-transform:uppercase">'
      +'&#9651; Exploit Simulation — Internet-Exposed Hosts'
      +'<span style="font-weight:400;color:#9ca3af;letter-spacing:normal;margin-left:8px">'+exposedRanked.length+' host'+(exposedRanked.length!==1?'s with active attack surface':'')+'</span>'
      +'</div>';

    exposedRanked.forEach(function(row){
      var a=row.a;var score=row.score;var tier=row.t.label;
      var tc=TCOL[tier];var tbd=TBD[tier];var tbg=TBG[tier];

      // Build risk factors for this host
      var factors=[];
      if(a.vulns&&a.vulns.length)
        factors.push({label:'CVEs',count:a.vulns.length,color:'#f97316',nav:'vulns'});
      if(critMisconfig>0)
        factors.push({label:'Non-Compliance',count:critMisconfig,color:'#f59e0b',nav:'compliance'});
      var secCnt=(a.ciemSecrets||[]).length+(a.genericSecrets||[]).length;
      if(secCnt>0)
        factors.push({label:'Secrets',count:secCnt,color:'#eab308',nav:'secrets-all'});
      if(!factors.length)factors.push({label:'At Risk',count:1,color:'#6b7280',nav:'asset-risk'});

      // MITRE tactic per factor
      var mFact=factors.map(function(f){
        if(f.label==='CVEs')return{t:'Exploitation',id:'T1203',c:'#f97316'};
        if(f.label==='Secrets')return{t:'Credential Access',id:'T1552',c:'#eab308'};
        if(f.label==='Non-Compliance')return{t:'Priv. Escalation',id:'T1078',c:'#8b5cf6'};
        return{t:'Persistence',id:'TA0003',c:'#6b7280'};
      });
      var hexFactors=factors.map(function(f,i){
        return{label:f.label,count:f.count,color:f.color,nav:f.nav,mitre:mFact[i]};
      });
      var hn=a.name.length>20?a.name.substring(0,19)+'…':a.name;
      var svg=hexKillChainSvg({
        attacker:{label:'ATTACKER',color:'#ff5e3a'},
        network:{label:'Internet',color:'#3b82f6'},
        factors:hexFactors,
        target:{label:hn,subLabel:a.publicIP||null,tier:tier,tierColor:tc,badge:true},
        animate:true,
      });

      // Risk findings list
      var findings='';
      if(a.vulns&&a.vulns.length){
        var top5=a.vulns.slice(0,5);
        findings+='<div style="margin-bottom:6px"><div style="font-size:9px;font-weight:700;color:#c2410c;letter-spacing:.06em;margin-bottom:3px">CVEs ('+a.vulns.length+')</div>'
          +top5.map(function(v){return'<span style="display:inline-block;font-family:monospace;font-size:9px;background:#fff7ed;border:1px solid #fdba74;border-radius:3px;padding:1px 6px;margin:1px 2px;color:#92400e">'+e(v.id||'')+'</span>';}).join('')
          +(a.vulns.length>5?'<span style="font-size:9px;color:#9ca3af;margin-left:4px">+' +(a.vulns.length-5)+' more</span>':'')
        +'</div>';
      }
      if(critMisconfig>0){
        findings+='<div style="margin-bottom:6px"><div style="font-size:9px;font-weight:700;color:#92400e;letter-spacing:.06em;margin-bottom:3px">Critical Misconfigurations ('+critMisconfig+')</div>'
          +'<span style="font-size:9px;color:#6b7280">Account-wide — affects all internet-exposed hosts</span>'
        +'</div>';
      }
      if(secCnt>0){
        findings+='<div style="margin-bottom:6px"><div style="font-size:9px;font-weight:700;color:#92400e;letter-spacing:.06em;margin-bottom:3px">Secrets / Credentials ('+(secCnt)+')</div>'
          +(a.ciemSecrets.length?'<span style="display:inline-block;font-size:9px;background:#fef2f2;border:1px solid #fca5a5;border-radius:3px;padding:1px 6px;margin:1px 2px;color:#b91c1c">CIEM: '+a.ciemSecrets.length+' high-perm</span>':'')
          +(a.genericSecrets.length?'<span style="display:inline-block;font-size:9px;background:#fffbeb;border:1px solid #fcd34d;border-radius:3px;padding:1px 6px;margin:1px 2px;color:#92400e">'+a.genericSecrets.length+' generic secret'+(a.genericSecrets.length!==1?'s':'')+'</span>':'')
        +'</div>';
      }

      // Remediation footer
      var remItems=[];
      if(a.vulns&&a.vulns.length)remItems.push('Patch '+a.vulns.length+' CVE'+(a.vulns.length!==1?'s':''));
      if(critMisconfig>0)remItems.push('Fix '+critMisconfig+' misconfiguration'+(critMisconfig!==1?'s':''));
      if(secCnt>0)remItems.push('Remove '+secCnt+' exposed secret'+(secCnt!==1?'s':''));

      var safeId=a.name.replace(/[^a-zA-Z0-9]/g,'-');
      html+='<div id="ar-host-'+safeId+'" style="margin:14px 16px;border:1px solid '+tbd+';border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.06)">'
        // Card header
        +'<div style="padding:8px 16px;background:'+tbg+';border-bottom:1px solid '+tbd+';display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
          +'<span style="font-family:SFMono-Regular,Consolas,monospace;font-size:13px;font-weight:700;color:#111827">'+e(a.name)+'</span>'
          +'<span style="font-size:9px;font-weight:700;color:'+tc+';letter-spacing:.08em;border:1px solid '+tc+';border-radius:3px;padding:2px 7px">'+tier+'</span>'
          +(a.publicIP
            ?'<span style="font-size:9px;font-weight:600;color:#dc2626;background:#fee2e2;border-radius:3px;padding:2px 8px">INTERNET &middot; '+e(a.publicIP)+'</span>'
            :'<span style="font-size:9px;font-weight:600;color:#dc2626;background:#fee2e2;border-radius:3px;padding:2px 8px">INTERNET EXPOSED</span>')
          +'<span style="margin-left:auto;font-size:11px;color:#6b7280">Risk Score: <b style="color:'+tc+'">'+score+'/100</b></span>'
        +'</div>'
        // SVG attack graph
        +'<div style="padding:6px 0;background:#fff">'+svg+'</div>'
        // Risk findings
        +(findings?'<div style="padding:10px 16px;background:#f9fafb;border-top:1px solid #e5e7eb">'+findings+'</div>':'')
        // Remediation footer
        +(remItems.length?'<div style="padding:8px 16px;background:#f0fdf4;border-top:1px solid #bbf7d0;font-size:10px;font-weight:600;color:#166534">&#10003; To close: '+remItems.join(' &nbsp;&middot;&nbsp; ')+'</div>':'')
      +'</div>';
    });

    html+='</div>';
  }

  // View removed from nav — skip DOM render, map is built above for openHostGraph
}


function nav(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  var ve=document.getElementById('view-'+name);if(ve)ve.classList.add('active');
  var ne=document.getElementById('nav-'+name);if(ne)ne.classList.add('active');
  history.replaceState(null,'','#'+name);
  if(name==='compliance')loadGovernanceTargets();
}

// ── Governance Report (FortiCNAPP Reports API) — powers the Generate Report modal's
// account/framework prompt below ──
let _govTargets=null,_govReportTypes=null,_govLoading=false,_govLoadedOk=false;

// Fills one cloud-account <select> from the already-fetched _govTargets (or a loading/
// empty state if not fetched yet) — factored out so the Generate Report modal (and any
// future caller) can share one fetch instead of each hitting the API.
function populateGovAccountSelect(sel){
  if(!sel)return;
  if(!_govLoadedOk){sel.innerHTML='<option value="">Loading cloud accounts (can take several seconds)…</option>';return;}
  if(!_govTargets||!_govTargets.length){sel.innerHTML='<option value="">No cloud accounts configured</option>';return;}
  sel.innerHTML='<option value="">Select cloud account…</option>'+_govTargets.map(function(t,i){
    return '<option value="'+i+'">'+e(t.label)+'</option>';
  }).join('');
}

async function loadGovernanceTargets(){
  var sels=[document.getElementById('rptgen-account-select')].filter(Boolean);
  if(_govLoadedOk){sels.forEach(populateGovAccountSelect);return;}
  if(_govLoading){sels.forEach(populateGovAccountSelect);return;}
  _govLoading=true;
  sels.forEach(populateGovAccountSelect);
  try{
    var res=await fetch('/api/governance/targets');
    var d=await res.json();
    if(d.error)throw new Error(d.error);
    _govTargets=d.targets||[];
    _govReportTypes=d.reportTypes||{};
    _govLoadedOk=true;
    sels.forEach(populateGovAccountSelect);
  }catch(err){
    sels.forEach(function(sel){sel.innerHTML='<option value="">Failed to load — click to retry</option>';});
    console.error('[governance] targets load failed:',err);
  }finally{
    _govLoading=false;
  }
}

// Fills a framework <select> + enables/disables its action button once a cloud account is
// picked — used by the Generate Report modal's account/framework/action elements.
function populateGovFrameworkOptions(accountSel,fwSel,actionBtn){
  var idx=accountSel.value;
  // Remember the framework picked before switching accounts — rebuilding the <select>'s
  // innerHTML below otherwise silently resets to the first option, so e.g. picking "CIS
  // AWS Foundations Benchmark v1.4" then switching accounts would drop back to whatever
  // framework happens to be first, not stick with what the user actually chose.
  var prevFramework=fwSel.value;
  if(idx===''||!_govTargets){
    fwSel.innerHTML='<option value="">Select account first…</option>';
    actionBtn.disabled=true;actionBtn.style.opacity='.5';
    return;
  }
  var t=_govTargets[idx];
  var opts=(_govReportTypes&&_govReportTypes[t.cloud])||[];
  fwSel.innerHTML=opts.length
    ? opts.map(function(o){return '<option value="'+e(o.value)+'">'+e(o.label)+'</option>';}).join('')
    : '<option value="">No frameworks available for '+e(t.cloud)+'</option>';
  if(prevFramework&&opts.some(function(o){return o.value===prevFramework;}))fwSel.value=prevFramework;
  actionBtn.disabled=!opts.length;actionBtn.style.opacity=opts.length?'1':'.5';
}

// cloud + frameworkLabel + accountLabel let the server persist this as the "last
// governance report" — reused by Generate Report / Report 2's Non-Compliance section.
function govReportUrl(t,reportType,frameworkLabel){
  return '/api/governance/report?reportType='+encodeURIComponent(reportType)+'&primaryQueryId='+encodeURIComponent(t.primaryQueryId)+(t.secondaryQueryId?'&secondaryQueryId='+encodeURIComponent(t.secondaryQueryId):'')
    +'&cloud='+encodeURIComponent(t.cloud)+'&frameworkLabel='+encodeURIComponent(frameworkLabel)+'&accountLabel='+encodeURIComponent(t.label);
}

// ── Generate Report modal — same account/framework picker as the Compliance tab's
// Governance box, but the point is to run it right before generating the customer
// report, so the report's Compliance section is scoped to what the user just picked
// (buildReportHtml() already prefers the freshest server-side lastGovernanceReport
// over the generic account-wide scan — this just makes running one part of the flow).
function openReportGenModal(ev){
  if(ev&&ev.preventDefault)ev.preventDefault();
  document.getElementById('rptgen-overlay').style.display='flex';
  document.getElementById('rptgen-status').textContent='';
  loadGovernanceTargets();
  return false;
}
function closeReportGenModal(){
  document.getElementById('rptgen-overlay').style.display='none';
}
function rptGenAccountChanged(){
  populateGovFrameworkOptions(document.getElementById('rptgen-account-select'),document.getElementById('rptgen-framework-select'),document.getElementById('rptgen-go-btn'));
}
async function runReportGenModal(){
  var accSel=document.getElementById('rptgen-account-select');
  var fwSel=document.getElementById('rptgen-framework-select');
  var idx=accSel.value;
  var reportType=fwSel.value;
  if(idx===''||!reportType||!_govTargets)return;
  var t=_govTargets[idx];
  var frameworkLabel=fwSel.options[fwSel.selectedIndex]?fwSel.options[fwSel.selectedIndex].text:reportType;
  var goBtn=document.getElementById('rptgen-go-btn');
  var status=document.getElementById('rptgen-status');
  goBtn.disabled=true;goBtn.textContent='Fetching…';
  status.style.color='#64748b';status.textContent='Running '+frameworkLabel+' against '+t.label+'…';
  try{
    var res=await fetch(govReportUrl(t,reportType,frameworkLabel));
    var d=await res.json();
    if(d.error)throw new Error(d.error);
    // Server now holds this as the "last governance report" — the /report route already
    // reads it in preference to the generic compliance scan, so just open it.
    var reportUrl=(document.getElementById('rpt-btn-link')&&document.getElementById('rpt-btn-link').getAttribute('href'))||'/report';
    window.open(reportUrl,'_blank');
    closeReportGenModal();
  }catch(err){
    status.style.color='#b91c1c';status.textContent='Failed to run report: '+(err.message||err);
  }finally{
    goBtn.disabled=false;goBtn.textContent='Generate Report';
  }
}

let _lastData=null;
let _renderedAssetMap=null;  // set by renderAssetRisk, read by openHostGraph
let _renderedPrivMap=null;   // set by _renderVulns, read by openHostGraph for private hosts
let _currentLabTab='global';
// Identity graph state
var _igNodePos={};var _igNW=185;var _igNH=38;var _igTrustMap={};

// ── Identity risk classification (client mirror of the server-side helpers near
// calcRiskScore()) — Admin + No-MFA + (unused entitlements ≥80% OR access key ≥180d old)
// → flat 80. Otherwise falls back to the raw FortiCNAPP CIEM risk_score. ──
function isServiceAccount(r){
  const pid=(r.PRINCIPAL_ID||'').toLowerCase(),nm=(r.NAME||'').toLowerCase(),p=(r.PROVIDER_TYPE||'').toLowerCase();
  return pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||p.includes('serviceprincipal')||p.includes('aad');
}
function isRoleType(r){
  const pid=(r.PRINCIPAL_ID||'').toLowerCase(),nm=(r.NAME||'').toLowerCase();
  return (pid.includes(':role/')||pid.includes(':assumed-role/')||nm.includes('role'))&&!isServiceAccount(r);
}
function isHighPermissive(r){
  const risks=(r.METRICS&&r.METRICS.risks)||[];
  const sev=((r.METRICS&&r.METRICS.risk_severity)||'').toLowerCase();
  return risks.includes('ALLOWS_FULL_ADMIN')||risks.includes('EXCESSIVE_PERMISSIONS')||sev==='critical'||sev==='high';
}
function isNoMfa(r){
  const risks=(r.METRICS&&r.METRICS.risks)||[];
  return risks.includes('PASSWORD_LOGIN_NO_MFA')||!r.MFA_ENABLED;
}
function unusedPctOf(r){
  const ec=r.ENTITLEMENT_COUNTS||{};
  const unusedCnt=ec.entitlements_unused_count,totalCnt=ec.entitlements_total_count||ec.entitlements_count;
  return ec.entitlements_unused_percentage!=null?ec.entitlements_unused_percentage
    :(unusedCnt!=null&&totalCnt?(unusedCnt/totalCnt)*100:null);
}
// Access-key age field name unverified — see docs/superpowers/specs/2026-07-28-risk-findings-
// weighting-design.md. Checks common casings; falls back to not-old if none match.
function isOldAccessKey(r,thresholdDays){
  thresholdDays=thresholdDays||180;
  const raw=r.ACCESS_KEYS;
  const keys=Array.isArray(raw)?raw:(raw&&typeof raw==='object'?[raw]:[]);
  return keys.some(k=>{
    if(!k||typeof k!=='object')return false;
    const created=k.create_date||k.CREATE_DATE||k.createDate||k.CreateDate||k.created_at||k.CREATED_AT;
    if(!created)return false;
    const ageDays=(Date.now()-new Date(created).getTime())/86400000;
    return Number.isFinite(ageDays)&&ageDays>=thresholdDays;
  });
}
function isAdminNoMfaIdentity(r){
  return !isServiceAccount(r)&&!isRoleType(r)&&isHighPermissive(r)&&isNoMfa(r);
}
function identityRiskScore(r){
  const qualifies=isAdminNoMfaIdentity(r)&&((unusedPctOf(r)??0)>=80||isOldAccessKey(r));
  return qualifies?80:Math.min(100,(r.METRICS?.risk_score||0)*100);
}

// Cloud Security Posture Score: higher = better posture (0–100).
// postureScore = 100 − mean(findingRiskScores).  No findings → 100.
// Alert: CRITICAL=80/HIGH=60/MEDIUM=40  |  CVE: riskScore×10 (only riskScore≥8)  |  Compliance: 80  |  Identity: see identityRiskScore()  |  Secret: 10
function calcPostureScore(d){
  const risks=[];
  (d.alerts||[]).forEach(r=>{const s=(r.severity||'').toLowerCase();risks.push(s==='critical'?80:s==='high'?60:40);});
  (d.vulns||[]).forEach(r=>{const rs=parseFloat(r.riskScore||0);if(rs>=8)risks.push(Math.min(100,rs*10));});
  (d.compliance||[]).forEach(()=>risks.push(80));
  (d.identities||[]).forEach(r=>risks.push(identityRiskScore(r)));
  (d.secretsAll||[]).forEach(()=>risks.push(10));
  return Math.max(0, Math.round(risks.length ? 100-risks.reduce((s,v)=>s+v,0)/risks.length : 100));
}
// Cloud Security Score maturity model — combines Option 2's progression with Option 1's
// executive meaning. Primary label is the tier name only (no negative wording); the
// executive interpretation is exposed separately via scoreTierDetail() for a tooltip/detail
// panel, not printed on the gauge itself.
// 81–100 Optimized (blue) · 61–80 Advanced (green) · 31–60 Managed (orange) · 0–30 Foundational (red)
function scoreColor(p){return p>=81?'#3b82f6':p>=61?'#22c55e':p>=31?'#f59e0b':'#ef4444';}
function scoreTier(p){return p>=81?'Optimized':p>=61?'Advanced':p>=31?'Managed':'Foundational';}
function scoreTierDetail(p){return p>=81?'Mature cloud security posture with proactive risk management and continuous improvement':p>=61?'Security posture is strong with effective controls and manageable residual risk':p>=31?'Core controls are established, but security gaps and optimization opportunities remain':'Security controls are immature; significant exposure and remediation priorities exist';}
function scoreBand(p){return scoreTier(p);}

function renderRiskFindings(d){
  const p=calcPostureScore(d);
  const color=scoreColor(p);
  const band=scoreBand(p);
  const na=d.alerts?.length??0,nv=riskFindingHostExposure(d).length,nc=d.compliance?.length??0,ni=riskFindingIdentities(d.identities).length,ns=(d.secretsAll||[]).length;
  document.getElementById('rf-k-a').textContent=na;
  document.getElementById('rf-k-v').textContent=nv;
  document.getElementById('rf-k-c').textContent=nc;
  document.getElementById('rf-k-i').textContent=ni;
  document.getElementById('rf-k-s').textContent=ns;
  document.getElementById('rf-n-s').textContent=ns||'0';
  document.getElementById('ov-a').textContent=na;
  document.getElementById('ov-v').textContent=nv;
  document.getElementById('ov-i').textContent=ni;
  document.getElementById('ov-c').textContent=nc;
  const base='https://'+d.account;
  const groups=[
    {key:'Alert',     label:'High Fidelity Alerts',       color:'#ef4444', tab:'alerts',      items:(d.alerts||[]).map(r=>{const s=(r.severity||'').toLowerCase();return{title:r.alertName,     copyVal:r.alertName||r.alertId,   detail:r.alertType,score:s==='critical'?80:s==='high'?60:40};})},
    {key:'CVE',       label:'Host Exposure',   color:'#f97316', tab:'vulns',       items:riskFindingHostExposure(d).map(r=>{const mt=r.machineTags||{};
      // machineTags.Hostname/Name (the actual instance identity) — NOT evalCtx.hostname,
      // which is the agent's own self-reported hostname and can legitimately differ from the
      // instance's real identity (e.g. "my-tools" vs "ip-172-31-19-180...") on the exact same
      // host, misleadingly implying a third, unrelated host in the detail text.
      const hostLabel=mt.Name||mt.Hostname||r.evalCtx?.hostname||'';
      return{title:r.vulnId||r.cveId, copyVal:r.vulnId||r.cveId, detail:(r.featureKey?.name||'')+' · '+hostLabel,score:parseFloat(r.cveRiskScore??r.riskScore??0)*10};})},
    {key:'Identity',  label:'Identities',                 color:'#8b5cf6', tab:'identities',  items:riskFindingIdentities(d.identities).map(r=>({title:r.NAME||r.PRINCIPAL_ID, copyVal:r.NAME||r.PRINCIPAL_ID, detail:(r.PROVIDER_TYPE||'')+' · No MFA',score:identityRiskScore(r)}))},
    {key:'Compliance',label:'Critical Misconfigurations', color:'#f59e0b', tab:'compliance',  items:(d.compliance||[]).map(r=>({title:r.title,     copyVal:r.alertId||r.title,       detail:(r.cloud||'').toUpperCase()+' · '+r.violations+' violations',score:80}))},
    {key:'Secret',    label:'Secrets Detected',           color:'#0ea5e9', tab:'secrets-all', items:(d.secretsAll||[]).map(r=>({title:r.SECRET_TYPE||'Secret', copyVal:r.HOSTNAME||r.SECRET_IDENTIFIER||r.SECRET_TYPE, detail:(r.HOSTNAME||'—')+' · '+tr(r.SECRET_IDENTIFIER||'',28),score:10}))},
  ].filter(g=>g.items.length);
  if(!groups.length){setBody('rf-table','<div class="state"><span>No risk findings</span></div>');return;}
  const scoreBadge=s=>{const cls=s>=80?'b-cr':s>=50?'b-hi':s>=20?'b-me':'b-ok';return'<span class="b '+cls+'">'+Math.round(s)+'</span>';};
  const rows=groups.map(g=>{
    const bodyId='rf-grp-'+g.key;
    const hdr='<tbody><tr class="rf-grp-toggle" data-body="'+bodyId+'" style="cursor:pointer;background:var(--card)">'
      +'<td colspan="3" style="padding:8px 12px;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--sub);border-left:3px solid '+g.color+'">'
        +'<span class="rf-grp-chevron" style="display:inline-block;width:11px;font-size:9px;color:var(--muted)">&#9654;</span>'
        +'<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:'+g.color+';margin-right:6px;vertical-align:middle"></span>'+e(g.label)
      +'</td>'
      +'<td style="padding:8px 12px;text-align:right"><a href="#" data-tab="'+g.tab+'" onclick="event.stopPropagation();nav(this.dataset.tab);return false;" style="display:inline-block;font-size:10px;font-weight:600;color:'+g.color+';background:'+g.color+'14;border-radius:10px;padding:2px 9px;text-decoration:none">'+g.items.length+' finding'+(g.items.length===1?'':'s')+' ↗</a></td>'
      +'</tr></tbody>';
    const detail='<tbody id="'+bodyId+'" style="display:none">'+g.items.map((r,i)=>'<tr style="'+(i%2?'background:var(--card)':'')+'">'
      +'<td class="p" colspan="2" style="display:flex;align-items:center;gap:4px;padding:6px 12px">'+e(tr(r.title,48))+'<button class="cp-btn" data-cp="'+e(r.copyVal||r.title)+'" title="Copy">'+cpIcon+'</button></td>'
      +'<td class="m" style="padding:6px 12px">'+e(tr(r.detail,36))+'</td>'
      +'<td class="r" style="padding:6px 12px">'+scoreBadge(r.score)+'</td>'
    +'</tr>').join('')+'</tbody>';
    return hdr+detail;
  }).join('');
  setBody('rf-table','<div class="tbl-wrap"><table><thead><tr><th colspan="2">Finding</th><th>Detail</th><th>Risk Score</th></tr></thead>'+rows+'</table></div>');
}

// ── CSP detection helpers (client-side) ──────────────────────────────────────
function cspOfAlert(r){
  const t=((r.alertType||'')+(r.alertName||'')).toUpperCase();
  if(t.includes('AWS')||t.includes('CLOUDTRAIL')||t.includes('EC2')||t.includes('S3'))return 'aws';
  if(t.includes('AZURE')||t.includes('AZ_'))return 'azure';
  if(t.includes('GCP')||t.includes('GOOGLE')||t.includes('GKE'))return 'gcp';
  return null;
}
function cspOfIdentity(r){
  const p=((r.PROVIDER_TYPE||r.CLOUD_PROVIDER||'')).toUpperCase();
  if(p.includes('AWS'))return 'aws';
  if(p.includes('AZURE'))return 'azure';
  if(p.includes('GCP')||p.includes('GOOGLE'))return 'gcp';
  return null;
}
// Rate-based Severity-Mix model — penalty is a weighted average of each severity
// bucket's SHARE of this cloud's total findings, not raw counts. A cloud with far more
// inventory (e.g. AWS with 233 identities vs Azure's 30) isn't penalized just for having
// more assets — only a genuinely worse ratio of critical/high findings lowers the score.
// Buckets: CRITICAL(weight 40) | HIGH(30) | MEDIUM(20) | LOW(10)
// penalty = Σ weight_b × (count_b / total)   score = 100 − penalty
function calcCspScore(d,csp){
  let C=0,H=0,M=0,L=0;
  // Alerts — severity from API ('Critical'|'High')
  (d.alerts||[]).filter(r=>cspOfAlert(r)===csp).forEach(r=>{
    const s=(r.severity||'').toLowerCase();
    if(s==='critical')C++;else if(s==='high')H++;else M++;
  });
  // Compliance violations — severity from policy definition
  (d.compliance||[]).filter(r=>(r.cloud||'')===csp).forEach(r=>{
    const s=(r.severity||'').toLowerCase();
    if(s==='critical')C++;else H++;
  });
  // Identities — bucket by identityRiskScore() (0–100 scale)
  (d.identities||[]).filter(r=>cspOfIdentity(r)===csp).forEach(r=>{
    const score=identityRiskScore(r);
    if(score>=80)C++;else if(score>=50)H++;else if(score>=20)M++;else L++;
  });
  const total=C+H+M+L;
  if(total===0)return null;
  const penalty=40*(C/total)+30*(H/total)+20*(M/total)+10*(L/total);
  return Math.max(0,Math.round(100-penalty));
}
function cspBadgeColor(csp){return{aws:'#FF9900',azure:'#0078D4',gcp:'#4285F4'}[csp]||'#94a3b8';}

function renderCspLab(d,csp){
  // Crit. Alerts is intentionally not a factor node here (unlike the Global panel):
  // cspOfAlert() classifies by keyword-matching alertType/alertName, which works for
  // control-plane alerts (CloudTrail etc.) but many alert categories (agent/anomaly —
  // e.g. NewExternalClientBadIp) carry no cloud-provider signal at all, so per-CSP
  // counts would silently undercount to 0 rather than reflect real attribution.
  const compliance=(d.compliance||[]).filter(r=>(r.cloud||'')===csp);
  const identities=(d.identities||[]).filter(r=>cspOfIdentity(r)===csp);
  // Same exposure logic as the Global panel's jnd3 (no relative-risk-score gate — see
  // renderLab), scoped to hosts tagged with this specific cloud via machineTags.VmProvider.
  const {map:_cHmap}=buildAssetRiskMap(d);
  const exposedHosts=Object.values(_cHmap).filter(h=>h.internetExposed===true&&h.cloud===csp);
  const raw=calcCspScore(d,csp);
  const p=raw!==null?raw:100;
  const color=scoreColor(p);
  const band=scoreBand(p);
  const bc=cspBadgeColor(csp);
  const badge=document.getElementById('clab-csp-badge');
  if(badge){badge.textContent=csp.toUpperCase();badge.style.background=bc;}
  const scoreEl=document.getElementById('clab-score');
  if(scoreEl){scoreEl.textContent=p;scoreEl.style.color=color;}
  const bandEl=document.getElementById('clab-band-txt');
  if(bandEl){bandEl.textContent=band;bandEl.title=scoreTierDetail(p);}
  const goalTier=scoreTier(p).toUpperCase();
  const factors=[
    {label:'Identities',   count:identities.length,   color:identities.length>0?'#ef4444':'#22c55e',   nav:'identities', mitre:{tactic:'Priv. Escalation',id:'TA0004',c:'#8b5cf6'}, badge:true},
    {label:'Exposed Hosts',count:exposedHosts.length,  color:exposedHosts.length>0?'#f97316':'#22c55e',  nav:'vulns',      mitre:{tactic:'Initial Access',id:'TA0001',c:'#ef4444'},   badge:true, tooltip:exposedHostsTooltip(exposedHosts)},
    {label:'Compliance',   count:compliance.length,    color:compliance.length>0?'#f59e0b':'#22c55e',    nav:'compliance', mitre:{tactic:'Lateral Movement',id:'TA0008',c:'#f59e0b'}, badge:true},
  ];
  const diagram=document.getElementById('lab-csp-diagram');
  if(diagram)diagram.innerHTML=hexKillChainSvg({
    attacker:{label:'ATTACKER',color:'#ff5e3a'},
    network:{label:'Internet',color:'#3b82f6'},
    factors,
    target:{label:'YOUR CLOUD',subLabel:exposedHostsSubLabel(exposedHosts),tooltip:exposedHostsTooltip(exposedHosts),tier:goalTier,tierColor:color},
    lineColor:color,
    animate:true,
  });
}

function switchVTab(tab){
  ['inet','priv'].forEach(function(t){
    const btn=document.getElementById('vtab-'+t);
    if(btn)btn.classList.toggle('active',t===tab);
    const panel=document.getElementById('vpanel-'+t);
    if(panel)panel.style.display=(t===tab)?'':'none';
  });
}

function switchIdentTab(tab){
  ['aws','azure','gcp'].forEach(function(t){
    const btn=document.getElementById('itab-'+t);
    if(btn)btn.classList.toggle('active',t===tab);
    const body=document.getElementById('ibody-'+t);
    if(body)body.style.display=(t===tab)?'':'none';
  });
  // Auto-load trust principals for all roles when opening a tab that shows role cards / rows
  const body=document.getElementById('ibody-'+tab);
  if(!body)return;
  const btns=body.querySelectorAll('.load-trust-btn:not([data-loaded])');
  btns.forEach(function(btn){
    btn.setAttribute('data-loaded','1');
    loadTrustPrincipals(btn);
  });
}

function switchLabTab(tab){
  _currentLabTab=tab;
  ['global','aws','azure','gcp'].forEach(t=>{
    const btn=document.getElementById('labtab-'+t);
    if(btn)btn.classList.toggle('active',t===tab);
  });
  const gp=document.getElementById('lab-global-panel');
  const cp=document.getElementById('lab-csp-panel');
  if(tab==='global'){
    if(gp)gp.style.display='';
    if(cp)cp.style.display='none';
  }else{
    if(gp)gp.style.display='none';
    if(cp)cp.style.display='';
    if(_lastData)renderCspLab(_lastData,tab);
  }
}

// Hover-tooltip text for the Exposed-Hosts diagram node — computed up front and passed
// as factors[].tooltip into hexKillChainSvg (the node is re-rendered from scratch each
// load(), so there's no persistent <title> element left to patch after the fact).
function exposedHostsTooltip(exposedHosts){
  if(!exposedHosts.length)return'No internet-exposed hosts detected';
  return exposedHosts.map(h=>h.name+(h.publicIP?' ('+h.publicIP+')':'')).join(', ');
}
// Compact IP list shown directly inside the "YOUR CLOUD" hex on the kill-chain diagram —
// short enough to fit the shape; full name+IP detail is on the hex's hover tooltip instead
// (was previously a separate caption row below the whole diagram, disconnected from it).
function exposedHostsSubLabel(exposedHosts){
  const withIp=exposedHosts.filter(h=>h.publicIP);
  if(!withIp.length)return null;
  if(withIp.length<=2)return withIp.map(h=>h.publicIP).join('  ·  ');
  return withIp.length+' exposed IPs';
}
// Visible IP-caption row below the diagram — shared by the Global panel (jnd3-ip-row)
// and each per-CSP panel (cjnd3-ip-row).
function renderExposedHostsCapRow(exposedHosts,capRowId){
  const capRow=document.getElementById(capRowId);
  if(!capRow)return;
  const withIp=exposedHosts.filter(h=>h.publicIP);
  if(withIp.length){
    capRow.style.display='';
    capRow.innerHTML=withIp.map(h=>'<b style="font-family:SFMono-Regular,Consolas,monospace">'+e(h.publicIP)+'</b> <span style="color:#9ca3af">('+e(h.name)+')</span>').join('&nbsp;&nbsp;·&nbsp;&nbsp;');
  }else{
    capRow.style.display='none';
  }
}
function renderLab(d){
  const p=calcPostureScore(d);
  const color=scoreColor(p);
  const band=scoreBand(p);
  const ls=document.getElementById('lab-score');ls.textContent=p;ls.style.color=color;
  const labBandEl=document.getElementById('lab-band-txt');
  labBandEl.textContent=band;labBandEl.title=scoreTierDetail(p);
  // Compute internet-exposed hosts for the Exposed Hosts node and per-host graphs
  const {map:_hmap,critMisc:_critMisc}=buildAssetRiskMap(d);
  const _allHosts=Object.values(_hmap);
  const _maxRisk=_allHosts.reduce(function(m,a){return Math.max(m,a.risk);},1);
  _allHosts.forEach(function(a){a.normalizedScore=Math.round(a.risk/_maxRisk*100);});
  // normalizedScore is relative to maxRisk across ALL hosts — a handful of private hosts
  // with huge unbounded CVE counts (threatRisk sums every CVE's score, uncapped per host)
  // can push maxRisk into the thousands and crush a genuinely internet-exposed host's
  // normalizedScore under any reasonable cutoff. This node counts exposure, not relative
  // risk rank, so it must not apply that threshold — matches the per-CSP panel below,
  // which already lists every internetExposed host with no score gate.
  const _exposedHosts=_allHosts.filter(function(h){return h.internetExposed===true;})
    .sort(function(a,b){return b.normalizedScore-a.normalizedScore;});
  const goalTier=scoreTier(p).toUpperCase();
  const factors=[
    {label:'Identities',   count:(d.identities||[]).length, color:(d.identities||[]).length>0?'#ef4444':'#22c55e', nav:'identities', mitre:{tactic:'Priv. Escalation',id:'TA0004',c:'#8b5cf6'}, badge:true},
    {label:'Crit. Alerts', count:(d.alerts||[]).length,      color:(d.alerts||[]).length>0?'#ef4444':'#22c55e',     nav:'alerts',     mitre:{tactic:'Discovery',id:'TA0007',c:'#f97316'},        badge:true},
    {label:'Exposed Hosts',count:_exposedHosts.length,       color:_exposedHosts.length>0?'#f97316':'#22c55e',      nav:'vulns',      mitre:{tactic:'Initial Access',id:'TA0001',c:'#ef4444'},   badge:true, tooltip:exposedHostsTooltip(_exposedHosts)},
    {label:'Compliance',   count:(d.compliance||[]).length,  color:(d.compliance||[]).length>0?'#f59e0b':'#22c55e', nav:'compliance', mitre:{tactic:'Lateral Movement',id:'TA0008',c:'#f59e0b'}, badge:true},
    {label:'Secrets',      count:(d.secretsAll||[]).length,  color:(d.secretsAll||[]).length>0?'#eab308':'#22c55e', nav:'secrets-all',mitre:{tactic:'Credential Access',id:'T1552',c:'#eab308'}, badge:true},
  ];
  const diagram=document.getElementById('lab-global-diagram');
  if(diagram)diagram.innerHTML=hexKillChainSvg({
    attacker:{label:'ATTACKER',color:'#ff5e3a'},
    network:{label:'Internet',color:'#3b82f6'},
    factors,
    target:{label:'YOUR CLOUD',subLabel:exposedHostsSubLabel(_exposedHosts),tooltip:exposedHostsTooltip(_exposedHosts),tier:goalTier,tierColor:color},
    lineColor:color,
    animate:true,
  });
  // Public Storage badge — separate stat, not one of the 5 attack-chain nodes above
  const storageCount=computeEffectivePublicStorage(d).findings.length;
  const sBadge=document.getElementById('lab-storage-badge');
  if(sBadge){
    sBadge.style.display=storageCount>0?'flex':'none';
    document.getElementById('lab-storage-cnt').textContent=storageCount;
    document.getElementById('lab-storage-plural').textContent=storageCount===1?'':'s';
  }
}

function closeHostGraph(){
  const ov=document.getElementById('host-graph-overlay');
  if(ov)ov.style.display='none';
}

function openHostGraph(hostName,resourceName){
  // ── Determine if this is a private host (from secretsAll) or internet-exposed ──
  var privHost=_renderedPrivMap&&(_renderedPrivMap[hostName.toLowerCase()]||_renderedPrivMap[hostName]);
  var isPrivate=!!privHost;

  // Internet-exposed path
  var host=null,score=0,tier='LOW',tc='#4b5563',tbd='#d1d5db',tbg='#f9fafb',cm=0,secCnt=0;
  if(!isPrivate){
    if(!_renderedAssetMap)return;
    const {map:hmap,maxRisk:maxR,critMisc:_cm}=_renderedAssetMap;
    const allH=Object.values(hmap);
    allH.forEach(function(a){a.normalizedScore=Math.round(a.risk/maxR*100);});
    host=allH.find(function(h){return h.name===hostName;});
    if(!host)return;
    cm=_cm;
    const TIER_COL={CRITICAL:'#b91c1c',HIGH:'#c2410c',MEDIUM:'#92400e',LOW:'#4b5563'};
    const TIER_BD ={CRITICAL:'#fca5a5',HIGH:'#fdba74',MEDIUM:'#fcd34d',LOW:'#d1d5db'};
    const TIER_BG ={CRITICAL:'#fff7f7',HIGH:'#fff7ed',MEDIUM:'#fffbeb',LOW:'#f9fafb'};
    score=host.normalizedScore||0;
    const _tier=(function(s,ex){if(s>=75)return ex?'CRITICAL':'MEDIUM';if(s>=50)return ex?'HIGH':'LOW';if(s>=30)return'MEDIUM';return'LOW';})(score,host.internetExposed);
    tier=_tier; tc=TIER_COL[tier]; tbd=TIER_BD[tier]; tbg=TIER_BG[tier];
    secCnt=(host.ciemSecrets||[]).length+(host.genericSecrets||[]).length;
  }

  // ── Build factors list ─────────────────────────────────────────────────────
  var factors=[];
  if(!isPrivate){
    if(host.vulns&&host.vulns.length)factors.push({label:'CVEs',count:host.vulns.length,color:'#f97316',nav:'vulns'});
    if(cm>0)factors.push({label:'Non-Compliance',count:cm,color:'#f59e0b',nav:'compliance'});
    if(secCnt>0)factors.push({label:'Secrets',count:secCnt,color:'#eab308',nav:'secrets-all'});
  } else {
    var ph=privHost;
    if(ph.vulns&&ph.vulns.length)factors.push({label:'CVEs',count:ph.vulns.length,color:'#f97316',nav:'vulns'});
    if(ph.ciemSecrets&&ph.ciemSecrets.length)factors.push({label:'CIEM Creds',count:ph.ciemSecrets.length,color:'#b91c1c',nav:'secrets-all'});
    if(ph.genericSecrets&&ph.genericSecrets.length)factors.push({label:'Secrets',count:ph.genericSecrets.length,color:'#92400e',nav:'secrets-all'});
    secCnt=(ph.ciemSecrets||[]).length+(ph.genericSecrets||[]).length;
    tc='#7c3aed'; tbd='#ddd6fe'; tbg='#f5f3ff'; tier='PRIVATE';
  }
  if(!factors.length)factors.push({label:'At Risk',count:1,color:'#6b7280',nav:'asset-risk'});

  // ── Deep Space hex diagram ──────────────────────────────────────────────
  var mFact=factors.map(function(f){
    if(f.label==='CVEs')return{t:'Exploitation',id:'T1203',c:'#f97316'};
    if(f.label.indexOf('Cred')>=0)return{t:'Credential Access',id:'T1552',c:'#eab308'};
    if(f.label==='Secrets')return{t:'Credential Access',id:'T1552',c:'#eab308'};
    if(f.label==='Non-Compliance')return{t:'Priv. Escalation',id:'T1078',c:'#8b5cf6'};
    return{t:'Persistence',id:'TA0003',c:'#6b7280'};
  });
  var hexFactors=factors.map(function(f,i){
    return{label:f.label,count:f.count,color:f.color,nav:f.nav,mitre:mFact[i]};
  });
  // Resource Name (e.g. "my-blogs"), when known, is far more identifiable in the hex
  // diagram than the raw hostname — prefer it, falling back to the raw hostname.
  var hnSource=resourceName||hostName;
  var hn=hnSource.length>20?hnSource.substring(0,19)+'…':hnSource;
  var svg=hexKillChainSvg({
    attacker:{label:isPrivate?'LATERAL ATTACK':'ATTACKER',color:isPrivate?'#ea580c':'#ff5e3a'},
    network:{label:isPrivate?'Private Network':'Internet',color:isPrivate?'#ea580c':'#3b82f6'},
    factors:hexFactors,
    target:{
      label:hn,
      subLabel:!isPrivate&&host.publicIP?'…':null,
      tier:tier,
      tierColor:tc,
      badge:true,
    },
    animate:true,
  });

  // ── Remediation footer ─────────────────────────────────────────────────────
  var remItems=[];
  if(!isPrivate){
    if(host.vulns&&host.vulns.length)remItems.push('Patch '+host.vulns.length+' CVE'+(host.vulns.length!==1?'s':''));
    if(cm>0)remItems.push('Fix '+cm+' misconfiguration'+(cm!==1?'s':''));
  }
  if(secCnt>0)remItems.push('Remove '+secCnt+' exposed secret'+(secCnt!==1?'s':''));

  var html='<div style="border-bottom:1px solid '+tbd+';padding:8px 20px;background:'+tbg+';display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
    +'<span style="font-family:SFMono-Regular,Consolas,monospace;font-size:13px;font-weight:700;color:#111827">'+e(hnSource)+'</span>'
    +'<span style="font-size:9px;font-weight:700;color:'+tc+';letter-spacing:.08em;border:1px solid '+tbd+';border-radius:3px;padding:2px 7px">'+tier+'</span>'
    +(!isPrivate&&host.publicIP?'<span style="font-size:9px;font-weight:600;color:#dc2626;background:#fee2e2;border-radius:3px;padding:2px 8px">'+e(host.publicIP)+'</span>':'')
    +(isPrivate?'<span style="font-size:9px;color:#6b7280">Lateral movement risk &middot; '+secCnt+' exposed credential'+(secCnt!==1?'s':'')+'</span>':'')
    +(isPrivate?'':'<span style="margin-left:auto;font-size:11px;color:#6b7280">Risk Score: <b style="color:'+tc+'">'+score+'/100</b></span>')
  +'</div>'
  +(!isPrivate&&host.publicIP?'<div id="hg-geo-bar" style="padding:5px 20px;background:#f8fafc;border-bottom:1px solid #e2e8f0;font-size:10px;color:#64748b;display:flex;align-items:center;gap:6px"><span style="color:#94a3b8;font-style:italic">Looking up GeoIP location…</span></div>':'')
  +'<div style="padding:8px 0">'+svg+'</div>'
  +(remItems.length?'<div style="padding:10px 20px;background:#f0fdf4;border-top:1px solid #bbf7d0;font-size:11px;font-weight:600;color:#166534">&#10003; To close this attack path: '+remItems.join(' &nbsp;&middot;&nbsp; ')+'</div>':'');

  document.getElementById('host-graph-title').textContent=(isPrivate?'Lateral Attack Path — ':'Attack Path — ')+hnSource;
  document.getElementById('host-graph-body').innerHTML=html;
  document.getElementById('host-graph-overlay').style.display='flex';

  // GeoIP only for internet-exposed hosts
  if(!isPrivate&&host.publicIP){
    (async function(){
      var ip=host.publicIP;
      try{
        if(!_geoCache[ip]){
          var r=await fetch('/api/geoip?ip='+encodeURIComponent(ip));
          _geoCache[ip]=await r.json();
        }
        var d=_geoCache[ip];
        if(d&&!d.error&&!d.status){
          var loc=(d.city||'')+(d.city&&d.country?', ':'')+( d.country||'');
          var geoEl=document.getElementById('hg-geo-txt');
          if(geoEl)geoEl.textContent=loc||ip;
          var bar=document.getElementById('hg-geo-bar');
          if(bar){
            var flag=d.country?'<img src="https://flagcdn.com/16x12/'+d.country.toLowerCase()+'.png" style="vertical-align:middle;border-radius:1px" width="16" height="12" alt="'+e(d.country)+'"/> ':'';
            bar.innerHTML=flag+'<b style="color:#1e293b">'+e(loc||ip)+'</b>'
              +(d.org?'&nbsp;&middot;&nbsp;<span style="color:#64748b">'+e(d.org)+'</span>':'')
              +'&nbsp;&middot;&nbsp;<span style="color:#ef4444;font-weight:600">Exposed to Internet</span>';
          }
        }
      }catch(ex){}
    })();
  }
}

async function load(){
  try{
    const d=await fetch('/api/data').then(r=>r.json());
    // Data not ready yet (server still fetching) — retry in 15s
    if(!d.fetchedAt){
      document.getElementById('live-dot').className='live-dot';
      document.getElementById('fetched-at').textContent='Loading…';
      setTimeout(load,15000);
      return;
    }
    _lastData=d;
    renderAlerts(d.alerts,d.errors?.alerts);
    _preTriageAll(d.alerts);
    renderVulns(d.vulns,d.errors?.vulns);
    renderCompliance(d.compliance,d.errors?.compliance);
    renderIdentities(d.identities,d.errors?.identities);
    renderSecretsAll(d.secretsAll,d.errors?.secretsAll);
    renderPublicStorage(d);
    renderFortiGate(d);
    renderExposedAssets(d);
    renderAttackPaths(d);
    renderInternetHostExposedBeta(d);
    renderAssetRisk(d);
    updateRiskScore(calcGlobalScoreFromCsp(d));
    updateCspGauges(d);
    renderRiskFindings(d);
    renderLab(d);
    if(_currentLabTab!=='global')renderCspLab(d,_currentLabTab);
    buildPie(d);
    document.getElementById('fetched-at').textContent=fmtDate(d.fetchedAt);
    const da=document.getElementById('dash-acct');if(da)da.textContent=d.account||'';
    const _db=d.daysBack||${DAYS_BACK};
    document.getElementById('footer-time').textContent='Assessment window: '+_db+' days';
    const _sa=document.getElementById('sub-alerts');
    if(_sa)_sa.textContent='Active threats & policy violations · last 14 days';
    const live=document.getElementById('live-dot');
    live.className='live-dot '+(Object.keys(d.errors||{}).length?'err':'ok');
    const bar=document.getElementById('err-bar');
    const errs=Object.entries(d.errors||{});
    if(errs.length){bar.textContent='Errors: '+errs.map(([k,v])=>k+': '+v).join(' | ');bar.classList.add('show');}
    else bar.classList.remove('show');
    cd=REFRESH;
  }catch(ex){
    document.getElementById('live-dot').className='live-dot err';
    console.error('/api/data failed:',ex);
  }
}

function startupSequence(){
  cd=10;
  _isStartup=true;
  // Defer fact cycling + load timer past script init so _fgAllFacts (let, line ~2376) is in scope
  setTimeout(function(){
    function _startupShowFact(){
      if(!_fgEnabled)return;
      var facts=(typeof _fgAllFacts!=='undefined'&&_fgAllFacts.length)?_fgAllFacts:FG_FACTS;
      if(!facts.length)return;
      var fact=facts[Math.floor(Math.random()*facts.length)];
      var card=document.getElementById('fg-inline');
      var factEl=document.getElementById('fg-inline-fact');
      var srcEl=document.getElementById('fg-inline-src');
      if(factEl)factEl.textContent=fact;
      if(srcEl)srcEl.textContent=fact.startsWith('📰')?'fortinet.com/blog':'fortinet.com/cloud-security-report-2026';
      if(card)card.classList.add('show');
    }
    _startupShowFact();
    var _startupFactTimer=setInterval(function(){if(_isStartup)_startupShowFact();},2000);
    setTimeout(function(){
      _isStartup=false;
      clearInterval(_startupFactTimer);
      load();
      setInterval(load,REFRESH*1000);
      cd=REFRESH;
    },10000);
  },0);
}

function updateRiskScore(p){
  const color=scoreColor(p);
  const arcLen=550;
  const fill=(p/100)*arcLen;
  const arc=document.getElementById('gauge-arc');
  if(arc){arc.setAttribute('stroke-dasharray',fill+' '+arcLen);}
  const gs=document.getElementById('gauge-score');
  if(gs){gs.textContent=p;gs.setAttribute('fill',color);}
  updateLadder(p);
}
function updateLadder(p){
  const band=p<31?'foundational':p<61?'managed':p<81?'advanced':'optimized';
  ['foundational','managed','advanced','optimized'].forEach(b=>{
    const el=document.getElementById('bubble-'+b);
    if(!el)return;
    el.setAttribute('opacity', b===band ? '1' : '0.35');
    el.style.filter = b===band ? 'url(#bub-glow)' : '';
  });
}

function calcGlobalScoreFromCsp(d){
  const scores=['aws','azure','gcp'].map(csp=>{const r=calcCspScore(d,csp);return r!==null?r:100;});
  return Math.round(scores.reduce((s,v)=>s+v,0)/scores.length);
}

function updateCspGauges(d){
  const arcLen=314;
  const co=(d.account||'').replace(/\.lacework\.net$/i,'')||'';
  const cspLabel={aws:'AWS',azure:'Azure',gcp:'GCP'};

  function cspSubAccounts(csp){
    const names=new Set();
    // Compliance — named accounts only, never raw numeric IDs
    (d.compliance||[]).filter(r=>(r.cloud||'')===csp||(csp==='azure'&&(r.cloud||'')==='cloud')).forEach(finding=>{
      (finding.resources||[]).slice(0,10).forEach(row=>{
        if(csp==='aws'){
          const alias=(row.ACCOUNT_ALIAS||'').trim();
          if(alias) names.add(alias);                   // named alias only
        } else if(csp==='azure'){
          const n=row.SUBSCRIPTION_NAME||row.TENANT_NAME||'';
          if(n) names.add(n);
        } else if(csp==='gcp'){
          const n=row.PROJECT_NAME||'';
          if(n) names.add(n);
        }
      });
    });
    // Fallback: identity email domain for GCP; skip AWS (no alias = no name)
    if(!names.size){
      (d.identities||[]).filter(r=>cspOfIdentity(r)===csp).forEach(r=>{
        const pid=r.PRINCIPAL_ID||'';
        if(csp==='gcp'){
          const m=pid.match(new RegExp('@([^.]+)\\.'));
          if(m) names.add(m[1]);
        }
      });
    }
    return [...names].slice(0,3);
  }

  ['aws','azure','gcp'].forEach(csp=>{
    const raw=calcCspScore(d,csp);
    const p=raw!==null?raw:100;
    const color=scoreColor(p);
    const band=scoreTier(p).toUpperCase();
    const arc=document.getElementById('csp-arc-'+csp);
    const scoreEl=document.getElementById('csp-score-'+csp);
    const bandEl=document.getElementById('csp-band-'+csp);
    const labelEl=document.getElementById('csp-label-'+csp);
    const orgEl=document.getElementById('csp-org-'+csp);
    const subEl=document.getElementById('csp-sub-'+csp);
    if(arc){arc.setAttribute('stroke',color);arc.setAttribute('stroke-dasharray',(p/100*arcLen)+' '+arcLen);}
    if(scoreEl){scoreEl.textContent=p;scoreEl.setAttribute('fill',color);}
    if(bandEl){bandEl.textContent=band;bandEl.setAttribute('fill',color);bandEl.setAttribute('title',scoreTierDetail(p));}
    if(labelEl){labelEl.textContent=cspLabel[csp];}
    if(orgEl)orgEl.textContent=co||'—';
    // FortiAccount: prefer d.subAccount (from LW key file / env), else CSP-derived names
    const fortiAcct=(d.subAccount||'').trim();
    const subs=fortiAcct?[fortiAcct]:cspSubAccounts(csp);
    if(subEl)subEl.textContent=subs.length?subs.join(' · '):'—';
  });
}

// ── Login ─────────────────────────────────────────────────────────────────────
function setCookie(name,val,days){
  const d=new Date();d.setTime(d.getTime()+days*86400000);
  document.cookie=name+'='+encodeURIComponent(val)+';expires='+d.toUTCString()+';path=/;SameSite=Lax';
}
function getCookie(name){
  const v=document.cookie.split(';').find(c=>c.trim().startsWith(name+'='));
  return v?decodeURIComponent(v.trim().slice(name.length+1)):null;
}

function wireReportBtn(user){
  if(!user) return;
  const params=new URLSearchParams({customer:(user.company||'Customer'),author:(user.first||'')+(user.last?' '+user.last:'')});
  const btn=document.getElementById('rpt-btn-link');
  if(btn)btn.href='/report?'+params.toString();
  const btn2=document.getElementById('rpt2-btn-link');
  if(btn2)btn2.href='/report2?'+params.toString();
  const btn3=document.getElementById('rpt3-btn-link');
  if(btn3)btn3.href='/report3?'+params.toString();
  const btn4=document.getElementById('rpt4-btn-link');
  if(btn4)btn4.href='/report4?'+params.toString();
}

function showUserBadge(user){
  const initials=((user.first||'?')[0]+(user.last||'?')[0]).toUpperCase();
  document.getElementById('tb-avatar').textContent=initials;
  document.getElementById('tb-name').textContent=(user.first||'')+' '+(user.last||'');
  document.getElementById('tb-role').textContent=(user.title?user.title+' · ':'')+( user.company||'');
  document.getElementById('tb-admin-badge').style.display='none';
  document.getElementById('top-bar').style.display='flex';
  const acct=document.getElementById('acct-lbl');
  if(acct&&user.company)acct.textContent=user.company;
}
function logout(){
  window.location.href='/';
}

startupSequence();
loadAdminSettings();



const ADMIN_SETTINGS_PWD='fortinetadmin';
let _adminUnlocked=false;
function unlockAdminSettings(){
  const inp=document.getElementById('admin-settings-pwd');
  const err=document.getElementById('admin-settings-pwd-err');
  if(!inp)return;
  if(inp.value===ADMIN_SETTINGS_PWD){
    _adminUnlocked=true;
    document.getElementById('admin-settings-lock').style.display='none';
    document.getElementById('admin-settings-content').style.display='block';
    if(err)err.style.display='none';
  }else{
    if(err)err.style.display='block';
    inp.value='';
    inp.focus();
  }
}

async function loadAdminSettings(){
  try{
    const s=await fetch('/api/settings').then(r=>r.json());
    const sec=s.refreshIntervalSec||86400;
    const sel=document.getElementById('settings-refresh-select');
    if(sel){
      const opts=[21600,43200,86400,172800];
      const closest=opts.reduce((a,b)=>Math.abs(b-sec)<Math.abs(a-sec)?b:a);
      sel.value=String(closest);
    }
    const cur=document.getElementById('settings-cur-interval');
    if(cur)cur.textContent=fmtSec(sec);
    setFooterInterval(sec);
    cd=sec;
    const days=s.daysBack||15;
    const dsel=document.getElementById('settings-days-select');
    if(dsel)dsel.value=String(days);
    const dcur=document.getElementById('settings-cur-days');
    if(dcur)dcur.textContent=days+' days';
  }catch(ex){}
}
// ── FortiCNAPP link vibrate + cowsay ─────────────────────────────────────────
const FG_FACTS=[
  "83% of cloud breaches in 2026 started with a misconfiguration — not a zero-day. Patch your posture first. 🔧",
  "67% of organizations experienced a cloud security incident in the past 12 months. Is yours next? 🎯",
  "The average cost of a cloud data breach reached $5.17M in 2026 — up 9% from the prior year. ☕ That's a lot of coffee.",
  "78% of cloud workloads still run with excessive IAM permissions. Least-privilege is the policy, not the reality. 🔑",
  "Organizations with CNAPP detected breaches 2.4× faster than those relying on point tools alone. ⚡",
  "Multi-cloud environments are 3.5× more likely to suffer a breach than single-cloud deployments. Complexity is the enemy. 🌐",
  "Credential theft was the initial vector in 64% of all cloud incidents. Rotate your keys — yes, all of them. 🔐",
  "91% of cloud environments had at least one critical misconfiguration at the time of assessment. Yours probably does too. 👀",
  "Container workloads with unpatched CVEs (CVSS ≥ 9) increased 41% year-over-year. Ship secure or ship slow. 📦",
  "The average dwell time before cloud breach detection: 197 days. FortiCNAPP cuts that to hours. ⏱️",
  "Shadow IT introduces ~1,200 ungoverned cloud services per enterprise annually. You can't protect what you can't see. 👻",
  "Secrets hardcoded in cloud workloads increased 38% in 2026. Your dev team is human. FortiCNAPP is not. 🤖",
  "73% of cloud-native apps had at least one high-severity vulnerability in their runtime environment. Ship fast, patch faster. 🚀",
  "Identity-based attacks now account for 71% of cloud lateral movement. Your IAM graph is an attacker's roadmap. 🗺️",
  "FortiCNAPP unified CSPM, CWPP, and CIEM cut mean-time-to-remediate by 58% vs. siloed tools. One platform. Full coverage. 🛡️"
];
const FG_COW_LINES=["  \\\\   ^__^","   \\\\  (oo)\\\\_____","      (__)\\\\     )","          ||----w |","          ||     ||"];
let _fgEnabled=true,_fgHideTimer=null,_fgLiveFacts=[],_fgAllFacts=FG_FACTS.slice();
// Fetch latest Fortinet blog headlines and merge with built-in facts
function _fgLoadLiveFacts(){
  fetch('/api/fg-facts').then(function(r){return r.json();}).then(function(d){
    if(d.facts&&d.facts.length){
      _fgLiveFacts=d.facts;
      _fgAllFacts=FG_FACTS.concat(_fgLiveFacts);
    }
  }).catch(function(){});
  // Refresh live facts every 30 min
  setTimeout(_fgLoadLiveFacts,1800000);
}
_fgLoadLiveFacts();
function _fgPickFact(){return _fgAllFacts[Math.floor(Math.random()*_fgAllFacts.length)];}
function _fgShowCard(){
  if(!_fgEnabled)return;
  const card=document.getElementById('fg-inline');
  const factEl=document.getElementById('fg-inline-fact');
  const srcEl=document.getElementById('fg-inline-src');
  if(!card||!factEl)return;
  const fact=_fgPickFact();
  factEl.textContent=fact;
  if(srcEl)srcEl.textContent=fact.startsWith('📰')?'fortinet.com/blog':'fortinet.com/cloud-security-report-2026';
  card.classList.add('show');
}
function _fgHideCard(){
  const card=document.getElementById('fg-inline');
  if(card)card.classList.remove('show');
}
let _fgFreqSec=30,_fgCycleTimer=null;
// Arrow blinks independently every 90-150s for 3s
function _fgArrowCycle(){
  if(!_fgEnabled){setTimeout(_fgArrowCycle,15000);return;}
  const arr=document.getElementById('fg-arrow');
  if(arr)arr.style.display='';
  setTimeout(function(){
    if(arr)arr.style.display='none';
    setTimeout(_fgArrowCycle,90000+Math.floor(Math.random()*60000));
  },3000);
}
setTimeout(_fgArrowCycle,5000);
// Card cycle — show for 10s, hide, wait _fgFreqSec, repeat
function _fgRunCycle(){
  if(_fgCycleTimer)clearTimeout(_fgCycleTimer);
  if(_fgHideTimer)clearTimeout(_fgHideTimer);
  if(_fgEnabled)_fgShowCard();
  _fgHideTimer=setTimeout(function(){
    _fgHideCard();
    _fgCycleTimer=setTimeout(_fgRunCycle,_fgFreqSec*1000);
  },10000);
}
function applyFactFreq(val){
  _fgFreqSec=parseInt(val,10)||30;
  _fgRunCycle();
  try{localStorage.setItem('fg-freq',String(_fgFreqSec));}catch(e){}
  const s=document.getElementById('settings-fact-saved');
  if(s){s.style.opacity='1';setTimeout(function(){s.style.opacity='0';},2000);}
}
function toggleFgVibe(on){
  _fgEnabled=on;
  const arr=document.getElementById('fg-arrow');
  if(!on){
    if(_fgCycleTimer){clearTimeout(_fgCycleTimer);_fgCycleTimer=null;}
    if(_fgHideTimer){clearTimeout(_fgHideTimer);_fgHideTimer=null;}
    if(arr)arr.style.display='none';
    _fgHideCard();
  } else {
    _fgRunCycle();
  }
  try{localStorage.setItem('fg-vibe',on?'1':'0');}catch(e){}
}
// Hover on FortiCNAPP link also triggers card
document.addEventListener('mouseover',function(ev){if(ev.target.closest('#fg-link'))_fgShowCard();});
document.addEventListener('mouseout',function(ev){if(ev.target.closest('#fg-link'))_fgHideCard();});
(function(){
  try{
    const savedVibe=localStorage.getItem('fg-vibe');
    _fgEnabled=savedVibe===null||savedVibe==='1';
    const savedFreq=parseInt(localStorage.getItem('fg-freq')||'30',10);
    _fgFreqSec=savedFreq||30;
    const cb=document.getElementById('settings-vibe-toggle');
    if(cb)cb.checked=_fgEnabled;
    const sel=document.getElementById('settings-fact-freq');
    if(sel)sel.value=String(_fgFreqSec);
    if(_fgEnabled)_fgRunCycle();
  }catch(e){}
})();
async function applySettings(){
  const sel=document.getElementById('settings-refresh-select');
  if(!sel)return;
  const sec=parseInt(sel.value,10);
  try{
    await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refreshIntervalSec:sec})});
    const cur=document.getElementById('settings-cur-interval');
    if(cur)cur.textContent=fmtSec(sec);
    setFooterInterval(sec);
    cd=sec;
    const saved=document.getElementById('settings-saved');
    if(saved){saved.style.opacity='1';setTimeout(()=>saved.style.opacity='0',2500);}
  }catch(ex){}
}
async function applyDaysBack(){
  const sel=document.getElementById('settings-days-select');
  if(!sel)return;
  const days=parseInt(sel.value,10);
  try{
    await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({daysBack:days})});
    const dcur=document.getElementById('settings-cur-days');
    if(dcur)dcur.textContent=days+' days';
    const saved=document.getElementById('settings-days-saved');
    if(saved){saved.style.opacity='1';setTimeout(()=>saved.style.opacity='0',2500);}
  }catch(ex){}
}
setFooterInterval(REFRESH);
setInterval(()=>{
  cd=Math.max(0,cd-1);
  const el=document.getElementById('countdown');
  if(!el)return;
  el.textContent=_isStartup
    ?'Populating dashboard in '+fmtSec(Math.max(0,cd))+'…'
    :'Next refresh in '+fmtSec(cd);
},1000);
(function(){var h=location.hash.replace('#','');if(h&&document.getElementById('view-'+h))nav(h);})();

// ── AI Investigation Chat ─────────────────────────────────────────────────────
// Pre-triage cache: { alertId -> { threadId, message, responseId } | 'pending' }
const _aiTriageCache={};

function _aiMarkBtn(alertId,ready){
  document.querySelectorAll('.ai-inv-btn[data-aid="'+alertId+'"]').forEach(function(b){
    if(ready){
      b.textContent='⚡ Triage';
      b.disabled=false;
      b.style.background='#16a34a';
      b.style.cursor='pointer';
      b.style.opacity='1';
      b.title='AI triage ready — click to start';
      b.classList.add('ai-ready');
    }else{
      b.textContent='🤖 Triage';
      b.disabled=true;
      b.style.background='#94a3b8';
      b.style.cursor='not-allowed';
      b.style.opacity='.7';
      b.title='AI triage preparing…';
      b.classList.remove('ai-ready');
    }
  });
}

async function _preTriage(alertId){
  const existing=_aiTriageCache[alertId];
  if(existing&&existing!=='pending'){_aiMarkBtn(alertId,true);return;}
  if(existing==='pending')return;
  _aiTriageCache[alertId]='pending';
  try{
    const ds=await _aiStartThread(alertId);
    if(ds.error||!ds.threadId){delete _aiTriageCache[alertId];return;}
    const rq=await _aiFetchRetry('/api/ai/message',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({threadId:ds.threadId,alertId,message:_AI_PROMPTS.triage})});
    const dq=await rq.json();
    if(dq.error){delete _aiTriageCache[alertId];return;}
    _aiTriageCache[alertId]={threadId:ds.threadId,message:dq.message||'',responseId:dq.responseId};
    _aiMarkBtn(alertId,true);
  }catch(e){delete _aiTriageCache[alertId];}
}

function _preTriageAll(alerts){
  var delay=0;
  (alerts||[]).forEach(function(r){
    var aid=r.alertId||'';
    var cached=_aiTriageCache[aid];
    if(cached&&cached!=='pending'){
      _aiMarkBtn(aid,true); // already cached — mark green immediately
    }else if(!cached){
      // New fetch — stagger to avoid hammering the API
      setTimeout(function(){_preTriage(aid);},delay);
      delay+=2000;
    }
    // 'pending' — already in-flight, do nothing
  });
}

// Pre-warm cache: start the AI thread as soon as the user hovers an Investigate button
const _aiWarmCache={};
document.addEventListener('mouseover',function(ev){
  const btn=ev.target.closest('.ai-inv-btn');
  if(!btn)return;
  const aid=btn.dataset.aid;
  if(!_aiWarmCache[aid])
    _aiWarmCache[aid]=_aiStartThread(aid);
},true);

document.addEventListener('click',function(ev){
  const btn=ev.target.closest('.ai-inv-btn');
  if(!btn||btn.disabled)return;
  openAiChat(btn.dataset.aid,btn.dataset.aname,btn.dataset.asev);
  // Auto-start triage text immediately — no second click required
  setTimeout(function(){pickAiPrompt('triage');},80);
});

function _aiStartThread(alertId){
  return _aiFetchRetry('/api/ai/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alertId})})
    .then(r=>r.json());
}

async function _aiFetchRetry(url,opts,tries=2){
  for(let i=0;i<tries;i++){
    try{return await fetch(url,opts);}
    catch(e){if(i===tries-1)throw e;await new Promise(r=>setTimeout(r,1500));}
  }
}

let _aiThreadId=null,_aiAlertId=null,_aiSending=false,_aiStartPromise=null;

const _AI_PROMPTS={
  triage:'Triage this alert: is it a true or false positive? State severity, what triggered it, affected resources, and the top 3 immediate actions.'
};

function openAiChat(alertId,alertName,severity){
  _aiThreadId=null;_aiAlertId=alertId;_aiSending=false;
  document.getElementById('ai-chat-title').textContent=alertName||('Alert '+alertId);
  document.getElementById('ai-chat-sub').textContent='Alert ID: '+alertId+(severity?' · '+severity:'');
  document.getElementById('ai-chat-body').innerHTML='';
  document.getElementById('ai-chat-input').value='';
  // Hide prompt-row — triage fires automatically on open
  document.getElementById('ai-prompt-row').style.display='none';
  document.getElementById('ai-btn-triage').disabled=true;
  document.getElementById('ai-chat-input').style.display='none';
  document.getElementById('ai-send-btn').style.display='none';
  document.getElementById('ai-chat-overlay').style.display='flex';
  _aiStartPromise=_aiWarmCache[alertId]||_aiStartThread(alertId);
  delete _aiWarmCache[alertId];
}

function _aiStartTimer(el,prefix){
  let s=0;
  const t=setInterval(()=>{el.textContent=prefix+' ('+( ++s)+'s)';},1000);
  return ()=>clearInterval(t);
}

async function pickAiPrompt(type){
  if(_aiSending)return;
  _aiSending=true;
  document.getElementById('ai-btn-triage').disabled=true;
  document.getElementById('ai-prompt-row').style.display='none';
  _aiAddMsg('user',type==='triage'?'Triage':'Incident Report');
  // Serve from pre-triage cache instantly
  const cached=_aiTriageCache[_aiAlertId];
  if(type==='triage'&&cached&&cached!=='pending'){
    _aiThreadId=cached.threadId;
    _aiStreamMsg('assistant',cached.message,cached.responseId);
    document.getElementById('ai-chat-input').style.display='flex';
    document.getElementById('ai-send-btn').style.display='flex';
    document.getElementById('ai-chat-input').focus();
    _aiSending=false;
    return;
  }
  const thinking=_aiAddMsg('thinking','Connecting to FortiCNAPP Agent AI…');
  const stopTimer=_aiStartTimer(thinking,'Connecting to FortiCNAPP Agent AI…');
  // Show a random cloud security fact while waiting, rotate every 15s
  const factEl=_aiAddMsg('fact',_fgPickFact());
  factEl.title='Did you know?';
  const factTimer=setInterval(function(){factEl.textContent=_fgPickFact();},15000);
  try{
    // Await pre-started thread (may already be ready)
    const ds=await _aiStartPromise;
    if(ds.error)throw new Error(ds.error);
    _aiThreadId=ds.threadId;
    thinking.textContent='Analysing alert… 0s';
    stopTimer();
    const stopTimer2=_aiStartTimer(thinking,'Analysing alert…');
    // Send canned question
    const rq=await _aiFetchRetry('/api/ai/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({threadId:_aiThreadId,alertId:_aiAlertId,message:_AI_PROMPTS[type]})});
    stopTimer2();
    const dq=await rq.json();
    clearInterval(factTimer);
    thinking.remove();
    factEl.remove();
    if(dq.error)_aiAddMsg('assistant','Error: '+dq.error);
    else _aiStreamMsg('assistant',dq.message||'(no response)',dq.responseId);
    document.getElementById('ai-prompt-row').style.display='none';
    document.getElementById('ai-chat-input').style.display='flex';
    document.getElementById('ai-send-btn').style.display='flex';
    document.getElementById('ai-chat-input').focus();
  }catch(err){
    clearInterval(factTimer);
    stopTimer();
    thinking.remove();
    factEl.remove();
    _aiAddMsg('assistant','Error: '+err.message);
    document.getElementById('ai-btn-triage').disabled=false;
  }finally{
    _aiSending=false;
  }
}

function _aiAddMsg(role,content,responseId){
  const body=document.getElementById('ai-chat-body');
  const d=document.createElement('div');
  d.className='ai-msg '+role;
  d.dataset.role=role;
  d.textContent=content;
  body.appendChild(d);
  if(role==='assistant'&&responseId){
    const fb=document.createElement('div');
    fb.className='ai-feedback';
    fb.innerHTML='<button class="ai-fb-btn" data-rid="'+responseId+'" data-val="positive" title="Helpful">&#x1F44D;</button>'
      +'<button class="ai-fb-btn" data-rid="'+responseId+'" data-val="negative" title="Not helpful">&#x1F44E;</button>'
      +'<span class="ai-fb-note">Rate this response</span>';
    fb.querySelectorAll('.ai-fb-btn').forEach(btn=>btn.addEventListener('click',function(){
      if(this.closest('.ai-feedback').dataset.voted)return;
      const rating=this.dataset.val;
      this.closest('.ai-feedback').dataset.voted='1';
      this.classList.add(rating==='positive'?'voted':'voted-neg');
      this.closest('.ai-feedback').querySelector('.ai-fb-note').textContent=rating==='positive'?"Thanks for the feedback!":"Thanks, we'll improve.";
      fetch('/api/ai/rate',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({threadId:_aiThreadId,responseId:this.dataset.rid,rating})});
    }));
    body.appendChild(fb);
  }
  body.scrollTop=body.scrollHeight;
  return d;
}

function _aiStreamMsg(role,content,responseId){
  const el=_aiAddMsg(role,'',responseId);
  const words=content.split(' ');
  let i=0;
  const body=document.getElementById('ai-chat-body');
  const t=setInterval(function(){
    if(i<words.length){
      el.textContent+=(i>0?' ':'')+words[i++];
      body.scrollTop=body.scrollHeight;
    }else{
      clearInterval(t);
    }
  },180);
}

async function sendAiMessage(){
  if(_aiSending||!_aiThreadId)return;
  const inp=document.getElementById('ai-chat-input');
  const msg=inp.value.trim();
  if(!msg)return;
  inp.value='';
  _aiSending=true;
  document.getElementById('ai-send-btn').disabled=true;
  _aiAddMsg('user',msg);
  const thinking=_aiAddMsg('thinking','Thinking…');
  try{
    const r=await fetch('/api/ai/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({threadId:_aiThreadId,alertId:_aiAlertId,message:msg})});
    const d=await r.json();
    thinking.remove();
    if(d.error)_aiAddMsg('assistant','Error: '+d.error);
    else _aiStreamMsg('assistant',d.message||'(no response)',d.responseId);
  }catch(err){
    thinking.remove();
    _aiAddMsg('assistant','Error: '+err.message);
  }finally{
    _aiSending=false;
    document.getElementById('ai-send-btn').disabled=false;
    document.getElementById('ai-chat-input').focus();
  }
}

function closeAiChat(){
  document.getElementById('ai-chat-overlay').style.display='none';
  _aiThreadId=null;_aiAlertId=null;
}

// ── Machine Details panel ─────────────────────────────────────────────────────
document.addEventListener('click',function(ev){
  const mb=ev.target.closest('.mach-inv-btn');
  if(mb)openMachineDetails(mb.dataset.hostname);
  const ib=ev.target.closest('.ident-det-btn');
  if(ib)openIdentityDetails(ib.dataset.pid);
  const cb=ev.target.closest('.comp-det-btn');
  if(cb)openComplianceDetails(cb.dataset.pid);
  const tb=ev.target.closest('.load-trust-btn');
  if(tb)loadTrustPrincipals(tb);
  const vb=ev.target.closest('.cve-det-btn');
  if(vb)openCveDetails(vb.dataset.cve);
  const xb=ev.target.closest('.toggle-host-cve');
  if(xb){
    var bd=document.getElementById(xb.dataset.body);
    if(bd){
      var open=bd.style.display!=='none';
      bd.style.display=open?'none':'block';
      xb.innerHTML=(open?'&#9654; ':'&#9660; ')+'CVEs';
    }
  }
  const gb=ev.target.closest('.rf-grp-toggle');
  if(gb){
    var gbd=document.getElementById(gb.dataset.body);
    if(gbd){
      var gopen=gbd.style.display!=='none';
      gbd.style.display=gopen?'none':'table-row-group';
      var chev=gb.querySelector('.rf-grp-chevron');
      if(chev)chev.innerHTML=gopen?'&#9654;':'&#9660;';
    }
  }
});

async function loadTrustPrincipals(btn){
  var pid=btn.dataset.pid;if(!pid)return;
  var container=document.getElementById('trust-'+pid);
  if(!container)return;
  btn.disabled=true;btn.textContent='Loading…';
  try{
    var r=await fetch('/api/identity-trust?pid='+encodeURIComponent(pid));
    var d=await r.json();
    btn.style.display='none';
    if(d.error){container.innerHTML='<div style="font-size:10px;color:#94a3b8">Trust info unavailable: '+e(d.error)+'</div>';return;}
    var principals=d.principals||[];
    if(!principals.length){container.innerHTML='<div style="font-size:10px;color:#94a3b8">No trust principals found</div>';return;}
    container.innerHTML='<div style="margin-top:4px;font-size:10px;font-weight:700;color:#475569;margin-bottom:3px">Can be assumed by:</div>'
      +'<div style="display:flex;flex-direction:column;gap:3px">'
      +principals.map(function(p){return'<div style="font-size:10px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:5px;padding:3px 8px;font-family:monospace;color:#0f172a;word-break:break-all">'
        +'<span style="font-weight:700;color:'+(p.type==='AWS'?'#d97706':p.type==='Service'?'#7c3aed':'#0369a1')+'">'+e(p.type||'?')+'</span> '
        +e(p.principal||'—')
      +'</div>';}).join('')
      +'</div>';
    // Update identity graph edges
    updateGraphEdges(pid, principals);
  }catch(ex){btn.disabled=false;btn.textContent='👥 Who can assume this role';container.innerHTML='<div style="font-size:10px;color:#ef4444">'+ex.message+'</div>';}
}

// ── Identity graph (SVG) ──────────────────────────────────────────────────────
function renderIdentityGraph(rows){
  var graphEl=document.getElementById('ibody-corr-graph');
  if(!graphEl)return;
  _igNodePos={};_igTrustMap={};

  // Classify nodes
  var roles=[],assumerNodes=[];
  rows.forEach(function(r){
    var pid=(r.PRINCIPAL_ID||'').toLowerCase();
    var nm=(r.NAME||'').toLowerCase();
    var pt=(r.PROVIDER_TYPE||'').toLowerCase();
    if(pid.includes(':root')||nm==='root')return;
    if(pid.includes(':role/')||nm.includes('role'))roles.push(r);
    else if(pid.includes(':user/')||nm.includes('user')||pid.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||pt.includes('serviceprincipal')||pt.includes('aad'))assumerNodes.push(r);
  });

  if(!roles.length&&!assumerNodes.length){graphEl.innerHTML='';return;}

  var NW=_igNW,NH=_igNH,VG=10,PAD=28,COL_GAP=150;
  var LX=PAD,RX=PAD+NW+COL_GAP;
  var svgW=RX+NW+PAD;
  var leftH=Math.max(1,assumerNodes.length)*(NH+VG)-VG;
  var rightH=Math.max(1,roles.length)*(NH+VG)-VG;
  var innerH=Math.max(leftH,rightH);
  var HDR=22;
  var svgH=innerH+PAD*2+HDR;

  function placeNodes(list,x){
    var blockH=list.length*(NH+VG)-VG;
    var startY=PAD+HDR+(innerH-blockH)/2;
    list.forEach(function(r,i){_igNodePos[r.PRINCIPAL_ID]={x:x,y:Math.max(PAD+HDR,startY)+i*(NH+VG)};});
  }
  placeNodes(assumerNodes,LX);
  placeNodes(roles,RX);

  function shortLbl(r){
    var s=r.NAME||r.PRINCIPAL_ID||'';
    var sl=s.lastIndexOf('/');if(sl>=0)s=s.slice(sl+1);
    return s.length>22?s.slice(0,20)+'…':s;
  }
  function svgEsc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

  var nodesHtml='';
  assumerNodes.forEach(function(r){
    var pos=_igNodePos[r.PRINCIPAL_ID];
    var pid=(r.PRINCIPAL_ID||'').toLowerCase();
    var isService=pid.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||(r.PROVIDER_TYPE||'').toLowerCase().includes('serviceprincipal');
    var col=isService?'#7c3aed':'#065f46';
    var bg=isService?'#f5f3ff':'#ecfdf5';
    var brdr=isService?'#ddd6fe':'#a7f3d0';
    var tag=isService?'SERVICE':'USER';
    nodesHtml+='<g transform="translate('+pos.x+','+pos.y+')" data-pid="'+svgEsc(r.PRINCIPAL_ID)+'">'
      +'<rect width="'+NW+'" height="'+NH+'" rx="5" fill="'+bg+'" stroke="'+brdr+'" stroke-width="1.5"/>'
      +'<text x="6" y="12" font-family="system-ui,sans-serif" font-size="8" font-weight="700" fill="'+col+'">'+tag+'</text>'
      +'<text x="6" y="27" font-family="system-ui,sans-serif" font-size="11" fill="#0f172a">'+svgEsc(shortLbl(r))+'</text>'
      +'</g>';
  });
  roles.forEach(function(r){
    var pos=_igNodePos[r.PRINCIPAL_ID];
    var rs=Math.round((r.METRICS&&r.METRICS.risk_score||0)*100);
    var col=rs>=70?'#dc2626':rs>=40?'#b45309':'#0369a1';
    var bg=rs>=70?'#fef2f2':rs>=40?'#fffbeb':'#f0f9ff';
    var brdr=rs>=70?'#fecaca':rs>=40?'#fde68a':'#bae6fd';
    nodesHtml+='<g transform="translate('+pos.x+','+pos.y+')" data-pid="'+svgEsc(r.PRINCIPAL_ID)+'">'
      +'<rect width="'+NW+'" height="'+NH+'" rx="5" fill="'+bg+'" stroke="'+brdr+'" stroke-width="1.5"/>'
      +'<text x="6" y="12" font-family="system-ui,sans-serif" font-size="8" font-weight="700" fill="'+col+'">IAM ROLE</text>'
      +'<text x="6" y="27" font-family="system-ui,sans-serif" font-size="11" fill="#0f172a">'+svgEsc(shortLbl(r))+'</text>'
      +(rs?'<text x="'+(NW-5)+'" y="'+(NH/2+5)+'" font-family="system-ui,sans-serif" font-size="12" font-weight="800" fill="'+col+'" text-anchor="end">'+rs+'</text>':'')
      +'</g>';
  });

  var hdrs='';
  if(assumerNodes.length)hdrs+='<text x="'+(LX+NW/2)+'" y="'+(PAD+14)+'" font-family="system-ui,sans-serif" font-size="9" font-weight="700" fill="#64748b" text-anchor="middle">USERS &amp; SERVICES ('+assumerNodes.length+')</text>';
  if(roles.length)hdrs+='<text x="'+(RX+NW/2)+'" y="'+(PAD+14)+'" font-family="system-ui,sans-serif" font-size="9" font-weight="700" fill="#64748b" text-anchor="middle">IAM ROLES ('+roles.length+')</text>';

  var defs='<defs><marker id="ig-arr" markerWidth="7" markerHeight="7" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#6366f1"/></marker></defs>';

  graphEl.innerHTML='<div style="overflow:auto;max-height:460px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;margin:10px 16px 6px">'
    +'<svg id="ig-svg" xmlns="http://www.w3.org/2000/svg" width="'+svgW+'" height="'+svgH+'" style="display:block">'
    +defs
    +'<g id="ig-edges"></g>'
    +'<g id="ig-nodes">'+nodesHtml+'</g>'
    +hdrs
    +'</svg>'
    +(assumerNodes.length===0?'<div style="font-size:10px;color:#94a3b8;text-align:center;padding:4px 0 8px">No users or service accounts in top identities — trust relationships will appear as arrows when roles load</div>':'')
    +'</div>';
}

function updateGraphEdges(rolePid,principals){
  _igTrustMap[rolePid]=principals;
  var edgesEl=document.getElementById('ig-edges');
  if(!edgesEl)return;
  var NW=_igNW,NH=_igNH;
  var edgesHtml='';

  // Build pid lookup set from known nodes
  var knownPids=Object.keys(_igNodePos);

  Object.keys(_igTrustMap).forEach(function(rPid){
    var rPos=_igNodePos[rPid];
    if(!rPos)return;
    var rX=rPos.x,rMY=rPos.y+NH/2;

    (_igTrustMap[rPid]||[]).forEach(function(p){
      var principal=p.principal||'';

      // Find a matching known node (left-side assumer)
      var matchPid=null;
      knownPids.forEach(function(kp){
        if(_igNodePos[kp].x<rX){
          if(kp===principal||kp.endsWith('/'+principal)||principal.endsWith('/'+kp.split('/').pop()))matchPid=kp;
        }
      });

      if(matchPid){
        var aPos=_igNodePos[matchPid];
        var x1=aPos.x+NW,y1=aPos.y+NH/2,x2=rX,y2=rMY;
        var cx=(x1+x2)/2;
        edgesHtml+='<path d="M'+x1+','+y1+' C'+cx+','+y1+' '+cx+','+y2+' '+x2+','+y2+'" fill="none" stroke="#6366f1" stroke-width="1.8" stroke-dasharray="5,3" marker-end="url(#ig-arr)" opacity="0.8">'
          +'<title>'+svgEsc(principal)+' can assume this role</title>'
          +'</path>';
      } else {
        // External principal not in our list — draw a floating label node on the left
        var extX=_igNodePos[rPid].x-_igNW-_igNW/2-10;
        if(extX<0)extX=2;
        var extY=rMY-NH/2;
        var short=principal;var sl=short.lastIndexOf('/');if(sl>=0)short=short.slice(sl+1);
        var col=p.type==='Service'?'#7c3aed':'#d97706';
        var bg2=p.type==='Service'?'#f5f3ff':'#fffbeb';
        var brdr2=p.type==='Service'?'#ddd6fe':'#fde68a';
        edgesHtml+='<g transform="translate('+extX+','+extY+')">'
          +'<rect width="'+(NW-10)+'" height="'+NH+'" rx="5" fill="'+bg2+'" stroke="'+brdr2+'" stroke-width="1"/>'
          +'<text x="5" y="12" font-family="system-ui,sans-serif" font-size="8" fill="'+col+'" font-weight="700">'+svgEsc(p.type)+'</text>'
          +'<text x="5" y="27" font-family="system-ui,sans-serif" font-size="9" fill="#0f172a">'+svgEsc(short.length>18?short.slice(0,16)+'…':short)+'</text>'
          +'</g>';
        var ex2=extX+(NW-10),ey2=extY+NH/2;
        edgesHtml+='<path d="M'+ex2+','+ey2+' C'+(ex2+40)+','+ey2+' '+(rX-40)+','+rMY+' '+rX+','+rMY+'" fill="none" stroke="#6366f1" stroke-width="1.5" stroke-dasharray="4,3" marker-end="url(#ig-arr)" opacity="0.7"/>';
      }
    });
  });

  edgesEl.innerHTML=edgesHtml;
}

function svgEsc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function closeMachPanel(){document.getElementById('mach-overlay').style.display='none';}

// ── Host Internet Exposure → Correlated Risk card jump ────────────────────────
document.addEventListener('click',function(ev){
  var btn=ev.target.closest('.goto-host-card-btn');
  if(!btn)return;
  openHostGraph(btn.dataset.hostname||'',btn.dataset.resourcename||'');
});

// ── Host Attack Path modal ─────────────────────────────────────────────────────
document.getElementById('host-graph-overlay').addEventListener('click',function(ev){if(ev.target===this)closeHostGraph();});
// Factor node clicks in both inline cards and modal
document.addEventListener('click',function(ev){
  var node=ev.target.closest('.hg-nav-node');
  if(node){
    if(node.closest('#host-graph-overlay'))closeHostGraph();
    nav(node.dataset.nav);
    return;
  }
  var btn=ev.target.closest('.ar-exposed-row');
  if(btn&&!ev.target.closest('.mach-inv-btn,.geo-btn,.cp-btn,.goto-host-card-btn'))openHostGraph(btn.dataset.hostname);
});

// ── GeoIP panel ───────────────────────────────────────────────────────────────
function closeGeoPanel(){document.getElementById('geo-overlay').style.display='none';}
document.getElementById('geo-overlay').addEventListener('click',function(ev){if(ev.target===this)closeGeoPanel();});
document.getElementById('rptgen-overlay').addEventListener('click',function(ev){if(ev.target===this)closeReportGenModal();});

const _geoCache={};
async function openGeoPanel(ip,hostname){
  const ov=document.getElementById('geo-overlay');
  const body=document.getElementById('geo-body');
  document.getElementById('geo-title').textContent='GeoIP: '+ip;
  document.getElementById('geo-sub').textContent=(hostname||ip)+' · Powered by ipinfo.io';
  body.innerHTML='<div style="color:#94a3b8;text-align:center;padding:20px">🌍 Looking up location…</div>';
  ov.style.display='flex';
  if(_geoCache[ip]){renderGeo(body,_geoCache[ip]);return;}
  try{
    const r=await fetch('/api/geoip?ip='+encodeURIComponent(ip));
    const d=await r.json();
    _geoCache[ip]=d;
    renderGeo(body,d);
  }catch(ex){
    body.innerHTML='<div style="color:#ef4444">Lookup failed: '+ex.message+'</div>';
  }
}

function renderGeo(body,d){
  if(d.error||d.status==='fail'){
    body.innerHTML='<div style="color:#ef4444;padding:8px">'+e(d.message||d.error||'Lookup failed')+'</div>';
    return;
  }
  const flag=d.country?'https://flagcdn.com/24x18/'+d.country.toLowerCase()+'.png':'';
  const rows=[
    ['IP',d.ip],
    ['Country',(flag?'<img src="'+flag+'" style="vertical-align:middle;margin-right:6px;border-radius:2px" width="24" height="18" alt=""/>':'')+e(d.country||'—')],
    ['Region',d.region],
    ['City',d.city],
    ['Coordinates',d.loc?'<a href="https://maps.google.com/?q='+encodeURIComponent(d.loc)+'" target="_blank" style="color:#0ea5e9">'+e(d.loc)+' ↗</a>':null],
    ['Organisation',d.org],
    ['ASN / ISP',d.org],
    ['Timezone',d.timezone],
    ['Hostname',d.hostname],
  ];
  // dedupe ASN/ISP and Organisation if same value
  const seen=new Set();
  const dedupedRows=rows.filter(([k,v])=>{
    const val=typeof v==='string'?v:(d[k.toLowerCase()]||'');
    if(!val)return false;
    if(seen.has(val))return false;
    seen.add(val);
    return true;
  });
  body.innerHTML='<table style="width:100%;border-collapse:collapse">'
    +dedupedRows.map(([k,v])=>'<tr style="border-bottom:1px solid #f1f5f9">'
      +'<td style="padding:7px 4px;font-size:11px;font-weight:700;color:#64748b;width:110px;vertical-align:top">'+e(k)+'</td>'
      +'<td style="padding:7px 4px;font-size:12px;color:#0f172a;word-break:break-word">'+(typeof v==='string'&&v.startsWith('<')?v:e(v||'—'))+'</td>'
    +'</tr>').join('')
    +'</table>';
}

document.addEventListener('click',function(ev){
  const btn=ev.target.closest('.geo-btn');
  if(btn)openGeoPanel(btn.dataset.ip,btn.dataset.host);
});

async function openCveDetails(cveId){
  const ov=document.getElementById('mach-overlay');
  const title=document.getElementById('mach-panel-title');
  const sub=document.getElementById('mach-panel-sub');
  const body=document.getElementById('mach-panel-body');
  title.textContent=cveId;
  sub.textContent='Querying FortiGuard Threat Intel & NVD…';
  body.innerHTML='<div class="state"><div class="spinner"></div><span>Fetching CVE details…</span></div>';
  ov.style.display='flex';
  try{
    const r=await fetch('/api/cve?id='+encodeURIComponent(cveId));
    const d=await r.json();
    if(d.error){body.innerHTML='<div class="state">Error: '+e(d.error)+'</div>';return;}

    const nvd=d.nvd;
    const fg=d.fg;
    const fgUrl=(fg?.url)||('https://www.fortiguard.com/threatintel-search?q='+encodeURIComponent(cveId));

    sub.textContent=nvd?(nvd.cvssSeverity||'')+(nvd.cvssScore?' · CVSS '+nvd.cvssScore:''):'No NVD data';

    const scoreColor=s=>s>=9?'#ef4444':s>=7?'#f97316':s>=4?'#f59e0b':'#22c55e';
    const mkRow=(k,v)=>v!=null&&v!==''?'<div class="mach-row"><span class="mach-key">'+k+'</span><span class="mach-val">'+e(String(v))+'</span></div>':'';

    const fgSection='<div class="mach-section">'
      +'<div class="mach-section-title" style="display:flex;align-items:center;justify-content:space-between">'
        +'<span>FortiGuard Threat Intel</span>'
        +'<a href="'+e(fgUrl)+'" target="_blank" style="font-size:10px;font-weight:700;color:#DA291C;text-decoration:none">Open ↗</a>'
      +'</div>'
      +(fg?.metaDesc?mkRow('Summary',fg.metaDesc):'')
      +(fg?.cvssHint?mkRow('CVSS (FortiGuard)','~'+fg.cvssHint):'')
      +(!fg?.metaDesc&&!fg?.cvssHint?'<div class="mach-row"><span class="mach-val" style="color:#94a3b8;font-family:sans-serif">Page is dynamically rendered — click Open to view in FortiGuard.</span></div>':'')
    +'</div>';

    const nvdSection=nvd?'<div class="mach-section" id="nvd-section">'
      +'<div class="mach-section-title">NVD Details</div>'
      +(nvd.cvssScore!=null?'<div class="mach-row"><span class="mach-key">CVSS '+nvd.cvssVersion+' Score</span><span class="mach-val" style="font-weight:800;font-size:14px;color:'+scoreColor(nvd.cvssScore)+'">'+nvd.cvssScore+' · '+(nvd.cvssSeverity||'—')+'</span></div>':'')
      +(nvd.cvssVector?mkRow('Vector',nvd.cvssVector):'')
      +(nvd.cwes?.length?mkRow('CWE',nvd.cwes.join(', ')):'')
      +(nvd.description?'<div class="mach-row" style="align-items:flex-start"><span class="mach-key">Description</span><span class="mach-val" style="font-family:sans-serif;white-space:normal;line-height:1.5">'+e(nvd.description)+'</span></div>':'')
      +mkRow('Published',nvd.published?nvd.published.slice(0,10):'—')
      +mkRow('Last Modified',nvd.lastModified?nvd.lastModified.slice(0,10):'—')
      +(nvd.references?.length?'<div class="mach-row" style="align-items:flex-start"><span class="mach-key">References</span><span class="mach-val" style="font-family:sans-serif;white-space:normal">'+nvd.references.map(u=>'<a href="'+e(u)+'" target="_blank" style="display:block;color:#2563eb;font-size:10px;margin-bottom:2px;overflow-wrap:break-word">'+e(u)+'</a>').join('')+'</span></div>':'')
    +'</div>':'<div class="mach-section"><div class="mach-section-title">NVD Details</div><div class="mach-row"><span class="mach-val" style="color:#94a3b8;font-family:sans-serif;white-space:normal">'+(d.nvdError||'NVD data unavailable')+' — use the FortiGuard link above.</span></div></div>';

    body.innerHTML=fgSection+nvdSection;
  }catch(err){
    body.innerHTML='<div class="state">Error: '+e(err.message)+'</div>';
    sub.textContent='Lookup failed';
  }
}

function openComplianceDetails(policyId){
  const ov=document.getElementById('mach-overlay');
  const title=document.getElementById('mach-panel-title');
  const sub=document.getElementById('mach-panel-sub');
  const body=document.getElementById('mach-panel-body');

  const policy=(_lastData?.compliance||[]).find(r=>r.alertId===policyId);
  if(!policy){body.innerHTML='<div class="state">Policy not found in cache.</div>';ov.style.display='flex';return;}

  title.textContent=policy.title||policyId;
  sub.textContent=policyId+' · '+(policy.violations||0)+' non-compliant resource'+(policy.violations!==1?'s':'');
  ov.style.display='flex';

  const resources=policy.resources||[];
  if(!resources.length){body.innerHTML='<div class="state">No resource details cached.</div>';return;}

  // Determine columns from first row — prioritise known key fields
  const PRIO=['RESOURCE_KEY','RESOURCE_ID','RESOURCE_ARN','URN','RESOURCE_IDENTIFIER','INSTANCE_ID','VM_ID','NAME','ACCOUNT_ID','ACCOUNT_ALIAS','REGION','LOCATION','RESOURCE_TYPE','SUBSCRIPTION_ID'];
  const allKeys=[...new Set(resources.flatMap(r=>Object.keys(r)))];
  const prioKeys=PRIO.filter(k=>allKeys.includes(k));
  const extraKeys=allKeys.filter(k=>!PRIO.includes(k)).slice(0,6);
  const cols=[...prioKeys,...extraKeys].slice(0,8);

  const headerHtml=cols.map(k=>'<th style="font-size:10px;font-weight:800;letter-spacing:.05em;text-transform:uppercase;color:#64748b;padding:6px 10px;border-bottom:1px solid #e2e8f0;white-space:nowrap">'+e(k.replace(/_/g,' '))+'</th>').join('');
  const rowsHtml=resources.map(r=>'<tr style="border-bottom:1px solid #f1f5f9">'
    +cols.map(k=>'<td style="font-size:11px;padding:5px 10px;font-family:monospace;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+e(String(r[k]||''))+'">'+e(String(r[k]??'—'))+'</td>').join('')
  +'</tr>').join('');

  body.innerHTML='<div style="width:100%;overflow-x:auto;overflow-y:visible"><table style="min-width:100%;border-collapse:collapse"><thead><tr>'+headerHtml+'</tr></thead><tbody>'+rowsHtml+'</tbody></table></div>'
    +'<div style="padding:8px 12px;font-size:10px;color:#94a3b8">'+resources.length+' resource'+(resources.length!==1?'s':'')+' shown (capped at 100) · '+e(policy.description||'')+'</div>';
}

async function openIdentityDetails(principalId){
  const ov=document.getElementById('mach-overlay');
  const title=document.getElementById('mach-panel-title');
  const sub=document.getElementById('mach-panel-sub');
  const body=document.getElementById('mach-panel-body');
  title.textContent=principalId.split('/').pop()||principalId;
  sub.textContent='Querying LW_CE_IDENTITIES…';
  body.innerHTML='<div class="state"><div class="spinner"></div><span>Loading identity details…</span></div>';
  ov.style.display='flex';
  try{
    const r=await fetch('/api/identity?principalId='+encodeURIComponent(principalId));
    const d=await r.json();
    if(d.error){body.innerHTML='<div class="state">Error: '+e(d.error)+'</div>';sub.textContent='Query failed';return;}
    const rows=d.rows||[];
    if(!rows.length){body.innerHTML='<div class="state">No identity record found.</div>';sub.textContent='No data';return;}
    const m=rows[0];
    sub.textContent=(m.PROVIDER_TYPE||'')+(m.NAME&&m.NAME!==principalId?' · '+m.NAME:'');

    const metrics=(typeof m.METRICS==='object'&&m.METRICS)?m.METRICS:{};
    const entCounts=(typeof m.ENTITLEMENT_COUNTS==='object'&&m.ENTITLEMENT_COUNTS)?m.ENTITLEMENT_COUNTS:{};
    const accessKeys=Array.isArray(m.ACCESS_KEYS)?m.ACCESS_KEYS:(typeof m.ACCESS_KEYS==='object'&&m.ACCESS_KEYS)?[m.ACCESS_KEYS]:[];

    const riskColor=s=>s>='high'||s==='critical'?'#ef4444':s==='medium'?'#f59e0b':'#22c55e';
    const riskScore=Math.round((metrics.risk_score||0)*100);
    const riskSev=(metrics.risk_severity||'—').toUpperCase();
    const riskFlags=(metrics.risks||[]);

    const mkRow=(k,v)=>v!=null&&v!==''?'<div class="mach-row"><span class="mach-key">'+k+'</span><span class="mach-val">'+e(String(v))+'</span></div>':'';

    const identSection='<div class="mach-section">'
      +'<div class="mach-section-title">Identity</div>'
      +mkRow('Principal ID',m.PRINCIPAL_ID)
      +mkRow('Name',m.NAME)
      +mkRow('Provider',m.PROVIDER_TYPE)
      +mkRow('Created',m.CREATED_TIME?fmtDate(m.CREATED_TIME):'—')
      +mkRow('Last Used',m.LAST_USED_TIME?fmtDate(m.LAST_USED_TIME):'—')
    +'</div>';

    const riskSection='<div class="mach-section">'
      +'<div class="mach-section-title">Risk</div>'
      +'<div class="mach-row"><span class="mach-key">Risk Score</span><span class="mach-val" style="font-weight:800;color:'+riskColor(riskSev.toLowerCase())+'">'+riskScore+' / 100</span></div>'
      +'<div class="mach-row"><span class="mach-key">Severity</span><span class="mach-val" style="font-weight:700;color:'+riskColor(riskSev.toLowerCase())+'">'+riskSev+'</span></div>'
      +(riskFlags.length?'<div class="mach-row"><span class="mach-key">Risk Flags</span><span class="mach-val">'+riskFlags.map(f=>'<span style="display:inline-block;background:#fef2f2;color:#dc2626;border:1px solid #fca5a5;border-radius:4px;padding:1px 6px;font-size:10px;margin:1px">'+e(f)+'</span>').join(' ')+'</span></div>':'')
      +'<div class="mach-row"><span class="mach-key">MFA</span><span class="mach-val" style="color:#ef4444;font-weight:700">NO MFA</span></div>'
    +'</div>';

    const entSection=Object.keys(entCounts).length?'<div class="mach-section">'
      +'<div class="mach-section-title">Entitlements</div>'
      +Object.entries(entCounts).map(([k,v])=>mkRow(k.replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase()),v)).join('')
    +'</div>':'';

    const keySection=accessKeys.length?'<div class="mach-section">'
      +'<div class="mach-section-title">Access Keys ('+accessKeys.length+')</div>'
      +accessKeys.map((k,i)=>{
        const kobj=(typeof k==='object'&&k)?k:{};
        return'<div style="padding:6px 12px;border-bottom:1px solid #f1f5f9">'
          +'<div style="font-size:10px;font-weight:700;color:#64748b;margin-bottom:3px">Key '+(i+1)+(kobj.access_key_id?' · <span style="font-family:monospace;color:#0f172a">'+e(kobj.access_key_id)+'</span>':'')+'</div>'
          +Object.entries(kobj).filter(([k2])=>k2!=='access_key_id').map(([k2,v2])=>mkRow(k2.replace(/_/g,' '),v2)).join('')
        +'</div>';
      }).join('')
    +'</div>':'';

    body.innerHTML=identSection+riskSection+entSection+keySection;
  }catch(err){
    body.innerHTML='<div class="state">Error: '+e(err.message)+'</div>';
    sub.textContent='Query failed';
  }
}

async function openMachineDetails(hostname){
  const ov=document.getElementById('mach-overlay');
  const title=document.getElementById('mach-panel-title');
  const sub=document.getElementById('mach-panel-sub');
  const body=document.getElementById('mach-panel-body');
  title.textContent=hostname;
  sub.textContent='Querying LW_HE_MACHINES…';
  body.innerHTML='<div class="state"><div class="spinner"></div><span>Loading host metadata…</span></div>';
  ov.style.display='flex';
  try{
    const r=await fetch('/api/machine?hostname='+encodeURIComponent(hostname));
    const d=await r.json();
    if(d.error){body.innerHTML='<div class="state">Error: '+e(d.error)+'</div>';sub.textContent='Query failed';return;}
    const rows=d.rows||[];
    if(!rows.length){body.innerHTML='<div class="state">No machine record found for this host.</div>';sub.textContent='No data';return;}
    const m=rows[0];
    sub.textContent='MID: '+(m.MID||'—');
    const tags=(typeof m.TAGS==='object'&&m.TAGS)?m.TAGS:{};

    // Key tag fields to surface
    const TAG_KEYS=[
      ['instanceId','Instance ID'],['instanceType','Instance Type'],
      ['aws:instance-id','Instance ID'],['aws:instance-type','Instance Type'],
      ['VmProvider','Cloud Provider'],['zone','Zone / AZ'],
      ['Hostname','Hostname (tag)'],['Account','Account'],
      ['aws:account','AWS Account'],['Region','Region'],['LwTokenShort','Agent Token'],
      ['Name','Name'],['Environment','Environment'],['Owner','Owner'],
      ['Project','Project'],['Team','Team'],
    ];
    const seen=new Set();
    const tagRows=TAG_KEYS.map(([k,label])=>{
      const val=tags[k];
      if(!val||seen.has(label))return'';
      seen.add(label);
      return'<div class="mach-row"><span class="mach-key">'+label+'</span><span class="mach-val">'+e(String(val))+'</span></div>';
    }).join('');

    // Extra tags not in the key list
    const extraTags=Object.entries(tags).filter(([k])=>!TAG_KEYS.some(([tk])=>tk===k)&&!seen.has(k)).slice(0,20)
      .map(([k,v])=>'<div class="mach-row"><span class="mach-key">'+e(k)+'</span><span class="mach-val">'+e(String(v||''))+'</span></div>').join('');

    body.innerHTML=
      '<div class="mach-section">'
        +'<div class="mach-section-title">Host</div>'
        +'<div class="mach-row"><span class="mach-key">Hostname</span><span class="mach-val">'+e(m.HOSTNAME||'—')+'</span></div>'
        +'<div class="mach-row"><span class="mach-key">Machine ID</span><span class="mach-val">'+e(m.MID||'—')+'</span></div>'
      +'</div>'
      +(tagRows||extraTags?
        '<div class="mach-section">'
          +'<div class="mach-section-title">Cloud &amp; Instance Metadata</div>'
          +(tagRows||'')+(extraTags||'')
        +'</div>':
        '<div class="mach-section"><div class="mach-row"><span class="mach-key">Tags</span><span class="mach-val" style="color:#94a3b8">No tag data available</span></div></div>'
      )
      +(rows.length>1?'<div style="font-size:10px;color:#94a3b8;padding:4px 8px">'+rows.length+' records found — showing most recent</div>':'');
  }catch(err){
    body.innerHTML='<div class="state">Error: '+e(err.message)+'</div>';
    sub.textContent='Query failed';
  }
}

</script>

<div id="ai-chat-overlay" class="ai-overlay" style="display:none" onclick="if(event.target===this)closeAiChat()">
  <div class="ai-panel">
    <div class="ai-hdr">
      <div class="ai-hdr-left">
        <div class="ai-hdr-tag">FortiCNAPP Agent AI</div>
        <div id="ai-chat-title" class="ai-hdr-title"></div>
        <div id="ai-chat-sub" class="ai-hdr-sub"></div>
      </div>
      <button class="ai-close" onclick="closeAiChat()" title="Close">✕</button>
    </div>
    <div id="ai-chat-body" class="ai-body"></div>
    <div class="ai-footer">
      <div id="ai-prompt-row" class="ai-prompt-row">
        <button class="ai-prompt-btn" id="ai-btn-triage" onclick="pickAiPrompt('triage')">&#x1F50D; Triage this Alert</button>
      </div>
      <input id="ai-chat-input" class="ai-input" style="display:none" placeholder="Ask a follow-up question…" onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendAiMessage()}" />
      <button id="ai-send-btn" class="ai-send" style="display:none" onclick="sendAiMessage()">Send</button>
    </div>
  </div>
</div>

<!-- Machine Details panel -->
<div id="mach-overlay" class="mach-overlay" style="display:none" onclick="if(event.target===this)closeMachPanel()">
  <div class="mach-panel">
    <div class="mach-hdr">
      <div class="mach-hdr-icon">&#x1F5A5;&#xFE0F;</div>
      <div style="flex:1;min-width:0">
        <div id="mach-panel-title" class="mach-title">—</div>
        <div id="mach-panel-sub" class="mach-sub">—</div>
      </div>
      <button onclick="closeMachPanel()" style="width:28px;height:28px;border-radius:7px;border:none;background:#f1f5f9;font-size:16px;color:#64748b;cursor:pointer;flex-shrink:0;display:flex;align-items:center;justify-content:center">✕</button>
    </div>
    <div id="mach-panel-body" class="mach-body"></div>
  </div>
</div>

</body>
</html>`;
}

const HTML = buildHtml(LW_ACCOUNT, INTERVAL);

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>Fortinet · Rapid Cloud Assessment</title></head>
<body style="font-family:sans-serif;padding:60px;background:#111827;color:#fff">
<h2>Fortinet &nbsp;·&nbsp; Rapid Cloud Assessment</h2>
<p style="margin:12px 0 24px;color:#9ca3af">Enter your business email to access the dashboard</p>
<form method="POST" action="/api/login" style="max-width:360px">
  <div style="margin-bottom:20px"><label style="display:block;margin-bottom:6px">Business Email</label>
  <input type="text" name="email" placeholder="you@company.com" style="width:100%;padding:10px;font-size:15px;border-radius:6px;border:1px solid #444;background:#1f2937;color:#fff"/></div>
  <input type="submit" value="Access Dashboard" style="width:100%;padding:13px;background:#c93428;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer"/>
</form>
</body></html>`;

const MOBILE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>Cloud Security Posture Score</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f8fafc;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:28px 16px 48px}
.logo{font-size:11px;font-weight:800;letter-spacing:.18em;text-transform:uppercase;color:#DA291C;margin-bottom:4px;text-align:center}
.subtitle{font-size:20px;font-weight:800;color:#0f172a;text-align:center;line-height:1.3;margin-bottom:20px;max-width:320px}
.gauge-wrap{width:100%;max-width:340px;margin:0 auto}
.band{font-size:15px;font-weight:700;text-align:center;margin-top:2px;min-height:22px;transition:color .4s}
.divider{width:100%;max-width:340px;border:none;border-top:1px solid #e2e8f0;margin:28px 0 20px}
.sec-title{font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:#64748b;width:100%;max-width:340px;margin-bottom:12px}
.steps{display:flex;flex-direction:column;gap:10px;width:100%;max-width:340px}
.step{background:#fff;border-radius:12px;padding:14px 16px;box-shadow:0 1px 4px rgba(0,0,0,.07);display:flex;gap:12px;align-items:flex-start}
a.step{text-decoration:none;color:inherit;display:flex;transition:box-shadow .15s}
a.step:hover{box-shadow:0 4px 16px rgba(0,0,0,.13)}
.step-bar{width:4px;border-radius:4px;flex-shrink:0;align-self:stretch;min-height:36px}
.step-n{font-size:13px;font-weight:900;color:#94a3b8;flex-shrink:0;padding-top:1px}
.step-body{}
.step-title{font-size:13px;font-weight:700;color:#0f172a;line-height:1.4}
.step-sub{font-size:11px;color:#94a3b8;margin-top:3px;line-height:1.4}
.meta{margin-top:28px;font-size:11px;color:#94a3b8;text-align:center;line-height:2}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#94a3b8;margin-right:4px;vertical-align:middle}
.dot.ok{background:#22c55e}.dot.err{background:#ef4444}
</style>
</head>
<body>
<div class="logo">Fortinet</div>
<div class="subtitle">Your current Cloud Security Posture Score</div>
<div class="gauge-wrap">
  <svg viewBox="0 0 400 245" style="display:block;width:100%;overflow:visible">
    <defs>
      <linearGradient id="mg" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">
        <stop offset="0%"     stop-color="#ef4444"/>
        <stop offset="20.6%"  stop-color="#ef4444"/>
        <stop offset="20.6%"  stop-color="#f59e0b"/>
        <stop offset="65.45%" stop-color="#f59e0b"/>
        <stop offset="65.45%" stop-color="#22c55e"/>
        <stop offset="90.45%" stop-color="#22c55e"/>
        <stop offset="90.45%" stop-color="#3b82f6"/>
        <stop offset="100%"   stop-color="#3b82f6"/>
      </linearGradient>
    </defs>
    <path fill="none" stroke="#e2e8f0" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>
    <path id="garc" fill="none" stroke="url(#mg)" stroke-width="34" stroke-linecap="round" stroke-dasharray="0 550" d="M 25,205 A 175,175 0 0,1 375,205"/>
    <line x1="86" y1="48" x2="108" y2="79"   stroke="white" stroke-width="3" stroke-linecap="round"/>
    <line x1="260" y1="20" x2="248" y2="57"  stroke="white" stroke-width="3" stroke-linecap="round"/>
    <line x1="357" y1="91" x2="326" y2="113" stroke="white" stroke-width="3" stroke-linecap="round"/>
    <text id="mscore" x="200" y="162" text-anchor="middle" font-size="64" font-weight="900" letter-spacing="-2" font-family="-apple-system,sans-serif" fill="#94a3b8">—</text>
    <text x="25"  y="232" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">0</text>
    <text x="375" y="232" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,sans-serif" fill="#cbd5e1">100</text>
  </svg>
</div>
<div id="m-band" class="band" style="font-size:13px;font-weight:800;text-align:center;margin-top:-4px;margin-bottom:8px;letter-spacing:.04em">—</div>
<hr class="divider">
<div class="sec-title">Exploit Simulation Layer</div>
<div class="steps" id="steps"></div>
<div class="meta">
  <span class="dot" id="ldot"></span>Fortinet Rapid Cloud Assessment Powered by FortiCNAPP<br>
  Last refresh: <span id="ltime">—</span>
</div>
<script>
function scoreColor(p){return p>=81?'#3b82f6':p>=61?'#22c55e':p>=31?'#f59e0b':'#ef4444';}
function scoreTier(p){return p>=81?'Optimized':p>=61?'Advanced':p>=31?'Managed':'Foundational';}
function scoreTierDetail(p){return p>=81?'Mature cloud security posture with proactive risk management and continuous improvement':p>=61?'Security posture is strong with effective controls and manageable residual risk':p>=31?'Core controls are established, but security gaps and optimization opportunities remain':'Security controls are immature; significant exposure and remediation priorities exist';}
function scoreBand(p){return scoreTier(p);}
function isServiceAccount(r){
  var pid=(r.PRINCIPAL_ID||'').toLowerCase(),nm=(r.NAME||'').toLowerCase(),p=(r.PROVIDER_TYPE||'').toLowerCase();
  return pid.indexOf('serviceaccount')!==-1||nm.indexOf('serviceaccount')!==-1||pid.indexOf('.iam.gserviceaccount.com')!==-1||p.indexOf('serviceprincipal')!==-1||p.indexOf('aad')!==-1;
}
function isRoleType(r){
  var pid=(r.PRINCIPAL_ID||'').toLowerCase(),nm=(r.NAME||'').toLowerCase();
  return (pid.indexOf(':role/')!==-1||pid.indexOf(':assumed-role/')!==-1||nm.indexOf('role')!==-1)&&!isServiceAccount(r);
}
function isHighPermissive(r){
  var risks=(r.METRICS&&r.METRICS.risks)||[];
  var sev=((r.METRICS&&r.METRICS.risk_severity)||'').toLowerCase();
  return risks.indexOf('ALLOWS_FULL_ADMIN')!==-1||risks.indexOf('EXCESSIVE_PERMISSIONS')!==-1||sev==='critical'||sev==='high';
}
function isNoMfa(r){
  var risks=(r.METRICS&&r.METRICS.risks)||[];
  return risks.indexOf('PASSWORD_LOGIN_NO_MFA')!==-1||!r.MFA_ENABLED;
}
function unusedPctOf(r){
  var ec=r.ENTITLEMENT_COUNTS||{};
  var unusedCnt=ec.entitlements_unused_count,totalCnt=ec.entitlements_total_count||ec.entitlements_count;
  return ec.entitlements_unused_percentage!=null?ec.entitlements_unused_percentage
    :(unusedCnt!=null&&totalCnt?(unusedCnt/totalCnt)*100:null);
}
// Access-key age field name unverified — see docs/superpowers/specs/2026-07-28-risk-findings-
// weighting-design.md. Checks common casings; falls back to not-old if none match.
function isOldAccessKey(r,thresholdDays){
  thresholdDays=thresholdDays||180;
  var raw=r.ACCESS_KEYS;
  var keys=Array.isArray(raw)?raw:(raw&&typeof raw==='object'?[raw]:[]);
  return keys.some(function(k){
    if(!k||typeof k!=='object')return false;
    var created=k.create_date||k.CREATE_DATE||k.createDate||k.CreateDate||k.created_at||k.CREATED_AT;
    if(!created)return false;
    var ageDays=(Date.now()-new Date(created).getTime())/86400000;
    return isFinite(ageDays)&&ageDays>=thresholdDays;
  });
}
function isAdminNoMfaIdentity(r){
  return !isServiceAccount(r)&&!isRoleType(r)&&isHighPermissive(r)&&isNoMfa(r);
}
function identityRiskScore(r){
  var up=unusedPctOf(r);
  var qualifies=isAdminNoMfaIdentity(r)&&((up==null?0:up)>=80||isOldAccessKey(r));
  return qualifies?80:Math.min(100,(r.METRICS&&r.METRICS.risk_score||0)*100);
}
function calcScore(d){
  var risks=[];
  (d.alerts||[]).forEach(function(r){var s=(r.severity||'').toLowerCase();risks.push(s==='critical'?80:s==='high'?60:40);});
  (d.vulns||[]).forEach(function(r){var rs=parseFloat(r.riskScore||0);if(rs>=8)risks.push(Math.min(100,rs*10));});
  (d.compliance||[]).forEach(function(){risks.push(80);});
  (d.identities||[]).forEach(function(r){risks.push(identityRiskScore(r));});
  (d.secretsAll||[]).forEach(function(){risks.push(10);});
  return Math.max(0,Math.round(risks.length?100-risks.reduce(function(s,v){return s+v;},0)/risks.length:100));
}
function buildSteps(d,p){
  var items=[];
  var hostRisk={};
  (d.vulns||[]).forEach(function(r){var h=r.evalCtx&&(r.evalCtx.hostname||r.evalCtx.mid)||'';if(!h)return;hostRisk[h]=(hostRisk[h]||0)+Math.min(100,parseFloat(r.riskScore||0)*10);});
  (d.secretsAll||[]).forEach(function(r){var h=r.HOSTNAME||r.MID||'';if(!h)return;hostRisk[h]=(hostRisk[h]||0)+50;});
  var riskVals=Object.values(hostRisk);
  var maxRisk=riskVals.length?Math.max.apply(null,riskVals):1;
  var assetCount=riskVals.filter(function(v){return Math.round(v/maxRisk*100)>20;}).length;
  if(assetCount>=1) items.push({color:'#6366f1',href:'/desktop#asset-risk',title:'Investigate '+assetCount+' asset'+(assetCount===1?'':'s')+' with Correlated Risk Findings',sub:'Hosts with combined CVEs and exposed secrets — highest priority targets'});
  if((d.identities||[]).length) items.push({color:'#ef4444',href:'/desktop#identities',title:'Fix '+d.identities.length+' High Permissive '+(d.identities.length===1?'identity':'identities')+' — enable MFA & Apply Least Privilege Access',sub:'Priority 1 · Identity compromise is the #1 breach vector'});
  if((d.alerts||[]).length)     items.push({color:'#f97316',href:'/desktop#alerts',title:'Investigate '+d.alerts.length+' open critical alert'+(d.alerts.length===1?'':'s'),sub:'Threat Center · Some may indicate an active breach'});
  if((d.vulns||[]).length)      items.push({color:'#f59e0b',href:'/desktop#vulns',title:'Patch '+d.vulns.length+' critical CVE'+(d.vulns.length===1?'':'s')+' with risk score ≥ 9.0',sub:'Focus on internet-exposed hosts first'});
  if((d.compliance||[]).length) items.push({color:'#3b82f6',href:'/desktop#compliance',title:'Remediate '+d.compliance.length+' non-compliant critical control'+(d.compliance.length===1?'':'s'),sub:'Compliance · Cloud misconfigurations'});
  if((d.secretsAll||[]).length) items.push({color:'#0ea5e9',href:'/desktop#secrets-all',title:'Rotate '+d.secretsAll.length+' exposed secret'+(d.secretsAll.length===1?'':'s')+' detected on hosts',sub:'API keys, tokens & credentials — revoke and re-issue immediately'});
  if(!items.length) items.push({color:'#22c55e',href:'/desktop',title:'Security posture is excellent — keep monitoring',sub:'Cloud Security Posture Score: '+p+'/100'});
  document.getElementById('steps').innerHTML=items.map(function(a,i){
    return '<a class="step" href="'+a.href+'"><div class="step-bar" style="background:'+a.color+'"></div><div class="step-n">'+(i+1)+'</div><div class="step-body"><div class="step-title">'+a.title+'</div><div class="step-sub">'+a.sub+'</div></div></a>';
  }).join('');
}
function refresh(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    var p=calcScore(d);
    var color=scoreColor(p);
    document.getElementById('garc').setAttribute('stroke-dasharray',(p/100*550).toFixed(1)+' 550');
    var ms=document.getElementById('mscore');if(ms){ms.textContent=p;ms.setAttribute('fill',color);}
    var mb=document.getElementById('m-band');if(mb){mb.textContent=scoreBand(p);mb.style.color=color;mb.title=scoreTierDetail(p);}
buildSteps(d,p);
    document.getElementById('ldot').className='dot ok';
    document.getElementById('ltime').textContent=new Date().toLocaleTimeString();
  }).catch(function(){document.getElementById('ldot').className='dot err';});
}
refresh();
setInterval(refresh,60000);
</script>
</body>
</html>`;


// ── Alpha: Inline Report Generator ────────────────────────────────────────────
const REPORT_CSS = `
        :root {
            /* ── Fortinet Brand: Red #DA291C · Black #000000 ── */
            --color-critical: #DA291C;          /* Fortinet Red */
            --color-critical-bg: #FDECEA;
            --color-critical-border: #DA291C;
            --color-high: #B87700;              /* Darkened accent-orange — readable on white at AA contrast */
            --color-high-bg: #FFF6DF;
            --color-medium: #B7770D;            /* Amber */
            --color-medium-bg: #FEF9E7;
            --color-low: #307FE2;               /* Accent blue — informational/low risk */
            --color-low-bg: #EAF2FD;
            --color-success: #2A9D66;           /* Accent green */
            --color-success-bg: #E7F7EF;
            --color-primary: #DA291C;           /* Fortinet Red — all primary accents */
            --color-primary-light: #F04030;
            --color-primary-dark: #000000;      /* Fortinet Black — all dark backgrounds */
            --color-text: #1A1A1A;
            --color-text-muted: #5A5A5A;
            --color-border: #D5D5D5;
            --color-bg-light: #F5F5F5;
            --color-bg-section: #FAFAFA;
            /* ── Extended accent palette (non-severity groupings, e.g. report4 finding categories) ── */
            --accent-blue: #307FE2;
            --accent-orange: #FFB900;
            --accent-green: #3CB17E;
            --accent-purple: #9063CD;
            --accent-teal: #2CCCD3;
        }

        @keyframes rec-glow {
            0%,100% { box-shadow: 0 0 0 0 rgba(218,41,28,0), 0 8px 40px rgba(0,0,0,0.35); }
            50%      { box-shadow: 0 0 0 4px rgba(218,41,28,0.22), 0 8px 40px rgba(0,0,0,0.35); }
        }
        @keyframes rec-pulse-badge {
            0%,100% { transform: scale(1); }
            50%      { transform: scale(1.06); }
        }
        .rec-context-banner         { animation: rec-glow 3s ease-in-out infinite; }
        .rec-badge-count            { animation: rec-pulse-badge 2.5s ease-in-out infinite; }

        @media print {
            @page {
                size: a3 landscape;
                margin: 1.2cm 1.5cm;
            }
            * {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                color-adjust: exact !important;
            }
            .page-break-before { page-break-before: always; clear: both; }
            .no-print { display: none !important; }
            tbody tr:hover { background: transparent !important; }
            .section-card, .finding-row, .kpi-card, .decision-card {
                page-break-inside: avoid;
                break-inside: avoid;
            }
            table tr {
                page-break-inside: avoid;
                break-inside: avoid;
            }
            table thead {
                display: table-header-group;
            }
            h2, h3, h4 {
                page-break-after: avoid;
                break-after: avoid;
            }
            section.pagebreak {
                page-break-before: always;
            }
            section.pagebreak:first-of-type {
                page-break-before: auto;
            }

            /* ── Tighten spacing for print — prevent large whitespace gaps ── */
            body { padding: 0 2rem; }
            /* Cover's 62vh min-height is for on-screen presence only — on a printed
               page it leaves no room for whatever immediately follows (e.g. report2's
               per-cloud gauges, meant to share the cover's page). Let it size to content. */
            .report-cover { min-height: auto !important; padding: 2rem 2.5rem 1.5rem !important; margin-bottom: 1rem !important; }
            h2 { margin: 1.5rem 0 1.2rem !important; }
            h3 { margin: 1.5rem 0 0.75rem !important; padding-bottom: 0.4rem !important; }
            h4 { margin: 1rem 0 0.5rem !important; }
            .narrative p { margin-bottom: 0.6rem !important; }
            .section-summary { margin: 1.5rem 0 1rem !important; }
            .narrative { margin-bottom: 1rem !important; }
            section { padding-bottom: 0 !important; }
            .product-grid { margin: 1rem 0 !important; gap: 0.8rem !important; }
            .findings-driver { margin: 1rem 0 1.5rem !important; }
            .toc { margin: 1rem 0 !important; }
            /* Keep banner + findings table together — no orphaned banner pages */
            .rec-context-banner { break-after: avoid; break-inside: avoid; }
            .findings-driver { break-inside: avoid; }

            /* Collapsed findings panels must still print in full — a PDF report can't
               omit rows just because they were collapsed for on-screen navigation. Plain
               div/class toggle (not native <details>) so this override reliably applies
               through Chromium's print pagination — see collapsibleFindings() comment. */
            .rpt-collapse { border: none !important; margin: 0.5rem 0 !important; }
            .rpt-collapse-summary { pointer-events: none; background: none !important; padding: 0.3rem 0 !important; }
            .rpt-collapse-summary .rpt-collapse-chevron { display: none; }
            .rpt-collapse-body { display: block !important; padding: 0 !important; }

            /* A static PDF can't run the unlock interaction — show the lock card as a
               plain placeholder, not a dead input/button. */
            .fc-lock-row, .fc-lock-error { display: none !important; }
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            width: 100%;
            max-width: 100%;
            margin: 0 auto;
            padding: 0 4rem;
            color: var(--color-text);
            background: #FFFFFF;
            line-height: 1.8;
            font-size: 14px;
        }

        /* ── Topbar ── */
        .report-topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 14px;
            height: 54px;
            padding: 0 2rem;
            background: var(--color-primary-dark);
            margin-bottom: 0;
        }
        .report-topbar-left { display: flex; align-items: center; gap: 14px; }
        .report-topbar .brand-logo { height: 18px; width: auto; color: #fff; flex-shrink: 0; }
        .report-topbar .brand-sep { width: 1px; height: 18px; background: rgba(255,255,255,0.2); flex-shrink: 0; }
        .report-topbar .topbar-title { font-size: 11px; font-weight: 700; color: rgba(255,255,255,0.75); letter-spacing: 1.8px; text-transform: uppercase; }
        .report-topbar .topbar-sub { font-size: 11px; color: rgba(255,255,255,0.5); }

        /* ── PDF export button (screen only) ── */
        .pdf-export-btn {
            position: fixed;
            bottom: 18px;
            left: 22px;
            z-index: 999;
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--color-primary);
            color: #fff;
            border: none;
            border-radius: 999px;
            padding: 11px 22px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            cursor: pointer;
            box-shadow: 0 4px 20px rgba(218,41,28,.4);
            font-family: inherit;
            transition: all .2s;
        }
        .pdf-export-btn:hover { background: var(--color-primary-light); transform: translateY(-2px); box-shadow: 0 8px 28px rgba(218,41,28,.5); }

        /* ── Cover / Title ── */
        .report-cover {
            background: linear-gradient(160deg, var(--color-primary-dark) 0%, var(--color-primary) 60%, var(--color-primary-light) 100%);
            color: white;
            padding: 3.5rem 2.5rem 2.5rem;
            margin-bottom: 2rem;
            text-align: center;
            display: flex;
            flex-direction: column;
            min-height: 62vh;
        }
        .report-cover .report-type {
            font-size: 0.8rem;
            font-weight: 700;
            letter-spacing: 3px;
            text-transform: uppercase;
            opacity: 0.75;
            margin-bottom: 1rem;
        }
        .report-cover h1 {
            font-size: 2.4rem;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 0.5rem;
            border: none;
        }
        .report-cover .subtitle {
            font-size: 1.15rem;
            opacity: 0.85;
            margin-bottom: 2rem;
        }
        .report-cover .meta-row {
            display: flex;
            gap: 2.5rem;
            flex-wrap: wrap;
            justify-content: center;
            font-size: 0.85rem;
            opacity: 0.8;
            border-top: 1px solid rgba(255,255,255,0.2);
            padding-top: 1.25rem;
            margin-top: auto;
        }
        .report-cover .meta-item strong { display: block; font-size: 0.7rem; letter-spacing: 1px; text-transform: uppercase; opacity: 0.6; }

        /* ── Section Headers ── */
        h2 {
            font-size: 1.6rem;
            font-weight: 800;
            letter-spacing: -0.01em;
            color: var(--color-primary-dark);
            border-left: 5px solid var(--color-primary);
            padding-left: 1rem;
            margin: 5.5rem 0 2.5rem;
            clear: both;
        }
        h2:first-of-type { margin-top: 3rem; }
        h3 {
            font-size: 1.15rem;
            font-weight: 600;
            color: var(--color-text);
            margin: 3.5rem 0 1.25rem;
            padding-bottom: 0.6rem;
            border-bottom: 1px solid var(--color-border);
            clear: both;
        }
        h4 {
            font-size: 1rem;
            font-weight: 600;
            color: var(--color-text);
            margin: 2.5rem 0 0.85rem;
            clear: both;
        }
        p { margin-bottom: 1.2rem; color: var(--color-text); line-height: 1.85; }

        /* ── TOC ── */
        .toc {
            background: var(--color-bg-light);
            border: 1px solid var(--color-border);
            border-radius: 14px;
            padding: 1.5rem 2rem;
            margin: 1.5rem auto 2rem;
        }
        .toc h3 { margin-top: 0; font-size: 1rem; color: var(--color-primary-dark); text-align: center; margin-bottom: 1.1rem; }
        .toc-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 0.75rem; }
        .toc-card {
            min-width: 0;
            border: 1px solid var(--color-border);
            border-top: 4px solid var(--color-primary);
            border-radius: 14px;
            padding: 1rem 1.1rem;
            background: white;
            text-decoration: none;
            display: block;
            transition: box-shadow 0.15s, transform 0.15s;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
        }
        .toc-card:hover { box-shadow: 0 8px 20px rgba(0,0,0,0.14); transform: translateY(-2px); }
        .toc-card .tc-num {
            font-size: 0.62rem;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--color-text-muted);
            margin-bottom: 0.3rem;
        }
        .toc-card .tc-count {
            font-size: 2.1rem;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 0.35rem;
            font-variant-numeric: tabular-nums;
            letter-spacing: -0.5px;
        }
        .toc-card .tc-title {
            font-size: 0.86rem;
            font-weight: 700;
            color: var(--color-primary-dark);
            margin-bottom: 0.3rem;
            line-height: 1.3;
        }
        .toc-card .tc-sub {
            font-size: 0.7rem;
            color: var(--color-text-muted);
            line-height: 1.45;
        }

        /* ── Dashboard Tile — big number + short label, no eyebrow/subtitle ── */
        .dash-tile-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; }
        @media screen and (max-width: 900px) { .dash-tile-grid { grid-template-columns: repeat(2, 1fr); } }
        .dash-tile {
            border: 1px solid var(--color-border);
            border-radius: 14px;
            padding: 1.75rem 1rem;
            background: white;
            text-align: center;
            text-decoration: none;
            display: block;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
            transition: box-shadow 0.15s, transform 0.15s;
        }
        .dash-tile:hover { box-shadow: 0 8px 20px rgba(0,0,0,0.14); transform: translateY(-2px); }
        .dash-tile .dt-count {
            font-size: 2.4rem;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 0.6rem;
            font-variant-numeric: tabular-nums;
            letter-spacing: -0.02em;
        }
        .dash-tile .dt-label { font-size: 0.92rem; color: var(--color-text); line-height: 1.35; }

        /* ── Cloud Services Security Risk Score panel ── */
        .csp-panel { background: #f1f3f8; border-radius: 20px; padding: 2rem; margin: 1rem 0; }
        .csp-panel-title { font-size: 1.7rem; font-weight: 800; color: #0f172a; margin: 0 0 0.35rem; border-left: 4px solid var(--color-primary); padding-left: 0.9rem; }
        .csp-panel-subtitle { font-size: 0.72rem; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: #64748b; padding-left: 1.3rem; margin: 0 0 1.75rem; }
        .csp-cards-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 1.5rem; }
        .csp-card2 { background: #fff; border-radius: 16px; padding: 1.5rem; box-shadow: 0 4px 16px rgba(15,23,42,0.07); position: relative; overflow: hidden; }
        .csp-card2-top { position: absolute; top: 0; left: 0; right: 0; height: 4px; }
        .csp-card2-head { display: flex; align-items: center; justify-content: space-between; margin: 0.5rem 0 1.75rem; }
        .csp-monitored { font-size: 0.76rem; font-weight: 700; color: #16a34a; display: inline-flex; align-items: center; gap: 5px; }
        .csp-monitored::before { content: ''; width: 7px; height: 7px; border-radius: 50%; background: #16a34a; flex-shrink: 0; }
        .csp-ring-row { display: flex; align-items: center; gap: 1.5rem; margin-bottom: 1.5rem; }
        .csp-ring-score { font-size: 2.6rem; font-weight: 900; line-height: 1; letter-spacing: -0.02em; }
        .csp-ring-max { font-size: 0.9rem; color: #94a3b8; font-weight: 600; margin: 0.25rem 0 0.35rem; }
        .csp-ring-tier { font-size: 0.72rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: #64748b; }
        .csp-stats-box { background: #f8fafc; border-radius: 12px; padding: 1rem 0.4rem; display: grid; grid-template-columns: repeat(4,1fr); gap: 0.4rem; margin-bottom: 1.25rem; }
        .csp-stats-box .csn { font-size: 1.35rem; font-weight: 800; text-align: center; }
        .csp-stats-box .csl { font-size: 0.6rem; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase; color: #64748b; text-align: center; margin-top: 2px; }
        .csp-cta-btn { display: block; text-align: center; width: 100%; padding: 0.9rem; border-radius: 10px; background: linear-gradient(135deg,#3b82f6,#2563eb); color: #fff !important; font-size: 0.76rem; font-weight: 800; letter-spacing: 1px; text-transform: uppercase; text-decoration: none; box-shadow: 0 4px 12px rgba(37,99,235,0.3); box-sizing: border-box; }
        .csp-summary-strip { background: #fff; border: 1px solid #e2e8f0; border-radius: 16px; display: grid; grid-template-columns: repeat(4,1fr); padding: 1.75rem 1rem; }
        .csp-summary-strip .css-num { font-size: 2rem; font-weight: 900; text-align: center; color: #0f172a; }
        .csp-summary-strip .css-label { font-size: 0.68rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: #64748b; text-align: center; margin-top: 0.3rem; }

        /* ── FortiCNAPP solution card — "why it matters + how FortiCNAPP helps", per section ── */
        .fc-solution { background: #F5F5F5; border: 1px solid var(--color-border); border-left: 4px solid var(--color-primary); border-radius: 0 12px 12px 0; padding: 1.5rem 1.75rem; margin: 1rem 0 1.5rem; }
        .fc-solution-head { font-size: 0.78rem; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase; color: var(--color-primary-dark); margin-bottom: 1rem; }
        .fc-solution-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem 2rem; margin-bottom: 1.25rem; }
        .fc-label { display: block; font-size: 0.65rem; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase; color: var(--color-primary); margin-bottom: 0.3rem; }
        .fc-solution-grid p { font-size: 0.82rem; color: var(--color-text); line-height: 1.55; margin: 0; }
        .fc-outcomes { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem 2rem; padding-top: 1.1rem; border-top: 1px solid var(--color-border); }
        .fc-outcomes ul { margin: 0.3rem 0 0 1.1rem; padding: 0; }
        .fc-outcomes li { font-size: 0.8rem; color: var(--color-text); line-height: 1.6; margin-bottom: 0.2rem; }

        /* ── Fortinet-only section lock gate — client-side only (no server session for
           report viewing), so this is a courtesy gate for internal/partner content, not
           a security boundary. Printed PDFs are generated headless with no unlock
           interaction, so a gated section always renders as the locked card, never the
           content underneath — kept out of the customer-facing export by construction. */
        .fc-lock-gate { max-width: 480px; margin: 2rem auto; text-align: center; border: 1px solid var(--color-border); border-top: 4px solid var(--color-primary); border-radius: 16px; padding: 2.5rem 2rem; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .fc-lock-icon { font-size: 2rem; margin-bottom: 0.75rem; }
        .fc-lock-title { font-size: 1rem; font-weight: 800; color: var(--color-primary-dark); margin-bottom: 0.5rem; }
        .fc-lock-desc { font-size: 0.82rem; color: var(--color-text-muted); line-height: 1.6; margin-bottom: 1.5rem; }
        .fc-lock-row { display: flex; gap: 0.5rem; }
        .fc-lock-row input { flex: 1; padding: 0.65rem 0.9rem; border: 1px solid var(--color-border); border-radius: 8px; font-size: 0.85rem; font-family: inherit; outline: none; }
        .fc-lock-row input:focus { border-color: var(--color-primary); }
        .fc-lock-row button { padding: 0.65rem 1.3rem; border: none; border-radius: 8px; background: var(--color-primary); color: #fff; font-weight: 700; font-size: 0.82rem; cursor: pointer; font-family: inherit; white-space: nowrap; }
        .fc-lock-row button:hover { background: var(--color-primary-light); }
        .fc-lock-error { display: none; color: var(--color-critical); font-size: 0.78rem; margin-top: 0.9rem; }

        /* ── KPI Cards ── */
        .kpi-grid { width: 100%; margin: 3rem 0; overflow: hidden; }
        .kpi-grid::after { content: ""; display: table; clear: both; }
        .kpi-card {
            float: left;
            width: 22%;
            margin-right: 4%;
            background: white;
            border-radius: 16px;
            padding: 1.75rem 1.25rem;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
            border: 1px solid var(--color-border);
            text-align: center;
            box-sizing: border-box;
        }
        .kpi-card:nth-child(4n) { margin-right: 0; }
        .kpi-card .kpi-number { font-size: 2.25rem; font-weight: 700; line-height: 1; margin-bottom: 0.35rem; }
        .kpi-card .kpi-label { font-size: 0.78rem; color: var(--color-text-muted); line-height: 1.35; }
        .kpi-card.critical { border-top: 4px solid var(--color-critical); }
        .kpi-card.high { border-top: 4px solid var(--color-high); }
        .kpi-card.medium { border-top: 4px solid var(--color-medium); }
        .kpi-card.info { border-top: 4px solid var(--color-primary); }
        .kpi-card.critical .kpi-number { color: var(--color-critical); }
        .kpi-card.high .kpi-number { color: var(--color-high); }
        .kpi-card.medium .kpi-number { color: var(--color-medium); }
        .kpi-card.info .kpi-number { color: var(--color-primary); }

        /* ── Badges ── */
        .badge {
            display: inline-block;
            padding: 0.2rem 0.65rem;
            border-radius: 6px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            white-space: nowrap;
        }
        .badge-critical { background: var(--color-critical-bg); color: var(--color-critical); border: 1px solid var(--color-critical-border); }
        .badge-high { background: var(--color-high-bg); color: var(--color-high); }
        .badge-medium { background: var(--color-medium-bg); color: var(--color-medium); }
        .badge-low { background: var(--color-low-bg); color: var(--color-low); }
        .badge-success { background: var(--color-success-bg); color: var(--color-success); }
        .badge-info { background: #EDEDED; color: #1A1A1A; }
        .badge-aws { background: #FF9900; color: white; }
        .badge-azure { background: #0078D4; color: white; }
        .badge-gcp { background: #4285F4; color: white; }
        .badge-mfa-off { background: var(--color-critical-bg); color: var(--color-critical); border: 1px solid var(--color-critical-border); }
        .badge-mfa-on { background: var(--color-success-bg); color: var(--color-success); }

        /* ── Collapsible findings panel — used when a table would otherwise run long ──
           Plain div + class toggle, not native <details>: Chromium's print pagination
           engine was confirmed (live, --print-to-pdf) to silently drop a closed
           <details>'s content for larger tables even with a forced display:block
           override — a real PDF lost 41+ rows of identity findings with no error. A
           class-based toggle has no native collapse semantics for print to mis-render. */
        .rpt-collapse { border: 1px solid var(--color-border); border-radius: 10px; overflow: hidden; margin: 0.75rem 0; }
        .rpt-collapse-summary {
            cursor: pointer; user-select: none;
            display: flex; align-items: center; gap: 8px;
            padding: 0.7rem 1.1rem;
            background: var(--color-bg-light);
            font-size: 0.78rem; font-weight: 700; color: var(--color-text);
        }
        .rpt-collapse-chevron { display: inline-block; font-size: 0.65rem; color: var(--color-text-muted); transition: transform 0.15s; }
        .rpt-collapse.open .rpt-collapse-chevron { transform: rotate(90deg); }
        .rpt-collapse-body { display: none; padding: 0 0.9rem 0.6rem; }
        .rpt-collapse.open .rpt-collapse-body { display: block; }
        .rpt-collapse-body table { margin: 0.5rem 0; }

        /* ── Tables ── */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 2.5rem 0;
            background: white;
            font-size: 0.83rem;
        }
        thead th {
            background: var(--color-primary-dark);
            color: white;
            font-weight: 600;
            font-size: 0.74rem;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            padding: 0.85rem 1rem;
            text-align: left;
            white-space: nowrap;
        }
        tbody tr { border-bottom: 1px solid var(--color-border); }
        tbody tr:nth-child(even) { background: var(--color-bg-section); }
        td { padding: 0.9rem 1rem; vertical-align: top; word-wrap: break-word; overflow-wrap: break-word; }

        /* Executive finding table — wider cells, no hard max-width */
        .exec-table { table-layout: auto; }
        .exec-table td, .exec-table th { font-size: 0.78rem; padding: 0.85rem 0.9rem; max-width: 220px; }
        .exec-table td.narrow { width: 28px; text-align: center; }
        .exec-table td.med { max-width: 140px; }
        .exec-table td.wide { max-width: 260px; }

        /* Summary / leadership table */
        .summary-table thead th { background: var(--color-primary); }
        .summary-table td { font-size: 0.82rem; }

        /* ── Info Boxes ── */
        .info-box {
            padding: 1.5rem 2rem;
            border-radius: 8px;
            margin: 2.5rem 0;
            display: flex;
            gap: 0.85rem;
            border: 1px solid;
        }
        .info-box.alert { background: var(--color-critical-bg); border-color: var(--color-critical-border); }
        .info-box.warning { background: var(--color-high-bg); border-color: var(--color-high); }
        .info-box.note { background: #F5F5F5; border-color: #BEBEBE; }
        .info-box.tip { background: var(--color-success-bg); border-color: #82E0AA; }
        .info-box-icon { font-size: 1.1rem; flex-shrink: 0; margin-top: 0.1rem; }
        .info-box-content { flex: 1; }
        .info-box-content strong { display: block; margin-bottom: 0.2rem; font-size: 0.85rem; }
        .info-box-content p { margin: 0; font-size: 0.82rem; }

        /* ── Decision Cards ── */
        .decision-row { width: 100%; margin: 2.5rem 0; overflow: hidden; }
        .decision-row::after { content: ""; display: table; clear: both; }
        .decision-card {
            float: left;
            width: 30%;
            margin-right: 5%;
            background: white;
            border: 1px solid var(--color-border);
            border-top: 4px solid var(--color-primary);
            border-radius: 14px;
            padding: 1.25rem;
            box-sizing: border-box;
        }
        .decision-card:nth-child(3n) { margin-right: 0; }
        .decision-card .decision-num {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 28px; height: 28px;
            background: var(--color-primary-dark);
            color: white;
            border-radius: 50%;
            font-weight: 700;
            font-size: 0.85rem;
            margin-bottom: 0.6rem;
        }
        .decision-card h4 { margin: 0 0 0.5rem; font-size: 0.92rem; color: var(--color-primary-dark); }
        .decision-card p { font-size: 0.8rem; color: var(--color-text-muted); margin: 0; }
        .decision-card.urgent { border-top-color: var(--color-critical); }
        .decision-card.urgent .decision-num { background: var(--color-critical); }

        /* ── Action Plan Table ── */
        .plan-table thead th { background: var(--color-primary-dark); }
        .plan-table td { padding: 1rem 1.1rem; font-size: 0.83rem; vertical-align: top; }
        .plan-table td:first-child { font-weight: 600; white-space: nowrap; color: var(--color-primary-dark); width: 110px; }
        .plan-table td:last-child { color: var(--color-text-muted); }

        /* ── Identity Risk Commentary ── */
        .commentary-box {
            background: linear-gradient(135deg, #F5F5F5 0%, #EBEBEB 100%);
            border: 1px solid #C8C8C8;
            border-left: 4px solid var(--color-primary);
            border-radius: 0 8px 8px 0;
            padding: 2rem 2.5rem;
            margin: 3rem 0;
        }
        .commentary-box h4 { margin-top: 0; color: var(--color-primary-dark); }

        /* ── Narrative ── */
        .narrative { background: var(--color-bg-section); border-left: 4px solid var(--color-primary); border-radius: 0 8px 8px 0; padding: 2rem 2.5rem; margin: 2.5rem 0; }
        .narrative p:last-child { margin-bottom: 0; }

        /* ── Promo ── */
        .promo-section { display: flex; justify-content: center; margin: 2rem 0; width: 100%; }
        .promo-section img { max-width: 85%; width: 85%; height: auto; display: block; margin: 0 auto; }
        .cover-image img { max-width: 70%; width: 70%; }

        /* ── Risk score chip ── */
        .risk-chip {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 700;
            background: var(--color-critical-bg);
            color: var(--color-critical);
            border: 1px solid var(--color-critical-border);
        }
        .risk-chip.high { background: var(--color-high-bg); color: var(--color-high); border-color: var(--color-high); }

        /* ── Host groups (CVEs grouped by Internet Exposure) ── */
        .host-exposure-summary {
            display: flex;
            gap: 1.75rem;
            margin: 0.5rem 0 2rem;
            flex-wrap: wrap;
        }
        .hes-item { font-size: 0.82rem; color: var(--color-text-muted); }
        .hes-item strong { color: var(--color-text); font-size: 1.05rem; }
        .hes-item.exposed strong { color: var(--color-critical); }
        .host-group {
            margin-bottom: 2rem;
            border: 1px solid var(--color-border);
            border-left: 5px solid var(--color-low);
            border-radius: 8px;
            overflow: hidden;
        }
        .host-group.exposed { border-left-color: var(--color-critical); }
        .host-group-header {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 0.85rem 1.25rem;
            background: var(--color-bg-light);
            flex-wrap: wrap;
            break-after: avoid;
            page-break-after: avoid;
        }
        .host-group-header .host-name { font-size: 0.92rem; font-weight: 700; color: var(--color-text); }
        .host-group-header .host-ip { font-size: 0.75rem; color: var(--color-text-muted); font-family: monospace; }
        .host-group-header .host-cve-count { margin-left: auto; font-size: 0.75rem; color: var(--color-text-muted); }
        .host-group table { margin: 0; }

        /* ── Apple-style Summary Chart ── */
        .apple-chart {
            background: #FFFFFF;
            border-radius: 18px;
            padding: 2rem 2.5rem 1.75rem;
            box-shadow:
                0 2px 4px rgba(0,0,0,0.06),
                0 8px 24px rgba(0,0,0,0.08),
                0 1px 0 rgba(255,255,255,0.9) inset;
            margin: 2.5rem 0;
            border: 1px solid rgba(0,0,0,0.06);
        }
        .apple-chart-title {
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--color-text-muted);
            margin-bottom: 1.1rem;
        }
        .chart-row {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin: 0.55rem 0;
        }
        .chart-row-label {
            width: 230px;
            flex-shrink: 0;
            font-size: 0.78rem;
            color: var(--color-text);
            font-weight: 500;
        }
        .chart-track {
            flex: 1;
            height: 22px;
            border-radius: 11px;
            background: #F0EFEF;
            box-shadow: inset 0 2px 5px rgba(0,0,0,0.13), inset 0 -1px 2px rgba(255,255,255,0.6);
            position: relative;
            overflow: hidden;
        }
        .chart-bar {
            height: 100%;
            border-radius: 11px;
            min-width: 4px;
            background: linear-gradient(180deg,
                #F05040 0%,
                #DA291C 45%,
                #B82015 100%
            );
            box-shadow:
                0 3px 8px rgba(218,41,28,0.45),
                inset 0 1px 0 rgba(255,255,255,0.35),
                inset 0 -1px 0 rgba(0,0,0,0.12);
            position: relative;
        }
        .chart-bar::after {
            content: '';
            position: absolute;
            top: 2px; left: 6px; right: 6px;
            height: 5px;
            border-radius: 3px;
            background: rgba(255,255,255,0.28);
        }
        .chart-row-value {
            width: 44px;
            flex-shrink: 0;
            font-size: 1.15rem;
            font-weight: 800;
            color: var(--color-critical);
            text-align: right;
            letter-spacing: -0.02em;
        }

        /* ── Host Priority Cards ── */
        .host-card-grid { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 1rem 0; }
        .host-card {
            flex: 0 1 calc(20% - 0.6rem);
            min-width: 140px;
            border: 1px solid var(--color-border);
            border-top: 3px solid var(--color-critical);
            border-radius: 10px;
            padding: 0.6rem 0.8rem;
            background: var(--color-bg-section);
            break-inside: avoid;
        }
        .host-card .host-name {
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--color-text);
            word-break: break-all;
            margin-bottom: 0.3rem;
        }
        .host-card .host-sevs {
            font-size: 0.7rem;
            color: var(--color-text-muted);
            white-space: pre-line;
            line-height: 1.5;
        }

        /* ── Security Gauge ── */
        .gauge-wrap { margin: 0.6rem 0; }
        .gauge-track {
            height: 10px;
            border-radius: 5px;
            background: #E8E8E8;
            overflow: hidden;
            position: relative;
        }
        .gauge-fill {
            height: 100%;
            border-radius: 5px;
            transition: width 0.3s ease;
        }
        .gauge-fill.critical { background: var(--color-critical); }
        .gauge-fill.high     { background: var(--color-high); }
        .gauge-fill.medium   { background: var(--color-medium); }
        .gauge-fill.low      { background: var(--color-success); }
        .gauge-label { font-size: 0.72rem; color: var(--color-text-muted); margin-bottom: 0.2rem; display: flex; justify-content: space-between; }
        .gauge-label strong { color: var(--color-text); }

        /* ── Assessment Intro Panels ── */
        .intro-grid { display: flex; gap: 1.5rem; margin: 2.5rem 0; flex-wrap: wrap; }
        .intro-card {
            flex: 1 1 calc(33% - 1rem);
            min-width: 220px;
            border-radius: 16px;
            padding: 1.75rem 1.75rem;
            background: white;
            border: 1px solid var(--color-border);
            border-top: 4px solid var(--color-primary);
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .intro-card .intro-eyebrow {
            font-size: 0.62rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--color-primary);
            margin-bottom: 0.5rem;
        }
        .intro-card h4 { margin: 0 0 0.9rem; font-size: 0.95rem; color: var(--color-primary-dark); }
        .intro-card p { font-size: 0.85rem; color: var(--color-text-muted); line-height: 1.85; margin: 0; }
        .intro-card p + p { margin-top: 0.9rem; }
        .intro-card p strong { color: var(--color-text); font-weight: 700; }

        /* ── Findings Driver Summary ── */
        .findings-driver {
            border: 1px solid var(--color-border);
            border-radius: 8px;
            overflow: hidden;
            margin: 2rem 0 3rem;
        }
        .findings-driver-header {
            background: var(--color-primary-dark);
            padding: 0.75rem 1.25rem;
            font-size: 0.7rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: #fff;
        }
        .findings-driver table {
            width: 100%;
            border-collapse: collapse;
        }
        .findings-driver table tr:not(:last-child) td {
            border-bottom: 1px solid var(--color-border);
        }
        .findings-driver table td {
            padding: 0.75rem 1.25rem;
            font-size: 0.8rem;
            vertical-align: middle;
        }
        .findings-driver table td:first-child {
            width: 38%;
            font-weight: 600;
            color: var(--color-text);
        }
        .findings-driver table td:nth-child(2) {
            color: var(--color-text-muted);
        }
        .findings-driver table tr.finding-row-active td:first-child {
            color: var(--color-critical);
        }
        .finding-chips { display: flex; flex-wrap: wrap; gap: 0.3rem; }

        /* ── Product Recommendation Cards ── */
        .product-grid { display: flex; flex-wrap: wrap; gap: 1.5rem; margin: 2.5rem 0; }
        .product-card {
            flex: 1 1 calc(50% - 0.5rem);
            min-width: 260px;
            border: 1px solid var(--color-border);
            border-top: 4px solid var(--color-primary);
            border-radius: 14px;
            padding: 1.25rem;
            background: var(--color-bg-section);
            break-inside: avoid;
        }
        .product-card .product-name {
            font-size: 1rem;
            font-weight: 700;
            color: var(--color-primary-dark);
            margin-bottom: 0.15rem;
        }
        .product-card .product-subtitle {
            font-size: 0.72rem;
            color: var(--color-primary);
            font-weight: 600;
            letter-spacing: 0.02em;
            text-transform: uppercase;
            margin-bottom: 0.55rem;
        }
        .product-card .product-addresses { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-bottom: 0.75rem; }
        .product-card .product-desc { font-size: 0.8rem; color: var(--color-text-muted); line-height: 1.55; margin-bottom: 0.5rem; }
        .product-card ul.product-caps { margin: 0.4rem 0 0 1.1rem; padding: 0; }
        .product-card ul.product-caps li { font-size: 0.78rem; color: var(--color-text); margin-bottom: 0.22rem; }

        /* ── Section Risk Summary Callout ── */
        .section-summary {
            background: #111111;
            border-left: 5px solid var(--color-primary);
            border-radius: 0 8px 8px 0;
            padding: 2rem 2.5rem;
            margin: 3.5rem 0 2rem;
        }
        .section-summary .ss-title {
            font-size: 0.68rem;
            font-weight: 700;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--color-primary);
            margin-bottom: 0.55rem;
        }
        .section-summary p {
            color: rgba(255,255,255,0.88);
            font-size: 0.82rem;
            margin-bottom: 0;
            line-height: 1.65;
        }

        /* ── Misc ── */
        .section-divider {
            border: none;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--color-border), transparent);
            margin: 4rem 0 0;
        }
        section.pagebreak {
            padding-top: 1rem;
            padding-bottom: 4rem;
        }
        section.pagebreak + section.pagebreak {
            border-top: 2px solid var(--color-border);
            padding-top: 1rem;
        }
        footer { margin-top: 5rem; padding: 2rem 2.5rem; background: var(--color-primary-dark); color: rgba(255,255,255,0.92); font-size: 0.78rem; text-align: center; }
        footer p { color: inherit; }
        .text-muted { color: var(--color-text-muted); }
        .text-critical { color: var(--color-critical); font-weight: 600; }
        ul.findings-list { margin: 0.5rem 0 0.5rem 1.25rem; }
        ul.findings-list li { margin-bottom: 0.2rem; font-size: 0.8rem; }
        .section-label {
            display: inline-block;
            background: var(--color-primary);
            color: white;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 1px;
            text-transform: uppercase;
            padding: 0.15rem 0.5rem;
            border-radius: 3px;
            margin-right: 0.4rem;
            vertical-align: middle;
        }
    `;

// Self-contained inline SVG — no external image request, matches the Fortinet
// wordmark used across the org's other customer-facing templates.
const FORTINET_LOGO_SVG = '<svg class="brand-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 487.6 55" aria-label="Fortinet"><path fill="currentColor" d="M279.9 11.7V0h13.4v54.8h-13.4V11.7zM220.9 0h51.7v11.8h-24.3v43.1H235V11.8h-14.1V0zm266.7 0v11.8h-24.3v43.1H450V11.8h-14.1V0h51.7zM0 0h58v11.8H13.4v11.7h38v11.8h-38v19.5H0V0zm374.5 0h54v11.8h-40.6v9.8h33.3v11.8h-33.3v9.8h41.3V55h-54.7V0zm-10.3 15.5v39.3h-13.4V15.5c0-2.1-1.6-3.7-3.7-3.7h-30v43.1h-13.4V0h45c8.5 0 15.5 7 15.5 15.5zM200.3 0h-45.7v54.8H168V35.3h30c1.6.1 2.9 1.4 2.9 3v16.6h13.4V38.1c0-2.9-1.6-5.4-4-6.8 2.9-2.7 4.7-6.6 4.7-10.8v-5.8c.1-8.1-6.5-14.7-14.7-14.7zm1.4 20.5c0 1.6-1.3 3-3 3H168V11.8h30.7c1.6 0 3 1.3 3 3v5.7z"/><path fill="#da291c" d="M144.2 20.4v14.2H122V20.4h22.2zM93.9 54.8H116V40.6H93.9v14.2zm50.3-42.9c0-6.6-5.3-11.9-11.9-11.9h-10.2v14.2h22.1v-2.3zM93.9 0v14.2H116V0H93.9zM65.7 20.4v14.2h22.1V20.4H65.7zM122 54.8h10.2c6.6 0 11.9-5.3 11.9-11.9v-2.3H122v14.2zM65.7 42.9c0 6.6 5.3 11.9 11.9 11.9h10.2V40.6H65.7v2.3zm0-31v2.3h22.1V0H77.6C71 0 65.7 5.3 65.7 11.9z"/></svg>';

// Shared report header — replaces the plain-text "FORTINET" wordmark used by
// buildReportHtml()/2/3/4 with the real logo + topbar layout (logo, separator,
// report label) so all four reports share one consistent, self-contained header.
function reportTopbarHtml(subtitle, logoOnly) {
  if (logoOnly) {
    return '<div class="report-topbar"><div class="report-topbar-left">' + FORTINET_LOGO_SVG + '</div></div>';
  }
  return '<div class="report-topbar"><div class="report-topbar-left">' + FORTINET_LOGO_SVG +
    '<div class="brand-sep"></div><span class="topbar-title">Rapid Cloud Assessment</span>' +
    (subtitle ? '<span class="topbar-sub">' + subtitle + '</span>' : '') +
    '</div></div>';
}

// Wraps a findings table behind a collapsed toggle once it exceeds `threshold` rows,
// so a long resource list doesn't force scrolling past it to reach the next section.
// `label` is a static string authored per call site (e.g. "Critical Findings"), never
// row data, so it's inlined unescaped.
//
// Deliberately NOT built on native <details>/<summary>: Chromium's print/PDF pagination
// engine (confirmed live, headless --print-to-pdf) silently drops a closed <details>'s
// content entirely for larger tables — the CSS override that forces display:block on a
// closed details' child doesn't reliably survive print layout, so whole sections (e.g. a
// 41-row identity table) vanished from the generated PDF with no visible content and no
// error. A plain div + class toggle has no such native collapse semantics for the print
// engine to mis-render — the content is always in normal flow; only a CSS class hides it
// on screen, and print unconditionally overrides that class away (see .rpt-collapse in
// the @media print block).
function collapsibleFindings(tableHtml, count, label, threshold) {
  if (count <= (threshold || 8)) return tableHtml;
  return '<div class="rpt-collapse">' +
    '<div class="rpt-collapse-summary" onclick="this.parentElement.classList.toggle(&quot;open&quot;)"><span class="rpt-collapse-chevron">&#9656;</span> Show all ' + count + ' ' + label + '</div>' +
    '<div class="rpt-collapse-body">' + tableHtml + '</div></div>';
}

// Renders a compliance finding's violating-resource list (URN/instance ID + a secondary
// label like region/type) as a collapsed-by-default panel — shared by buildReportHtml's
// and buildReportHtml2's compliance tables so both stay in sync. Div+class toggle, not
// native <details> — see collapsibleFindings() above for why.
function violatingResourcesHtml(resources, esc) {
  if (!Array.isArray(resources) || !resources.length) return '';
  const urnKeys = ['URN','RESOURCE_ID','RESOURCE_KEY','RESOURCE_ARN','RESOURCE_IDENTIFIER','INSTANCE_ID','VM_ID','PRINCIPAL_ID','NAME'];
  const firstRow = resources[0] || {};
  const urnKey = urnKeys.find(k => firstRow[k] !== undefined) || Object.keys(firstRow)[0] || '';
  if (!urnKey) return '';
  const labelKeys = ['REGION','LOCATION','CLOUD','TYPE','RESOURCE_TYPE','SUBSCRIPTION_ID'];
  const labelKey = labelKeys.find(k => firstRow[k] !== undefined) || '';
  const shown = resources.slice(0, 50);
  const table = '<table style="width:100%;font-size:9px;border-collapse:collapse">' +
    '<thead><tr style="background:#f1f5f9"><th style="padding:3px 6px;text-align:left;font-weight:700;color:#64748b">'+esc(urnKey)+'</th>'+
    (labelKey?'<th style="padding:3px 6px;text-align:left;font-weight:700;color:#64748b">'+esc(labelKey)+'</th>':'')+
    '</tr></thead><tbody>'+
    shown.map((row,ri) => {
      const urnVal = row[urnKey] !== undefined ? String(row[urnKey]) : '—';
      const lblVal = labelKey && row[labelKey] !== undefined ? String(row[labelKey]) : '';
      return '<tr style="'+(ri%2?'background:#f8fafc':'')+'">'
        +'<td style="padding:2px 6px;font-family:monospace;color:#1e293b;word-break:break-all">'+esc(urnVal)+'</td>'
        +(labelKey?'<td style="padding:2px 6px;color:#64748b">'+esc(lblVal)+'</td>':'')
        +'</tr>';
    }).join('')+
    (resources.length>50?'<tr><td colspan="2" style="padding:3px 6px;color:#94a3b8;font-style:italic">… and '+(resources.length-50)+' more</td></tr>':'')+
    '</tbody></table>';
  return '<div class="rpt-collapse" style="margin-top:6px">' +
    '<div class="rpt-collapse-summary" style="padding:0.35rem 0.6rem;font-size:10px" onclick="this.parentElement.classList.toggle(&quot;open&quot;)">' +
    '<span class="rpt-collapse-chevron">&#9656;</span> ' + resources.length + ' Violating Resource' + (resources.length===1?'':'s') +
    '</div><div class="rpt-collapse-body" style="padding:0 0.4rem 0.3rem">' + table + '</div></div>';
}

// Produces a deep copy of the cached findings with real infrastructure
// identifiers swapped for consistent fake placeholders, so a report can be
// shared publicly (sales collateral, docs) without leaking customer data.
// Layout/format/scores/counts are untouched — only identifying values change.
function sanitizeCacheData(data) {
  const out = JSON.parse(JSON.stringify(data || {}));
  const seen = {};
  let counters = {};
  function fake(category, real, format) {
    if (real === undefined || real === null || real === '') return real;
    const key = category + '|' + real;
    if (seen[key]) return seen[key];
    counters[category] = (counters[category] || 0) + 1;
    const val = format(counters[category]);
    seen[key] = val;
    return val;
  }
  const pad = n => String(n).padStart(2, '0');
  const fakeHost   = h => fake('host',   h, n => 'sample-host-' + pad(n));
  const fakeMid    = m => fake('mid',    m, n => 'sample-mid-' + pad(n));
  const fakeIdent  = p => fake('ident',  p, n => 'Sample-Identity-' + pad(n));
  const fakeArn    = a => fake('arn',    a, n => 'arn:aws:iam::111111111111:role/Sample-Identity-' + pad(n));
  const fakeSecret = s => fake('secret', s, n => 'sample-secret-' + pad(n));
  const fakeRes    = r => fake('res',    r, n => 'sample-resource-' + pad(n));

  const SENSITIVE_RESOURCE_KEYS = ['URN','RESOURCE_ID','RESOURCE_KEY','RESOURCE_ARN','RESOURCE_IDENTIFIER','INSTANCE_ID','VM_ID','PRINCIPAL_ID','NAME','ACCOUNT_ID','ACCOUNT_ALIAS','SUBSCRIPTION_ID'];

  function scrubText(text) {
    if (!text) return text;
    let t = String(text);
    t = t.replace(/arn:aws:[a-z0-9-]+::\d{12}:[^\s,;()]+/gi, m => fakeArn(m));
    t = t.replace(/\b\d{12}\b/g, m => fake('acct', m, () => '111111111111'));
    t = t.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, m => fake('ip', m, n => '10.0.0.' + n));
    t = t.replace(/[\w.+-]+@[\w-]+\.[\w.-]+/g, m => fake('email', m, () => 'user@example.com'));
    Object.keys(seen).forEach(key => {
      const real = key.slice(key.indexOf('|') + 1);
      if (real && real.length > 3 && t.includes(real)) t = t.split(real).join(seen[key]);
    });
    return t;
  }

  (out.identities || []).forEach(r => {
    const orig = r.PRINCIPAL_ID || r.NAME || '';
    if (orig) {
      const label = fakeIdent(orig);
      if (r.PRINCIPAL_ID) r.PRINCIPAL_ID = fakeArn(r.PRINCIPAL_ID);
      if (r.NAME) r.NAME = label;
    }
    if (Array.isArray(r._trustPrincipals)) {
      r._trustPrincipals = r._trustPrincipals.map(p => ({ type: p.type, principal: scrubText(p.principal) }));
    }
  });

  (out.vulns || []).forEach(r => {
    if (r.evalCtx && r.evalCtx.hostname) r.evalCtx.hostname = fakeHost(r.evalCtx.hostname);
    if (r.evalCtx && r.evalCtx.mid)      r.evalCtx.mid      = fakeMid(r.evalCtx.mid);
    if (r.mid) r.mid = fakeMid(r.mid);
  });

  (out.secretsAll || []).concat(out.secrets || []).forEach(r => {
    if (r.HOSTNAME) r.HOSTNAME = fakeHost(r.HOSTNAME);
    if (r.MID)      r.MID      = fakeMid(r.MID);
    if (r.SECRET_IDENTIFIER) r.SECRET_IDENTIFIER = fakeSecret(r.SECRET_IDENTIFIER);
  });

  (out.compliance || []).forEach(c => {
    if (Array.isArray(c.resources)) {
      c.resources.forEach(row => {
        SENSITIVE_RESOURCE_KEYS.forEach(k => {
          if (row[k] !== undefined && row[k] !== null && row[k] !== '') row[k] = fakeRes(row[k]);
        });
      });
    }
  });

  (out.alerts || []).forEach(r => {
    if (r.alertInfo && r.alertInfo.description) r.alertInfo.description = scrubText(r.alertInfo.description);
  });

  return out;
}

// Groups CVE rows by host and flags internet exposure — shared by both report builders.
function groupVulnsByHost(vulns) {
  const map = {};
  (vulns || []).forEach(function(r) {
    const mt = r.machineTags;
    const mtObj = (mt && typeof mt === 'object' && !Array.isArray(mt)) ? mt : null;
    const host = (mtObj && mtObj.Hostname) || (r.evalCtx && r.evalCtx.hostname) || r.mid || 'Unknown Host';
    if (!map[host]) {
      const pubIp = (mtObj && (mtObj.ExternalIp || mtObj.PublicIp || mtObj.publicIp)) || '';
      map[host] = { name: host, exposed: !!(mtObj && mtObj.lw_InternetExposure === 'Yes'), pubIp, rows: [], maxRisk: 0 };
    }
    const g = map[host];
    // cveRiskScore is the CVE's own severity score; riskScore is a broader composite that
    // can diverge significantly (e.g. a CVE at cveRiskScore 9.95 with riskScore 6.3) — use
    // cveRiskScore first so host sort order reflects actual CVE severity, matching how
    // fetchVulns() itself defines "CVE risk" (see its NOTE comment above).
    const rs = parseFloat(r.cveRiskScore ?? r.riskScore ?? 0);
    if (rs > g.maxRisk) g.maxRisk = rs;
    g.rows.push(r);
  });
  const hosts = Object.values(map).sort(function(a, b) {
    if (a.exposed !== b.exposed) return a.exposed ? -1 : 1;
    return b.maxRisk - a.maxRisk;
  });
  const exposedCount  = hosts.filter(function(h){ return h.exposed; }).length;
  const internalCount = hosts.length - exposedCount;
  return { hosts, exposedCount, internalCount };
}

// Server-side port of the dashboard's client-only buildAssetRiskMap() (inside buildHtml's
// template literal, not reachable from Node) — per-host correlated risk (CIEM/secrets/CVE/misconfig).
const CIEM_SECRET_TYPES = ['SSH_PRIVATE_KEY','SSH_PRIVATE_KEYS','RSA','ECDSA','ED25519',
  'AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY','AWS_CREDENTIALS','AWS_SECRET',
  'GOOGLE_OAUTH_TOKEN','GCP_SERVICE_ACCOUNT','AZURE_CLIENT_SECRET','AZURE_SAS_TOKEN'];
function computeAssetRiskMap(vulns, secretsAll, compliance) {
  const ciemSet = {}; CIEM_SECRET_TYPES.forEach(t => ciemSet[t] = true);
  const map = {};
  (vulns || []).forEach(function(r) {
    const mt = r.machineTags;
    const mtObj = (mt && typeof mt === 'object' && !Array.isArray(mt)) ? mt : null;
    const host = (mtObj && mtObj.Hostname) || (r.evalCtx && r.evalCtx.hostname) || r.mid || '';
    if (!host) return;
    if (!map[host]) map[host] = { name: host, vulns: [], ciemSecrets: [], genericSecrets: [], risk: 0, ciem: 0, secretRisk: 0, threatRisk: 0, miscRisk: 0, internetExposed: false };
    const w = Math.min(100, parseFloat(r.riskScore || 0) * 10);
    map[host].vulns.push({ id: r.vulnId || '', score: parseFloat(r.riskScore || 0), w });
    map[host].threatRisk += w; map[host].risk += w;
    if (mtObj && mtObj.lw_InternetExposure === 'Yes') map[host].internetExposed = true;
  });
  (secretsAll || []).forEach(function(r) {
    const sh = (r.HOSTNAME || '').toLowerCase();
    if (!sh) return;
    const keys = Object.keys(map);
    const matchKey = keys.find(function(k) {
      const kl = k.toLowerCase();
      return kl === sh || sh.indexOf(kl) === 0 || kl.indexOf(sh.split('.')[0]) === 0;
    });
    if (!matchKey) return;
    const t = (r.SECRET_TYPE || '').toUpperCase();
    if (ciemSet[t]) { map[matchKey].ciemSecrets.push(r.SECRET_TYPE); map[matchKey].ciem += 100; map[matchKey].risk += 100; }
    else { map[matchKey].genericSecrets.push(r.SECRET_TYPE); map[matchKey].secretRisk += 50; map[matchKey].risk += 50; }
  });
  const critMisc = (compliance || []).filter(c => (c.severity || '').toLowerCase() === 'critical').length;
  const miscBoost = Math.min(60, critMisc * 10);
  if (miscBoost > 0) Object.values(map).forEach(a => { if (a.risk > 0) { a.miscRisk = miscBoost; a.risk += miscBoost; } });
  const allA = Object.values(map);
  const maxRisk = allA.reduce((mx, a) => Math.max(mx, a.risk), 1);
  allA.forEach(a => { a.normalizedScore = Math.round(a.risk / maxRisk * 100); });
  return { map, maxRisk, critMisc };
}

// Server-side port of the dashboard's client-only computeEffectivePublicStorage() (inside
// buildHtml's template literal, not reachable from Node) — merges raw CSPM publicStorage
// policy/ACL findings with LW_APA_EXPOSURE_PATHS-traced storage findings, minus the known-
// stale-CSPM-snapshot exclusion list. Any report/page showing "current" public storage
// exposure should call this instead of reading cache.publicStorage directly — the raw CSPM
// snapshot can lag the live cloud account (see STALE_STORAGE_FINDINGS comment below).
function computeEffectivePublicStorage(data) {
  // Known-stale CSPM snapshot entries: resources FortiCNAPP's last scan captured as public
  // but that no longer exist in the live cloud account (confirmed 2026-07-27 — Azure
  // returns ResourceNotFound, not a public-access-denied error, for this container). Not a
  // detection-logic bug; the fix is a fresh FortiCNAPP Azure CSPM re-scan. Keep in sync with
  // the client-side copy in buildHtml()'s computeEffectivePublicStorage().
  const STALE_STORAGE_FINDINGS = ['juiceshopswagger'];
  const findings = ((data && data.publicStorage) || []).filter(f => STALE_STORAGE_FINDINGS.indexOf(f.name) === -1);

  const epByBucket = {};
  [['s3', 'S3 Bucket'], ['azureBlob', 'Azure Blob Storage']].forEach(([key, label]) => {
    ((data && data.exposurePaths && data.exposurePaths[key]) || []).forEach(r => {
      const nm = r.TARGET && r.TARGET.displayName;
      if (!nm) return;
      r._resourceLabel = label;
      (epByBucket[nm] = epByBucket[nm] || []).push(r);
    });
  });
  const existingNames = {};
  findings.forEach(f => { f.severity = f.severity || 'critical'; existingNames[f.name] = true; });
  Object.keys(epByBucket).forEach(nm => {
    if (existingNames[nm]) return;
    const rec = epByBucket[nm][0];
    findings.push({
      cloud: (rec.PROVIDER_TYPE || 'aws').toLowerCase(),
      name: nm,
      account: rec.DOMAIN_ID || '—',
      region: '—',
      resourceType: rec._resourceLabel + ' (Verified Internet Path)',
      severity: 'high',
      urn: (rec.TARGET && rec.TARGET.key && (rec.TARGET.key.arn || rec.TARGET.key.id)) || nm,
    });
  });
  return { findings, epByBucket };
}

// Cloud Security Score maturity model — mirrors the client scoreColor/scoreTier exactly.
// Primary label is the tier name only (no negative wording); scoreTierDetail() is the
// executive interpretation, surfaced as a tooltip/caption rather than printed on the gauge.
// 81–100 Optimized (blue) · 61–80 Advanced (green) · 31–60 Managed (orange) · 0–30 Foundational (red)
function scoreTierColor(p){return p>=81?'#3b82f6':p>=61?'#22c55e':p>=31?'#f59e0b':'#ef4444';}
function scoreTier(p){return p>=81?'Optimized':p>=61?'Advanced':p>=31?'Managed':'Foundational';}
function scoreTierDetail(p){return p>=81?'Mature cloud security posture with proactive risk management and continuous improvement':p>=61?'Security posture is strong with effective controls and manageable residual risk':p>=31?'Core controls are established, but security gaps and optimization opportunities remain':'Security controls are immature; significant exposure and remediation priorities exist';}

// Server-side scoring — mirrors client calcGlobalScoreFromCsp / calcCspScore exactly.
// Shared by both report builders (MultiCloud + per-cloud CSPM score gauges).
function computeCspScores(data) {
  function cspOfAlert(r) {
    const t = ((r.alertType||'')+(r.alertName||'')).toUpperCase();
    if (t.includes('AWS')||t.includes('CLOUDTRAIL')||t.includes('EC2')||t.includes('S3')) return 'aws';
    if (t.includes('AZURE')||t.includes('AZ_')) return 'azure';
    if (t.includes('GCP')||t.includes('GOOGLE')||t.includes('GKE')) return 'gcp';
    return null;
  }
  function cspOfIdentity(r) {
    const p = ((r.PROVIDER_TYPE||r.CLOUD_PROVIDER||'')).toUpperCase();
    if (p.includes('AWS')) return 'aws';
    if (p.includes('AZURE')) return 'azure';
    if (p.includes('GCP')||p.includes('GOOGLE')) return 'gcp';
    return null;
  }
  function calcCspScore(csp) {
    let C=0, H=0, M=0, L=0;
    const findings = [];
    (data.alerts||[]).filter(r=>cspOfAlert(r)===csp).forEach(r=>{
      const s=(r.severity||'').toLowerCase();
      let weight;
      if(s==='critical'){C++;weight='Critical';}else if(s==='high'){H++;weight='High';}else{M++;weight='Medium';}
      findings.push({ type:'Alert', title: r.alertName||r.alertType||'—', weight, rawSeverity: r.severity||'—' });
    });
    (data.compliance||[]).filter(r=>(r.cloud||'')===csp).forEach(r=>{
      const s=(r.severity||'').toLowerCase();
      let weight;
      if(s==='critical'){C++;weight='Critical';}else{H++;weight='High';}
      findings.push({ type:'Misconfiguration', title: r.title||'—', weight, rawSeverity: r.severity||'—' });
    });
    (data.identities||[]).filter(r=>cspOfIdentity(r)===csp).forEach(r=>{
      const score=identityRiskScore(r);
      let weight;
      if(score>=80){C++;weight='Critical';}else if(score>=50){H++;weight='High';}else if(score>=20){M++;weight='Medium';}else{L++;weight='Low';}
      const label = r.NAME || (r.PRINCIPAL_ID||'').split('/').pop() || r.PRINCIPAL_ID || '—';
      findings.push({ type:'Identity', title: label, weight, rawSeverity: (r.METRICS&&r.METRICS.risk_severity)||'—' });
    });
    const total = C+H+M+L;
    if(total===0) return { score: null, findings: [] };
    // Rate-based: each bucket's share of this cloud's total findings, not raw counts —
    // see calcCspScore() client-side for the full rationale.
    const penalty = 40*(C/total)+30*(H/total)+20*(M/total)+10*(L/total);
    const score = Math.max(0, Math.round(100-penalty));
    return { score, findings, counts: { C, H, M, L } };
  }
  const awsCalc = calcCspScore('aws'), azureCalc = calcCspScore('azure'), gcpCalc = calcCspScore('gcp');
  const cspScores   = { aws: awsCalc.score, azure: azureCalc.score, gcp: gcpCalc.score };
  const cspFindings = { aws: awsCalc.findings, azure: azureCalc.findings, gcp: gcpCalc.findings };
  const cspCounts   = { aws: awsCalc.counts, azure: azureCalc.counts, gcp: gcpCalc.counts };
  const cspVals   = ['aws','azure','gcp'].map(c => cspScores[c] !== null ? cspScores[c] : 100);
  const score     = Math.round(cspVals.reduce((s,v)=>s+v,0)/cspVals.length);
  const sBand     = scoreTier(score);
  const sColor    = scoreTierColor(score);
  const sDetail   = scoreTierDetail(score);
  return { cspScores, cspFindings, cspCounts, score, sBand, sColor, sDetail };
}

// Shared TOC card renderer — big colored count + category color-coding so the
// "Discovered Risk Findings" contents pop, instead of uniform small-text cards.
function tocCardHtml(href, count, color, numLabel, title, sub) {
  return '<a href="'+href+'" class="toc-card" style="border-top-color:'+color+'">' +
    '<div class="tc-num">'+numLabel+'</div>' +
    '<div class="tc-count" style="color:'+color+'">'+count+'</div>' +
    '<div class="tc-title">'+title+'</div>' +
    '<div class="tc-sub">'+sub+'</div>' +
  '</a>';
}

// Simplified dashboard tile — just a big number + short two-line label, no eyebrow/
// subtitle text. Used by report2's "Critical Risk Findings" summary grid, which needs
// to read at a glance rather than double as a table of contents like tocCardHtml above.
function dashboardTileHtml(href, count, color, label) {
  return '<a href="'+href+'" class="dash-tile">' +
    '<div class="dt-count" style="color:'+color+'">'+count+'</div>' +
    '<div class="dt-label">'+label+'</div>' +
  '</a>';
}

function assetRiskTier(score, exposed) {
  if (score >= 75) return exposed ? { label: 'CRITICAL', color: '#DA291C' } : { label: 'MEDIUM', color: '#B7770D' };
  if (score >= 50) return exposed ? { label: 'HIGH', color: '#CC4A1A' } : { label: 'LOW', color: '#5A5A5A' };
  if (score >= 30) return { label: 'MEDIUM', color: '#B7770D' };
  return { label: 'LOW', color: '#5A5A5A' };
}

// Shared "Exploit Simulation Layer" attack-path diagram — dark "Deep Space" hex-panel
// style, left-to-right: Attacker -> Network boundary -> Risk-factor nodes (1-5, fanned
// vertically) -> Target. One canonical definition: called directly here (Node, PDF
// report) and embedded byte-identical into the client <script> via
// hexKillChainSvg.toString() (see buildHtml()). Must stay a pure function of `spec` —
// no DOM, no fetch, no closures over anything outside its own parameters — or the
// client embed silently breaks.
// See docs/superpowers/specs/2026-07-16-exploit-simulation-diagram-revamp-design.md
function hexKillChainSvg(spec) {
  function hexPoints(cx, cy, w, h) {
    var half = w / 2, tip = h * 0.3;
    return [
      [cx - half, cy],
      [cx - half + tip, cy - h / 2],
      [cx + half - tip, cy - h / 2],
      [cx + half, cy],
      [cx + half - tip, cy + h / 2],
      [cx - half + tip, cy + h / 2],
    ].map(function (p) { return p[0] + ',' + p[1]; }).join(' ');
  }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

  var attacker = spec.attacker || { label: 'ATTACKER', color: '#ff5e3a' };
  var network  = spec.network  || { label: 'Internet', color: '#3b82f6' };
  var factors  = spec.factors  || [];
  var target   = spec.target   || { label: 'TARGET', tier: 'LOW', tierColor: '#3b82f6' };
  var lineColor = spec.lineColor || attacker.color;
  var animate  = spec.animate !== false;

  var n = Math.max(1, factors.length);
  var W = 1000;
  var H = Math.max(340, n * 108 + 90);
  var CY = H / 2;
  var AX = 90, NX = 300, FX = 620, TX = 900;
  var AW = 108, AH = 68;
  var FW = 168, FH = 78;
  var TW = 150, TH = 96;
  var NR = 56;
  var spacing = 108;

  var fy = [];
  for (var i = 0; i < n; i++) fy.push(CY + (i - (n - 1) / 2) * spacing);

  // Must be unique per call, not just per shape: the Global diagram, each per-CSP tab, and
  // the per-host Attack Path modal can all have SVGs sitting in the DOM at once (inactive
  // tabs/panels are hidden via CSS, not removed). Two diagrams with the same factor count
  // produced the same id here before, so their <defs> (gradient/filter) collided — the
  // browser resolves url(#id) against whichever element it finds first in document order,
  // silently breaking the fill/drop-shadow on the other one. A running counter guarantees
  // every call gets its own id regardless of shape.
  hexKillChainSvg._seq = (hexKillChainSvg._seq || 0) + 1;
  var sid = 'hkc' + hexKillChainSvg._seq.toString(36);

  var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet" ' +
    'style="width:100%;display:block;font-family:-apple-system,BlinkMacSystemFont,sans-serif" ' +
    'xmlns="http://www.w3.org/2000/svg">';

  svg += '<defs>' +
    '<radialGradient id="' + sid + 'bg" cx="30%" cy="35%" r="85%">' +
    '<stop offset="0%" stop-color="#101c3d"/><stop offset="100%" stop-color="#050914"/>' +
    '</radialGradient>' +
    '<filter id="' + sid + 'd" x="-40%" y="-40%" width="180%" height="180%">' +
    '<feDropShadow dx="0" dy="3" stdDeviation="7" flood-color="rgba(0,0,0,.45)"/>' +
    '</filter>' +
    '</defs>';

  svg += '<rect x="0" y="0" width="' + W + '" height="' + H + '" fill="url(#' + sid + 'bg)"/>';

  svg += '<g stroke="rgba(148,163,184,.08)" stroke-width="1">';
  for (var gx = 0; gx <= W; gx += 50) svg += '<line x1="' + gx + '" y1="0" x2="' + gx + '" y2="' + H + '"/>';
  svg += '</g>';

  svg += '<rect x="0" y="0" width="' + (NX - 40) + '" height="' + H + '" fill="' + attacker.color + '" opacity=".05"/>';
  svg += '<rect x="' + (NX - 40) + '" y="0" width="' + (FX - NX - 20) + '" height="' + H + '" fill="' + network.color + '" opacity=".04"/>';
  svg += '<rect x="' + (FX - 20) + '" y="0" width="' + (TX - FX) + '" height="' + H + '" fill="#94a3b8" opacity=".04"/>';
  svg += '<rect x="' + TX + '" y="0" width="' + (W - TX) + '" height="' + H + '" fill="' + target.tierColor + '" opacity=".06"/>';

  var dash = animate ? ' stroke-dasharray="6 14"' : '';
  function animAttr(delay) { return animate ? ' style="animation:path-flow 1.1s linear infinite ' + delay + 's"' : ''; }

  svg += '<g stroke="' + lineColor + '" stroke-width="2.5" stroke-linecap="round" fill="none"' + dash + '>';
  svg += '<line x1="' + (AX + AW / 2) + '" y1="' + CY + '" x2="' + (NX - NR) + '" y2="' + CY + '"' + animAttr(0) + '/>';
  for (var j = 0; j < n; j++) {
    svg += '<line x1="' + (NX + NR) + '" y1="' + CY + '" x2="' + (FX - FW / 2) + '" y2="' + fy[j] + '"' + animAttr(0.15 * j) + '/>';
    svg += '<line x1="' + (FX + FW / 2) + '" y1="' + fy[j] + '" x2="' + (TX - TW / 2) + '" y2="' + CY + '"' + animAttr(0.15 * j + 0.3) + '/>';
  }
  svg += '</g>';

  svg += '<polygon points="' + hexPoints(AX, CY, AW, AH) + '" fill="' + attacker.color + '" filter="url(#' + sid + 'd)"/>';
  svg += '<text x="' + AX + '" y="' + (CY + AH / 2 + 16) + '" text-anchor="middle" font-size="9" font-weight="700" fill="#cbd5e1" letter-spacing="1.5">' + esc(attacker.label) + '</text>';

  svg += '<circle cx="' + NX + '" cy="' + CY + '" r="' + NR + '" fill="rgba(59,130,246,.08)" stroke="' + network.color + '" stroke-width="2" stroke-dasharray="9 5"/>';
  svg += '<text x="' + NX + '" y="' + (CY + 5) + '" text-anchor="middle" font-size="13" fill="' + network.color + '" font-style="italic" font-family="Georgia,serif">' + esc(network.label) + '</text>';

  factors.forEach(function (f, idx) {
    var navAttr = f.nav ? ' class="hg-nav-node" data-nav="' + esc(f.nav) + '" style="cursor:pointer"' : '';
    svg += '<polygon points="' + hexPoints(FX, fy[idx], FW, FH) + '" fill="' + f.color + '" filter="url(#' + sid + 'd)"' + navAttr + '>';
    if (f.tooltip) svg += '<title>' + esc(f.tooltip) + '</title>';
    svg += '</polygon>';
    svg += '<text x="' + FX + '" y="' + (fy[idx] - 8) + '" text-anchor="middle" font-size="10" font-weight="700" fill="white" style="pointer-events:none">' + esc(f.label) + '</text>';
    svg += '<text x="' + FX + '" y="' + (fy[idx] + 20) + '" text-anchor="middle" font-size="24" font-weight="900" fill="white" style="pointer-events:none">' + f.count + '</text>';
    if (f.mitre) {
      svg += '<text x="' + FX + '" y="' + (fy[idx] + FH / 2 + 16) + '" text-anchor="middle" font-size="7.5" font-weight="700" fill="' + (f.mitre.c || '#94a3b8') + '" opacity=".85" letter-spacing=".04em">' + esc(f.mitre.tactic) + ' &middot; ' + esc(f.mitre.id) + '</text>';
    }
    if (f.badge) {
      svg += '<circle cx="' + (FX + FW / 2 - 10) + '" cy="' + (fy[idx] - FH / 2 + 8) + '" r="9" fill="#FCD34D"/>';
      svg += '<text x="' + (FX + FW / 2 - 10) + '" y="' + (fy[idx] - FH / 2 + 12) + '" text-anchor="middle" font-size="11" font-weight="900" fill="#92400E" style="pointer-events:none">!</text>';
    }
  });

  svg += '<polygon points="' + hexPoints(TX, CY, TW, TH) + '" fill="' + target.tierColor + '" filter="url(#' + sid + 'd)">';
  if (target.tooltip) svg += '<title>' + esc(target.tooltip) + '</title>';
  svg += '</polygon>';
  // Label sits near the hex's tapered top edge (narrowest point), so a long string can
  // overflow past the polygon's slanted sides even after the ~20-char truncation callers
  // already do — textLength/lengthAdjust forces it to fit within a safe width regardless
  // of exact character count, instead of guessing per-string truncation lengths.
  var targetLabelAttrs = (target.label && target.label.length > 12) ? ' textLength="100" lengthAdjust="spacingAndGlyphs"' : '';
  svg += '<text x="' + TX + '" y="' + (CY - TH / 2 + 22) + '" text-anchor="middle" font-size="10" font-weight="700" fill="white"' + targetLabelAttrs + '>' + esc(target.label) + '</text>';
  if (target.subLabel) svg += '<text id="hg-geo-txt" x="' + TX + '" y="' + CY + '" text-anchor="middle" font-size="8" fill="rgba(255,255,255,.75)" font-style="italic">' + esc(target.subLabel) + '</text>';
  svg += '<text x="' + TX + '" y="' + (CY + TH / 2 - 14) + '" text-anchor="middle" font-size="9" font-weight="800" fill="rgba(255,255,255,.9)" letter-spacing="1.5">' + esc(target.tier) + '</text>';
  if (target.badge) {
    svg += '<circle cx="' + (TX + TW / 2 - 6) + '" cy="' + (CY - TH / 2 + 6) + '" r="11" fill="#FCD34D"/>';
    svg += '<text x="' + (TX + TW / 2 - 6) + '" y="' + (CY - TH / 2 + 11) + '" text-anchor="middle" font-size="13" font-weight="900" fill="#92400E">!</text>';
  }

  svg += '</svg>';
  return svg;
}

// Static SVG risk-breakdown diagram for one host — a simplified stand-in for the
// dashboard's interactive Exploit Graph (which depends on live browser globals + GeoIP).
function hostRiskDiagramSvg(asset, esc) {
  const tier = assetRiskTier(asset.normalizedScore, asset.internetExposed);
  const factors = [];
  if (asset.ciem > 0) factors.push({ label: 'CIEM Credentials', count: Math.round(asset.ciem / 100), color: '#DA291C', mitre: { tactic: 'Credential Access', id: 'T1552', c: '#eab308' }, badge: true });
  if (asset.secretRisk > 0) factors.push({ label: 'Exposed Secrets', count: Math.round(asset.secretRisk / 50), color: '#CC4A1A', mitre: { tactic: 'Credential Access', id: 'T1552', c: '#eab308' }, badge: true });
  if ((asset.vulns || []).length) factors.push({ label: 'CVE Exposure', count: asset.vulns.length, color: '#B7770D', mitre: { tactic: 'Exploitation', id: 'T1203', c: '#f97316' }, badge: true });
  if (asset.miscRisk > 0) factors.push({ label: 'Misconfigurations', count: Math.round(asset.miscRisk / 10), color: '#2C5280', mitre: { tactic: 'Priv. Escalation', id: 'T1078', c: '#8b5cf6' }, badge: true });
  if (!factors.length) factors.push({ label: 'At Risk', count: 1, color: '#6b7280', badge: true });

  const svg = hexKillChainSvg({
    attacker: { label: 'ATTACKER', color: '#ff5e3a' },
    network: { label: asset.internetExposed ? 'Internet' : 'Private Network', color: '#3b82f6' },
    factors,
    target: {
      // Do not pre-escape here — hexKillChainSvg escapes target.label internally;
      // escaping twice would turn "&" into "&amp;amp;" in any hostname containing one.
      label: asset.name.length > 20 ? asset.name.substring(0, 19) + '…' : asset.name,
      tier: tier.label,
      tierColor: tier.color,
      badge: true,
    },
    animate: false,
  });
  return '<div style="font-size:11px;color:#5A5A5A;margin-bottom:6px;font-family:-apple-system,sans-serif">' +
    tier.label + ' RISK TIER &middot; Score ' + asset.normalizedScore + '/100' +
    (asset.internetExposed ? ' &middot; Internet Exposed' : ' &middot; Internal Only') +
    '</div>' + svg;
}

// Converts the last-run Governance Report (named framework, e.g. "CIS AWS Foundations
// Benchmark v1.4") into the same row shape as the ad-hoc Policies-based `compliance`
// array, so both PDF builders can drop it in as a direct replacement. Scoped to
// Medium/High/Critical NonCompliant findings only — same filter as the live panel.
function governanceReportToComplianceRows(gov) {
  if (!gov || !gov.data) return null;
  const reportObj = Array.isArray(gov.data.data) ? (gov.data.data[0] || {}) : (gov.data.data || gov.data || {});
  const allRecs = reportObj.recommendations || reportObj.Recommendations || [];
  if (!Array.isArray(allRecs) || !allRecs.length) return null;
  const SEV_LABEL = { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low', 5: 'Info' };
  const rows = allRecs
    .filter(r => r.STATUS === 'NonCompliant' && r.SEVERITY != null && r.SEVERITY <= 3)
    .map(r => {
      const viol = r.VIOLATIONS || r.violations || [];
      return {
        alertId: r.REC_ID || r.recommendationId || r.id || '',
        cloud: gov.cloud || 'cloud',
        title: r.TITLE || r.title || '—',
        description: (r.CATEGORY || r.category || '') + (gov.frameworkLabel ? ' — ' + gov.frameworkLabel : ''),
        severity: SEV_LABEL[r.SEVERITY] || 'High',
        violations: r.RESOURCE_COUNT != null ? r.RESOURCE_COUNT : (Array.isArray(viol) ? viol.length : 0),
        resources: Array.isArray(viol) ? viol : [],
      };
    });
  return rows.length ? rows : null;
}

function buildReportHtml(data, meta) {
  const customer = ((meta && meta.customer) || 'Customer').trim();
  const author   = ((meta && meta.author)   || 'Fortinet').trim();
  const dateStr  = new Date().toLocaleDateString('en-US', {weekday:'long',year:'numeric',month:'long',day:'numeric'});

  const alerts     = data.alerts     || [];
  // "Critical CVE Vulnerabilities" report section — dashboard-wide fetch already caps at
  // cveRiskScore>=8 (API hard filter), but this section is tighter: only the highest-risk
  // CVEs (>=9) make the customer-facing report.
  const vulns      = (data.vulns || []).filter(r => parseFloat(r.riskScore || 0) >= 9);
  // governanceReportToComplianceRows() can surface Medium-severity recommendations (its
  // own filter allows SEVERITY<=3, i.e. Critical/High/Medium) — this report section is
  // titled "Critical Non-Compliance Findings", so narrow to Critical/High only here,
  // regardless of which source (generic scan vs. named governance framework) produced it.
  const compliance = (governanceReportToComplianceRows(lastGovernanceReport) || data.compliance || [])
    .filter(r => ['critical','high'].includes((r.severity || '').toLowerCase()));
  const secrets    = data.secrets    || [];
  const secretsAll = data.secretsAll || [];

  // Identity Risk report filter — every Cloud User (not role/service account) that is
  // both High Privilege (full admin, can self-escalate, or holds excessive grants) AND
  // has no MFA. Matches the dashboard's own Identity & Access Risk definition rather than
  // the old narrower "literally named admin + ≥90% unused entitlements" rule.
  const identities = (data.identities || []).filter(function(r) {
    const pid = (r.PRINCIPAL_ID || '').toLowerCase();
    const pt  = (r.PROVIDER_TYPE || '').toLowerCase();
    const isRoleOrService = pid.includes(':role/') || pid.includes(':assumed-role/') ||
      pid.includes('serviceaccount') || pid.includes('.iam.gserviceaccount.com') ||
      pt.includes('serviceprincipal') || pt.includes('role');
    const isCloudUser = !isRoleOrService;

    const risks = (r.METRICS && r.METRICS.risks) || [];
    const isHighPriv = risks.includes('ALLOWS_FULL_ADMIN') || risks.includes('ALLOWS_PRIVILEGE_ESCALATION') || risks.includes('EXCESSIVE_PERMISSIONS');
    const noMfa = risks.includes('PASSWORD_LOGIN_NO_MFA') || risks.includes('AWS_ROOT_USER_PASSWORD_LOGIN_NO_MFA');

    return isCloudUser && isHighPriv && noMfa;
  });
  // Cloud classification for grouping — same PROVIDER_TYPE heuristic used dashboard-wide.
  function cspOfIdentity(r) {
    const p = (r.PROVIDER_TYPE || r.CLOUD_PROVIDER || '').toUpperCase();
    if (p.includes('AWS')) return 'aws';
    if (p.includes('AZURE')) return 'azure';
    if (p.includes('GCP') || p.includes('GOOGLE')) return 'gcp';
    return 'other';
  }

  // Server-side scoring — mirrors client calcGlobalScoreFromCsp / calcCspScore exactly
  const { cspScores, score, sBand, sColor, sDetail } = computeCspScores(data);
  const total  = alerts.length + vulns.length + compliance.length + identities.length;

  // Helpers
  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function fmt(ts) {
    if (!ts) return '—';
    try { return new Date(ts).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); } catch(_) { return String(ts); }
  }
  function sevBadge(s) {
    const m = {critical:'badge-critical',high:'badge-high',medium:'badge-medium',low:'badge-low'};
    const cls = m[(s||'').toLowerCase()] || 'badge-info';
    return '<span class="badge '+cls+'">'+esc(s||'—')+'</span>';
  }
  function cspBadge(c) {
    const m = {aws:'badge-aws',azure:'badge-azure',gcp:'badge-gcp'};
    const cls = m[(c||'').toLowerCase()] || 'badge-info';
    return '<span class="badge '+cls+'">'+esc((c||'').toUpperCase()||'—')+'</span>';
  }

  // ── Alerts rows
  const alertRows = alerts.length ? alerts.map(function(r,i) {
    const desc = ((r.alertInfo && r.alertInfo.description)||'').replace(/\s+/g,' ').slice(0,200);
    const timeStr = r.startTime ? new Date(r.startTime).toLocaleString('en-US',{month:'long',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}) : '—';
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td><small class="text-muted">'+esc(r.alertId||'—')+'</small></td>'+
      '<td><span class="badge badge-critical">Critical</span></td>'+
      '<td class="wide"><strong>'+esc(r.alertName||'—')+'</strong></td>'+
      '<td class="med"><small class="text-muted">'+esc(r.alertType||'—')+'</small></td>'+
      '<td><small>'+esc(timeStr)+'</small></td>'+
      '<td><span class="badge badge-critical" title="Attacker activity">Malicious</span></td>'+
      '<td class="wide">'+esc(desc||'—')+'</td>'+
      '<td class="wide">This alert indicates anomalous behavior that may represent an active security incident or policy violation.</td>'+
      '<td class="wide">Investigate the alert in FortiCNAPP; correlate with cloud activity logs; escalate if the activity is unauthorized.</td>'+
      '</tr>';
  }).join('') : '<tr><td colspan="10" style="text-align:center;color:#999;padding:1.5rem">No critical alerts</td></tr>';

  // ── Vuln rows grouped by host, with Internet Exposure badge per host ─────────
  function vulnRowCells(r, i) {
    const rs  = parseFloat(r.riskScore||0);
    const pkg = (r.featureKey && r.featureKey.name) || '—';
    const ver = (r.featureKey && r.featureKey.version) || '';
    const fixVer = (r.fixInfo && r.fixInfo.fixed_version) || '';
    const fixAvailable = r.fixInfo && (r.fixInfo.fix_available === true || String(r.fixInfo.fix_available) === '1');
    const fixVerCell = fixVer ? '<strong>'+esc(fixVer)+'</strong>' :
                        fixAvailable ? '<span class="text-muted">Available — see vendor advisory</span>' :
                        '<span class="text-muted">No fix available</span>';
    const fixCell = fixVer ? 'Update <strong>'+esc(pkg)+'</strong> to '+esc(fixVer) :
                    fixAvailable ? 'Vendor fix available — apply immediately' : 'No fix available yet — apply mitigating controls';
    const outcome = rs >= 10
      ? 'Full system compromise enabling ransomware deployment, data exfiltration, or lateral movement.'
      : 'Remote code execution enabling host compromise, data exfiltration, or privilege escalation.';
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td><span class="badge badge-critical">Critical</span></td>'+
      '<td><strong>'+esc(r.vulnId||r.cveId||'—')+'</strong><br><small class="text-muted">'+esc((r.evalCtx&&r.evalCtx.imageId)?'Container':'Host')+'</small></td>'+
      '<td style="text-align:center"><span class="risk-chip'+(rs<10?' high':'')+'">'+rs.toFixed(1)+'</span></td>'+
      '<td class="med"><strong>'+esc(pkg)+'</strong>'+(ver?'<br><small class="text-muted">'+esc(ver)+'</small>':'')+'</td>'+
      '<td class="med">'+fixVerCell+'</td>'+
      '<td class="wide">'+esc(outcome)+'</td>'+
      '<td class="med">'+fixCell+'</td>'+
      '<td><span class="badge badge-critical">Immediate</span></td>'+
      '</tr>';
  }

  const { hosts: vulnHosts } = groupVulnsByHost(vulns);
  // Exposed/Internal host counts reflect the FULL vuln population the server fetched
  // (riskScore>=8, the API's own cap), not just the >=9 subset used for the CVE listing
  // below — otherwise a host that's genuinely internet-exposed but has no single CVE
  // scoring >=9 right now would silently disappear from "how many hosts are exposed"
  // instead of just having no CVEs listed under it.
  const { exposedCount: exposedHostCount, internalCount: internalHostCount } = groupVulnsByHost(data.vulns || []);

  const vulnHostGroups = vulnHosts.map(function(h) {
    const critCnt = h.rows.filter(function(r){ return parseFloat(r.riskScore||0) >= 10; }).length;
    const badge = h.exposed
      ? '<span class="badge badge-critical">&#9889; Internet Exposed</span>'
      : '<span class="badge badge-info">Internal Only</span>';
    return '<div class="host-group'+(h.exposed?' exposed':'')+'">' +
      '<div class="host-group-header">' +
        '<span class="host-name">'+esc(h.name)+'</span>' +
        badge +
        (h.pubIp ? '<span class="host-ip">'+esc(h.pubIp)+'</span>' : '') +
        '<span class="host-cve-count">'+h.rows.length+' CVE'+(h.rows.length===1?'':'s')+(critCnt?' &middot; '+critCnt+' Risk Score ≥ 10.0':'')+'</span>' +
      '</div>' +
      '<table class="exec-table"><thead><tr>' +
      '<th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:140px">Vulnerability (CVE)</th>' +
      '<th style="width:60px">Risk Score</th><th style="width:130px">Package / Version</th>' +
      '<th style="width:110px">Fixed Version</th>' +
      '<th style="width:190px">Attacker Outcome if Exploited</th>' +
      '<th style="width:130px">Recommended Fix</th><th style="width:65px">Priority</th>' +
      '</tr></thead><tbody>'+h.rows.map(vulnRowCells).join('')+'</tbody></table>' +
    '</div>';
  }).join('');

  // ── Compliance rows, grouped by resource type (EC2, S3, Azure VM, ...) ──────
  // Title-keyword fallback only — used when a finding's own resources don't carry a
  // recognizable SERVICE/RESOURCE_TYPE (e.g. account-wide checks with no resource rows).
  function compServiceArea(title) {
    const t = (title||'').toLowerCase();
    if (/mfa|multi.factor|authenticat|iam|identity|access|password/.test(t)) return 'Identity &amp; Access';
    if (/encrypt|kms|key|tls|ssl/.test(t)) return 'Data Protection';
    if (/s3|bucket|storage|object/.test(t)) return 'Storage Security';
    if (/network|vpc|sg|security.group|firewall|port/.test(t)) return 'Network Security';
    if (/log|audit|trail|monitor|cloudtrail/.test(t)) return 'Logging &amp; Audit';
    if (/backup|snapshot|recovery/.test(t)) return 'Resilience';
    return 'Cloud Security';
  }
  // Real resource-type categorization — reads SERVICE/RESOURCE_TYPE straight off the
  // finding's own violating resources (e.g. "ec2:security-group", "s3:bucket",
  // "microsoft.storage/storageaccounts", "compute.googleapis.com/Instance") instead of
  // guessing from the policy title. Falls back to compServiceArea() when a finding has
  // no resource rows or an unrecognized type (e.g. account-wide/organization checks).
  const AWS_SVC_LABELS = { ec2:'EC2', s3:'S3', iam:'IAM', rds:'RDS', kms:'KMS', lambda:'Lambda', cloudtrail:'CloudTrail', vpc:'VPC', eks:'EKS', ecs:'ECS', dynamodb:'DynamoDB', sns:'SNS', sqs:'SQS', elasticloadbalancing:'ELB', cloudfront:'CloudFront', route53:'Route 53', redshift:'Redshift', efs:'EFS', ecr:'ECR', secretsmanager:'Secrets Manager', apigateway:'API Gateway', autoscaling:'Auto Scaling', config:'AWS Config', guardduty:'GuardDuty', cloudwatch:'CloudWatch', organizations:'Organizations' };
  const AZURE_SVC_LABELS = { compute:'Azure VM', storage:'Storage Account', network:'Network', keyvault:'Key Vault', sql:'Azure SQL', recoveryservices:'Recovery Services', authorization:'IAM (Azure AD)', web:'App Service', containerservice:'AKS', security:'Security Center', insights:'Monitor', dbforpostgresql:'PostgreSQL', dbformysql:'MySQL', documentdb:'Cosmos DB' };
  const GCP_SVC_LABELS = { compute:'Compute Engine', storage:'Cloud Storage', iam:'IAM', container:'GKE', sqladmin:'Cloud SQL', bigquery:'BigQuery' };
  function compResourceCategory(r) {
    const r0 = (Array.isArray(r.resources) && r.resources[0]) || {};
    const rt = String(r0.RESOURCE_TYPE || '').toLowerCase();
    const svc = String(r0.SERVICE || '').toLowerCase();
    if (rt.includes(':')) {                        // AWS: "ec2:security-group"
      const service = rt.split(':')[0];
      return AWS_SVC_LABELS[service] || service.toUpperCase();
    }
    if (rt.startsWith('microsoft.')) {              // Azure: "microsoft.compute/virtualmachines"
      const provider = rt.split('/')[0].replace('microsoft.', '');
      return AZURE_SVC_LABELS[provider] || (provider.charAt(0).toUpperCase() + provider.slice(1));
    }
    if (rt.includes('.googleapis.com')) {           // GCP: "compute.googleapis.com/Instance"
      const service = rt.split('.')[0];
      return GCP_SVC_LABELS[service] || service.toUpperCase();
    }
    if (svc && svc !== 'resource-graph') return GCP_SVC_LABELS[svc] || AWS_SVC_LABELS[svc] || svc.toUpperCase();
    return compServiceArea(r.title);
  }
  function compRowHtml(r, i) {
    const isCrit = (r.severity||'').toLowerCase()==='critical';
    const bg = isCrit ? ' style="background:#FDECEA;"' : (i%2===1?' style="background:#FAFAFA;"':'');
    const ctxRisk = 'Misconfigured or non-compliant control expands the attack surface, enabling unauthorized access or data exposure across '+((r.cloud||'cloud').toUpperCase())+' resources.';
    const bizImpact = 'Regulatory non-compliance, potential data breach, audit failure, and reputational risk.';
    const recFix = (r.description||'').slice(0,200) || 'Remediate the control violation per the policy guidance and re-evaluate in FortiCNAPP.';
    const resourceHtml = violatingResourcesHtml(r.resources, esc);
    return '<tr'+bg+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td>'+sevBadge(r.severity)+'</td>'+
      '<td class="wide"><strong>'+esc(r.title||'—')+'</strong>'+resourceHtml+'</td>'+
      '<td class="med">'+cspBadge(r.cloud)+'<br><small class="text-muted">'+esc(r.alertId||'')+'</small></td>'+
      '<td class="wide">'+esc(ctxRisk)+'</td>'+
      '<td class="wide">'+esc(bizImpact)+'</td>'+
      '<td class="wide">'+esc(recFix)+'</td>'+
      '<td><span class="badge badge-critical">Immediate</span></td>'+
      '</tr>';
  }
  const COMP_TABLE_HEAD =
    '<thead><tr>' +
    '<th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:220px">Finding</th>' +
    '<th style="width:120px">Cloud Scope</th>' +
    '<th style="width:190px">Contextual Risk</th><th style="width:190px">Business Impact</th>' +
    '<th style="width:190px">Recommended Fix</th><th style="width:70px">Priority</th>' +
    '</tr></thead>';
  const compByCategory = {};
  compliance.forEach(function(r) {
    const cat = compResourceCategory(r);
    (compByCategory[cat] = compByCategory[cat] || []).push(r);
  });
  const compCategoryGroups = compliance.length ? Object.keys(compByCategory).sort(function(a, b) {
    const d = compByCategory[b].length - compByCategory[a].length;
    return d !== 0 ? d : a.localeCompare(b);
  }).map(function(cat) {
    const rows = compByCategory[cat];
    return '<div class="comp-category-group" style="margin-bottom:22px">' +
      '<div style="padding:6px 0;margin-top:12px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#1A1A1A;border-bottom:2px solid #DA291C">'+esc(cat)+' <span style="font-weight:400;color:#9ca3af">('+rows.length+' finding'+(rows.length===1?'':'s')+')</span></div>' +
      '<table class="exec-table">'+COMP_TABLE_HEAD+'<tbody>'+rows.map(compRowHtml).join('')+'</tbody></table>' +
    '</div>';
  }).join('') : '<p style="text-align:center;color:#999;padding:1.5rem">No compliance findings</p>';

  // ── Identity rows
  function idRowHtml(r, i) {
    const risks   = (r.METRICS && r.METRICS.risks) || [];
    const rs      = (r.METRICS && r.METRICS.risk_score) || 0;
    const isAdmin = risks.includes('ALLOWS_FULL_ADMIN');
    const noMfa   = risks.includes('PASSWORD_LOGIN_NO_MFA') || risks.includes('AWS_ROOT_USER_PASSWORD_LOGIN_NO_MFA');
    const ec = r.ENTITLEMENT_COUNTS || {};
    const unusedCnt = ec.entitlements_unused_count;
    const totalCnt  = ec.entitlements_total_count || ec.entitlements_count;
    const unusedPct = ec.entitlements_unused_percentage;
    const idlePct = unusedPct != null ? Math.round(unusedPct)+'%'
                  : (unusedCnt != null && totalCnt) ? Math.round((unusedCnt/totalCnt)*100)+'%'
                  : '—';
    const privBadge = isAdmin ? '<span class="badge badge-critical">Admin</span>' : '<span class="badge badge-high">Privileged</span>';
    const mfaBadge  = noMfa   ? '<span class="badge badge-mfa-off">No MFA</span>' : '<span class="badge badge-mfa-on">MFA ON</span>';
    const riskNarr  = isAdmin && noMfa
      ? '<strong class="text-critical">CRITICAL:</strong> Full admin with no MFA — single credential theft enables complete environment compromise.'
      : isAdmin
        ? '<strong class="text-critical">HIGH:</strong> Full admin privileges — any compromise allows unrestricted access to all resources.'
        : '<strong class="text-critical">HIGH:</strong> No MFA on privileged account — credential theft risk with no second factor protection.';
    const recFix = isAdmin && noMfa
      ? 'Enforce MFA immediately. Replace standing admin with JIT privilege escalation.'
      : isAdmin
        ? 'Apply least-privilege policy; remove wildcard permissions; audit all actions.'
        : 'Enable MFA immediately; rotate credentials; review recent activity.';
    const bg = rs>0.6 ? ' style="background:#FDECEA;"' : (i%2===1?' style="background:#FAFAFA;"':'');
    return '<tr'+bg+'>'+
      '<td><strong>'+esc(r.NAME||r.PRINCIPAL_ID||'—')+'</strong><br><small class="text-muted">'+esc(r.PRINCIPAL_ID||r.PROVIDER_TYPE||'')+'</small></td>'+
      '<td>'+privBadge+'</td>'+
      '<td>'+mfaBadge+'</td>'+
      '<td>'+(r.LAST_USED_TIME ? fmt(r.LAST_USED_TIME) : '<span class="text-muted">Never / Unknown</span>')+'</td>'+
      '<td style="text-align:center">'+(unusedCnt!=null ? '<strong class="text-critical">'+idlePct+'</strong><br><small class="text-muted">idle</small>' : '—')+'</td>'+
      '<td class="wide">'+riskNarr+'</td>'+
      '<td class="wide">'+esc(recFix)+'</td>'+
      '</tr>';
  }
  const ID_TABLE_HEAD =
    '<thead><tr>' +
    '<th style="width:160px">Identity</th><th style="width:80px">Privilege</th><th style="width:65px">MFA</th>' +
    '<th style="width:130px">Last Login</th><th style="width:100px">Idle Entitlements</th>' +
    '<th style="width:220px">Risk</th><th style="width:180px">Recommended Fix</th>' +
    '</tr></thead>';
  // Grouped per cloud (AWS, then Azure, then GCP — fixed order, not by count) so each
  // cloud's high-privilege, no-MFA users are reviewed as their own block.
  const ID_CLOUD_LABELS = { aws: 'AWS', azure: 'Azure', gcp: 'GCP', other: 'Other' };
  const idByCloud = { aws: [], azure: [], gcp: [], other: [] };
  identities.forEach(function(r) { idByCloud[cspOfIdentity(r)].push(r); });
  const idCategoryGroups = identities.length ? ['aws', 'azure', 'gcp', 'other'].filter(function(csp) {
    return idByCloud[csp].length;
  }).map(function(csp) {
    const rows = idByCloud[csp];
    return '<div class="id-cloud-group" style="margin-bottom:22px">' +
      '<div style="padding:6px 0;margin-top:12px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:#1A1A1A;border-bottom:2px solid #DA291C">'+esc(ID_CLOUD_LABELS[csp])+' <span style="font-weight:400;color:#9ca3af">('+rows.length+' high-privilege user'+(rows.length===1?'':'s')+' &middot; no MFA)</span></div>' +
      '<table class="exec-table">'+ID_TABLE_HEAD+'<tbody>'+rows.map(idRowHtml).join('')+'</tbody></table>' +
    '</div>';
  }).join('') : '<p style="text-align:center;color:#999;padding:1.5rem">No high-privilege, no-MFA cloud users found</p>';

  // ── Recommended Next Steps (mirrors mobile buildSteps logic) ────────────────
  const nextSteps = (function buildNextSteps() {
    const hostRisk = {};
    vulns.forEach(r => { const h=(r.evalCtx&&(r.evalCtx.hostname||r.evalCtx.mid))||''; if(h) hostRisk[h]=(hostRisk[h]||0)+Math.min(100,parseFloat(r.riskScore||0)*10); });
    secretsAll.forEach(r => { const h=r.HOSTNAME||r.MID||''; if(h) hostRisk[h]=(hostRisk[h]||0)+50; });
    const riskVals=Object.values(hostRisk);
    const maxRisk=riskVals.length?Math.max(...riskVals):1;
    const assetCount=riskVals.filter(v=>Math.round(v/maxRisk*100)>20).length;
    const steps=[];
    if(assetCount>=1)   steps.push({color:'#6366f1',title:'Investigate '+assetCount+' asset'+(assetCount===1?'':'s')+' with Correlated Risk Findings',sub:'Hosts with combined CVEs and exposed secrets represent the highest-priority attack surface. Begin remediation here.',action:'Cross-reference CVE and secrets findings by hostname in the CVE and Secrets sections of this report. Prioritise internet-facing hosts.'});
    if(identities.length) steps.push({color:'#ef4444',title:'Fix '+identities.length+' High-Permissive '+(identities.length===1?'Identity':'Identities')+' — Enable MFA & Apply Least Privilege',sub:'Identity compromise is the #1 cloud breach vector. Over-permissive accounts with no MFA are easily weaponised.',action:'Review the Identity Risk section. Enforce MFA on all human identities and apply least-privilege scoping to service accounts.'});
    if(alerts.length)     steps.push({color:'#f97316',title:'Investigate '+alerts.length+' Open Critical Alert'+(alerts.length===1?'':'s'),sub:'Critical alerts may indicate an active breach or ongoing threat. Each alert warrants immediate triage.',action:'Review every alert in the Critical Alerts section. Correlate with cloud activity logs and escalate any confirmed malicious activity.'});
    if(vulns.length)      steps.push({color:'#f59e0b',title:'Patch '+vulns.length+' Critical CVE'+(vulns.length===1?'':'s')+' with Risk Score ≥ 9.0',sub:'Internet-exposed hosts running known critical CVEs are primary targets for automated exploitation.',action:'Prioritise patching on internet-exposed hosts. Review the Critical Vulnerabilities section for affected packages and versions.'});
    if(compliance.length) steps.push({color:'#3b82f6',title:'Remediate '+compliance.length+' Non-Compliant Critical Control'+(compliance.length===1?'':'s'),sub:'Cloud misconfigurations and policy violations create systematic risk that compounds over time.',action:'Review the Compliance section. Focus on controls flagged as Critical first; many can be remediated with a single configuration change.'});
    if(secretsAll.length) steps.push({color:'#0ea5e9',title:'Rotate '+secretsAll.length+' Exposed Secret'+(secretsAll.length===1?'':'s')+' Detected on Hosts',sub:'API keys, tokens and credentials found on hosts must be considered compromised and replaced immediately.',action:'Review the Secrets section. Revoke each exposed credential at the source, re-issue with restricted scope, and audit access logs for misuse.'});
    if(!steps.length)     steps.push({color:'#22c55e',title:'Security Posture is Excellent — Maintain Continuous Monitoring',sub:'No critical findings were detected during this assessment window.',action:'Continue scheduled assessments and ensure alerting is configured for new resources added to the environment.'});
    return steps;
  })();

  const nextStepsSection =
    '<section id="next-steps" class="pagebreak">\n<h2>Exploit Simulation Layer</h2>\n' +
    '<p style="color:#5A5A5A;margin-bottom:24px">The following prioritised actions are derived from the findings in this report. Address them in order — each step reduces your attack surface and improves your Cloud Security Posture Score.</p>' +
    '<table style="width:100%;border-collapse:collapse">' +
    '<thead><tr style="background:#f5f5f5"><th style="padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:#5A5A5A;width:32px">#</th>' +
    '<th style="padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:#5A5A5A">Action</th>' +
    '<th style="padding:10px 14px;text-align:left;font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:#5A5A5A;width:280px">How to Execute</th></tr></thead><tbody>' +
    nextSteps.map((s,i) =>
      '<tr style="border-bottom:1px solid #e5e7eb">' +
      '<td style="padding:14px;vertical-align:top"><div style="width:28px;height:28px;border-radius:50%;background:'+s.color+';color:#fff;font-size:13px;font-weight:800;display:flex;align-items:center;justify-content:center;line-height:1">'+(i+1)+'</div></td>' +
      '<td style="padding:14px;vertical-align:top"><div style="font-size:13px;font-weight:700;color:#1A1A1A;margin-bottom:4px">'+esc(s.title)+'</div><div style="font-size:12px;color:#5A5A5A;line-height:1.5">'+esc(s.sub)+'</div></td>' +
      '<td style="padding:14px;vertical-align:top;font-size:12px;color:#374151;line-height:1.5;border-left:1px solid #e5e7eb">'+esc(s.action)+'</td>' +
      '</tr>'
    ).join('') +
    '</tbody></table>\n</section>';

  // ── Build HTML ──────────────────────────────────────────────────────────────
  const tocCards = [
    alerts.length     ? tocCardHtml('#alerts', alerts.length, '#ef4444', '01 — Alerts', 'Critical Alerts', 'open critical alert'+(alerts.length===1?'':'s')) : '',
    compliance.length ? tocCardHtml('#compliance', compliance.length, '#f59e0b', '02 — Compliance', 'Critical Non-Compliance', 'control failure'+(compliance.length===1?'':'s')) : '',
    vulns.length      ? tocCardHtml('#vulnerabilities', vulns.length, '#f97316', '03 — CVEs', 'Critical Vulnerabilities', 'CVE'+(vulns.length===1?'':'s')+' with risk score ≥ 9') : '',
    identities.length ? tocCardHtml('#identity', identities.length, '#8b5cf6', '04 — Identity', 'Identity Risk', 'identity risk'+(identities.length===1?'':'s')) : '',
    secretsAll.length ? tocCardHtml('#secrets-all', secretsAll.length, '#0ea5e9', '05 — Secrets', 'Secrets Found', 'secret'+(secretsAll.length===1?'':'s')+' detected across hosts') : '',
    tocCardHtml('#next-steps', nextSteps.length, '#6366f1', '06 — Simulation', 'Exploit Simulation Layer', 'prioritised action'+(nextSteps.length===1?'':'s')+' to improve your posture'),
  ].filter(Boolean).join('\n      ');


  const alertSection = alerts.length ? (
    '<section id="alerts" class="pagebreak">\n<h2>1. Critical Alerts</h2>\n' +
    '<table class="exec-table"><thead><tr>' +
    '<th class="narrow">#</th><th style="width:50px">ID</th><th style="width:55px">Severity</th>' +
    '<th style="width:150px">Alert</th><th style="width:100px">Type</th><th style="width:105px">Time</th>' +
    '<th style="width:130px">IP or Domain Reputation</th><th style="width:160px">Description</th>' +
    '<th style="width:150px">Why It Matters</th><th style="width:160px">Recommended Next Action</th>' +
    '</tr></thead><tbody>'+alertRows+'</tbody></table>\n</section>'
  ) : '';

  const compSection = compliance.length ? (
    '<section id="compliance" class="pagebreak">\n<h2>2. Critical Non-Compliance Findings — by Resource Type</h2>\n' +
    compCategoryGroups +
    '\n</section>'
  ) : '';

  const vulnSection = vulns.length ? (
    '<section id="vulnerabilities" class="pagebreak">\n<h2>3. Critical CVE Vulnerabilities — by Host Internet Exposure</h2>\n' +
    '<div class="host-exposure-summary">' +
      '<span class="hes-item exposed"><strong>'+exposedHostCount+'</strong> Internet-Exposed Host'+(exposedHostCount===1?'':'s')+'</span>' +
      '<span class="hes-item"><strong>'+internalHostCount+'</strong> Internal Host'+(internalHostCount===1?'':'s')+'</span>' +
      '<span class="hes-item"><strong>'+vulns.length+'</strong> Total Critical CVE'+(vulns.length===1?'':'s')+'</span>' +
    '</div>\n' +
    vulnHostGroups +
    '\n</section>'
  ) : '';

  const idSection = identities.length ? (
    '<section id="identity" class="pagebreak">\n<h2>4. Identity Risk — High-Privilege Cloud Users Without MFA, by Cloud</h2>\n' +
    idCategoryGroups +
    '\n</section>'
  ) : '';

  const secretsAllRows = secretsAll.length ? secretsAll.map(function(r, i) {
    const lastSeen = r.END_TIME ? new Date(r.END_TIME).toLocaleString('en-US', {month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}) : '—';
    const bg = i % 2 ? ' style="background:#FAFAFA;"' : '';
    return '<tr'+bg+'>' +
      '<td><strong>'+esc(r.HOSTNAME||'—')+'</strong></td>' +
      '<td><small class="text-muted">'+esc(r.MID||'—')+'</small></td>' +
      '<td>'+esc(r.OS||'—')+'</td>' +
      '<td><span class="badge badge-critical">'+esc(r.SECRET_TYPE||'—')+'</span></td>' +
      '<td class="wide"><code style="font-size:0.8rem">'+esc(r.SECRET_IDENTIFIER||'—')+'</code></td>' +
      '<td><small>'+esc(lastSeen)+'</small></td>' +
      '</tr>';
  }).join('') : '';

  const secretsAllSection = secretsAll.length ? (
    '<section id="secrets-all" class="pagebreak">\n<h2>5. Secrets Found</h2>\n' +
    '<table class="exec-table"><thead><tr>' +
    '<th style="width:160px">Hostname</th><th style="width:140px">Instance ID</th>' +
    '<th style="width:80px">OS</th><th style="width:120px">Secret Type</th>' +
    '<th style="width:220px">Secret Identifier</th><th style="width:130px">Last Seen Time</th>' +
    '</tr></thead><tbody>'+secretsAllRows+'</tbody></table>\n</section>'
  ) : '';




  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
  '  <meta charset="UTF-8">\n' +
  '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
  '  <title>Rapid Cloud Assessment – '+esc(customer)+'</title>\n' +
  '  <style type="text/css">\n' + REPORT_CSS + '\n' +
  '  </style>\n</head>\n<body>\n' +
  reportTopbarHtml('Cloud Security Risk Findings') + '\n' +
  '<button type="button" class="pdf-export-btn no-print" onclick="window.print()">&#128196; Export to PDF</button>\n' +
  '<div class="report-cover">\n' +
  '  <div class="report-type">Rapid Cloud Assessment · Cloud Security Risk Findings</div>\n' +
  '  <h1>Cloud Security Posture Report</h1>\n' +
  '  <div class="subtitle">'+esc(customer)+'</div>\n' +
  (function(){
    const arcLen=550, fill=Math.round((score/100)*arcLen);
    function miniGauge(label, p, bgColor) {
      const arcL=314, f=Math.round((p/100)*arcL);
      const c=scoreTierColor(p);
      const band=scoreTier(p).toUpperCase();
      return '<div style="display:flex;flex-direction:column;align-items:center;gap:4px">'+
        '<div style="font-size:9px;font-weight:900;letter-spacing:.12em;padding:3px 10px;border-radius:4px;color:#fff;background:'+bgColor+'">'+label+'</div>'+
        '<svg viewBox="-10 -10 270 155" style="width:130px;overflow:visible">'+
          '<path fill="none" stroke="rgba(255,255,255,0.15)" stroke-width="14" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>'+
          '<path fill="none" stroke="'+c+'" stroke-width="14" stroke-linecap="round" stroke-dasharray="'+f+' '+arcL+'" d="M 25,120 A 100,100 0 0,1 225,120"/>'+
          '<text x="125" y="102" text-anchor="middle" font-size="38" font-weight="900" font-family="-apple-system,sans-serif" fill="'+c+'">'+p+'</text>'+
          '<text x="125" y="118" text-anchor="middle" font-size="9" font-weight="700" font-family="-apple-system,sans-serif" fill="rgba(255,255,255,0.6)" letter-spacing=".05em">'+band+'</text>'+
        '</svg>'+
      '</div>';
    }
    const awsP   = cspScores.aws   !== null ? cspScores.aws   : 100;
    const azureP = cspScores.azure !== null ? cspScores.azure : 100;
    const gcpP   = cspScores.gcp   !== null ? cspScores.gcp   : 100;
    return '  <div style="margin:1rem auto 0;max-width:380px;width:100%">\n'+
      '  <svg viewBox="0 0 400 240" style="display:block;width:100%;overflow:visible">\n'+
      '    <defs><linearGradient id="rg" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">'+
      '<stop offset="0%" stop-color="#ef4444"/>'+
      '<stop offset="20.6%"   stop-color="#ef4444"/>'+
      '<stop offset="20.6%"   stop-color="#f59e0b"/>'+
      '<stop offset="65.45%" stop-color="#f59e0b"/>'+
      '<stop offset="65.45%" stop-color="#22c55e"/>'+
      '<stop offset="90.45%" stop-color="#22c55e"/>'+
      '<stop offset="90.45%" stop-color="#3b82f6"/>'+
      '<stop offset="100%" stop-color="#3b82f6"/>'+
      '</linearGradient></defs>\n'+
      '    <path fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <path fill="none" stroke="url(#rg)" stroke-width="34" stroke-linecap="round" stroke-dasharray="'+fill+' '+arcLen+'" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <line x1="86" y1="48" x2="108" y2="79"   stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="260" y1="20" x2="248" y2="57"  stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="357" y1="91" x2="326" y2="113" stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <text x="200" y="165" text-anchor="middle" font-size="72" font-weight="900" letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="white">'+score+'</text>\n'+
      '    <text x="-8" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">0</text>\n'+
      '    <text x="408" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">100</text>\n'+
      '  </svg>\n'+
      '  <div style="text-align:center;font-size:.82rem;font-weight:700;letter-spacing:.08em;color:white;margin-top:2px;text-transform:uppercase">'+esc(sBand)+'</div>\n'+
      '  <div style="text-align:center;font-size:.68rem;font-weight:600;letter-spacing:.1em;color:rgba(255,255,255,0.75);margin-top:6px">'+esc(sDetail)+'</div>\n'+
      '  <div style="text-align:center;font-size:.68rem;font-weight:600;letter-spacing:.1em;color:rgba(255,255,255,0.55);margin-top:6px;text-transform:uppercase">The objective is to achieve <span style="color:#3b82f6;font-weight:800">Optimized</span></div>\n'+
      '  </div>\n';
  })()+
  '  <div class="meta-row">\n' +
  '    <div class="meta-item"><strong>Prepared For</strong>'+esc(customer)+'</div>\n' +
  '    <div class="meta-item"><strong>Report Date</strong>'+dateStr+'</div>\n' +
  '    <div class="meta-item"><strong>Author</strong>'+esc(author)+'</div>\n' +
  '    <div class="meta-item"><strong>Classification</strong>Confidential</div>\n' +
  '  </div>\n</div>\n' +
  '<div class="toc"><h3>Discovered Risk Findings</h3><div class="toc-cards">\n      '+tocCards+'\n</div></div>\n' +
  (function(){
    const awsP   = cspScores.aws   !== null ? cspScores.aws   : 100;
    const azureP = cspScores.azure !== null ? cspScores.azure : 100;
    const gcpP   = cspScores.gcp   !== null ? cspScores.gcp   : 100;
    function bigGauge(label, bgColor, logoSvg, p){
      const arcL=314, f=Math.round((p/100)*arcL);
      const c=scoreTierColor(p), band=scoreTier(p);
      return '<div style="display:flex;flex-direction:column;align-items:center;gap:8px;flex:1;min-width:200px">'+
        '<div style="display:flex;align-items:center;justify-content:center;gap:8px;height:34px;padding:0 18px;border-radius:999px;color:#fff;background:'+bgColor+'">'+
          '<span style="display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;flex-shrink:0">'+logoSvg+'</span>'+
          '<span style="font-size:13px;font-weight:900;letter-spacing:.1em;line-height:1">'+label+'</span>'+
        '</div>'+
        '<svg viewBox="-10 -10 270 160" style="width:200px;overflow:visible">'+
          '<path fill="none" stroke="#e2e8f0" stroke-width="18" stroke-linecap="round" d="M 25,130 A 100,100 0 0,1 225,130"/>'+
          '<path fill="none" stroke="'+c+'" stroke-width="18" stroke-linecap="round" stroke-dasharray="'+f+' '+arcL+'" d="M 25,130 A 100,100 0 0,1 225,130"/>'+
          '<text x="125" y="108" text-anchor="middle" font-size="52" font-weight="900" font-family="-apple-system,Inter,sans-serif" fill="'+c+'">'+p+'</text>'+
          '<text x="125" y="128" text-anchor="middle" font-size="10" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="#64748b" letter-spacing=".08em">'+band.toUpperCase()+'</text>'+
        '</svg>'+
        '<div style="text-align:center;font-size:11px;color:#64748b;margin-top:-4px">CSPM Security Score — <span style="color:'+c+';font-weight:700">'+p+'/100</span></div>'+
      '</div>';
    }
    const awsLogo='<svg viewBox="0 0 24 14" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><path fill="#FF9900" d="M6.76 5.52c0 .28.03.5.08.66.06.16.14.33.25.51.04.06.05.12.05.17 0 .08-.05.15-.15.23l-.5.33c-.07.05-.14.07-.2.07-.08 0-.16-.04-.24-.11a2.5 2.5 0 01-.29-.38 6.3 6.3 0 01-.25-.47c-.63.74-1.42 1.11-2.37 1.11-.68 0-1.22-.19-1.61-.58-.39-.38-.59-.89-.59-1.52 0-.67.24-1.22.72-1.62.48-.4 1.12-.6 1.93-.6.27 0 .54.02.83.07.29.04.58.11.89.19v-.56c0-.58-.12-1-.37-1.23-.25-.24-.67-.35-1.27-.35-.27 0-.55.03-.84.1-.29.06-.57.15-.85.27-.13.06-.22.09-.28.1-.06.02-.1.03-.13.03-.12 0-.17-.08-.17-.25v-.4c0-.13.02-.23.06-.29.04-.06.12-.12.24-.18.27-.14.6-.26.98-.35.38-.1.79-.14 1.22-.14.93 0 1.61.21 2.05.63.43.42.65 1.06.65 1.92v2.54zm-3.27 1.22c.26 0 .53-.05.81-.14.28-.1.53-.27.74-.51.13-.15.22-.32.27-.51.05-.2.08-.43.08-.7v-.34a6.7 6.7 0 00-.72-.13 5.9 5.9 0 00-.74-.05c-.52 0-.9.1-1.16.31-.25.21-.38.5-.38.89 0 .36.09.63.28.81.18.19.44.27.82.27zm6.25.84c-.14 0-.24-.02-.3-.07-.07-.04-.12-.14-.17-.28L7.4 2.6c-.05-.15-.07-.25-.07-.3 0-.12.06-.18.18-.18h.73c.15 0 .25.02.31.07.06.04.11.14.16.28l1.36 5.36 1.26-5.36c.04-.15.09-.24.15-.28.06-.05.17-.07.31-.07h.6c.15 0 .25.02.31.07.06.04.12.14.15.28l1.28 5.43 1.4-5.43c.05-.15.1-.24.16-.28.06-.05.16-.07.3-.07h.7c.12 0 .18.06.18.18 0 .04-.01.08-.02.13l-.03.17-1.85 6.63c-.05.15-.1.24-.17.28-.06.05-.16.07-.3.07h-.64c-.15 0-.25-.02-.31-.07-.06-.05-.12-.15-.15-.29L12.2 3.32l-1.25 5.11c-.04.15-.09.24-.15.29-.06.05-.17.07-.31.07h-.65zm9.94.18c-.4 0-.8-.05-1.18-.14-.38-.1-.68-.2-.88-.32-.12-.07-.2-.15-.23-.22a.56.56 0 01-.05-.22v-.41c0-.17.06-.25.18-.25.05 0 .1.01.15.03.05.02.12.05.2.09.27.12.57.21.89.28.32.06.63.1.95.1.5 0 .9-.09 1.17-.26.27-.18.41-.43.41-.76 0-.22-.07-.41-.21-.56-.14-.15-.41-.29-.8-.41l-1.14-.35c-.58-.18-1-.45-1.27-.8a1.9 1.9 0 01-.4-1.17c0-.34.07-.64.22-.9.15-.26.35-.49.6-.67.25-.19.53-.33.86-.43.33-.1.68-.14 1.04-.14.18 0 .37.01.55.04.19.02.36.06.53.1.16.04.32.09.46.14.15.06.26.11.34.17.11.07.19.15.23.22.04.07.06.16.06.28v.38c0 .17-.06.26-.18.26-.06 0-.16-.03-.29-.1-.44-.2-.93-.3-1.48-.3-.46 0-.82.08-1.07.23-.25.15-.38.38-.38.7 0 .23.08.43.23.58.15.15.44.3.86.43l1.12.35c.57.18.98.43 1.23.76.25.33.37.7.37 1.12 0 .35-.07.66-.2.94-.14.28-.33.52-.58.72-.25.2-.55.35-.9.46-.36.1-.75.16-1.17.16z"/></svg>';
    const azureLogo='<svg viewBox="0 0 18 14" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><path fill="#fff" d="M10.46 0L6.3 7.27l4.27 4.8H3.5L0 14h18L10.46 0z"/></svg>';
    const gcpLogo='<svg viewBox="0 0 24 24" width="100%" height="100%" preserveAspectRatio="xMidYMid meet"><circle cx="12" cy="12" r="12" fill="none"/><path fill="#4285F4" d="M12 5.5a6.5 6.5 0 015.5 9.98l1.42 1.42A8.5 8.5 0 0012 3.5v2z"/><path fill="#EA4335" d="M5.52 17.52A6.5 6.5 0 0112 5.5v-2A8.5 8.5 0 003.5 18.94l2.02-1.42z"/><path fill="#FBBC05" d="M12 18.5a6.47 6.47 0 01-6.48-1l-2.02 1.44A8.5 8.5 0 0012 20.5v-2z"/><path fill="#34A853" d="M17.5 15.48A6.47 6.47 0 0112 18.5v2a8.5 8.5 0 006.92-4.6l-1.42-1.42z"/></svg>';
    const hasAws=cspScores.aws!==null, hasAzure=cspScores.azure!==null, hasGcp=cspScores.gcp!==null;
    const detectedCSPs=[hasAws&&'AWS',hasAzure&&'Azure',hasGcp&&'GCP'].filter(Boolean).join(', ')||'No CSP data detected';
    return '<section class="pagebreak" style="padding:2.5rem 2rem;min-height:70vh;display:flex;flex-direction:column">\n'+
      '<div style="text-align:center;margin-bottom:2rem">\n'+
      '  <div style="font-size:.72rem;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8;margin-bottom:.5rem">Cloud Security Posture Score by Cloud Provider</div>\n'+
      '  <h2 style="margin:0 0 .4rem;padding:0;border:none;font-size:1.8rem;color:#1e293b">Per-Cloud Security Score</h2>\n'+
      '  <div style="font-size:.85rem;color:#64748b">Individual CSPM compliance scores for each detected cloud environment — <strong>'+detectedCSPs+'</strong></div>\n'+
      '</div>\n'+
      '<div style="display:flex;justify-content:center;align-items:flex-start;gap:40px;flex-wrap:wrap;flex:1;padding:1rem 0">\n'+
        (hasAws   ? bigGauge('AWS',   '#232F3E', awsLogo,   awsP)   : '')+
        (hasAzure ? bigGauge('Azure', '#0078D4', azureLogo, azureP) : '')+
        (hasGcp   ? bigGauge('GCP',   '#1a73e8', gcpLogo,   gcpP)   : '')+
      '</div>\n'+
      '<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1rem 1.5rem;margin-top:auto;font-size:.82rem;color:#64748b;text-align:center">\n'+
      '  Scores reflect CSPM compliance posture per cloud environment. <strong style="color:#3b82f6">81–100</strong> = Optimized &nbsp;·&nbsp; <strong style="color:#22c55e">61–80</strong> = Advanced &nbsp;·&nbsp; <strong style="color:#f59e0b">31–60</strong> = Managed &nbsp;·&nbsp; <strong style="color:#ef4444">0–30</strong> = Foundational\n'+
      '</div>\n'+
      '</section>\n';
  })()+
  alertSection + '\n' + compSection + '\n' + vulnSection + '\n' + idSection + '\n' + secretsAllSection + '\n' + nextStepsSection + '\n' +
  '<div class="report-ending" style="page-break-before:always;background:#000;color:#fff;padding:48px 64px;display:flex;flex-direction:column;gap:32px">' +
  '<div style="text-align:center">' +
  '<div style="font-size:15px;font-weight:700;letter-spacing:.06em;margin-bottom:14px">RAPID CLOUD ASSESSMENT REPORT &mdash; Powered by FortiCNAPP</div>' +
  '<div style="font-size:13px;color:#d1d5db;margin-bottom:10px">Prepared for: '+esc(customer)+' &nbsp;&middot;&nbsp; Report Date: '+dateStr+' &nbsp;&middot;&nbsp; Author: '+esc(author)+'</div>' +
  '<div style="font-size:11px;color:#6b7280">This report is confidential and intended solely for the named recipient. Generated by the FortiCNAPP Extensible Reporting Tool.</div>' +
  '</div>' +
  '<div style="display:flex;align-items:center;justify-content:space-between;gap:32px">' +
  '<div style="display:flex;align-items:center;gap:0">' +
  '<span style="font-size:52px;font-weight:500;color:#d1d5db;letter-spacing:.04em;font-family:Helvetica Neue,Helvetica,Arial,sans-serif;line-height:1">F</span>' +
  '<svg viewBox="0 0 100 100" width="46" height="46" style="margin:0 2px;vertical-align:middle">' +
  '<rect x="5" y="5" width="39" height="28" rx="9" fill="#888"/>' +
  '<rect x="56" y="5" width="39" height="28" rx="9" fill="#888"/>' +
  '<rect x="5" y="41" width="39" height="18" rx="5" fill="#888"/>' +
  '<rect x="56" y="41" width="39" height="18" rx="5" fill="#888"/>' +
  '<rect x="5" y="67" width="39" height="28" rx="9" fill="#888"/>' +
  '<rect x="56" y="67" width="39" height="28" rx="9" fill="#888"/>' +
  '</svg>' +
  '<span style="font-size:52px;font-weight:500;color:#d1d5db;letter-spacing:.04em;font-family:Helvetica Neue,Helvetica,Arial,sans-serif;line-height:1">RTINET&#174;</span>' +
  '</div>' +
  '<div style="text-align:center">' +
  '<div style="background:#fff;border-radius:10px;padding:10px;display:inline-block">' +
  '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAAEsAQMAAABDsxw2AAAABlBMVEUAAAD///7S3q9LAAAACXBIWXMAAA7EAAAOxAGVKw4bAAACQklEQVRoge2aO46EMAyGjSgoOQJHydHgaHMUjkBJgcj6lYTXajWZlXaL38VoxnyVbX7byRDB/oOFqLYStXsj3yZ3rdTao/gC9oDJB/Vrt7U7kfnnYRGnONhGYI8YR3PpV3FweGmciIZjvCdgv4B1MbKX0zCF1zB7WoD9iFG7Wa1q+RJ163MWgL2JuTjETYrXbFiSWtBVQ4A5ZjrqxUoSzTA7Zo8isHosGzulaQkW556fbvRkwMw0vIu6G6tWrufBZIAd1p2AfYBxh1qyhnLP8npuJStUihzYERPjaMqknkZQdutvUdkUXmB1GPf6mbS1lxE0zaCNqgUBe8DUOJppBJ3GqG+9yACV7g+sEgsycLL5CCqT06BF7KPUaOIA7IyJhMoipM2eg1m0QFWWDj0LWA3Geyb3LA563L1FiUPTouVMwB4wNt3PfQSVjTK/9c0p3sBqMBMH1tSY9nMpaJutSEbQo4YAyxgdF6Go1Ut6vGkLZc4CsErMs7ClUSroc8tCEQdgN8wXSNfQoN3pJg7AarCgi9DS5fOPUXNwFQdgV0w3o3K8adH8ZqMEVoMNcaHORykraSleU4vDfgrshPkiFM8zkqyY2ozy4TywCixZl4Lui+fabZQdwG5YsCjers5lVdqb8tYDq8M0FanXe4vSevYsRGDPWDhfnadT9qs4APsIKze+4iDyXh/TH42APWMpmBbdXi6DolyimQGrxdSrWBqlhtlG0PMoBeyEWYVKa9e73XEKPiPZycetZwF7B4P9vX0B1hFily6412wAAAAASUVORK5CYII=" width="130" height="130" alt="QR" style="display:block"/>' +
  '</div>' +
  '<div style="font-size:10px;color:#9ca3af;margin-top:8px;letter-spacing:.03em">fortinet.com/resources/reports/cloud-security</div>' +
  '</div>' +
  '</div>' +
  '</div>\n</body>\n</html>';
}

// ── Report 2 (beta) — wider-scope assessment report ───────────────────────────
// Sections: MultiCloud + per-Cloud risk score, Exploit Simulation Layer, per-host risk
// diagrams, master Risk Findings list, non-compliance by cloud, admin/user MFA gaps,
// Azure/GCP roles & service accounts with high unused privilege, vuln hosts by exposure,
// loose-permission SSH keys, discovered secrets.
function buildReportHtml2(data, meta) {
  const customer = ((meta && meta.customer) || 'Customer').trim();
  const author   = ((meta && meta.author)   || 'Fortinet').trim();
  const dateStr  = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  const alerts      = data.alerts      || [];
  const vulns       = data.vulns       || [];
  const compliance  = governanceReportToComplianceRows(lastGovernanceReport) || data.compliance || [];
  const identities  = data.identities  || [];
  const sshKeys     = data.secrets     || []; // loose-permission SSH keys (chmod > 400)
  const secretsAll  = data.secretsAll  || [];

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function fmt(ts) { if (!ts) return '—'; try { return new Date(ts).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); } catch(_) { return String(ts); } }
  function sevBadge(s) { const m={critical:'badge-critical',high:'badge-high',medium:'badge-medium',low:'badge-low'}; return '<span class="badge '+(m[(s||'').toLowerCase()]||'badge-info')+'">'+esc(s||'—')+'</span>'; }
  function cspBadge(c) { const m={aws:'badge-aws',azure:'badge-azure',gcp:'badge-gcp'}; return '<span class="badge '+(m[(c||'').toLowerCase()]||'badge-info')+'">'+esc((c||'').toUpperCase()||'—')+'</span>'; }

  const { cspScores, cspCounts, score, sBand, sColor } = computeCspScores(data);
  const total = alerts.length + vulns.length + compliance.length + identities.length;

  // ── Identity classification helpers ───────────────────────────────────────
  function cloudOfIdentity(r) {
    const p = (r.PROVIDER_TYPE||'').toLowerCase(), pid = (r.PRINCIPAL_ID||'').toLowerCase();
    if (p.includes('aws') || pid.includes('arn:aws')) return 'aws';
    if (p.includes('azure') || p.includes('aad') || p.includes('serviceprincipal')) return 'azure';
    if (p.includes('gcp') || p.includes('google') || pid.includes('.iam.gserviceaccount.com')) return 'gcp';
    return 'other';
  }
  function isServiceAccount(r) {
    const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase(), p=(r.PROVIDER_TYPE||'').toLowerCase();
    return pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||p.includes('serviceprincipal')||p.includes('aad');
  }
  function isRoleType(r) {
    const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase();
    return (pid.includes(':role/')||pid.includes(':assumed-role/')||nm.includes('role')) && !isServiceAccount(r);
  }
  function unusedPctOf(r) {
    const ec = r.ENTITLEMENT_COUNTS || {};
    const unusedCnt = ec.entitlements_unused_count, totalCnt = ec.entitlements_total_count || ec.entitlements_count;
    return ec.entitlements_unused_percentage != null ? ec.entitlements_unused_percentage
      : (unusedCnt != null && totalCnt ? (unusedCnt/totalCnt)*100 : null);
  }
  function isHighPermissive(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    const sev = (r.METRICS && r.METRICS.risk_severity || '').toLowerCase();
    return risks.includes('ALLOWS_FULL_ADMIN') || risks.includes('EXCESSIVE_PERMISSIONS') || sev === 'critical' || sev === 'high';
  }
  function isNoMfa(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    return risks.includes('PASSWORD_LOGIN_NO_MFA') || !r.MFA_ENABLED;
  }
  function identityLabel(r) { return r.NAME || (r.PRINCIPAL_ID||'').split('/').pop() || r.PRINCIPAL_ID || '—'; }

  // ── 7. Cloud Admin & Cloud User — High Permissive + No MFA ────────────────
  const adminUserRows = identities.filter(r => !isServiceAccount(r) && !isRoleType(r) && isHighPermissive(r) && isNoMfa(r));

  // ── CIEM: identities with an active access key ≥180 days old (isOldAccessKey, server.js~1451) ──
  const oldAccessKeyRows = identities.filter(r => isOldAccessKey(r));

  // Checks the already-fetched cache.exposurePaths (LW_APA_EXPOSURE_PATHS graph-traced
  // Internet→Target attack paths) for a confirmed hop-by-hop path to this host — a
  // stronger signal than the topological lw_InternetExposure tag alone. Matches by EC2
  // instance ID first (exact), falling back to hostname/displayName containment for both
  // EC2 and Azure VM targets. Purely additive — doesn't change exposed/not-exposed
  // classification, only adds a "Verified Path" badge when a live traced path exists.
  function verifiedExposurePath(hostGroup) {
    const ep = data.exposurePaths;
    if (!ep) return false;
    const firstRow = hostGroup.rows[0] || {};
    const mt = (firstRow.machineTags && typeof firstRow.machineTags === 'object') ? firstRow.machineTags : {};
    const instanceId = mt.InstanceId || '';
    const nameLower = (hostGroup.name || '').toLowerCase();
    const hitsEc2 = (ep.ec2 || []).some(p => {
      const t = p.TARGET || {};
      return (instanceId && t.key && t.key.id === instanceId) ||
        (nameLower && t.displayName && t.displayName.toLowerCase().includes(nameLower));
    });
    if (hitsEc2) return true;
    return (ep.azureVm || []).some(p => {
      const t = p.TARGET || {};
      return nameLower && t.displayName && t.displayName.toLowerCase() === nameLower;
    });
  }

  // ── 8. IAM / RBAC roles (AWS, Azure, GCP) — High Permissive + Unused Privilege ≥ 80% ─
  const iamRoleRows = identities.filter(r => {
    const up = unusedPctOf(r);
    return isRoleType(r) && isHighPermissive(r) && up != null && up >= 80;
  });
  // Who can assume each role — parsed server-side from TRUST_POLICY (fetchIdentities)
  function inboundLinkedIdentitiesHtml(r) {
    const tp = r._trustPrincipals || [];
    if (!tp.length) return '<span class="text-muted">No trust policy data available</span>';
    return tp.map(p => {
      const label = p.principal || '—';
      const parts = String(label).split('/');
      const short = parts.length > 2 ? '…/' + parts.slice(-2).join('/') : label;
      return '<span class="badge badge-info" style="font-family:monospace;font-weight:500;margin:1px 3px 1px 0;display:inline-block" title="'+esc(label)+'">'+esc(p.type||'?')+' '+esc(short)+'</span>';
    }).join(' ');
  }

  // ── 9. Cloud Service Accounts — High Permissive + Unused Privilege ≥ 80% ──
  const serviceAccountRows = identities.filter(r => {
    const up = unusedPctOf(r);
    return isServiceAccount(r) && isHighPermissive(r) && up != null && up >= 80;
  });

  // ── 10/11. Vuln hosts grouped by internet exposure (shared with Report 1) ─
  const { hosts: vulnHostsAll, exposedCount: exposedHostCount, internalCount: internalHostCount } = groupVulnsByHost(vulns);
  // A host can be raw-tagged not-exposed (lw_InternetExposure, topological) while
  // FortiCNAPP's own traced Internet→host path engine (exposurePaths) confirms a live
  // route — the two signals can disagree (confirmed live: RJ-RSYSLOG had 29 Critical CVEs
  // invisible in this report because its topological tag lagged behind the verified traced
  // path). Treat a verified path as authoritative for exposed/private classification here,
  // not just a decorative "Verified Path" badge on hosts already classified exposed.
  const effectivelyExposed = h => h.exposed || verifiedExposurePath(h);
  const exposedVulnHosts = vulnHostsAll
    .filter(effectivelyExposed)
    .map(h => ({ ...h, rows: h.rows.filter(r => parseFloat(r.cveRiskScore ?? r.riskScore ?? 0) >= 9) }))
    .filter(h => h.rows.length > 0);
  const privateVulnHosts = vulnHostsAll.filter(h => !effectivelyExposed(h));
  // Dashboard tile — total Critical CVE count across exposed hosts, distinct from the
  // host-count tile (a dashboard KPI, not used by the host-exposure section itself).
  const criticalCveExposedHostCount = exposedVulnHosts.reduce((sum, h) => sum + h.rows.length, 0);

  function vulnRowCells(r, i) {
    const rs = parseFloat(r.cveRiskScore ?? r.riskScore ?? 0);
    const pkg = (r.featureKey && r.featureKey.name) || '—';
    const ver = (r.featureKey && r.featureKey.version) || '';
    const fixVer = (r.fixInfo && r.fixInfo.fixed_version) || '';
    const fixCell = fixVer ? 'Update <strong>'+esc(pkg)+'</strong> to '+esc(fixVer) :
                    (r.fixInfo && r.fixInfo.fix_available) ? 'Vendor fix available — apply immediately' : 'No fix available yet — apply mitigating controls';
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td><span class="badge badge-critical">Critical</span></td>'+
      '<td><strong>'+esc(r.vulnId||r.cveId||'—')+'</strong></td>'+
      '<td style="text-align:center"><span class="risk-chip'+(rs<10?' high':'')+'">'+rs.toFixed(1)+'</span></td>'+
      '<td class="med"><strong>'+esc(pkg)+'</strong>'+(ver?'<br><small class="text-muted">'+esc(ver)+'</small>':'')+'</td>'+
      '<td class="med">'+fixCell+'</td>'+
      '</tr>';
  }
  function hostGroupsHtml(hostList) {
    return hostList.map(h => {
      const badge = h.exposed ? '<span class="badge badge-critical">&#9889; Internet Exposed</span>' : '<span class="badge badge-info">Internal Only</span>';
      const table = '<table class="exec-table"><thead><tr>' +
        '<th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:140px">Vulnerability (CVE)</th>' +
        '<th style="width:60px">Risk Score</th><th style="width:130px">Package / Version</th><th style="width:180px">Recommended Fix</th>' +
        '</tr></thead><tbody>'+h.rows.map(vulnRowCells).join('')+'</tbody></table>';
      return '<div class="host-group'+(h.exposed?' exposed':'')+'">' +
        '<div class="host-group-header">' +
          '<span class="host-name">'+esc(h.name)+'</span>' + badge +
          (h.pubIp ? '<span class="host-ip">'+esc(h.pubIp)+'</span>' : '') +
          '<span class="host-cve-count">'+h.rows.length+' CVE'+(h.rows.length===1?'':'s')+'</span>' +
        '</div>' +
        collapsibleFindings(table, h.rows.length, 'CVEs') +
      '</div>';
    }).join('');
  }

  // ── 12. SSH keys too open ───────────────────────────────────────────────────
  const sshKeyRows = sshKeys.length ? sshKeys.map((r, i) => {
    const mode = r.FILE_PERMISSIONS != null ? '0'+(Number(r.FILE_PERMISSIONS) & 0o777).toString(8).padStart(3,'0') : '—';
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td><strong>'+esc(r.HOSTNAME||'—')+'</strong></td>'+
      '<td class="wide"><code style="font-size:0.8rem">'+esc(r.FILE_PATH||'—')+'</code></td>'+
      '<td>'+esc(r.SSH_KEY_TYPE||'—')+'</td>'+
      '<td style="text-align:center"><span class="badge badge-critical">'+esc(mode)+'</span></td>'+
    '</tr>';
  }).join('') : '';

  // ── 6. Cloud Critical Non-Compliance — grouped by cloud (no verified framework mapping available) ─
  const compByCloud = {};
  compliance.forEach(r => { const c = (r.cloud||'other').toLowerCase(); (compByCloud[c] = compByCloud[c] || []).push(r); });
  const compCloudGroups = Object.keys(compByCloud).sort().map(c => {
    const rows = compByCloud[c];
    const table = '<table class="exec-table"><thead><tr><th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:220px">Finding</th><th style="width:280px">Description</th><th style="width:70px">Violations</th></tr></thead><tbody>' +
      rows.map((r,i) => '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
        '<td class="narrow">'+(i+1)+'</td><td>'+sevBadge(r.severity)+'</td>'+
        '<td class="wide"><strong>'+esc(r.title||'—')+'</strong>'+violatingResourcesHtml(r.resources, esc)+'</td>'+
        '<td class="wide">'+esc((r.description||'').slice(0,180))+'</td>'+
        '<td style="text-align:center">'+esc(r.violations||0)+'</td></tr>').join('') +
      '</tbody></table>';
    return '<div class="host-group" id="non-compliance-'+esc(c)+'">' +
      '<div class="host-group-header">' + cspBadge(c) + '<span class="host-cve-count">'+rows.length+' finding'+(rows.length===1?'':'s')+'</span></div>' +
      collapsibleFindings(table, rows.length, 'findings') +
      '</div>';
  }).join('');

  // ── 4. Internet-Exposed Host Risk Diagrams — top 2 highest-risk exposed hosts ──
  const { map: assetMap } = computeAssetRiskMap(vulns, secretsAll, compliance);
  // Same verified-path reclassification as exposedVulnHosts below — computeAssetRiskMap's
  // internetExposed only reads the raw lw_InternetExposure tag, so this diagram could pick
  // its "top 2 exposed hosts" from a stale/incomplete exposed set, same root cause as the
  // host-exposure table bug above (confirmed live with RJ-RSYSLOG).
  Object.values(assetMap).forEach(a => {
    if (!a.internetExposed && verifiedExposurePath({ name: a.name, rows: [] })) a.internetExposed = true;
  });
  const topAssets = Object.values(assetMap).filter(a => a.internetExposed).sort((a,b) => b.normalizedScore - a.normalizedScore).slice(0, 2);
  const hostDiagramsHtml = topAssets.length ? topAssets.map(a =>
    '<div style="margin-bottom:2rem;padding:1.5rem;border:1px solid var(--color-border);border-radius:8px;background:#fff">' + hostRiskDiagramSvg(a, esc) + '</div>'
  ).join('') : '<div class="section-summary"><p>No internet-exposed hosts with correlated risk data were found in this assessment window.</p></div>';

  // ── 13. List of Secrets ──────────────────────────────────────────────────────
  const secretsAllRows = secretsAll.length ? secretsAll.map((r,i) => {
    const lastSeen = r.END_TIME ? new Date(r.END_TIME).toLocaleString('en-US',{month:'short',day:'numeric',year:'numeric',hour:'numeric',minute:'2-digit'}) : '—';
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td><strong>'+esc(r.HOSTNAME||'—')+'</strong></td>'+
      '<td><small class="text-muted">'+esc(r.MID||'—')+'</small></td>'+
      '<td>'+esc(r.OS||'—')+'</td>'+
      '<td><span class="badge badge-critical">'+esc(r.SECRET_TYPE||'—')+'</span></td>'+
      '<td class="wide"><code style="font-size:0.8rem">'+esc(r.SECRET_IDENTIFIER||'—')+'</code></td>'+
      '<td><small>'+esc(lastSeen)+'</small></td>'+
      '</tr>';
  }).join('') : '';

  // ── Identity table row renderer (shared shape for sections 7/8/9) ──────────
  function identityRowsHtml(rows, includeUnused, includeInbound) {
    const cols = 5 + (includeUnused?1:0) + (includeInbound?1:0);
    return rows.length ? rows.map((r,i) => {
      const risks = (r.METRICS && r.METRICS.risks) || [];
      const isAdmin = risks.includes('ALLOWS_FULL_ADMIN');
      const noMfa = isNoMfa(r);
      const up = unusedPctOf(r);
      const bg = isAdmin && noMfa ? ' style="background:#FDECEA;"' : (i%2===1?' style="background:#FAFAFA;"':'');
      return '<tr'+bg+'>'+
        '<td><strong>'+esc(identityLabel(r))+'</strong><br><small class="text-muted">'+esc(r.PRINCIPAL_ID||'')+'</small></td>'+
        '<td>'+cspBadge(cloudOfIdentity(r))+'</td>'+
        '<td>'+(isAdmin?'<span class="badge badge-critical">Admin</span>':'<span class="badge badge-high">Privileged</span>')+'</td>'+
        '<td>'+(noMfa?'<span class="badge badge-mfa-off">No MFA</span>':'<span class="badge badge-mfa-on">MFA ON</span>')+'</td>'+
        '<td>'+(r.LAST_USED_TIME?fmt(r.LAST_USED_TIME):'<span class="text-muted">Never / Unknown</span>')+'</td>'+
        (includeUnused ? '<td style="text-align:center">'+(up!=null?Math.round(up)+'%':'—')+'</td>' : '') +
        (includeInbound ? '<td class="wide">'+inboundLinkedIdentitiesHtml(r)+'</td>' : '') +
        '</tr>';
    }).join('') : '<tr><td colspan="'+cols+'" style="text-align:center;color:#999;padding:1.5rem">None found</td></tr>';
  }

  // ── CIEM: access-key rotation rows ─────────────────────────────────────────
  function oldAccessKeyRowsHtml(rows) {
    return rows.length ? rows.map((r,i) => {
      const ageDays = oldestActiveKeyAgeDays(r);
      return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
        '<td><strong>'+esc(identityLabel(r))+'</strong><br><small class="text-muted">'+esc(r.PRINCIPAL_ID||'')+'</small></td>'+
        '<td>'+cspBadge(cloudOfIdentity(r))+'</td>'+
        '<td style="text-align:center"><span class="badge badge-high">'+(ageDays!=null?Math.round(ageDays)+' days':'—')+'</span></td>'+
        '<td>'+(r.LAST_USED_TIME?fmt(r.LAST_USED_TIME):'<span class="text-muted">Never / Unknown</span>')+'</td>'+
        '</tr>';
    }).join('') : '<tr><td colspan="4" style="text-align:center;color:#999;padding:1.5rem">None found</td></tr>';
  }

  // ── Internet-Accessible Storage ─────────────────────────────────────────────
  // Raw data.publicStorage only has policy/ACL-confirmed findings AND can still contain
  // known-stale CSPM snapshot entries (a resource the last scan saw as public but that no
  // longer exists live). computeEffectivePublicStorage() (server.js~7568) is the same merge
  // the dashboard's Public Storage Exposure panel uses: it drops those stale entries and
  // adds buckets found only via a verified traced Internet path (cache.exposurePaths.s3/
  // azureBlob) that never had a policy/ACL finding of their own — without it this section
  // silently showed 1 stale Azure entry while missing every traced-path-only S3 bucket.
  const publicStorageRows = computeEffectivePublicStorage(data).findings;
  function publicStorageRowsHtml(rows) {
    return rows.length ? rows.map((r,i) => '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td>'+cspBadge(r.cloud)+'</td>'+
      '<td><strong>'+esc(r.name||'—')+'</strong></td>'+
      '<td>'+esc(r.resourceType||'—')+'</td>'+
      '<td>'+sevBadge(r.severity)+'</td>'+
      '<td><small class="text-muted">'+esc(r.account||'—')+'</small></td>'+
      '<td class="wide"><code style="font-size:0.78rem;word-break:break-all">'+esc(r.urn||'—')+'</code></td>'+
      '</tr>').join('') : '<tr><td colspan="6" style="text-align:center;color:#999;padding:1.5rem">None found</td></tr>';
  }

  // Stat callout — cites the 2026 Fortinet Cloud Security Report (survey of 1,163
  // cybersecurity leaders/practitioners) to ground each risk category in the wider
  // industry picture, not just this tenant's own numbers. Reuses .section-summary, the
  // dark red-accent callout box already used elsewhere in this report.
  function statCalloutHtml(label, text) {
    return '<div class="section-summary"><div class="ss-title">'+esc(label)+'</div><p>'+text+'</p></div>';
  }

  // "Why this matters + how FortiCNAPP helps" — one per risk-finding section, sourced from
  // the FortiCNAPP capability mapping matrix. capability/provides/doIt/manage are the
  // matrix's own columns; technical/business are arrays of bullet strings synthesized from
  // that same row to close each section with a concrete outcome, not just a description.
  function fcSolutionHtml(capability, provides, doIt, manage, technical, business) {
    return '<div class="fc-solution">'+
      '<div class="fc-solution-head">Why This Matters &amp; How FortiCNAPP Helps</div>'+
      '<div class="fc-solution-grid">'+
        '<div><span class="fc-label">FortiCNAPP Capability</span><p>'+capability+'</p></div>'+
        '<div><span class="fc-label">What FortiCNAPP Provides</span><p>'+provides+'</p></div>'+
        '<div><span class="fc-label">What to Do</span><p>'+doIt+'</p></div>'+
        '<div><span class="fc-label">How to Manage</span><p>'+manage+'</p></div>'+
      '</div>'+
      '<div class="fc-outcomes">'+
        '<div><span class="fc-label">Technical Outcomes</span><ul>'+technical.map(t=>'<li>'+t+'</li>').join('')+'</ul></div>'+
        '<div><span class="fc-label">Business Outcomes</span><ul>'+business.map(t=>'<li>'+t+'</li>').join('')+'</ul></div>'+
      '</div>'+
    '</div>';
  }

  // ── Sections ──────────────────────────────────────────────────────────────
  const rcaIntroSection =
    '<section style="padding:1.5rem 2rem 0">\n' +
    '<h2>1. Introduction &mdash; What is the Fortinet Security Maturity Assessment</h2>\n' +
    '<p style="color:#5A5A5A;font-size:13px;line-height:1.7;margin-bottom:14px">A Security Maturity Assessment (<strong>SMA</strong>), Powered by <strong>FortiCNAPP</strong>, provides '+esc(customer)+' with a clear view of the most critical cloud risks across identity, exposure, secrets, and vulnerabilities so they can prioritize remediation, strengthen resilience, and improve the organization&rsquo;s overall Risk Security Score.</p>\n' +
    '<p style="color:#5A5A5A;font-size:13px;line-height:1.7;margin-bottom:20px">FortiCNAPP continuously collects cloud telemetry, identities, configurations, and activity data to establish a security baseline, correlates risks across vulnerabilities, misconfigurations, identity exposure, and data risks into a unified Cloud Security Risk Score, and enables teams to prioritize remediation, reduce exposure, and continuously improve cloud security posture.</p>\n' +
    '<div class="intro-grid">\n' +
    '<div class="intro-card"><div class="intro-eyebrow">Step 1</div><h4>Collect</h4>' +
    '<p>FortiCNAPP continuously collects <strong>telemetry, configuration, identity, and activity data</strong> from connected cloud environments&mdash;including <strong>AWS, Azure, GCP, and OCI</strong>.</p></div>\n' +
    '<div class="intro-card"><div class="intro-eyebrow">Step 2</div><h4>Correlate &amp; Prioritize</h4>' +
    '<p>FortiCNAPP AI Engine correlates <strong>vulnerabilities, misconfigurations, identity risks, runtime threats, and data exposure</strong> into a <strong>unified Cloud Security Risk Score</strong>.</p></div>\n' +
    '<div class="intro-card"><div class="intro-eyebrow">Step 3</div><h4>Remediate &amp; Improve</h4>' +
    '<p>Address the <strong>prioritized findings</strong> that reduce risk, measure improvements, and <strong>continuously monitor</strong> your cloud security posture.</p></div>\n' +
    '</div>\n' +
    '</section>';

  const ciemSection =
    '<section id="ciem" class="pagebreak">\n<h2>3. CIEM &amp; Identity Risk</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', 'Identity &amp; Access Security ranks as the top cloud-native concern for <strong>77%</strong> of organizations, and <strong>69%</strong> report having actually experienced an identity/access security incident in the past 12 months — the single most commonly reported category of cloud incident.') +
    fcSolutionHtml('CIEM',
      'Analyzes cloud identities, permissions, entitlements, and privilege relationships across AWS, Azure, and GCP. Cloud identities are often over-permissioned, creating risks from excessive entitlements, dormant accounts, and toxic access combinations. Without continuous least-privilege management, organizations face increased exposure to cloud breaches, account takeover, and data exfiltration.',
      'Remove excessive permissions, enforce least privilege, disable unused identities.',
      'Continuously monitor identity risk, perform entitlement reviews, track privilege changes.',
      ['Full visibility into over-privileged identities and stale access keys across all clouds', 'Automated least-privilege recommendations based on actual entitlement usage', 'Continuous entitlement drift detection'],
      ['Reduces the #1 cited cloud breach vector (identity compromise)', 'Lowers audit findings tied to excessive access', 'Strengthens regulatory compliance posture (SOC 2, ISO 27001)']
    ) +
    '<h3 id="ciem-mfa" style="margin-top:2rem">Admin &amp; User — High Permissive, No MFA</h3>\n' +
    collapsibleFindings(
      '<table class="exec-table"><thead><tr><th style="width:180px">Identity</th><th style="width:70px">Cloud</th><th style="width:80px">Privilege</th><th style="width:70px">MFA</th><th style="width:130px">Last Login</th></tr></thead><tbody>' +
      identityRowsHtml(adminUserRows, false) + '</tbody></table>',
      adminUserRows.length, 'identities'
    ) +
    '<h3 id="ciem-keys">Access Keys Not Rotated &ge; 180 Days</h3>\n' +
    collapsibleFindings(
      '<table class="exec-table"><thead><tr><th style="width:180px">Identity</th><th style="width:70px">Cloud</th><th style="width:100px">Key Age</th><th style="width:130px">Last Used</th></tr></thead><tbody>' +
      oldAccessKeyRowsHtml(oldAccessKeyRows) + '</tbody></table>',
      oldAccessKeyRows.length, 'identities'
    ) + '\n</section>';

  const secretsSshSection =
    '<section id="secrets-ssh" class="pagebreak">\n<h2>4. Secrets &amp; SSH Key Exposure</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', 'A single exposed credential or private key is often the pivot point in a breach: an overprivileged identity paired with an exposed secret turns an isolated finding into a direct path to compromise. Identity-related incidents were reported by <strong>69%</strong> of organizations in the past 12 months.') +
    fcSolutionHtml('Agentless CWPP',
      'Agentless workload discovery and security analysis to identify exposed secrets and sensitive artifacts across cloud workloads.',
      'Remove exposed secrets, rotate credentials, eliminate hardcoded keys.',
      'Continuously scan workloads, monitor credential exposure, integrate remediation workflows with DevSecOps.',
      ['Agentless scanning finds hardcoded secrets and permissive SSH keys with zero deployment overhead', 'Direct integration with DevSecOps remediation workflows'],
      ['Prevents credential-based lateral movement and data breach', 'Reduces incident response cost and time-to-remediate']
    ) +
    '<h3 id="secrets-list" style="margin-top:2rem">Secrets Found on Hosts</h3>\n' +
    (secretsAll.length ? collapsibleFindings(
      '<table class="exec-table"><thead><tr><th style="width:160px">Hostname</th><th style="width:140px">Instance ID</th><th style="width:80px">OS</th><th style="width:120px">Secret Type</th><th style="width:220px">Secret Identifier</th><th style="width:130px">Last Seen</th></tr></thead><tbody>' +
      secretsAllRows + '</tbody></table>',
      secretsAll.length, 'secrets'
    ) : '<p style="text-align:center;color:#999;padding:1.5rem">No secrets found</p>') +
    '<h3 id="ssh-keys">Permissive SSH Keys Access</h3>\n' +
    '<p style="color:#5A5A5A;margin-bottom:16px;font-size:12px">Private key files with permissions looser than chmod 400 — readable/writable beyond the owner.</p>' +
    (sshKeys.length ? collapsibleFindings(
      '<table class="exec-table"><thead><tr><th style="width:160px">Hostname</th><th style="width:280px">File Path</th><th style="width:100px">Key Type</th><th style="width:90px">Permissions</th></tr></thead><tbody>' +
      sshKeyRows + '</tbody></table>',
      sshKeys.length, 'SSH keys'
    ) : '<p style="text-align:center;color:#999;padding:1.5rem">No overly-permissive SSH keys found</p>') + '\n</section>';

  const hostExposureSection =
    '<section id="host-exposure" class="pagebreak">\n<h2>5. Internet-Exposed Host Risk</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>59%</strong> of organizations cite Workload &amp; Runtime Security as a top cloud-native concern, and <strong>42%</strong> report an actual workload/runtime security incident in the past 12 months — attackers use automation to find exposed, vulnerable hosts faster than manual review can keep up with.') +
    statCalloutHtml('FortiGuard Labs Global Threat Landscape Report', 'Internet-facing systems are continuously targeted: FortiGuard Labs recorded <strong>122 billion</strong> exploitation attempts in 2025 — every internet-exposed host in this assessment is a live target in that volume.') +
    fcSolutionHtml('Agentless CWPP + CSPM + Risk Score',
      'Identifies internet-facing workloads, vulnerabilities, cloud misconfigurations, and exposure paths.',
      'Reduce unnecessary exposure, harden configurations, patch vulnerabilities.',
      'Continuously monitor attack surface, correlate exposure with workload risk, prioritize remediation.',
      ['Verified, hop-by-hop traced exposure paths — not just topological exposure tags', 'Correlates vulnerability severity with actual internet reachability'],
      ['Shrinks the external attack surface attackers scan first', 'Prioritizes limited remediation resources on real exposure, not noise']
    ) +
    '<h3 style="margin-top:2rem">Risk Diagram — Two Highest-Risk Exposed Hosts</h3>\n' +
    hostDiagramsHtml +
    '<h3>High-Vulnerability Internet-Exposed Hosts</h3>\n' +
    '<p style="color:#5A5A5A;margin-bottom:16px;font-size:12px">Showing CVEs with a Risk Score &ge; 9.0 on internet-exposed hosts. A green "Verified Path" badge means FortiCNAPP traced an actual hop-by-hop Internet&rarr;host network path — not just a topological exposure tag.</p>' +
    fcSolutionHtml('Agentless CWPP Vulnerability Management + Risk Scores (Impact Score, Package Score, Container Score)',
      'Correlates workload vulnerabilities with internet exposure, vulnerable packages, container image risks, asset criticality, and impact scoring to identify the highest-risk hosts.',
      'Patch critical vulnerabilities, update vulnerable packages, rebuild vulnerable container images, apply compensating controls.',
      'Continuously track vulnerability posture, monitor Risk Score changes, enforce remediation SLAs, validate risk reduction after fixes.',
      ['Multi-factor Risk Score (Impact, Package, Container) ranks hosts by true exploitability, not raw CVE count', 'Continuous re-scoring validates that remediation actually reduced risk'],
      ['Focuses engineering effort on the handful of hosts that matter most', 'Demonstrable, measurable risk reduction over time for leadership reporting']
    ) +
    (exposedVulnHosts.length ?
      '<div class="host-exposure-summary"><span class="hes-item exposed"><strong>'+exposedVulnHosts.length+'</strong> Host'+(exposedVulnHosts.length===1?'':'s')+'</span></div>\n' +
      exposedVulnHosts.map(h => {
        const verified = verifiedExposurePath(h);
        const badge = '<span class="badge badge-critical">&#9889; Internet Exposed</span>' + (verified ? ' <span class="badge badge-success">&#10003; Verified Path</span>' : '');
        const table = '<table class="exec-table"><thead><tr>' +
          '<th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:140px">Vulnerability (CVE)</th>' +
          '<th style="width:60px">Risk Score</th><th style="width:130px">Package / Version</th><th style="width:180px">Recommended Fix</th>' +
          '</tr></thead><tbody>'+h.rows.map(vulnRowCells).join('')+'</tbody></table>';
        return '<div class="host-group exposed">' +
          '<div class="host-group-header">' +
            '<span class="host-name">'+esc(h.name)+'</span>' + badge +
            (h.pubIp ? '<span class="host-ip">'+esc(h.pubIp)+'</span>' : '') +
            '<span class="host-cve-count">'+h.rows.length+' CVE'+(h.rows.length===1?'':'s')+'</span>' +
          '</div>' +
          collapsibleFindings(table, h.rows.length, 'CVEs') +
        '</div>';
      }).join('')
    : '<p style="text-align:center;color:#999;padding:1.5rem">No internet-exposed hosts with high-risk CVEs found</p>') +
    '\n</section>';

  const storageSection =
    '<section id="storage" class="pagebreak">\n<h2>6. Internet-Accessible Storage</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>66%</strong> of organizations cite Data Exposure &amp; Privacy Security as a top concern, and <strong>54%</strong> report an actual data exposure incident in the past 12 months. A single misconfigured storage bucket can turn into a direct path to a breach when combined with an overprivileged identity.') +
    fcSolutionHtml('CSPM + DSPM',
      'Detects cloud misconfigurations, public exposure, and sensitive data risks.',
      'Remove public access, correct permissions, enable encryption and access controls.',
      'Continuously monitor storage posture, enforce policies, detect configuration drift.',
      ['Combines policy/ACL checks with verified traced internet paths to catch storage exposure that pure CSPM scans miss', 'Configuration-drift detection flags changes as they happen'],
      ['Prevents the most common cause of cloud data breaches (public storage)', 'Protects customer trust and avoids regulatory data-exposure penalties']
    ) +
    (publicStorageRows.length ? collapsibleFindings(
      '<table class="exec-table" style="margin-top:16px"><thead><tr><th style="width:70px">Cloud</th><th style="width:180px">Resource</th><th style="width:180px">Type</th><th style="width:70px">Severity</th><th style="width:160px">Account</th><th>Resource URN</th></tr></thead><tbody>' +
      publicStorageRowsHtml(publicStorageRows) + '</tbody></table>',
      publicStorageRows.length, 'storage resources'
    ) : '<p style="text-align:center;color:#999;padding:1.5rem;margin-top:16px">No internet-accessible storage found</p>') + '\n</section>';

  const privateVulnSection = privateVulnHosts.length ? (
    '<section id="vuln-private" class="pagebreak">\n<h2>7. Private Host Vulnerability</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>66%</strong> of organizations lack strong confidence in their ability to detect and respond to cloud threats in real time, up from 64% the prior year — internal, non-internet-facing hosts are often the biggest blind spot in that gap.') +
    fcSolutionHtml('Agentless CWPP Vulnerability Management',
      'Identifies vulnerable workloads and software weaknesses without requiring agents.',
      'Patch vulnerabilities, harden workloads, segment critical systems.',
      'Continuously assess vulnerabilities, prioritize based on exploitability and business impact.',
      ['Agentless coverage of internal hosts with zero deployment friction', 'Exploitability-based prioritization, not just CVSS severity'],
      ['Reduces lateral-movement risk after an initial breach', 'Lowers the blast radius of any single compromised host']
    ) +
    '<div class="host-exposure-summary"><span class="hes-item"><strong>'+privateVulnHosts.length+'</strong> Host'+(privateVulnHosts.length===1?'':'s')+'</span></div>\n' +
    hostGroupsHtml(privateVulnHosts) + '\n</section>'
  ) : '';

  const nonComplianceSection = compliance.length ? (
    '<section id="non-compliance" class="pagebreak">\n<h2>8. Cloud Critical Non-Compliance Findings</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>70%</strong> of organizations cite Configuration &amp; Posture Security as a top cloud-native concern, and <strong>65%</strong> report an actual configuration/posture-related incident in the past 12 months — the second most common category of cloud incident after identity.') +
    fcSolutionHtml('CSPM',
      'Continuous cloud posture assessment, compliance monitoring, and misconfiguration detection.',
      'Remediate critical findings and assign ownership.',
      'Maintain compliance dashboards, monitor posture drift, automate policy enforcement.',
      ['Continuous, automated posture checks across every connected cloud account', 'Policy-level findings with resource-level violation detail'],
      ['Reduces audit prep time and compliance risk (CIS/NIST/PCI)', 'Demonstrates due diligence to auditors, regulators, and customers']
    ) +
    '<p style="color:#5A5A5A;margin-bottom:16px;font-size:12px">Grouped by cloud provider. Findings are not currently mapped to a named compliance framework (CIS/NIST/PCI) in this integration — severity and policy title are shown as-is from FortiCNAPP.</p>' +
    compCloudGroups + '\n</section>'
  ) : '';

  const iamRolesSection =
    '<section id="iam-roles" class="pagebreak">\n<h2>9. IAM / RBAC Roles — High Permissive, Unused Privilege &ge; 80%</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>81%</strong> of organizations using a cloud security platform prioritize security outcomes such as fewer misconfigurations and <strong>reduced excessive permissions</strong> as the measure of program success.') +
    fcSolutionHtml('CIEM',
      'Identifies overprivileged users, unused permissions, and risky access paths.',
      'Reduce permissions, implement least privilege, enforce MFA.',
      'Perform continuous entitlement analysis, access reviews, and privilege optimization.',
      ['Inbound trust-policy analysis shows exactly who can assume each over-privileged role', 'Usage-based entitlement scoring, not just granted permissions'],
      ['Closes privilege-escalation paths before they’re exploited', 'Supports least-privilege compliance requirements']
    ) +
    '<p style="color:#5A5A5A;margin-bottom:16px;font-size:12px">"Linked Identities — Inbound" lists every principal (AWS account/user/role, Azure service principal, GCP service account, or federated identity) whose trust policy allows it to assume this role.</p>' +
    collapsibleFindings(
      '<table class="exec-table"><thead><tr><th style="width:150px">Role</th><th style="width:60px">Cloud</th><th style="width:70px">Privilege</th><th style="width:55px">MFA</th><th style="width:100px">Last Used</th><th style="width:75px">Unused Entitlements</th><th>Linked Identities — Inbound</th></tr></thead><tbody>' +
      identityRowsHtml(iamRoleRows, true, true) + '</tbody></table>',
      iamRoleRows.length, 'roles'
    ) + '\n</section>';

  const serviceAccountsSection =
    '<section id="service-accounts" class="pagebreak">\n<h2>10. Cloud Service Accounts — High Permissive, Unused Privilege &ge; 80%</h2>\n' +
    statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>61%</strong> of organizations cite Data &amp; Identity Complexity — including the sprawl of non-human identities like service accounts — as a top operational challenge to effective cloud security.') +
    fcSolutionHtml('CIEM',
      'Analyzes machine identities, service accounts, permissions, and entitlement risks.',
      'Right-size permissions, remove unused access, replace static credentials.',
      'Continuously monitor workload identities, enforce least privilege, review service account activity.',
      ['Extends identity risk analysis to non-human identities, the fastest-growing identity category', 'Flags static, long-lived credentials for rotation'],
      ['Reduces the sprawling, often-invisible service-account attack surface', 'Prevents a top identity-complexity challenge from becoming a breach vector']
    ) +
    collapsibleFindings(
      '<table class="exec-table"><thead><tr><th style="width:180px">Service Account</th><th style="width:70px">Cloud</th><th style="width:80px">Privilege</th><th style="width:70px">MFA</th><th style="width:130px">Last Used</th><th style="width:90px">Unused Entitlements</th></tr></thead><tbody>' +
      identityRowsHtml(serviceAccountRows, true) + '</tbody></table>',
      serviceAccountRows.length, 'service accounts'
    ) + '\n</section>';

  // ── 11. FortiCNAPP Capability Mapping — rolls up every section's "why it matters /
  // how FortiCNAPP helps" card into one reference table, plus the capability→outcome
  // summary and an executive one-liner for leadership audiences skimming to the end. ──
  const capabilityMappingRows = [
    ['Secrets &amp; SSH Key Exposure', 'Exposed secrets, SSH keys, API tokens, certificates, and sensitive credentials discovered in cloud workloads', 'Agentless CWPP', 'Agentless workload discovery and security analysis to identify exposed secrets and sensitive artifacts across cloud workloads', 'Remove exposed secrets, rotate credentials, eliminate hardcoded keys', 'Continuously scan workloads, monitor credential exposure, integrate remediation workflows with DevSecOps'],
    ['CIEM &amp; Identity Risk', 'Excessive permissions, unused privileges, dormant identities, risky IAM/RBAC relationships', 'CIEM', 'Analyzes cloud identities, permissions, entitlements, and privilege relationships across AWS, Azure, and GCP', 'Remove excessive permissions, enforce least privilege, disable unused identities', 'Continuously monitor identity risk, perform entitlement reviews, track privilege changes'],
    ['Internet-Exposed Host Risk', 'Publicly accessible cloud workloads with vulnerabilities or weak security posture', 'Agentless CWPP + CSPM + Risk Score', 'Identifies internet-facing workloads, vulnerabilities, cloud misconfigurations, and exposure paths', 'Reduce unnecessary exposure, harden configurations, patch vulnerabilities', 'Continuously monitor attack surface, correlate exposure with workload risk, prioritize remediation'],
    ['Prioritized High-Vulnerability Internet-Exposed Hosts', 'Internet-facing hosts with critical vulnerabilities prioritized using exposure, vulnerability severity, exploitability, package risk, container risk, and business impact', 'Agentless CWPP Vulnerability Management + Risk Scores (Impact Score, Package Score, Container Score)', 'Correlates workload vulnerabilities with internet exposure, vulnerable packages, container image risks, asset criticality, and impact scoring to identify highest-risk hosts', 'Patch critical vulnerabilities, update vulnerable packages, rebuild vulnerable container images, apply compensating controls', 'Continuously track vulnerability posture, monitor Risk Score changes, enforce remediation SLAs, validate risk reduction after fixes'],
    ['Public Access Storage', 'Cloud storage resources exposed publicly due to incorrect permissions or configuration', 'CSPM + DSPM', 'Detects cloud misconfigurations, public exposure, and sensitive data risks', 'Remove public access, correct permissions, enable encryption and access controls', 'Continuously monitor storage posture, enforce policies, detect configuration drift'],
    ['Private Host Critical Vulnerability', 'Internal workloads containing critical vulnerabilities without direct internet exposure', 'Agentless CWPP Vulnerability Management', 'Identifies vulnerable workloads and software weaknesses without requiring agents', 'Patch vulnerabilities, harden workloads, segment critical systems', 'Continuously assess vulnerabilities, prioritize based on exploitability and business impact'],
    ['Cloud Critical Non-Compliance Findings', 'Critical cloud security misconfigurations violating CIS, NIST, PCI-DSS, ISO, or organizational policies', 'CSPM', 'Continuous cloud posture assessment, compliance monitoring, and misconfiguration detection', 'Remediate critical findings and assign ownership', 'Maintain compliance dashboards, monitor posture drift, automate policy enforcement'],
    ['IAM / RBAC Roles &mdash; High Permissive, Unused Privilege &ge;80%', 'Human identities with excessive permissions where most assigned privileges are unused', 'CIEM', 'Identifies overprivileged users, unused permissions, and risky access paths', 'Reduce permissions, implement least privilege, enforce MFA', 'Perform continuous entitlement analysis, access reviews, and privilege optimization'],
    ['Cloud Service Accounts &mdash; High Permissive, Unused Privilege &ge;80%', 'Service accounts, workload identities, and service principals with excessive unused permissions', 'CIEM', 'Analyzes machine identities, service accounts, permissions, and entitlement risks', 'Right-size permissions, remove unused access, replace static credentials', 'Continuously monitor workload identities, enforce least privilege, review service account activity'],
  ];
  const capabilityOutcomeRows = [
    ['Agentless CWPP', 'Workload discovery, exposed secrets detection, vulnerability identification, package risk analysis, container risk analysis'],
    ['CWPP Vulnerability Management + Risk Scores', 'Prioritized remediation of high-impact vulnerabilities using Impact Score, Package Score, Container Score, exposure, and asset context'],
    ['CIEM', 'Identity entitlement analysis, excessive privilege detection, least-privilege enforcement'],
    ['CSPM', 'Cloud misconfiguration detection, compliance monitoring, security posture improvement'],
    ['DSPM', 'Sensitive data discovery, data exposure prevention, privacy risk reduction'],
    ['FortiCNAPP Risk Score', 'Business-risk prioritization by correlating security findings, exposure, impact, and asset criticality'],
  ];
  const capabilityMappingSection =
    '<section id="capability-mapping" class="pagebreak">\n' +
    '<div class="fc-lock-gate" id="fc-lock-11">' +
      '<div class="fc-lock-icon">&#128274;</div>' +
      '<div class="fc-lock-title">Fortinet-Only Content</div>' +
      '<div class="fc-lock-desc">This section is restricted to Fortinet personnel. Enter your Fortinet email address to view.</div>' +
      '<div class="fc-lock-row"><input type="email" id="fc-lock-email-11" placeholder="you@fortinet.com" onkeydown="if(event.key===\'Enter\')fcUnlockSection(\'11\')">' +
      '<button type="button" onclick="fcUnlockSection(\'11\')">Unlock</button></div>' +
      '<div class="fc-lock-error" id="fc-lock-error-11">Please enter a valid @fortinet.com email address.</div>' +
    '</div>' +
    '<div class="fc-locked-content" id="fc-locked-content-11" style="display:none">' +
    '<h2>11. FortiCNAPP Capability Mapping</h2>\n' +
    '<div style="overflow-x:auto"><table class="exec-table" style="min-width:900px"><thead><tr>' +
    '<th style="width:150px">Security Challenge</th><th style="width:220px">Outcome / Finding</th><th style="width:150px">FortiCNAPP Capability</th><th style="width:220px">What FortiCNAPP Provides</th><th style="width:180px">What to Do?</th><th style="width:220px">How to Manage?</th>' +
    '</tr></thead><tbody>' +
    capabilityMappingRows.map((r,i) => '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+r.map(c=>'<td class="wide">'+c+'</td>').join('')+'</tr>').join('') +
    '</tbody></table></div>\n' +
    '<h3 style="margin-top:2.5rem">FortiCNAPP Capability &rarr; Security Outcome Mapping</h3>\n' +
    '<table class="exec-table"><thead><tr><th style="width:280px">FortiCNAPP Capability</th><th>Security Outcomes</th></tr></thead><tbody>' +
    capabilityOutcomeRows.map((r,i) => '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'><td><strong>'+r[0]+'</strong></td><td class="wide">'+r[1]+'</td></tr>').join('') +
    '</tbody></table>\n' +
    statCalloutHtml('Forrester Total Economic Impact&trade; Study &mdash; commissioned by Lacework, 2022', 'A Forrester TEI study of a composite Lacework customer organization documented a <strong>342% ROI over three years</strong>, <strong>$2.3M</strong> in total quantified benefits, and an <strong>$1.79M</strong> net present value. Additional outcomes: up to <strong>86%</strong> reduction in alert volume, <strong>~95%</strong> false-positive elimination, and <strong>80% faster</strong> threat investigation. <em>Date context: this study was commissioned in 2022, prior to the Fortinet acquisition (August 2024), and does not reflect current Security Fabric integration (FortiSOAR, FortiGate, FortiAnalyzer).</em>') +
    statCalloutHtml('Executive Outcome Statement', 'FortiCNAPP reduces cloud attack risk by correlating workload vulnerabilities, internet exposure, identity privilege, misconfigurations, and data risks into prioritized remediation actions based on business impact &mdash; further reducing Mean Time to Respond (MTTR) to minutes, cutting alert noise, and strengthening compliance posture against frameworks such as CIS, HIPAA, NIST, and PCI-DSS.') +
    '</div>\n</section>';

  const tocCards = [
    dashboardTileHtml('#ciem-mfa', adminUserRows.length, '#ef4444', 'Admins / Users<br>No MFA'),
    dashboardTileHtml('#ciem-keys', oldAccessKeyRows.length, '#f59e0b', 'Cloud User Keys Not Rotated<br>&ge; 180 Days'),
    dashboardTileHtml('#secrets-list', secretsAll.length, '#3b82f6', 'Permissive Secrets<br>Access'),
    dashboardTileHtml('#ssh-keys', sshKeys.length, '#92400e', 'Permissive SSH<br>Key Access'),
    dashboardTileHtml('#host-exposure', exposedVulnHosts.length, '#f97316', 'Internet-Exposed<br>Hosts'),
    dashboardTileHtml('#host-exposure', criticalCveExposedHostCount, '#dc2626', 'Critical CVE<br>Internet Host Exposed'),
    dashboardTileHtml('#storage', publicStorageRows.length, '#7c3aed', 'Storage<br>Internet Accessible'),
    dashboardTileHtml('#vuln-private', privateVulnHosts.length, '#9a3412', 'Private Hosts<br>Highly Vulnerable'),
  ].join('\n      ');

  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
  '  <meta charset="UTF-8">\n' +
  '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
  '  <title>Security Maturity Assessment (Beta) – '+esc(customer)+'</title>\n' +
  '  <style type="text/css">\n' + REPORT_CSS + '\n' +
  '  </style>\n</head>\n<body>\n' +
  reportTopbarHtml(null, true) + '\n' +
  '<button type="button" class="pdf-export-btn no-print" onclick="window.print()">&#128196; Export to PDF</button>\n' +
  '<div class="report-cover">\n' +
  '  <h1>Security Maturity Assessment Report</h1>\n' +
  (function() {
    const arcLen=550, fill=Math.round((score/100)*arcLen);
    return '  <div id="risk-score" style="margin:1rem auto 0;max-width:380px;width:100%">\n'+
      '  <svg viewBox="0 0 400 240" style="display:block;width:100%;overflow:visible">\n'+
      '    <defs><linearGradient id="rg2" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">'+
      '<stop offset="0%" stop-color="#ef4444"/><stop offset="20.6%" stop-color="#ef4444"/>'+
      '<stop offset="20.6%" stop-color="#f59e0b"/><stop offset="65.45%" stop-color="#f59e0b"/>'+
      '<stop offset="65.45%" stop-color="#22c55e"/><stop offset="90.45%" stop-color="#22c55e"/>'+
      '<stop offset="90.45%" stop-color="#3b82f6"/><stop offset="100%" stop-color="#3b82f6"/>'+
      '</linearGradient></defs>\n'+
      '    <path fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <path fill="none" stroke="url(#rg2)" stroke-width="34" stroke-linecap="round" stroke-dasharray="'+fill+' '+arcLen+'" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <line x1="86" y1="48" x2="108" y2="79"   stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="260" y1="20" x2="248" y2="57"  stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="357" y1="91" x2="326" y2="113" stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <text x="200" y="165" text-anchor="middle" font-size="72" font-weight="900" letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="white">'+score+'</text>\n'+
      '    <text x="-8" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">0</text>\n'+
      '    <text x="408" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">100</text>\n'+
      '  </svg>\n'+
      '  <div style="text-align:center;font-size:.82rem;font-weight:700;letter-spacing:.08em;color:white;margin-top:2px;text-transform:uppercase">Risk Score — MultiCloud &middot; '+esc(sBand)+'</div>\n'+
      '  </div>\n';
  })() +
  '  <div class="meta-row">\n' +
  '    <div class="meta-item"><strong>Prepared For</strong>'+esc(customer)+'</div>\n' +
  '    <div class="meta-item"><strong>Report Date</strong>'+dateStr+'</div>\n' +
  '    <div class="meta-item"><strong>Author</strong>'+esc(author)+'</div>\n' +
  '    <div class="meta-item"><strong>Classification</strong>Confidential</div>\n' +
  '  </div>\n</div>\n' +
  rcaIntroSection +
  '<div class="toc"><h3>Critical Risk Findings</h3><div class="dash-tile-grid">\n      '+tocCards+'\n</div></div>\n' +
  (function() {
    // Ring gauge (donut progress indicator) — replaces the old half-circle arc gauge to
    // match the new panel design. Circle math: r=52 → circumference ≈326.7; dashoffset
    // shrinks as score rises, rotated -90deg so the fill starts at 12 o'clock.
    function ringGauge(p) {
      const r = 52, circ = 2 * Math.PI * r;
      const offset = circ * (1 - Math.max(0, Math.min(100, p)) / 100);
      const c = scoreTierColor(p);
      return '<svg viewBox="0 0 120 120" width="108" height="108" style="flex-shrink:0">'+
        '<circle cx="60" cy="60" r="'+r+'" fill="none" stroke="#e5e7eb" stroke-width="11"/>'+
        '<circle cx="60" cy="60" r="'+r+'" fill="none" stroke="'+c+'" stroke-width="11" stroke-linecap="round" '+
          'stroke-dasharray="'+circ.toFixed(1)+'" stroke-dashoffset="'+offset.toFixed(1)+'" transform="rotate(-90 60 60)"/>'+
      '</svg>';
    }
    // Per-cloud "VIEW CRITICAL ISSUES" shortcut — deep-links to that cloud's own
    // Non-Compliance group when one exists (most common source of critical findings),
    // else falls back to the CIEM/Identity section so the button always goes somewhere useful.
    function cspCriticalIssuesHref(cspKey) {
      return (compByCloud[cspKey] || []).length ? '#non-compliance-'+cspKey : '#ciem-mfa';
    }
    function cspCard(label, bgColor, cspKey) {
      const p = cspScores[cspKey];
      const counts = cspCounts[cspKey] || { C:0, H:0, M:0, L:0 };
      const c = scoreTierColor(p), band = scoreTier(p);
      return '<div class="csp-card2">'+
        '<div class="csp-card2-top" style="background:'+bgColor+'"></div>'+
        '<div class="csp-card2-head">'+
          '<span style="font-size:13px;font-weight:900;letter-spacing:.08em;padding:6px 16px;border-radius:6px;color:#fff;background:'+bgColor+'">'+label+'</span>'+
          '<span class="csp-monitored">Monitored</span>'+
        '</div>'+
        '<div class="csp-ring-row">'+
          ringGauge(p)+
          '<div><div class="csp-ring-score" style="color:'+c+'">'+p+'</div>'+
          '<div class="csp-ring-max">/100</div>'+
          '<div class="csp-ring-tier">'+esc(band)+'</div></div>'+
        '</div>'+
        '<div class="csp-stats-box">'+
          '<div><div class="csn" style="color:var(--color-critical)">'+counts.C+'</div><div class="csl">Critical</div></div>'+
          '<div><div class="csn" style="color:var(--color-high)">'+counts.H+'</div><div class="csl">High</div></div>'+
          '<div><div class="csn" style="color:var(--color-medium)">'+counts.M+'</div><div class="csl">Medium</div></div>'+
          '<div><div class="csn" style="color:var(--color-success)">'+counts.L+'</div><div class="csl">Low</div></div>'+
        '</div>'+
        '<a href="'+cspCriticalIssuesHref(cspKey)+'" class="csp-cta-btn">View Critical Issues</a>'+
      '</div>';
    }
    const hasAws=cspScores.aws!==null, hasAzure=cspScores.azure!==null, hasGcp=cspScores.gcp!==null;
    const activeClouds = ['aws','azure','gcp'].filter(k => cspScores[k] !== null);
    const totalCritical = activeClouds.reduce((s,k) => s + ((cspCounts[k]||{}).C||0), 0);
    const totalIssues = activeClouds.reduce((s,k) => { const c=cspCounts[k]||{}; return s+(c.C||0)+(c.H||0)+(c.M||0)+(c.L||0); }, 0);
    const avgRiskScore = activeClouds.length ? Math.round(activeClouds.reduce((s,k) => s+cspScores[k], 0) / activeClouds.length) : 0;
    // No "pagebreak" class here — this section must stay on the cover page, directly
    // below the main MultiCloud gauge, not start a new printed page (see .report-cover
    // above and the section.pagebreak:first-of-type rule in REPORT_CSS).
    return '<section style="padding:1.5rem 2rem 2.5rem;display:flex;flex-direction:column">\n'+
      '<h2>2. Cloud Service Providers Security Risk Score</h2>\n'+
      statCalloutHtml('2026 Fortinet Cloud Security Report', '<strong>88%</strong> of organizations now operate across hybrid or multi-cloud environments, and <strong>81%</strong> rely on two or more cloud providers to run critical workloads — every additional provider adds its own configurations, permissions, and blind spots to track.') +
      fcSolutionHtml('CSPM + CIEM + CWPP &mdash; Unified Multi-Cloud Risk Correlation',
        'As cloud environments spread across multiple platforms and scale rapidly, the attack surface becomes increasingly fragmented. New accounts, workloads, identities, applications, and data stores are continuously created, making it challenging for security teams to maintain visibility, correlate risks, and respond effectively across complex cloud environments. FortiCNAPP correlates posture, identity, workload, and secrets findings from every connected cloud into one normalized Risk Score per provider, so fragmentation never becomes a blind spot.',
        'Review each cloud&rsquo;s score and Critical findings first, starting with the lowest-scoring provider.',
        'Track score trends over time per cloud, and re-baseline as new accounts, services, and regions are added.',
        ['One normalized 0-100 score per cloud, computed the same way across AWS, Azure, and GCP so scores are directly comparable', 'Aggregates Alerts, Misconfigurations, and Identity risk into a single per-cloud rollup'],
        ['Gives leadership a single, comparable risk metric across every cloud provider in use', 'Surfaces which cloud environment needs investment first, without manual cross-tool correlation']
      ) +
      '<div class="csp-panel">\n'+
      '<div class="csp-panel-title">Cloud Service Providers Security Risk Score</div>\n'+
      '<div class="csp-panel-subtitle">Real-Time CSPM Dashboard Across Multi-Cloud Environments</div>\n'+
      '<div class="csp-cards-row">\n'+
        (hasAws   ? cspCard('AWS',   '#232F3E', 'aws')   : '')+
        (hasAzure ? cspCard('Azure', '#0078D4', 'azure') : '')+
        (hasGcp   ? cspCard('GCP',   '#1a73e8', 'gcp')   : '')+
        (!hasAws && !hasAzure && !hasGcp ? '<div class="section-summary"><p>No per-cloud data detected in this assessment window.</p></div>' : '')+
      '</div>\n'+
      (activeClouds.length ? '<div class="csp-summary-strip">\n'+
        '<div><div class="css-num">'+totalCritical+'</div><div class="css-label">Total Critical Issues</div></div>\n'+
        '<div><div class="css-num">'+avgRiskScore+'</div><div class="css-label">Average Risk Score</div></div>\n'+
        '<div><div class="css-num">'+totalIssues+'</div><div class="css-label">Total Issues to Remediate</div></div>\n'+
        '<div><div class="css-num">'+activeClouds.length+'</div><div class="css-label">Cloud Providers Monitored</div></div>\n'+
      '</div>\n' : '')+
      '</div>\n</section>\n';
  })() +
  ciemSection + '\n' + secretsSshSection + '\n' + hostExposureSection + '\n' + storageSection + '\n' +
  privateVulnSection + '\n' + nonComplianceSection + '\n' +
  iamRolesSection + '\n' + serviceAccountsSection + '\n' + capabilityMappingSection + '\n' +
  '<div class="report-ending" style="page-break-before:always;background:#000;color:#fff;padding:48px 64px;display:flex;flex-direction:column;gap:32px">' +
  '<div style="text-align:center">' +
  '<div style="font-size:15px;font-weight:700;letter-spacing:.06em;margin-bottom:14px">Security Maturity Assessment Report - Powered by FortiCNAPP</div>' +
  '<div style="font-size:13px;color:#d1d5db;margin-bottom:10px">Prepared for: '+esc(customer)+' &nbsp;&middot;&nbsp; Report Date: '+dateStr+' &nbsp;&middot;&nbsp; Author: '+esc(author)+'</div>' +
  '<div style="font-size:11px;color:#6b7280">This is a beta report format and its layout/sections may change. Confidential — intended solely for the named recipient.</div>' +
  '</div></div>\n' +
  '<script>function fcUnlockSection(n){' +
    'var email=(document.getElementById("fc-lock-email-"+n).value||"").trim().toLowerCase();' +
    'if(/@fortinet\\.com$/.test(email)){' +
      'document.getElementById("fc-lock-"+n).style.display="none";' +
      'document.getElementById("fc-locked-content-"+n).style.display="block";' +
    '}else{' +
      'document.getElementById("fc-lock-error-"+n).style.display="block";' +
    '}' +
  '}</script>\n' +
  '</body>\n</html>';
}

// ── Report 3 (Cloud Overview) — condensed 4-page, chart-first summary for managers ──
// Reuses the same shared helpers as Report 1/2 (computeCspScores, computeAssetRiskMap,
// groupVulnsByHost via CIEM_SECRET_TYPES) so its numbers always match the detailed
// reports — just visualized instead of tabulated. No detail tables, no per-finding lists.
function buildReportHtml3(data, meta) {
  const customer = ((meta && meta.customer) || 'Customer').trim();
  const author   = ((meta && meta.author)   || 'Fortinet').trim();
  const dateStr  = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  const alerts      = data.alerts      || [];
  const vulns       = data.vulns       || [];
  const compliance  = governanceReportToComplianceRows(lastGovernanceReport) || data.compliance || [];
  const identities  = data.identities  || [];
  const secretsAll  = data.secretsAll  || [];
  const publicStorage = computeEffectivePublicStorage(data).findings;

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  const { cspScores, score, sBand } = computeCspScores(data);

  // ── Page 2: findings by category donut ─────────────────────────────────────
  const catCounts = [
    { key: 'Alerts',             n: alerts.length,     color: '#DA291C' },
    { key: 'CVEs',                n: vulns.length,      color: '#CC4A1A' },
    { key: 'Misconfigurations',  n: compliance.length,  color: '#B7770D' },
    { key: 'Identities',         n: identities.length,  color: '#2C5280' },
    { key: 'Secrets',            n: secretsAll.length,  color: '#7c3aed' },
  ];
  const catTotal = catCounts.reduce((s,c) => s + c.n, 0);
  const topCat = catCounts.reduce((a,b) => b.n > a.n ? b : a, catCounts[0]);

  function donutSvg(segs, total) {
    const R = 80, CIRC = 2 * Math.PI * R, GAP = 6;
    const active = segs.filter(s => s.n > 0).length || 1;
    const usable = CIRC - GAP * active;
    let cum = 0;
    const arcs = segs.map(s => {
      const len = total === 0 ? 0 : (s.n / total) * usable;
      const arc = '<circle cx="110" cy="110" r="'+R+'" fill="none" stroke="'+s.color+'" stroke-width="30" '+
        'stroke-dasharray="'+len.toFixed(1)+' '+(CIRC-len).toFixed(1)+'" stroke-dashoffset="'+(-cum).toFixed(1)+'" transform="rotate(-90 110 110)"/>';
      if (s.n > 0) cum += len + GAP;
      return arc;
    }).join('');
    return '<svg viewBox="0 0 220 220" style="width:220px;height:220px;flex-shrink:0">'+
      '<circle cx="110" cy="110" r="'+R+'" fill="none" stroke="#e2e8f0" stroke-width="30"/>'+
      arcs+
      '<text x="110" y="104" text-anchor="middle" font-size="40" font-weight="900" font-family="-apple-system,Inter,sans-serif" fill="#1e293b">'+total+'</text>'+
      '<text x="110" y="126" text-anchor="middle" font-size="10" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="#64748b" letter-spacing=".05em">TOTAL FINDINGS</text>'+
    '</svg>';
  }

  // ── Page 3: identity classification (duplicated from buildReportHtml2 — report
  // builders are independently maintained, see module docstring) ────────────────
  function isServiceAccount(r) {
    const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase(), p=(r.PROVIDER_TYPE||'').toLowerCase();
    return pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||p.includes('serviceprincipal')||p.includes('aad');
  }
  function isRoleType(r) {
    const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase();
    return (pid.includes(':role/')||pid.includes(':assumed-role/')||nm.includes('role')) && !isServiceAccount(r);
  }
  function unusedPctOf(r) {
    const ec = r.ENTITLEMENT_COUNTS || {};
    const unusedCnt = ec.entitlements_unused_count, totalCnt = ec.entitlements_total_count || ec.entitlements_count;
    return ec.entitlements_unused_percentage != null ? ec.entitlements_unused_percentage
      : (unusedCnt != null && totalCnt ? (unusedCnt/totalCnt)*100 : null);
  }
  function isHighPermissive(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    const sev = (r.METRICS && r.METRICS.risk_severity || '').toLowerCase();
    return risks.includes('ALLOWS_FULL_ADMIN') || risks.includes('EXCESSIVE_PERMISSIONS') || sev === 'critical' || sev === 'high';
  }
  function isNoMfa(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    return risks.includes('PASSWORD_LOGIN_NO_MFA') || !r.MFA_ENABLED;
  }
  const adminUserCount = identities.filter(r => !isServiceAccount(r) && !isRoleType(r) && isHighPermissive(r) && isNoMfa(r)).length;
  const iamRoleCount = identities.filter(r => { const up=unusedPctOf(r); return isRoleType(r) && isHighPermissive(r) && up!=null && up>=80; }).length;
  const serviceAccountCount = identities.filter(r => { const up=unusedPctOf(r); return isServiceAccount(r) && isHighPermissive(r) && up!=null && up>=80; }).length;
  const ciemSet = {}; CIEM_SECRET_TYPES.forEach(t => ciemSet[t] = true);
  const ciemSecretCount = secretsAll.filter(r => ciemSet[(r.SECRET_TYPE||'').toUpperCase()]).length;
  const genericSecretCount = secretsAll.length - ciemSecretCount;

  function statTile(n, label, color) {
    return '<div style="flex:1;min-width:150px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:22px 16px;text-align:center">'+
      '<div style="font-size:38px;font-weight:900;color:'+color+'">'+n+'</div>'+
      '<div style="font-size:10.5px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:8px;line-height:1.4">'+label+'</div>'+
    '</div>';
  }

  // ── Page 4: top risk assets — Internet-Exposed Hosts + Publicly Accessible Storage
  // ONLY (not the full correlated-risk asset list — see computeAssetRiskMap for that) ──
  const { map: assetMap } = computeAssetRiskMap(vulns, secretsAll, compliance);
  const exposedHosts = Object.values(assetMap)
    .filter(a => a.internetExposed)
    .sort((a,b) => b.normalizedScore - a.normalizedScore);
  function driverTag(a) {
    const drivers = [];
    if (a.ciem > 0) drivers.push('CIEM credential');
    if (a.secretRisk > 0) drivers.push('secret');
    if (a.threatRisk > 0) drivers.push('CVE exposure');
    if (a.miscRisk > 0) drivers.push('misconfiguration');
    return drivers.join(', ') || '—';
  }
  const exposedHostsHtml = exposedHosts.length ? exposedHosts.map(a => {
    const tier = assetRiskTier(a.normalizedScore, a.internetExposed);
    return '<div style="display:flex;align-items:center;gap:16px;padding:14px 18px;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:10px">'+
      '<div style="width:64px;text-align:center;flex-shrink:0">'+
        '<div style="font-size:22px;font-weight:900;color:'+tier.color+'">'+a.normalizedScore+'</div>'+
        '<div style="font-size:8px;font-weight:800;letter-spacing:.05em;color:'+tier.color+'">'+tier.label+'</div>'+
      '</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:#1e293b;word-break:break-word">'+esc(a.name)+' <span style="font-size:9px;font-weight:800;color:#fff;background:#DA291C;border-radius:3px;padding:1px 6px;margin-left:4px;vertical-align:middle">INTERNET-EXPOSED</span></div>'+
        '<div style="font-size:11px;color:#64748b;margin-top:2px">Driven by: '+esc(driverTag(a))+'</div>'+
      '</div>'+
    '</div>';
  }).join('') : '<div class="section-summary"><p>No internet-exposed hosts with correlated risk data were found in this assessment window.</p></div>';

  const publicStorageHtml = publicStorage.length ? publicStorage.map(s => {
    const isConfirmed = (s.severity||'critical') === 'critical';
    return '<div style="display:flex;align-items:center;gap:16px;padding:14px 18px;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:10px">'+
      '<div style="width:78px;text-align:center;flex-shrink:0">'+
        '<span style="font-size:9px;font-weight:800;letter-spacing:.05em;color:#fff;background:'+(isConfirmed?'#DA291C':'#CC4A1A')+';border-radius:4px;padding:3px 6px;white-space:nowrap">'+(isConfirmed?'PUBLIC':'VERIFIED PATH')+'</span>'+
      '</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:#1e293b;word-break:break-word">'+esc(s.name)+' <span style="font-size:9px;font-weight:800;color:#fff;background:'+cspBadgeColor3(s.cloud)+';border-radius:3px;padding:1px 6px;margin-left:4px;vertical-align:middle">'+esc((s.cloud||'').toUpperCase())+'</span></div>'+
        '<div style="font-size:11px;color:#64748b;margin-top:2px">'+esc(s.resourceType||'Object storage')+' &middot; account: '+esc(s.account||'—')+'</div>'+
      '</div>'+
    '</div>';
  }).join('') : '<div class="section-summary"><p>No publicly accessible storage was found in this assessment window.</p></div>';
  function cspBadgeColor3(c){ return {aws:'#FF9900',azure:'#0078D4',gcp:'#4285F4'}[c]||'#94a3b8'; }

  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
  '  <meta charset="UTF-8">\n' +
  '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
  '  <title>Cloud Overview Report – '+esc(customer)+'</title>\n' +
  '  <style type="text/css">\n' + REPORT_CSS + '\n' +
  '  </style>\n</head>\n<body>\n' +
  reportTopbarHtml('Cloud Overview') + '\n' +
  '<button type="button" class="pdf-export-btn no-print" onclick="window.print()">&#128196; Export to PDF</button>\n' +
  '<div class="report-cover">\n' +
  '  <div class="report-type">Rapid Cloud Assessment · Cloud Overview</div>\n' +
  '  <h1>Cloud Security Overview</h1>\n' +
  '  <div class="subtitle">'+esc(customer)+'</div>\n' +
  (function() {
    const arcLen=550, fill=Math.round((score/100)*arcLen);
    function miniGauge(label, bgColor, p) {
      const pv = p !== null ? p : 100;
      const arcL=314, f=Math.round((pv/100)*arcL);
      const c=scoreTierColor(pv);
      return '<div style="display:flex;flex-direction:column;align-items:center;gap:4px">'+
        '<div style="font-size:9px;font-weight:900;letter-spacing:.12em;padding:3px 10px;border-radius:4px;color:#fff;background:'+bgColor+'">'+label+'</div>'+
        '<svg viewBox="-10 -10 270 155" style="width:120px;overflow:visible">'+
          '<path fill="none" stroke="rgba(255,255,255,0.15)" stroke-width="14" stroke-linecap="round" d="M 25,120 A 100,100 0 0,1 225,120"/>'+
          '<path fill="none" stroke="'+c+'" stroke-width="14" stroke-linecap="round" stroke-dasharray="'+f+' '+arcL+'" d="M 25,120 A 100,100 0 0,1 225,120"/>'+
          '<text x="125" y="102" text-anchor="middle" font-size="36" font-weight="900" font-family="-apple-system,sans-serif" fill="'+c+'">'+pv+'</text>'+
        '</svg>'+
      '</div>';
    }
    return '  <div style="margin:1rem auto 0;max-width:380px;width:100%">\n'+
      '  <svg viewBox="0 0 400 240" style="display:block;width:100%;overflow:visible">\n'+
      '    <defs><linearGradient id="rg3" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">'+
      '<stop offset="0%" stop-color="#ef4444"/><stop offset="20.6%" stop-color="#ef4444"/>'+
      '<stop offset="20.6%" stop-color="#f59e0b"/><stop offset="65.45%" stop-color="#f59e0b"/>'+
      '<stop offset="65.45%" stop-color="#22c55e"/><stop offset="90.45%" stop-color="#22c55e"/>'+
      '<stop offset="90.45%" stop-color="#3b82f6"/><stop offset="100%" stop-color="#3b82f6"/>'+
      '</linearGradient></defs>\n'+
      '    <path fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <path fill="none" stroke="url(#rg3)" stroke-width="34" stroke-linecap="round" stroke-dasharray="'+fill+' '+arcLen+'" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <line x1="86" y1="48" x2="108" y2="79"   stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="260" y1="20" x2="248" y2="57"  stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="357" y1="91" x2="326" y2="113" stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <text x="200" y="165" text-anchor="middle" font-size="72" font-weight="900" letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="white">'+score+'</text>\n'+
      '    <text x="-8" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">0</text>\n'+
      '    <text x="408" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">100</text>\n'+
      '  </svg>\n'+
      '  <div style="text-align:center;font-size:.82rem;font-weight:700;letter-spacing:.08em;color:white;margin-top:2px;text-transform:uppercase">Cloud Security Risk Score — '+esc(sBand)+'</div>\n'+
      '  </div>\n'+
      '  <div style="display:flex;justify-content:center;gap:28px;margin-top:1.5rem;flex-wrap:wrap">\n'+
        miniGauge('AWS', '#232F3E', cspScores.aws)+
        miniGauge('AZURE', '#0078D4', cspScores.azure)+
        miniGauge('GCP', '#1a73e8', cspScores.gcp)+
      '  </div>\n';
  })()+
  '  <div class="meta-row">\n' +
  '    <div class="meta-item"><strong>Prepared For</strong>'+esc(customer)+'</div>\n' +
  '    <div class="meta-item"><strong>Report Date</strong>'+dateStr+'</div>\n' +
  '    <div class="meta-item"><strong>Author</strong>'+esc(author)+'</div>\n' +
  '    <div class="meta-item"><strong>Classification</strong>Confidential</div>\n' +
  '  </div>\n</div>\n' +
  '<section class="pagebreak" style="padding:2.5rem 2rem;min-height:60vh">\n'+
  '  <h2>2. Risk Findings Overview</h2>\n'+
  '  <p style="color:#5A5A5A;margin-bottom:24px;font-size:12px">Every finding discovered across this assessment window, grouped by category.</p>\n'+
  '  <div style="display:flex;align-items:center;gap:48px;flex-wrap:wrap;justify-content:center">\n'+
      donutSvg(catCounts, catTotal)+
  '    <div>\n'+
        catCounts.map(c => '<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'+
          '<span style="width:12px;height:12px;border-radius:3px;background:'+c.color+';flex-shrink:0"></span>'+
          '<span style="font-size:13px;color:#1e293b;min-width:140px">'+esc(c.key)+'</span>'+
          '<span style="font-size:13px;font-weight:800;color:#1e293b">'+c.n+'</span>'+
        '</div>').join('')+
  '    </div>\n'+
  '  </div>\n'+
  (catTotal > 0 ? '  <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1rem 1.5rem;margin-top:2rem;font-size:.85rem;color:#64748b;text-align:center">Largest contributor: <strong style="color:#1e293b">'+esc(topCat.key)+'</strong> ('+topCat.n+' of '+catTotal+' findings)</div>\n' : '')+
  '</section>\n'+
  '<section class="pagebreak" style="padding:2.5rem 2rem;min-height:60vh">\n'+
  '  <h2>3. Identity &amp; Secrets Snapshot</h2>\n'+
  '  <p style="color:#5A5A5A;margin-bottom:24px;font-size:12px">High-permissive identities and exposed credentials found across all connected cloud accounts.</p>\n'+
  '  <div style="display:flex;gap:16px;flex-wrap:wrap">\n'+
      statTile(adminUserCount, 'High-Permissive Users, No MFA', '#DA291C')+
      statTile(iamRoleCount, 'High-Permissive IAM / RBAC Roles', '#CC4A1A')+
      statTile(serviceAccountCount, 'High-Permissive Service Accounts', '#B7770D')+
      statTile(ciemSecretCount, 'CIEM Credentials Exposed', '#7c3aed')+
      statTile(genericSecretCount, 'Other Secrets Found', '#2C5280')+
  '  </div>\n'+
  '</section>\n'+
  '<section class="pagebreak" style="padding:2.5rem 2rem;min-height:60vh">\n'+
  '  <h2>4. Top Risk Assets</h2>\n'+
  '  <p style="color:#5A5A5A;margin-bottom:20px;font-size:12px">The two attack surfaces most likely to be actively targeted: internet-exposed hosts and publicly accessible storage.</p>\n'+
  '  <div style="font-size:12px;font-weight:800;color:#1e293b;text-transform:uppercase;letter-spacing:.05em;margin-bottom:10px">Internet-Exposed Hosts ('+exposedHosts.length+')</div>\n'+
      exposedHostsHtml+
  '  <div style="font-size:12px;font-weight:800;color:#1e293b;text-transform:uppercase;letter-spacing:.05em;margin:20px 0 10px">Storage with Public Access ('+publicStorage.length+')</div>\n'+
      publicStorageHtml+
  '  <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:1.2rem 1.5rem;margin-top:1.5rem">\n'+
  '    <div style="font-size:12px;font-weight:800;color:#1e293b;margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">Recommended Next Steps</div>\n'+
  '    <div style="font-size:12px;color:#475569;line-height:1.9">'+
        '1. Rotate or revoke exposed CIEM credentials and secrets on the highest-risk assets above.<br>'+
        '2. Enforce MFA for every high-permissive user identified in the Identity &amp; Secrets snapshot.<br>'+
        '3. Prioritize patching for internet-exposed hosts carrying Critical CVEs before addressing internal-only findings.'+
  '    </div>\n'+
  '  </div>\n'+
  '</section>\n'+
  '<div class="report-ending" style="page-break-before:always;background:#000;color:#fff;padding:48px 64px;display:flex;flex-direction:column;gap:32px">' +
  '<div style="text-align:center">' +
  '<div style="font-size:15px;font-weight:700;letter-spacing:.06em;margin-bottom:14px">RAPID CLOUD ASSESSMENT — CLOUD OVERVIEW &mdash; Powered by FortiCNAPP</div>' +
  '<div style="font-size:13px;color:#d1d5db;margin-bottom:10px">Prepared for: '+esc(customer)+' &nbsp;&middot;&nbsp; Report Date: '+dateStr+' &nbsp;&middot;&nbsp; Author: '+esc(author)+'</div>' +
  '<div style="font-size:11px;color:#6b7280">This report is confidential and intended solely for the named recipient. For the full detailed findings, see the Cloud Security Report.</div>' +
  '</div>' +
  '</div>\n</body>\n</html>';
}

// ── /report4 (BETA) — narrative assessment-style report: Scope & Objectives, Cloud
// Environment Overview, Assessment Methodology, Risk Findings Categories, Evidence &
// Affected Assets, Internet Exposed Resources, Immediate & Long-Term Actions. Reuses the
// shared helpers (computeCspScores, computeAssetRiskMap, computeEffectivePublicStorage,
// groupVulnsByHost, tocCardHtml, REPORT_CSS) rather than duplicating their logic — only the
// identity classification helpers are local to this builder, per the "independently
// maintained report builders" convention documented above. Section 4's four categories are
// curated, not a keyword classifier over every finding type — see the section comment below.
function buildReportHtml4(data, meta) {
  const customer = ((meta && meta.customer) || 'Customer').trim();
  const author   = ((meta && meta.author)   || 'Fortinet').trim();
  const dateStr  = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  const alerts      = data.alerts      || [];
  const vulns       = data.vulns       || [];
  const compliance  = governanceReportToComplianceRows(lastGovernanceReport) || data.compliance || [];
  const identities  = data.identities  || [];
  const secretsAll  = data.secretsAll  || [];
  const publicStorage = computeEffectivePublicStorage(data).findings;

  function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function fmt(ts) { if (!ts) return '—'; try { return new Date(ts).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'}); } catch(_) { return String(ts); } }
  function sevBadge(s) { const m={critical:'badge-critical',high:'badge-high',medium:'badge-medium',low:'badge-low'}; return '<span class="badge '+(m[(s||'').toLowerCase()]||'badge-info')+'">'+esc(s||'—')+'</span>'; }
  function cspBadge(c) { const m={aws:'badge-aws',azure:'badge-azure',gcp:'badge-gcp'}; return '<span class="badge '+(m[(c||'').toLowerCase()]||'badge-info')+'">'+esc((c||'').toUpperCase()||'—')+'</span>'; }

  const { cspScores, cspCounts, score, sBand } = computeCspScores(data);

  // ── Identity classification (duplicated per-report convention — see module docstring) ──
  function isServiceAccount(r) {
    const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase(), p=(r.PROVIDER_TYPE||'').toLowerCase();
    return pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com')||p.includes('serviceprincipal')||p.includes('aad');
  }
  function isRoleType(r) {
    const pid=(r.PRINCIPAL_ID||'').toLowerCase(), nm=(r.NAME||'').toLowerCase();
    return (pid.includes(':role/')||pid.includes(':assumed-role/')||nm.includes('role')) && !isServiceAccount(r);
  }
  function isHighPermissive(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    const sev = (r.METRICS && r.METRICS.risk_severity || '').toLowerCase();
    return risks.includes('ALLOWS_FULL_ADMIN') || risks.includes('EXCESSIVE_PERMISSIONS') || sev === 'critical' || sev === 'high';
  }
  function isNoMfa(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    return risks.includes('PASSWORD_LOGIN_NO_MFA') || !r.MFA_ENABLED;
  }
  function identityLabel(r) { return r.NAME || (r.PRINCIPAL_ID||'').split('/').pop() || r.PRINCIPAL_ID || '—'; }
  function cloudOfIdentity(r) {
    const p = (r.PROVIDER_TYPE||'').toLowerCase(), pid = (r.PRINCIPAL_ID||'').toLowerCase();
    if (p.includes('aws') || pid.includes('arn:aws')) return 'aws';
    if (p.includes('azure') || p.includes('aad') || p.includes('serviceprincipal')) return 'azure';
    if (p.includes('gcp') || p.includes('google') || pid.includes('.iam.gserviceaccount.com')) return 'gcp';
    return 'other';
  }
  // "Admin Users Without MFA" means exactly that: true full-admin (ALLOWS_FULL_ADMIN),
  // not the broader isHighPermissive() (which also fires on EXCESSIVE_PERMISSIONS or a
  // plain critical/high risk_severity) — and excludes cloud root accounts, which show up
  // as noisy near-duplicate "root — no MFA" rows across every AWS account and are rarely
  // the actionable finding here.
  function isFullAdmin(r) {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    return risks.includes('ALLOWS_FULL_ADMIN');
  }
  function isRootAccount(r) {
    const pid = (r.PRINCIPAL_ID||'').toLowerCase(), nm = (r.NAME||'').toLowerCase();
    return nm === 'root' || pid.endsWith(':root');
  }
  const adminNoMfaRows = identities.filter(r => !isServiceAccount(r) && !isRoleType(r) && !isRootAccount(r) && isFullAdmin(r) && isNoMfa(r));
  const highPermRoleRows = identities.filter(r => isRoleType(r) && isHighPermissive(r));
  const { exposedCount: exposedHostCount, internalCount: internalHostCount } = groupVulnsByHost(vulns);

  // ── Section 5 data, computed early so Section 4 can reference it: per-host correlated
  // risk, tying every finding type back to the resource it was found on. ──
  const { map: assetMap } = computeAssetRiskMap(vulns, secretsAll, compliance);
  const evidenceAssets = Object.values(assetMap).filter(a => a.risk > 0).sort((a,b) => b.normalizedScore - a.normalizedScore).slice(0, 15);

  // Secrets found specifically on hosts already confirmed internet-exposed — matching
  // heuristic mirrors computeAssetRiskMap's own hostname-prefix matching above. Computed
  // early so both Section 4 (categories) and Section 6d (detail table) can reuse it.
  const exposedNames = Object.keys(assetMap).filter(k => assetMap[k].internetExposed).map(k => k.toLowerCase());
  function hostIsExposed(hostname) {
    const h = (hostname||'').toLowerCase(); if (!h) return false;
    return exposedNames.some(k => k===h || h.indexOf(k)===0 || k.indexOf(h.split('.')[0])===0);
  }
  const exposedHostSecrets = secretsAll.filter(r => hostIsExposed(r.HOSTNAME));

  // ── Section 2: Cloud Environment Overview — list only clouds actually observed in this
  // tenant's data. This integration has no OCI data source, so OCI is never claimed here. ──
  const cloudLabel = { aws: 'AWS', azure: 'Microsoft Azure', gcp: 'Google Cloud Platform' };
  const cloudsSeen = ['aws','azure','gcp'].filter(c => cspScores[c] !== null);
  const cloudsListStr = cloudsSeen.length
    ? cloudsSeen.map(c => cloudLabel[c]).join(cloudsSeen.length > 1 ? ', ' : '')
    : 'AWS, Microsoft Azure, and Google Cloud Platform';

  // ── Section 4: Risk Findings Categories — four curated categories (not a keyword
  // classifier over every finding type): Identity & Access is scoped to admin/no-MFA
  // identities and high-permission roles only, Misconfiguration is Critical-severity
  // compliance findings only, and the other two mirror Section 6's exposure evidence. ──
  const CONTROL_AREAS = ['Identity & Access','Misconfiguration (Critical)','Secrets on Exposed Host','Internet Accessible Storage'];
  const AREA_COLORS = { 'Identity & Access':'#8b5cf6', 'Misconfiguration (Critical)':'#B7770D', 'Secrets on Exposed Host':'#0ea5e9', 'Internet Accessible Storage':'#f97316' };
  const controlAreaBuckets = {}; CONTROL_AREAS.forEach(a => controlAreaBuckets[a] = []);
  adminNoMfaRows.forEach(r => controlAreaBuckets['Identity & Access'].push({ title: identityLabel(r)+' — Admin, no MFA', severity: 'Critical', source: 'Admin' }));
  highPermRoleRows.forEach(r => controlAreaBuckets['Identity & Access'].push({ title: identityLabel(r)+' — high-permission role', severity: 'High', source: 'Role' }));
  compliance.filter(r => (r.severity||'').toLowerCase() === 'critical').forEach(r => controlAreaBuckets['Misconfiguration (Critical)'].push({ title: r.title||r.alertId||'Misconfiguration', severity: 'Critical', source: 'Misconfiguration' }));
  exposedHostSecrets.forEach(r => controlAreaBuckets['Secrets on Exposed Host'].push({ title: (r.SECRET_TYPE||'Secret')+' on '+(r.HOSTNAME||'unknown host'), severity: 'High', source: 'Secret' }));
  publicStorage.forEach(r => controlAreaBuckets['Internet Accessible Storage'].push({ title: (r.name||'—')+' — public access', severity: r.severity||'critical', source: 'Public Storage' }));
  const sevRank = s => ({critical:0,high:1,medium:2,low:3}[(s||'').toLowerCase()] ?? 4);
  const controlAreaSummary = CONTROL_AREAS.map(area => {
    const items = controlAreaBuckets[area].slice().sort((a,b) => sevRank(a.severity)-sevRank(b.severity));
    return { area, items, count: items.length, color: AREA_COLORS[area] };
  });
  const controlAreaTotal = controlAreaSummary.reduce((s,a) => s+a.count, 0);
  function driverTag(a) {
    const drivers = [];
    if (a.ciem > 0) drivers.push(a.ciemSecrets.length+' CIEM credential'+(a.ciemSecrets.length===1?'':'s'));
    if (a.secretRisk > 0) drivers.push(a.genericSecrets.length+' secret'+(a.genericSecrets.length===1?'':'s'));
    if (a.threatRisk > 0) drivers.push(a.vulns.length+' CVE'+(a.vulns.length===1?'':'s'));
    if (a.miscRisk > 0) drivers.push('critical misconfiguration exposure');
    return drivers.join(', ') || '—';
  }
  const evidenceRowsHtml = evidenceAssets.length ? evidenceAssets.map((a,i) => {
    const tier = assetRiskTier(a.normalizedScore, a.internetExposed);
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td><strong>'+esc(a.name)+'</strong></td>'+
      '<td style="text-align:center">'+(a.internetExposed?'<span class="badge badge-critical">Internet-Exposed</span>':'<span class="badge badge-info">Private</span>')+'</td>'+
      '<td style="text-align:center"><span class="risk-chip'+(a.normalizedScore>=75?' high':'')+'">'+a.normalizedScore+'</span></td>'+
      '<td style="text-align:center;color:'+tier.color+';font-weight:700">'+tier.label+'</td>'+
      '<td class="wide">'+esc(driverTag(a))+'</td>'+
    '</tr>';
  }).join('') : '<tr><td colspan="5" style="text-align:center;color:#999;padding:1.5rem">No correlated-risk assets were found in this assessment window</td></tr>';

  // ── Section 6: Internet Exposed Resources — hosts, storage, admin/no-MFA, and secrets
  // found specifically on internet-exposed hosts. ──
  const exposedHosts = evidenceAssets.filter(a => a.internetExposed);
  // Individual risk findings behind a host's "Driven by:" summary — re-joined from the raw
  // vulns/secretsAll arrays (not assetMap's aggregated ciemSecrets/genericSecrets/vulns,
  // which only carry a type string and a score) so the detail column can show package/fix
  // version for CVEs and absolute file path for secrets. Host-key matching mirrors
  // computeAssetRiskMap's own join logic exactly, so results line up with the score above.
  function vulnHostKey(r) {
    const mt = r.machineTags;
    const mtObj = (mt && typeof mt === 'object' && !Array.isArray(mt)) ? mt : null;
    return (mtObj && mtObj.Hostname) || (r.evalCtx && r.evalCtx.hostname) || r.mid || '';
  }
  function hostSecretDetails(hostName) {
    const kl = (hostName||'').toLowerCase();
    return secretsAll.filter(r => {
      const sh = (r.HOSTNAME||'').toLowerCase();
      if (!sh) return false;
      return kl===sh || sh.indexOf(kl)===0 || kl.indexOf(sh.split('.')[0])===0;
    });
  }
  const ciemTypeSet = {}; CIEM_SECRET_TYPES.forEach(t => ciemTypeSet[t] = true);
  function hostFindingsHtml(a) {
    const rows = [];
    hostSecretDetails(a.name).forEach(r => {
      const isCiem = ciemTypeSet[(r.SECRET_TYPE||'').toUpperCase()];
      rows.push({ label: r.SECRET_TYPE||'Secret', type: isCiem?'CIEM Credential':'Secret', detail: r.FILE_PATH||'—', severity: isCiem?'Critical':'High' });
    });
    vulns.filter(r => vulnHostKey(r) === a.name)
      .slice()
      .sort((x,y) => parseFloat(y.cveRiskScore??y.riskScore??0) - parseFloat(x.cveRiskScore??x.riskScore??0))
      .forEach(r => {
        const score = parseFloat(r.cveRiskScore ?? r.riskScore ?? 0);
        const pkg = (r.featureKey && r.featureKey.name) || 'unknown package';
        const ver = (r.featureKey && r.featureKey.version) || '';
        const fixVer = (r.fixInfo && r.fixInfo.fixed_version) || '';
        const detail = pkg+(ver?' '+ver:'')+(fixVer ? ' → '+fixVer : ((r.fixInfo && r.fixInfo.fix_available) ? ' — fix available' : ' — no fix available'));
        rows.push({ label: r.vulnId||r.cveId||'CVE', type: 'CVE — Risk '+score.toFixed(1), detail, severity: score>=9?'Critical':'High' });
      });
    if (a.miscRisk > 0) rows.push({ label: 'Critical misconfiguration exposure (account-wide)', type: 'Misconfiguration', detail: '—', severity: 'Critical' });
    if (!rows.length) return '<p style="text-align:center;color:#999;font-size:11px;padding:10px 0">No individual findings recorded</p>';
    return '<table class="exec-table" style="margin-top:8px"><thead><tr><th>Finding</th><th style="width:150px">Type</th><th>Detail</th><th style="width:80px">Severity</th></tr></thead><tbody>'+
      rows.map(r => '<tr><td class="wide">'+esc(r.label)+'</td><td class="m">'+esc(r.type)+'</td><td class="m">'+esc(r.detail||'—')+'</td><td>'+sevBadge(r.severity)+'</td></tr>').join('')+
    '</tbody></table>';
  }
  const exposedHostsHtml = exposedHosts.length ? exposedHosts.map(a => {
    const tier = assetRiskTier(a.normalizedScore, a.internetExposed);
    const findingCount = (a.ciemSecrets||[]).length + (a.genericSecrets||[]).length + (a.vulns||[]).length + (a.miscRisk>0?1:0);
    return '<details style="border:1px solid #e2e8f0;border-radius:8px;margin-bottom:10px">'+
      '<summary style="cursor:pointer;padding:14px 18px;display:flex;align-items:center;gap:16px">'+
        '<div style="width:64px;text-align:center;flex-shrink:0">'+
          '<div style="font-size:22px;font-weight:900;color:'+tier.color+'">'+a.normalizedScore+'</div>'+
          '<div style="font-size:8px;font-weight:800;letter-spacing:.05em;color:'+tier.color+'">'+tier.label+'</div>'+
        '</div>'+
        '<div style="flex:1;min-width:0">'+
          '<div style="font-size:13px;font-weight:700;color:#1e293b;word-break:break-word">'+esc(a.name)+'</div>'+
          '<div style="font-size:11px;color:#64748b;margin-top:2px">Driven by: '+esc(driverTag(a))+'</div>'+
        '</div>'+
        '<div style="font-size:10.5px;font-weight:700;color:#DA291C;white-space:nowrap;flex-shrink:0">'+findingCount+' finding'+(findingCount===1?'':'s')+' — expand</div>'+
      '</summary>'+
      '<div style="padding:0 18px 16px 98px">'+hostFindingsHtml(a)+'</div>'+
    '</details>';
  }).join('') : '<div class="section-summary"><p>No internet-exposed hosts with correlated risk data were found in this assessment window.</p></div>';

  function cspBadgeColor4(c){ return {aws:'#FF9900',azure:'#0078D4',gcp:'#4285F4'}[c]||'#94a3b8'; }
  const publicStorageHtml = publicStorage.length ? publicStorage.map(s => {
    const isConfirmed = (s.severity||'critical') === 'critical';
    return '<div style="display:flex;align-items:center;gap:16px;padding:14px 18px;border:1px solid #e2e8f0;border-radius:8px;margin-bottom:10px">'+
      '<div style="width:96px;text-align:center;flex-shrink:0">'+
        '<span style="font-size:9px;font-weight:800;letter-spacing:.05em;color:#fff;background:'+(isConfirmed?'#DA291C':'#CC4A1A')+';border-radius:4px;padding:3px 6px;white-space:nowrap">'+(isConfirmed?'PUBLIC':'VERIFIED PATH')+'</span>'+
      '</div>'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:700;color:#1e293b;word-break:break-word">'+esc(s.name)+' <span style="font-size:9px;font-weight:800;color:#fff;background:'+cspBadgeColor4(s.cloud)+';border-radius:3px;padding:1px 6px;margin-left:4px;vertical-align:middle">'+esc((s.cloud||'').toUpperCase())+'</span></div>'+
        '<div style="font-size:11px;color:#64748b;margin-top:2px">'+esc(s.resourceType||'Object storage')+' &middot; account: '+esc(s.account||'—')+'</div>'+
      '</div>'+
    '</div>';
  }).join('') : '<div class="section-summary"><p>No publicly accessible storage was found in this assessment window.</p></div>';

  const adminNoMfaRowsHtml = adminNoMfaRows.length ? adminNoMfaRows.map((r,i) => {
    const risks = (r.METRICS && r.METRICS.risks) || [];
    const isAdmin = risks.includes('ALLOWS_FULL_ADMIN');
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td><strong>'+esc(identityLabel(r))+'</strong><br><small class="text-muted">'+esc(r.PRINCIPAL_ID||'')+'</small></td>'+
      '<td>'+cspBadge(cloudOfIdentity(r))+'</td>'+
      '<td>'+(isAdmin?'<span class="badge badge-critical">Admin</span>':'<span class="badge badge-high">Privileged</span>')+'</td>'+
      '<td>'+(r.LAST_USED_TIME?fmt(r.LAST_USED_TIME):'<span class="text-muted">Never / Unknown</span>')+'</td>'+
    '</tr>';
  }).join('') : '<tr><td colspan="4" style="text-align:center;color:#999;padding:1.5rem">No high-privilege identities without MFA were found</td></tr>';

  // exposedHostSecrets was already computed above (Section 4 needs it too).
  const exposedHostSecretsHtml = exposedHostSecrets.length ? exposedHostSecrets.map((r,i) => '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td><strong>'+esc(r.HOSTNAME||'—')+'</strong></td>'+
      '<td><span class="badge badge-critical">'+esc(r.SECRET_TYPE||'—')+'</span></td>'+
      '<td class="wide"><code style="font-size:0.8rem">'+esc(r.SECRET_IDENTIFIER||'—')+'</code></td>'+
    '</tr>').join('') : '<tr><td colspan="3" style="text-align:center;color:#999;padding:1.5rem">No secrets were found on internet-exposed hosts</td></tr>';

  // ── Section 7: Immediate and Long-Term Actions — every bullet is conditional on real
  // findings above; nothing here is fabricated boilerplate. ──
  const immediateActions = [];
  if (exposedHosts.length) immediateActions.push('Patch or isolate the '+exposedHosts.length+' internet-exposed host'+(exposedHosts.length===1?'':'s')+' carrying correlated risk before addressing internal-only findings.');
  if (publicStorage.length) immediateActions.push('Restrict public access on the '+publicStorage.length+' publicly accessible storage resource'+(publicStorage.length===1?'':'s')+' identified in this assessment.');
  if (adminNoMfaRows.length) immediateActions.push('Enforce MFA immediately for the '+adminNoMfaRows.length+' high-privilege identit'+(adminNoMfaRows.length===1?'y':'ies')+' currently authenticating without it.');
  if (exposedHostSecrets.length) immediateActions.push('Rotate or revoke the '+exposedHostSecrets.length+' secret'+(exposedHostSecrets.length===1?'':'s')+' discovered on internet-exposed hosts — treat as compromised.');
  if (!immediateActions.length) immediateActions.push('No immediate, internet-reachable exposures were identified in this assessment window — proceed with the long-term hardening actions below.');

  const longTermActions = [];
  if (controlAreaBuckets['Identity & Access'].length) longTermActions.push('Adopt least-privilege IAM/RBAC roles and periodic access reviews; retire unused entitlements flagged in this assessment.');
  if (exposedHostCount > 0) longTermActions.push('Review inbound security-group/NSG/firewall rules and remove overly permissive (0.0.0.0/0) allowances.');
  if (controlAreaBuckets['Misconfiguration (Critical)'].length) longTermActions.push('Remediate the flagged Critical misconfigurations and re-scan to confirm closure.');
  if (controlAreaBuckets['Internet Accessible Storage'].length) longTermActions.push('Apply default-deny public-access policies on cloud storage and audit bucket/container ACLs on a recurring schedule.');
  if (controlAreaBuckets['Secrets on Exposed Host'].length) longTermActions.push('Adopt automated secret scanning and rotation policies for internet-facing cloud workloads.');
  if (!longTermActions.length) longTermActions.push('Maintain current controls and re-run this assessment periodically to catch newly introduced risk.');
  longTermActions.push('Re-run this Rapid Cloud Assessment on a recurring cadence to track remediation progress over time.');

  // ── TOC ──────────────────────────────────────────────────────────────────────
  const tocCards = [
    tocCardHtml('#control-areas', controlAreaTotal, '#8b5cf6', '04 — Categories', 'Risk Findings Categories', 'finding'+(controlAreaTotal===1?'':'s')+' across identity, misconfigurations, secrets &amp; storage'),
    tocCardHtml('#evidence', evidenceAssets.length, '#DA291C', '05 — Evidence', 'Evidence &amp; Affected Assets', 'asset'+(evidenceAssets.length===1?'':'s')+' with correlated risk'),
    tocCardHtml('#exposed-hosts', exposedHosts.length, '#f97316', '06a — Hosts', 'Internet-Exposed Hosts', 'host'+(exposedHosts.length===1?'':'s')+' reachable from the internet'),
    tocCardHtml('#exposed-storage', publicStorage.length, '#CC4A1A', '06b — Storage', 'Publicly Accessible Storage', 'resource'+(publicStorage.length===1?'':'s')+' with public access'),
    tocCardHtml('#exposed-admin', adminNoMfaRows.length, '#ef4444', '06c — Admin', 'Admin Users Without MFA', 'identit'+(adminNoMfaRows.length===1?'y':'ies')),
    tocCardHtml('#exposed-secrets', exposedHostSecrets.length, '#0ea5e9', '06d — Secrets', 'Secrets on Exposed Hosts', 'secret'+(exposedHostSecrets.length===1?'':'s')+' found on internet-exposed hosts'),
  ].filter(Boolean).join('\n      ');

  // ── Section 4 grid markup ───────────────────────────────────────────────────
  const controlAreaGridHtml = controlAreaSummary.map(a => {
    const itemsHtml = a.items.slice(0, 5).map(it => '<tr>'+
      '<td class="wide" style="word-break:break-word">'+esc(it.title)+'</td>'+
      '<td style="width:70px">'+sevBadge(it.severity)+'</td>'+
    '</tr>').join('');
    return '<div style="min-width:0;border:1px solid #e2e8f0;border-radius:10px;overflow:hidden">'+
      '<div style="padding:14px 16px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between;background:#FAFAFA">'+
        '<span style="font-size:12px;font-weight:800;color:'+a.color+';text-transform:uppercase;letter-spacing:.04em">'+esc(a.area)+'</span>'+
        '<span style="font-size:20px;font-weight:900;color:'+a.color+'">'+a.count+'</span>'+
      '</div>'+
      (a.items.length ? '<table class="exec-table" style="margin:0"><tbody>'+itemsHtml+'</tbody></table>' :
        '<p style="text-align:center;color:#999;font-size:11px;padding:16px">No findings in this control area</p>')+
    '</div>';
  }).join('');

  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
  '  <meta charset="UTF-8">\n' +
  '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
  '  <title>Rapid Cloud Assessment (BETA) – '+esc(customer)+'</title>\n' +
  '  <style type="text/css">\n' + REPORT_CSS + '\n' +
  '  </style>\n</head>\n<body>\n' +
  reportTopbarHtml('Full Report (BETA)') + '\n' +
  '<button type="button" class="pdf-export-btn no-print" onclick="window.print()">&#128196; Export to PDF</button>\n' +
  '<div class="report-cover">\n' +
  '  <div class="report-type">Rapid Cloud Assessment · Full Report (BETA)</div>\n' +
  '  <h1>Cloud Security Assessment Report</h1>\n' +
  '  <div class="subtitle">'+esc(customer)+'</div>\n' +
  (function() {
    const arcLen=550, fill=Math.round((score/100)*arcLen);
    return '  <div style="margin:1rem auto 0;max-width:380px;width:100%">\n'+
      '  <svg viewBox="0 0 400 240" style="display:block;width:100%;overflow:visible">\n'+
      '    <defs><linearGradient id="rg4" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">'+
      '<stop offset="0%" stop-color="#ef4444"/><stop offset="20.6%" stop-color="#ef4444"/>'+
      '<stop offset="20.6%" stop-color="#f59e0b"/><stop offset="65.45%" stop-color="#f59e0b"/>'+
      '<stop offset="65.45%" stop-color="#22c55e"/><stop offset="90.45%" stop-color="#22c55e"/>'+
      '<stop offset="90.45%" stop-color="#3b82f6"/><stop offset="100%" stop-color="#3b82f6"/>'+
      '</linearGradient></defs>\n'+
      '    <path fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <path fill="none" stroke="url(#rg4)" stroke-width="34" stroke-linecap="round" stroke-dasharray="'+fill+' '+arcLen+'" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <line x1="86" y1="48" x2="108" y2="79"   stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="260" y1="20" x2="248" y2="57"  stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="357" y1="91" x2="326" y2="113" stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <text x="200" y="165" text-anchor="middle" font-size="72" font-weight="900" letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="white">'+score+'</text>\n'+
      '    <text x="-8" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">0</text>\n'+
      '    <text x="408" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">100</text>\n'+
      '  </svg>\n'+
      '  <div style="text-align:center;font-size:.82rem;font-weight:700;letter-spacing:.08em;color:white;margin-top:2px;text-transform:uppercase">Cloud Security Risk Score — '+esc(sBand)+'</div>\n'+
      '  </div>\n';
  })()+
  '  <div class="meta-row">\n' +
  '    <div class="meta-item"><strong>Prepared For</strong>'+esc(customer)+'</div>\n' +
  '    <div class="meta-item"><strong>Report Date</strong>'+dateStr+'</div>\n' +
  '    <div class="meta-item"><strong>Author</strong>'+esc(author)+'</div>\n' +
  '    <div class="meta-item"><strong>Classification</strong>Confidential (Beta Report)</div>\n' +
  '  </div>\n</div>\n' +
  '<div class="toc"><h3>Report Contents</h3><div class="toc-cards">\n      '+tocCards+'\n</div></div>\n' +
  '<section id="scope" class="pagebreak">\n<h2>1. Scope and Objectives</h2>\n' +
  '<div class="narrative"><p>Accelerate cloud risk reduction by strengthening cloud security posture, improving configuration hygiene, and enhancing runtime threat detection across '+esc(customer)+'’s cloud environment'+(cloudsSeen.length===1?'':'s')+'.</p>' +
  '<p>This Rapid Cloud Assessment passively ingests structured data from FortiCNAPP to generate this report — no agents are installed and no changes are made to the environment as part of this assessment.</p></div>\n' +
  '</section>\n' +
  '<section id="cloud-overview" class="pagebreak">\n<h2>2. Cloud Environment Overview</h2>\n' +
  '<div class="narrative"><p>This assessment covers '+esc(customer)+'’s public cloud environment'+(cloudsSeen.length===1?'':'s')+' across '+esc(cloudsListStr)+'. Coverage reflects the FortiCNAPP cloud integrations currently connected to this tenant.</p></div>\n' +
  '<div style="display:flex;gap:16px;flex-wrap:wrap">' +
    ['aws','azure','gcp'].filter(c => cspScores[c] !== null).map(c => {
      const counts = cspCounts[c] || { C:0, H:0, M:0, L:0 };
      const total = counts.C+counts.H+counts.M+counts.L;
      return '<div style="flex:1;min-width:180px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:18px 16px;text-align:center">'+
        cspBadge(c)+
        '<div style="font-size:32px;font-weight:900;color:'+scoreTierColor(cspScores[c])+';margin-top:10px">'+cspScores[c]+'</div>'+
        '<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:4px">CSPM Score</div>'+
        '<div style="font-size:11px;color:#64748b;margin-top:8px">'+total+' finding'+(total===1?'':'s')+'</div>'+
      '</div>';
    }).join('') +
  '</div>\n</section>\n' +
  '<section id="methodology" class="pagebreak">\n<h2>3. Assessment Methodology</h2>\n' +
  '<div class="narrative"><p>For a period of '+dynamicDaysBack+' days, FortiCNAPP Rapid Cloud Assessment collected structured data through passive, read-only integration with '+esc(customer)+'’s cloud service provider APIs.</p>' +
  '<p>No credentials were shared with Fortinet and no changes were made to the environment as part of this data collection.</p></div>\n' +
  '</section>\n' +
  '<section id="control-areas" class="pagebreak">\n<h2>4. Risk Findings Categories</h2>\n' +
  '<p style="color:#5A5A5A;margin-bottom:20px;font-size:12px">Identity & Access is scoped to admin users without MFA and high-permission roles; Misconfiguration covers Critical-severity findings only; the remaining two mirror the internet-exposed evidence detailed in Section 6.</p>\n' +
  '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:20px">'+controlAreaGridHtml+'</div>\n' +
  '</section>\n' +
  '<section id="evidence" class="pagebreak">\n<h2>5. Evidence and Affected Assets</h2>\n' +
  '<p style="color:#5A5A5A;margin-bottom:16px;font-size:12px">Asset inventory tying each correlated risk factor (exposed credentials, CVEs, and critical misconfigurations) back to the resource it was found on.</p>\n' +
  '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:20px">' +
    [
      [internalHostCount, 'Vulnerable Private Hosts'],
      [exposedHostCount, 'Internet-Exposed Hosts'],
      [identities.length, 'Identities Inventoried'],
      [publicStorage.length, 'Publicly Accessible Storage'],
    ].map(([n,label]) => '<div style="flex:1;min-width:150px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:18px 16px;text-align:center">'+
      '<div style="font-size:32px;font-weight:900;color:#DA291C">'+n+'</div>'+
      '<div style="font-size:10px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.05em;margin-top:6px">'+label+'</div>'+
    '</div>').join('') +
  '</div>\n' +
  '<table class="exec-table"><thead><tr><th>Asset</th><th style="width:130px">Exposure</th><th style="width:80px">Score</th><th style="width:80px">Tier</th><th>Evidence</th></tr></thead><tbody>'+evidenceRowsHtml+'</tbody></table>\n' +
  '</section>\n' +
  '<section id="internet-exposed" class="pagebreak">\n<h2>6. Internet Exposed Resources</h2>\n' +
  '<p style="color:#5A5A5A;margin-bottom:20px;font-size:12px">Externally reachable assets — the attack surface most likely to be actively targeted.</p>\n' +
  '<h3 id="exposed-hosts" style="font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#1e293b;margin-bottom:10px">6a. Internet-Exposed Hosts ('+exposedHosts.length+')</h3>\n' +
  exposedHostsHtml + '\n' +
  '<h3 id="exposed-storage" style="font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#1e293b;margin:24px 0 10px">6b. Publicly Accessible Storage ('+publicStorage.length+')</h3>\n' +
  publicStorageHtml + '\n' +
  '<h3 id="exposed-admin" style="font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#1e293b;margin:24px 0 10px">6c. Admin Users Without MFA ('+adminNoMfaRows.length+')</h3>\n' +
  '<table class="exec-table"><thead><tr><th>Identity</th><th style="width:70px">Cloud</th><th style="width:90px">Privilege</th><th style="width:130px">Last Login</th></tr></thead><tbody>'+adminNoMfaRowsHtml+'</tbody></table>\n' +
  '<h3 id="exposed-secrets" style="font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#1e293b;margin:24px 0 10px">6d. Secrets on Internet-Exposed Hosts ('+exposedHostSecrets.length+')</h3>\n' +
  '<table class="exec-table"><thead><tr><th style="width:180px">Hostname</th><th style="width:140px">Secret Type</th><th>Secret Identifier</th></tr></thead><tbody>'+exposedHostSecretsHtml+'</tbody></table>\n' +
  '</section>\n' +
  '<section id="actions" class="pagebreak">\n<h2>7. Immediate and Long-Term Actions</h2>\n' +
  '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:20px">' +
    '<div style="border:1px solid #e2e8f0;border-radius:10px;overflow:hidden">'+
      '<div style="padding:14px 16px;background:var(--color-critical-bg);border-bottom:1px solid #e2e8f0"><span style="font-size:12px;font-weight:800;color:var(--color-critical);text-transform:uppercase;letter-spacing:.04em">Immediate Actions</span></div>'+
      '<div style="padding:16px 18px;font-size:12.5px;color:#374151;line-height:2">'+
        immediateActions.map((a,i) => (i+1)+'. '+esc(a)).join('<br>')+
      '</div>'+
    '</div>'+
    '<div style="border:1px solid #e2e8f0;border-radius:10px;overflow:hidden">'+
      '<div style="padding:14px 16px;background:var(--color-low-bg);border-bottom:1px solid #e2e8f0"><span style="font-size:12px;font-weight:800;color:var(--color-low);text-transform:uppercase;letter-spacing:.04em">Long-Term Actions</span></div>'+
      '<div style="padding:16px 18px;font-size:12.5px;color:#374151;line-height:2">'+
        longTermActions.map((a,i) => (i+1)+'. '+esc(a)).join('<br>')+
      '</div>'+
    '</div>'+
  '</div>\n</section>\n' +
  '<div class="report-ending" style="page-break-before:always;background:#000;color:#fff;padding:48px 64px;display:flex;flex-direction:column;gap:32px">' +
  '<div style="text-align:center">' +
  '<div style="font-size:15px;font-weight:700;letter-spacing:.06em;margin-bottom:14px">RAPID CLOUD ASSESSMENT (BETA) — Powered by FortiCNAPP</div>' +
  '<div style="font-size:13px;color:#d1d5db;margin-bottom:10px">Prepared for: '+esc(customer)+' &nbsp;&middot;&nbsp; Report Date: '+dateStr+' &nbsp;&middot;&nbsp; Author: '+esc(author)+'</div>' +
  '<div style="font-size:11px;color:#6b7280">This report is confidential and intended solely for the named recipient.</div>' +
  '</div>' +
  '</div>\n</body>\n</html>';
}


// ── HTTP server ───────────────────────────────────────────────────────────────

const NO_CACHE = { 'Cache-Control': 'no-cache, no-store, must-revalidate', 'Pragma': 'no-cache', 'Expires': '0' };
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function requestHandler(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, CORS);
    res.end();
    return;
  }
  if (req.method === 'POST' && req.url === '/api/register') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { first, last, title, company, email } = JSON.parse(body);
        const handle = ((first||'')+(last||'').charAt(0)).toLowerCase();
        const ts = new Date().toISOString();
        const row = [ts, first, last, title, company, email, handle]
          .map(v => `"${(v||'').replace(/"/g,'""')}"`)
          .join(',') + '\n';
        fs.appendFileSync(CONTACTS_CSV, row);
        console.log(`[register] ${handle} — ${first} ${last} (${title}) @ ${company} <${email}>`);
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }
  const ua = req.headers['user-agent'] || '';
  const isMobile = /Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua);

  if (req.url === '/api/settings' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
    res.end(JSON.stringify({ refreshIntervalSec: dynamicInterval, daysBack: dynamicDaysBack }));
    return;
  }
  if (req.url === '/api/settings' && req.method === 'POST') {
    let body = '';
    req.on('data', d => body += d);
    req.on('end', () => {
      try {
        const payload = JSON.parse(body);
        if (payload.refreshIntervalSec !== undefined) {
          const minSec = 6 * 3600, maxSec = 48 * 3600;
          const sec = payload.refreshIntervalSec;
          if (typeof sec === 'number' && sec >= minSec && sec <= maxSec) {
            dynamicInterval = sec;
            if (!MOCK_FILE) startRefreshTimer();
            res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
            res.end(JSON.stringify({ ok: true, refreshIntervalSec: dynamicInterval, daysBack: dynamicDaysBack }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
            res.end(JSON.stringify({ error: 'refreshIntervalSec must be between 21600 and 172800' }));
          }
        } else if (payload.daysBack !== undefined) {
          const d = payload.daysBack;
          if (d === 7 || d === 14 || d === 15 || d === 21 || d === 30) {
            dynamicDaysBack = d;
            res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
            res.end(JSON.stringify({ ok: true, daysBack: dynamicDaysBack }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
            res.end(JSON.stringify({ error: 'daysBack must be 7, 14, 15, 21, or 30' }));
          }
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({ error: 'Unknown setting' }));
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: 'Bad request' }));
      }
    });
    return;
  }
  if (req.url === '/api/ai/start' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        const alertId = payload.alertId;
        const lwBody = {
          conversationContext: {
            metaInstructions: `User is asking about this alert? {alertId:${alertId}}`,
            entities: [],
            entityPayloads: [],
          },
          providerConfig: { provider: 'bedrock', modelConfig: { type: 'claude-v5' } },
        };
        const { status, resp } = await postRaw('AiAssistants/start', lwBody, 120000);
        if (status !== 200 && status !== 201) {
          res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({ error: `AI Assistant returned HTTP ${status}: ${JSON.stringify(resp).slice(0,200)}` }));
          return;
        }
        const threadId = resp?.data?.threadId || null;
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ threadId }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  if (req.url === '/api/ai/message' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        if (!payload.threadId) throw new Error('threadId required');
        const lwBody = {
          userQuestion: payload.message,
          conversationContext: {
            metaInstructions: `User is asking about this alert? {alertId:${payload.alertId}}`,
            entities: [],
            entityPayloads: [],
          },
          providerConfig: { provider: 'bedrock', modelConfig: { type: 'claude-v5' } },
          history: [],
        };
        const { status, resp } = await putRaw(`AiAssistants/${payload.threadId}`, lwBody, 120000);
        if (status !== 200 && status !== 201) {
          res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({ error: `AI response returned HTTP ${status}: ${JSON.stringify(resp).slice(0,200)}` }));
          return;
        }
        const answer = resp?.data?.response?.assistantResponse || '';
        const responseId = resp?.data?.response?.responseId || null;
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ message: answer, responseId }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  if (req.url.startsWith('/api/cve') && req.method === 'GET') {
    (async () => {
      try {
        const id = decodeURIComponent((req.url.split('id=')[1]||'').split('&')[0]);
        if (!id) { res.writeHead(400, CORS); res.end(JSON.stringify({ error: 'id required' })); return; }
        const data = await fetchCveDetails(id);
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify(data));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    })();
    return;
  }

  if (req.url.startsWith('/api/geoip') && req.method === 'GET') {
    (async () => {
      const ip = (req.url.split('ip=')[1] || '').split('&')[0];
      const clean = decodeURIComponent(ip).trim();
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(clean)) {
        res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: 'invalid ip' })); return;
      }
      if (geoIpCache[clean]) {
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify(geoIpCache[clean])); return;
      }
      try {
        const { status: gst, body: data } = await request('GET', 'ipinfo.io', `/${clean}/json`, { Accept: 'application/json', 'User-Agent': 'FortiCNAPP-RCA/1.0' }, null, 8000);
        if (gst !== 200) throw new Error(`ipinfo HTTP ${gst}`);
        geoIpCache[clean] = data;
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify(data));
      } catch (e) {
        console.log(`[geoip] lookup failed for ${clean}: ${e.message}`);
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: e.message }));
      }
    })();
    return;
  }

  if (req.url.startsWith('/api/identity-trust') && req.method === 'GET') {
    try {
      const pid = decodeURIComponent((req.url.split('pid=')[1] || '').split('&')[0]);
      if (!pid) { res.writeHead(400, CORS); res.end(JSON.stringify({ error: 'pid required' })); return; }
      // Serve from cached identity data — trust principals are pre-parsed at fetch time
      const cached = (cache.identities || []).find(r => r.PRINCIPAL_ID === pid);
      const principals = cached?._trustPrincipals || [];
      res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
      res.end(JSON.stringify({ principals }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
      res.end(JSON.stringify({ error: e.message, principals: [] }));
    }
    return;
  }

  if (req.url.startsWith('/api/identity') && req.method === 'GET') {
    (async () => {
      try {
        const pid = decodeURIComponent((req.url.split('principalId=')[1]||'').split('&')[0]).replace(/'/g, "\\'");
        if (!pid) { res.writeHead(400, CORS); res.end(JSON.stringify({ error: 'principalId required' })); return; }
        const tf = timeFilter();
        const queryText = `{source { LW_CE_IDENTITIES } filter { PRINCIPAL_ID = '${pid}' } return distinct {PRINCIPAL_ID, PROVIDER_TYPE, NAME, LAST_USED_TIME, CREATED_TIME, METRICS, ACCESS_KEYS, ENTITLEMENT_COUNTS}}`;
        const rows = await post('Queries/execute', { query: { queryText }, arguments: [
          { name: 'StartTimeRange', value: tf.startTime },
          { name: 'EndTimeRange',   value: tf.endTime   },
        ]});
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ rows: rows || [] }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    })();
    return;
  }

  if (req.url.startsWith('/api/machine') && req.method === 'GET') {
    (async () => {
      try {
        const hostname = decodeURIComponent((req.url.split('hostname=')[1]||'').split('&')[0]).replace(/'/g,'');
        if (!hostname) { res.writeHead(400, CORS); res.end(JSON.stringify({ error: 'hostname required' })); return; }
        const tf = timeFilter();
        const queryText = `{source { LW_HE_MACHINES } filter { HOSTNAME = '${hostname}' } return {MID, HOSTNAME, TAGS}}`;
        const rows = await post('Queries/execute', { query: { queryText }, arguments: [
          { name: 'StartTimeRange', value: tf.startTime },
          { name: 'EndTimeRange',   value: tf.endTime   },
        ]});
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ rows: rows || [] }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    })();
    return;
  }

  if (req.url.startsWith('/api/governance/targets') && req.method === 'GET') {
    (async () => {
      try {
        const targets = await fetchGovernanceTargets();
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ targets, reportTypes: GOVERNANCE_REPORT_TYPES }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    })();
    return;
  }

  if (req.url.startsWith('/api/governance/report') && req.method === 'GET') {
    (async () => {
      try {
        const qs = new URL(req.url, 'http://localhost').searchParams;
        const reportType        = qs.get('reportType') || '';
        const primaryQueryId    = qs.get('primaryQueryId') || '';
        const secondaryQueryId  = qs.get('secondaryQueryId') || '';
        const cloud             = qs.get('cloud') || '';
        const frameworkLabel    = qs.get('frameworkLabel') || reportType;
        const accountLabel      = qs.get('accountLabel') || '';
        if (!reportType || !primaryQueryId) {
          res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
          res.end(JSON.stringify({ error: 'reportType and primaryQueryId are required' }));
          return;
        }
        let path = `Reports?primaryQueryId=${encodeURIComponent(primaryQueryId)}&format=json&reportType=${encodeURIComponent(reportType)}`;
        if (secondaryQueryId) path += `&secondaryQueryId=${encodeURIComponent(secondaryQueryId)}`;
        const resp = await get(path);
        // Persist as the "last governance report" — reused by Generate Report / Report 2.
        lastGovernanceReport = { data: resp, cloud, reportType, frameworkLabel, accountLabel, fetchedAt: new Date().toISOString() };
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify(resp ?? {}));
      } catch (err) {
        res.writeHead(502, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    })();
    return;
  }

  if (req.url === '/api/ai/rate' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        if (!payload.threadId || !payload.responseId || !payload.rating) throw new Error('threadId, responseId and rating required');
        const lwBody = { responseId: payload.responseId, rating: payload.rating, ...(payload.feedback ? { feedback: payload.feedback } : {}) };
        const { status } = await putRaw(`AiAssistants/${payload.threadId}/rate`, lwBody, 30000);
        res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ ok: status === 200 || status === 204 }));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json', ...CORS });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  if (req.url === '/api/fg-facts') {
    (async () => {
      const blogFacts = [];
      try {
        const { status, raw } = await request('GET', 'www.fortinet.com', '/blog/cloud-security',
          { 'Accept': 'text/html', 'User-Agent': 'Mozilla/5.0 (compatible; FortiCNAPP-RCA/1.0)' }, null, 12000);
        if (status === 200 && raw) {
          // Extract article titles from heading links
          const re = /<h[23][^>]*>[\s\S]{0,60}<a[^>]*>([^<]{20,180})<\/a>/gi;
          let m;
          while ((m = re.exec(raw)) !== null) {
            const t = m[1].trim().replace(/&amp;/g,'&').replace(/&#39;/g,"'").replace(/&quot;/g,'"').replace(/\s+/g,' ');
            if (t && !blogFacts.find(f => f.includes(t.slice(0,30)))) {
              blogFacts.push('📰 Fortinet Blog: ' + t);
            }
            if (blogFacts.length >= 8) break;
          }
        }
      } catch(e) { /* network unavailable — return empty */ }
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', ...CORS });
      res.end(JSON.stringify({ facts: blogFacts }));
    })();
  } else if (req.url === '/api/data') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', ...CORS });
    res.end(JSON.stringify(cache));
  } else if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...CORS });
    res.end('OK');
  } else if (req.url === '/mobile') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(MOBILE_HTML);
  } else if (req.url === '/desktop') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(HTML);
  } else if (req.url.startsWith('/report4')) {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    const customer = (qs.get('customer') || 'Customer').trim();
    const author   = (qs.get('author')   || 'Fortinet').trim();
    const sanitize = /^(1|true|yes)$/i.test(qs.get('sanitize') || '');
    if (!cache.fetchedAt) {
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end('<body style="font-family:sans-serif;padding:2rem"><h2>⏳ Dashboard data not yet loaded</h2><p>Please wait a moment and try again.</p></body>');
      return;
    }
    (async () => {
    await ensureFreshCache();
    const reportData = sanitize ? sanitizeCacheData(cache) : cache;
    const reportHtml = buildReportHtml4(reportData, { customer, author });
    const reportPath = path.join(__dirname, 'rca4.html');
    const pdfPath    = path.join(__dirname, 'rca4.pdf');
    fs.writeFile(reportPath, reportHtml, err => {
      if (err) { console.error('[report4] html save failed:', err.message); return; }
      console.log('[report4] saved html to', reportPath);
      const { execFile } = require('child_process');
      execFile('chromium-browser', [
        '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
        '--print-to-pdf=' + pdfPath, 'file://' + reportPath
      ], (err2) => {
        if (err2) execFile('chromium', [
          '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
          '--print-to-pdf=' + pdfPath, 'file://' + reportPath
        ], (err3) => {
          if (err3) console.error('[report4] pdf generation failed:', err3.message);
          else console.log('[report4] saved pdf to', pdfPath);
        });
        else console.log('[report4] saved pdf to', pdfPath);
      });
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(reportHtml);
    })();
  } else if (req.url.startsWith('/report3')) {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    const customer = (qs.get('customer') || 'Customer').trim();
    const author   = (qs.get('author')   || 'Fortinet').trim();
    const sanitize = /^(1|true|yes)$/i.test(qs.get('sanitize') || '');
    if (!cache.fetchedAt) {
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end('<body style="font-family:sans-serif;padding:2rem"><h2>⏳ Dashboard data not yet loaded</h2><p>Please wait a moment and try again.</p></body>');
      return;
    }
    (async () => {
    await ensureFreshCache();
    const reportData = sanitize ? sanitizeCacheData(cache) : cache;
    const reportHtml = buildReportHtml3(reportData, { customer, author });
    const reportPath = path.join(__dirname, 'rca3.html');
    const pdfPath    = path.join(__dirname, 'rca3.pdf');
    fs.writeFile(reportPath, reportHtml, err => {
      if (err) { console.error('[report3] html save failed:', err.message); return; }
      console.log('[report3] saved html to', reportPath);
      const { execFile } = require('child_process');
      execFile('chromium-browser', [
        '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
        '--print-to-pdf=' + pdfPath, 'file://' + reportPath
      ], (err2) => {
        if (err2) execFile('chromium', [
          '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
          '--print-to-pdf=' + pdfPath, 'file://' + reportPath
        ], (err3) => {
          if (err3) console.error('[report3] pdf generation failed:', err3.message);
          else console.log('[report3] saved pdf to', pdfPath);
        });
        else console.log('[report3] saved pdf to', pdfPath);
      });
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(reportHtml);
    })();
  } else if (req.url.startsWith('/report2')) {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    const customer = (qs.get('customer') || 'Customer').trim();
    const author   = (qs.get('author')   || 'Fortinet').trim();
    const sanitize = /^(1|true|yes)$/i.test(qs.get('sanitize') || '');
    if (!cache.fetchedAt) {
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end('<body style="font-family:sans-serif;padding:2rem"><h2>⏳ Dashboard data not yet loaded</h2><p>Please wait a moment and try again.</p></body>');
      return;
    }
    (async () => {
    await ensureFreshCache();
    const reportData = sanitize ? sanitizeCacheData(cache) : cache;
    const reportHtml = buildReportHtml2(reportData, { customer, author });
    const reportPath = path.join(__dirname, 'rca2.html');
    const pdfPath    = path.join(__dirname, 'rca2.pdf');
    fs.writeFile(reportPath, reportHtml, err => {
      if (err) { console.error('[report2] html save failed:', err.message); return; }
      console.log('[report2] saved html to', reportPath);
      const { execFile } = require('child_process');
      execFile('chromium-browser', [
        '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
        '--print-to-pdf=' + pdfPath, 'file://' + reportPath
      ], (err2) => {
        if (err2) execFile('chromium', [
          '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
          '--print-to-pdf=' + pdfPath, 'file://' + reportPath
        ], (err3) => {
          if (err3) console.error('[report2] pdf generation failed:', err3.message);
          else console.log('[report2] saved pdf to', pdfPath);
        });
        else console.log('[report2] saved pdf to', pdfPath);
      });
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(reportHtml);
    })();
  } else if (req.url.startsWith('/report')) {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    const customer = (qs.get('customer') || 'Customer').trim();
    const author   = (qs.get('author')   || 'Fortinet').trim();
    const sanitize = /^(1|true|yes)$/i.test(qs.get('sanitize') || '');
    if (!cache.fetchedAt) {
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end('<body style="font-family:sans-serif;padding:2rem"><h2>⏳ Dashboard data not yet loaded</h2><p>Please wait a moment and try again.</p></body>');
      return;
    }
    (async () => {
    await ensureFreshCache();
    const reportData = sanitize ? sanitizeCacheData(cache) : cache;
    const reportHtml = buildReportHtml(reportData, { customer, author });
    const reportPath = path.join(__dirname, 'rca.html');
    const pdfPath    = path.join(__dirname, 'rca.pdf');
    fs.writeFile(reportPath, reportHtml, err => {
      if (err) { console.error('[report] html save failed:', err.message); return; }
      console.log('[report] saved html to', reportPath);
      const { execFile } = require('child_process');
      execFile('chromium-browser', [
        '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
        '--print-to-pdf=' + pdfPath, 'file://' + reportPath
      ], (err2) => {
        if (err2) execFile('chromium', [
          '--headless', '--disable-gpu', '--no-sandbox', '--disable-dev-shm-usage',
          '--print-to-pdf=' + pdfPath, 'file://' + reportPath
        ], (err3) => {
          if (err3) console.error('[report] pdf generation failed:', err3.message);
          else console.log('[report] saved pdf to', pdfPath);
        });
        else console.log('[report] saved pdf to', pdfPath);
      });
    });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(reportHtml);
    })();
  } else if (req.method === 'POST' && req.url === '/api/login') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      const p = new URLSearchParams(body);
      const email = (p.get('email') || '').trim();
      const company = (p.get('company') || '').trim();
      if (email) {
        const ts = new Date().toISOString();
        const row = [ts, email.split('@')[0], '', '', company, email, ''].join(',') + '\n';
        fs.appendFile('/app/contacts.csv', row, () => {});
      }
      // Serve dashboard directly — no redirect, so self-signed cert cookie issues don't matter
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end(HTML);
    });
  } else if (isMobile && req.url === '/') {
    res.writeHead(302, { Location: '/mobile', ...CORS });
    res.end();
  } else if (req.url === '/') {
    const authed = /rca_auth=/.test(req.headers.cookie || '');
    if (!authed) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end(LOGIN_HTML);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end(HTML);
    }
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
    res.end(HTML);
  }
}

function startApp(listeningPort, protocol) {
  const mode = MOCK_FILE ? 'MOCK' : 'LIVE';
  const url  = `${protocol}://localhost:${listeningPort}`;
  console.log('\n┌──────────────────────────────────────────────────┐');
  console.log(`│  Fortinet Rapid Cloud Assessment Powered by FortiCNAPP — ${mode.padEnd(11)}│`);
  console.log('├──────────────────────────────────────────────────┤');
  console.log(`│  Account  : ${LW_ACCOUNT.padEnd(37)}│`);
  if (MOCK_FILE) {
    console.log(`│  Mock     : ${MOCK_FILE.padEnd(37)}│`);
  } else {
    console.log(`│  Refresh  : every ${String(INTERVAL + 's').padEnd(32)}│`);
  }
  console.log(`│  Open     : ${url.padEnd(37)}│`);
  console.log('└──────────────────────────────────────────────────┘\n');

  if (MOCK_FILE) {
    try {
      const raw = fs.readFileSync(MOCK_FILE, 'utf8');
      cache = { ...cache, ...JSON.parse(raw) };
      console.log(`[mock] Loaded ${MOCK_FILE} (${raw.length} bytes) — no API calls will be made\n`);
    } catch (e) {
      console.error(`[mock] Failed to load ${MOCK_FILE}:`, e.message);
    }
  } else {
    loadCacheFromDisk(); // restore last-known-good data immediately, before the first live fetch
    resolveReachableIP(LW_ACCOUNT).then(ip => { accountIP = ip; }).catch(() => {})
      .finally(() => {
        refreshData().catch(e => console.error('[startup]', e.message));
        startRefreshTimer();
      });
    setInterval(() => {
      resolveReachableIP(LW_ACCOUNT).then(ip => { if (ip) accountIP = ip; }).catch(() => {});
    }, 24 * 60 * 60 * 1000);
  }
}

if (TLS_CERT && TLS_KEY) {
  // ── HTTPS mode ─────────────────────────────────────────────────────────────
  let tlsOpts;
  try {
    tlsOpts = { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  } catch (e) {
    console.error(`[tls] Cannot read cert/key: ${e.message}`);
    process.exit(1);
  }
  https.createServer(tlsOpts, requestHandler).listen(PORT_TLS, () => {
    startApp(PORT_TLS, 'https');
  });
  // Plain HTTP → HTTPS redirect
  http.createServer((req, res) => {
    const host = (req.headers.host || 'localhost').replace(/:\d+$/, '');
    const target = `https://${host}${req.url}`;
    res.writeHead(301, { Location: target });
    res.end();
  }).listen(PORT, () => {
    console.log(`[tls] HTTP :${PORT} → HTTPS :${PORT_TLS} redirect active`);
  });
} else {
  // ── HTTP mode (default) ────────────────────────────────────────────────────
  http.createServer(requestHandler).listen(PORT, () => {
    startApp(PORT, 'http');
  });
}
