#!/usr/bin/env node
// Fortinet Rapid Cloud Assessment empowered by FortiCNAPP — Live Dashboard
// Usage:  node server.js   |   open http://localhost:8080
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
const PORT       = Number(process.env.PORT)     || 8080;
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
const DAYS_BACK  = 28;   // look-back window default
let dynamicDaysBack = DAYS_BACK;
const MOCK_FILE  = process.env.MOCK_FILE  || '';   // set to mock_data.json to skip API calls
// ─────────────────────────────────────────────────────────────────────────────

let token       = null;
let tokenExpiry = 0;
let cache = {
  alerts: [], vulns: [], compliance: [], identities: [],
  fetchedAt: null, errors: {}, account: LW_ACCOUNT, subAccount: LW_SUBACCOUNT,
  riskScore: 0, daysBack: DAYS_BACK,
  summary: { alerts: 0, vulns: 0, compliance: 0, identities: 0 },
};

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
      ...(resolvedIP ? { lookup: (_h, _o, cb) => cb(null, resolvedIP, 4) } : {}),
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
        resolve({ status: res.statusCode, body: parsed, raw });
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

async function withRetry(fn, label, retries = 3) {
  for (let i = 0; i < retries; i++) {
    try {
      const result = await fn();
      if (result.status < 500) return result;
      console.log(`  [retry] ${label} got ${result.status}, attempt ${i + 1}/${retries}`);
    } catch (e) {
      console.log(`  [retry] ${label} error: ${e.message}, attempt ${i + 1}/${retries}`);
      if (i === retries - 1) throw e;
    }
    await new Promise(r => setTimeout(r, 2000 * (i + 1)));
  }
  return fn();
}

async function post(path, body) {
  const tok = await ensureToken();
  const { status, body: resp } = await withRetry(
    () => request('POST', LW_ACCOUNT, `/api/v2/${path}`, { Authorization: `Bearer ${tok}` }, body),
    path,
  );
  if (status === 204) return [];
  if (status !== 200 && status !== 201)
    throw new Error(`POST ${path} → HTTP ${status}: ${JSON.stringify(resp).slice(0, 200)}`);
  return Array.isArray(resp?.data) ? resp.data : (Array.isArray(resp) ? resp : []);
}

async function get(path) {
  const tok = await ensureToken();
  const { status, body: resp } = await withRetry(
    () => request('GET', LW_ACCOUNT, `/api/v2/${path}`, { Authorization: `Bearer ${tok}` }, null),
    path,
  );
  if (status === 204) return null;
  if (status !== 200 && status !== 201)
    throw new Error(`GET ${path} → HTTP ${status}: ${JSON.stringify(resp).slice(0, 200)}`);
  return resp;
}

async function postRaw(path, body, timeoutMs = 30000) {
  const tok = await ensureToken();
  const { status, body: resp } = await request('POST', LW_ACCOUNT, `/api/v2/${path}`, { Authorization: `Bearer ${tok}` }, body, timeoutMs);
  return { status, resp };
}

async function putRaw(path, body, timeoutMs = 30000) {
  const tok = await ensureToken();
  const { status, body: resp } = await request('PUT', LW_ACCOUNT, `/api/v2/${path}`, { Authorization: `Bearer ${tok}` }, body, timeoutMs);
  return { status, resp };
}


function timeFmt(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

function timeFilter(days) {
  const end   = new Date();
  const start = new Date(Date.now() - (days || dynamicDaysBack) * 86400000);
  // NOTE: Lacework v2 search uses singular "timeFilter" not "timeFilters"
  return { startTime: timeFmt(start), endTime: timeFmt(end) };
}

// ── 1. Alerts — POST /api/v2/Alerts/search ───────────────────────────────────

// Alerts API caps at 7 days per request — split into chunks if window > 7
function alertTimeWindows() {
  const total = dynamicDaysBack;
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
  const windows = alertTimeWindows();
  const batches = await Promise.all(windows.flatMap(tf => [
    post('Alerts/search', { timeFilter: tf, filters: [{ field: 'severity', expression: 'eq', value: 'Critical' }], paging: { rows: 500 } }),
    post('Alerts/search', { timeFilter: tf, filters: [{ field: 'severity', expression: 'eq', value: 'High'     }], paging: { rows: 500 } }),
  ]));
  const rows = batches.flat();
  const CATS = new Set(['anomaly', 'composite']);
  const filtered = rows
    .filter(r => { const s = (r.status || '').toLowerCase(); return s === 'open' || s === 'in progress'; })
    .filter(r => CATS.has((r.derivedFields?.category || '').toLowerCase()));
  console.log('[alerts] raw:',rows.length,'after hf filter:',filtered.length);
  return filtered
    .sort((a, b) => new Date(b.startTime || 0) - new Date(a.startTime || 0))
    .slice(0, 50);
}

// ── 2. Vulns — POST /api/v2/Vulnerabilities/Hosts/search ─────────────────────
// riskScore >= 9 filtered client-side (not cveProps.cvssV3Score)

async function fetchVulns() {
  const rows = await post('Vulnerabilities/Hosts/search', {
    timeFilter: timeFilter(7), // API hard-caps at 7 days
    filters: [{ field: 'severity', expression: 'eq', value: 'Critical' }],
    paging: { rows: 100 },
  });
  return rows
    .filter(r => parseFloat(r.riskScore ?? 0) >= 9)
    .sort((a, b) => parseFloat(b.riskScore ?? 0) - parseFloat(a.riskScore ?? 0))
    .slice(0, 10);
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

async function fetchCompliance() {
  // Step 1 — get Critical/High compliance policy definitions (includes description)
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
    .slice(0, 15);
    console.log(`  [compliance] ${all.filter(p=>p.policyType==='Compliance').length} total compliance policies, evaluating ${policies.length} critical`);
  } catch (e) {
    console.log(`  [compliance/Policies] ${e.message.slice(0,120)}`);
    return [];
  }

  // Step 2 — run policy queries in parallel batches of 3 (avoids rate-limit, ~3× faster than sequential)
  const findings = [];
  const tf2 = timeFilter();
  const BATCH = 3;

  async function runPolicy(p) {
    try {
      const rows = await post('Queries/execute', {
        query: { queryText: p.queryText },
        arguments: [
          { name: 'StartTimeRange', value: tf2.startTime },
          { name: 'EndTimeRange',   value: tf2.endTime   },
        ],
      });
      console.log(`  [compliance] ${p.policyId} → ${rows.length} rows`);
      if (rows.length) return {
        alertId:     p.policyId,
        cloud:       policyCloud(p.queryId || p.policyId),
        title:       p.title || p.policyId,
        description: p.description || '—',
        severity:    'Critical',
        violations:  rows.length,
        resources:   rows.slice(0, 100),
      };
    } catch (e) {
      console.log(`  [compliance] ${p.policyId} ERR: ${e.message.slice(0,80)}`);
      if (e.message.includes('429')) await new Promise(r => setTimeout(r, 5000));
    }
    return null;
  }

  for (let i = 0; i < policies.length && findings.length < 10; i += BATCH) {
    const batch = policies.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(runPolicy));
    results.forEach(r => r && findings.push(r));
    // Push partial results to cache so client sees them on next poll
    if (findings.length) {
      cache = { ...cache, compliance: findings.slice().sort((a, b) => b.violations - a.violations) };
    }
    if (i + BATCH < policies.length && findings.length < 10) {
      await new Promise(r => setTimeout(r, 500));
    }
  }

  console.log(`  [compliance] ${findings.length} policies with violations`);
  return findings.sort((a, b) => b.violations - a.violations);
}

// ── 4. Identities — POST /api/v2/Queries/execute (LQL) ───────────────────────
// LW_CE_IDENTITIES dataset — filters for PASSWORD_LOGIN_NO_MFA + ALLOWS_FULL_ADMIN

async function fetchIdentities() {
  const tf = timeFilter();
  const queryText = `{
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

  const rows = await post('Queries/execute', {
    query: { queryText },
    arguments: [
      { name: 'StartTimeRange', value: tf.startTime },
      { name: 'EndTimeRange',   value: tf.endTime   },
    ],
  });

  console.log(`  [identities] total returned: ${rows.length}`);
  if (rows.length) console.log(`  [identities] sample: ${JSON.stringify(rows[0]).slice(0, 300)}`);

  // Include all high-permissive identities: full admin OR high/critical risk severity
  const HIGH_SEV = new Set(['critical', 'high']);
  return rows
    .filter(r => {
      const risks = r.METRICS?.risks ?? [];
      const sev   = (r.METRICS?.risk_severity || '').toLowerCase();
      return risks.includes('ALLOWS_FULL_ADMIN') || HIGH_SEV.has(sev);
    })
    .sort((a, b) => {
      const aAdmin = (a.METRICS?.risks ?? []).includes('ALLOWS_FULL_ADMIN') ? 0 : 1;
      const bAdmin = (b.METRICS?.risks ?? []).includes('ALLOWS_FULL_ADMIN') ? 0 : 1;
      if (aAdmin !== bAdmin) return aAdmin - bAdmin;
      return (b.METRICS?.risk_score || 0) - (a.METRICS?.risk_score || 0);
    })
    .slice(0, 25);
}

// ── 5. Secrets All — POST /api/v2/Queries/execute (LQL) ──────────────────────
// LW_HE_SECRETS_ALL dataset — all discovered secrets across hosts

async function fetchSecretsAll() {
  const tf = timeFilter();
  const queryText = `{source { LW_HE_SECRETS_ALL } return distinct {BATCH_START_TIME, BATCH_END_TIME, BATCH_ID, RECORD_CREATED_TIME, MID, HOSTNAME, IS_IN_CONTAINER, CONTAINER_KEY, FILE_PATH, SECRET_TYPE, SECRET_METADATA}}`;
  const tok = await ensureToken();
  const all = [];

  // First page
  const { status: s1, body: r1 } = await request(
    'POST', LW_ACCOUNT, '/api/v2/Queries/execute',
    { Authorization: `Bearer ${tok}` },
    { query: { queryText }, arguments: [
      { name: 'StartTimeRange', value: tf.startTime },
      { name: 'EndTimeRange',   value: tf.endTime   },
    ] },
  );
  if (s1 !== 200 && s1 !== 201) throw new Error(`Queries/execute → HTTP ${s1}`);
  if (Array.isArray(r1?.data)) all.push(...r1.data);

  // Follow pages
  let nextUrl = r1?.paging?.urls?.nextPage || null;
  while (nextUrl) {
    const u = new URL(nextUrl);
    const { status: sN, body: rN } = await request(
      'GET', LW_ACCOUNT, u.pathname + u.search,
      { Authorization: `Bearer ${tok}` }, null,
    );
    if (sN !== 200) break;
    if (Array.isArray(rN?.data)) all.push(...rN.data);
    nextUrl = rN?.paging?.urls?.nextPage || null;
  }

  const filtered = all.filter(r => {
    const path = (r.FILE_PATH || '');
    const meta = (typeof r.SECRET_METADATA === 'object' && r.SECRET_METADATA) ? r.SECRET_METADATA : {};
    const p = meta.file_permissions;

    // Always drop system SSH host keys — server identity keys, not user secrets
    if (/etc\/ssh\/ssh_host_/i.test(path)) return false;

    // For secrets with known permissions, only surface those more permissive than
    // chmod 400 (owner read-only). (p & 0o377) !== 0 = any bit beyond owner-read is set.
    if (p !== undefined && p !== null) return (p & 0o377) !== 0;

    // Permissions not available — include (conservative: don't miss real findings)
    return true;
  });
  console.log(`  [secrets-all] total: ${all.length}, after exclusions: ${filtered.length}`);
  return filtered;
}

// ── 6. Secrets SSH Keys — POST /api/v2/Queries/execute (LQL) ─────────────────
// LW_HE_SECRETS_SSH_PRIVATE_KEYS dataset — SSH private keys detected on hosts

async function fetchSecrets() {
  const tf = timeFilter();
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
  });
  console.log(`  [secrets-ssh] total permissive (>chmod 400): ${rows.length}`);
  return rows;
}

// ── Main refresh ──────────────────────────────────────────────────────────────

function calcRiskScore(alerts, vulns, identities) {
  const topIdent = identities.reduce((m, i) => Math.max(m, (i.METRICS?.risk_score || 0) * 100), 0);
  const topCve   = vulns.reduce((m, v) => Math.max(m, parseFloat(v.riskScore || 0) * 10), 0);
  const alertPts = Math.min(alerts.length * 3, 15);
  return Math.min(100, Math.round(topIdent * 0.60 + topCve * 0.25 + alertPts));
}

async function refreshData() {
  console.log(`\n[${new Date().toISOString()}] Refreshing…`);
  const errors = {};

  // Phase 1: fast parallel fetch — update cache immediately so UI is responsive
  const [a, v, i, s, sa] = await Promise.allSettled([
    fetchAlerts(),
    fetchVulns(),
    fetchIdentities(),
    fetchSecrets(),
    fetchSecretsAll(),
  ]);

  function unwrap(res, key) {
    if (res.status === 'fulfilled') return res.value;
    errors[key] = res.reason?.message ?? String(res.reason);
    console.error(`  [${key}] ERROR: ${errors[key]}`);
    return [];
  }

  const alerts     = unwrap(a,  'alerts');
  const vulns      = unwrap(v,  'vulns');
  const identities = unwrap(i,  'identities');
  const secrets    = unwrap(s,  'secrets');
  const secretsAll = unwrap(sa, 'secretsAll');

  // Publish fast data right away; compliance will update the cache when ready
  cache = {
    ...cache,
    alerts, vulns, identities, secrets, secretsAll,
    fetchedAt: new Date().toISOString(),
    errors,
    account: LW_ACCOUNT,
    daysBack: dynamicDaysBack,
    riskScore: calcRiskScore(alerts, vulns, identities),
    summary: { alerts: alerts.length, vulns: vulns.length, compliance: cache.compliance?.length ?? 0, identities: identities.length, secrets: secrets.length, secretsAll: secretsAll.length },
  };

  // Phase 2: compliance runs after (avoids rate-limit collision with identities LQL)
  const c = await fetchCompliance().then(v => ({ status: 'fulfilled', value: v }))
                                   .catch(e => ({ status: 'rejected', reason: e }));
  const freshComp  = unwrap(c, 'compliance');
  // Retain last good compliance result when rate-limited (429 → empty list)
  const compliance = freshComp.length > 0 ? freshComp : (cache.compliance ?? []);

  cache = {
    ...cache,
    compliance,
    summary: {
      alerts:     alerts.length,
      vulns:      vulns.length,
      compliance: compliance.length,
      identities: identities.length,
      secrets:    secrets.length,
      secretsAll: secretsAll.length,
    },
  };

  console.log(`[done] alerts:${alerts.length} vulns:${vulns.length} compliance:${compliance.length} identities:${identities.length}`);
  if (Object.keys(errors).length) console.log('[errors]', errors);
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
  --bg:#f5f7fa;--surface:#ffffff;--card:#f0f2f6;--card2:#eaecf2;
  --border:#dde2ea;--border2:#c8cfd9;
  --text:#0f172a;--sub:#475569;--muted:#94a3b8;
  --accent:#DA291C;--accent-l:#e84038;--accent-dim:rgba(218,41,28,.1);
  --cr:#ef4444;--cr-bg:rgba(239,68,68,.08);--cr-bd:rgba(239,68,68,.3);
  --hi:#f97316;--hi-bg:rgba(249,115,22,.08);--hi-bd:rgba(249,115,22,.3);
  --me:#d97706;--me-bg:rgba(217,119,6,.08);
  --ok:#16a34a;--ok-bg:rgba(22,163,74,.08);--ok-bd:rgba(22,163,74,.3);
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Inter',BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;line-height:1.55;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#c8cfd9;border-radius:2px}

/* ── Report header ── */
.rpt-header{background:#ffffff;border-bottom:1px solid var(--border);padding:18px 28px}
.rpt-top{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:0}
.rpt-brand{display:flex;align-items:center;gap:14px}
.logo{width:46px;height:46px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.logo svg{width:24px;height:24px;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.rpt-title{font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.3px}
.rpt-sub{font-size:11px;color:var(--accent);text-transform:uppercase;letter-spacing:.12em;margin-top:2px}
.rpt-meta{text-align:right;font-size:11px;color:var(--muted);line-height:1.9;justify-self:end}
.rpt-meta b{color:var(--sub)}
.live-row{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted);justify-content:flex-end}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--muted)}
.live-dot.ok{background:var(--ok);box-shadow:0 0 6px rgba(52,211,153,.5);animation:blink 2.5s ease-in-out infinite}
.live-dot.err{background:var(--cr)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
@keyframes step1-flash{0%,100%{box-shadow:0 6px 24px rgba(239,68,68,.38),0 0 0 0 rgba(239,68,68,.7)}50%{box-shadow:0 6px 24px rgba(239,68,68,.38),0 0 0 18px rgba(239,68,68,0)}}

/* ── Risk Score Mountain ── */
.rs-block{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:10px 36px;border-left:1px solid var(--border2);border-right:1px solid var(--border2)}
.rs-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);margin-bottom:6px}
.rs-num{font-size:48px;font-weight:900;line-height:1;letter-spacing:-3px;color:var(--text);transition:color .4s}
.mountain{display:flex;align-items:flex-end;gap:5px;height:28px;margin:8px 0 6px}
.mt-bar{width:14px;border-radius:3px 3px 0 0;background:var(--border2);transition:background .4s}
.mt-bar.lit{background:currentColor}
.mt-1{height:7px}.mt-2{height:14px}.mt-3{height:21px}.mt-4{height:28px}
.rs-band{font-size:12px;font-weight:700;letter-spacing:.1em;transition:color .4s}

/* ── KPI summary bar ── */
.kpi-bar{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
.kpi{background:var(--surface);padding:16px 22px;position:relative;overflow:hidden;cursor:default;transition:background .15s;box-shadow:0 1px 3px rgba(15,23,42,.06)}
.kpi:hover{background:var(--card2)}
.kpi::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.kpi.red::before{background:var(--cr)}
.kpi.orange::before{background:var(--hi)}
.kpi.yellow::before{background:var(--me)}
.kpi.teal::before{background:var(--accent)}
.kpi-label{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px}
.kpi-val{font-size:32px;font-weight:800;line-height:1;letter-spacing:-1px;color:var(--text)}
.kpi.red .kpi-val{color:var(--cr)}
.kpi.orange .kpi-val{color:var(--hi)}
.kpi.yellow .kpi-val{color:var(--me)}
.kpi.teal .kpi-val{color:var(--accent-l)}
.kpi-desc{font-size:11px;color:var(--muted);margin-top:5px}

/* ── Error notice ── */
.err-notice{background:var(--cr-bg);border-bottom:1px solid var(--cr-bd);padding:8px 28px;font-size:11px;color:var(--cr);display:none}
.err-notice.show{display:block}

/* ── Section layout ── */
.sections{display:grid;grid-template-columns:repeat(2,1fr);gap:0;border-top:1px solid var(--border)}
@media(max-width:1000px){.sections{grid-template-columns:1fr}}
.section{border-right:1px solid var(--border);border-bottom:1px solid var(--border);background:var(--surface)}
.section:nth-child(even){border-right:none}

/* ── Section header ── */
.sec-hdr{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--border);background:var(--card2)}
.sec-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
.si-red{background:var(--cr-bg);border:1px solid var(--cr-bd)}
.si-orange{background:var(--hi-bg);border:1px solid var(--hi-bd)}
.si-yellow{background:var(--me-bg);border:1px solid rgba(234,179,8,.25)}
.si-teal{background:var(--accent-dim);border:1px solid rgba(13,148,136,.25)}
.sec-title{font-size:13px;font-weight:600;color:var(--text)}
.sec-desc{font-size:11px;color:var(--muted);margin-top:1px}
.sec-count{margin-left:auto;font-size:11px;font-weight:700;padding:3px 10px;border-radius:5px;border:1px solid var(--border)}
.sec-count.bad{color:var(--cr);background:var(--cr-bg);border-color:var(--cr-bd)}
.sec-count.ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}

/* ── Table ── */
.tbl-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:11px}
thead{position:sticky;top:0;z-index:2}
thead th{text-align:left;padding:5px 10px;font-size:9.5px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--card);border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:hover{background:rgba(99,102,241,.04)}
tbody tr:last-child{border-bottom:none}
td{padding:5px 10px;vertical-align:middle;color:var(--sub)}
td.p{color:var(--text);font-weight:500;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.desc{color:var(--sub);max-width:420px;white-space:normal;word-break:break-word;line-height:1.4}
td.m{font-family:'SFMono-Regular',Consolas,monospace;font-size:10px;color:var(--muted);white-space:nowrap}
td.r{text-align:right;padding-right:10px;white-space:nowrap;width:1%}

/* ── Badges ── */
.b{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.b::before{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}
.b-cr{color:var(--cr);background:var(--cr-bg);border-color:var(--cr-bd)}
.b-hi{color:var(--hi);background:var(--hi-bg);border-color:var(--hi-bd)}
.b-me{color:var(--me);background:var(--me-bg)}
.b-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}
.b-nt{color:var(--muted);background:rgba(78,100,128,.15)}
.risk-score{font-size:12px;font-weight:800;color:var(--cr)}
.tag-admin{font-size:10px;font-weight:700;color:var(--cr);background:var(--cr-bg);border:1px solid var(--cr-bd);padding:1px 6px;border-radius:3px;letter-spacing:.03em}
.tag-nomfa{font-size:10px;font-weight:700;color:var(--hi);background:var(--hi-bg);border:1px solid var(--hi-bd);padding:1px 6px;border-radius:3px}

/* ── Row severity strip ── */
.strip-cr td:first-child{border-left:3px solid var(--cr)}
.strip-hi td:first-child{border-left:3px solid var(--hi)}
.strip-me td:first-child{border-left:3px solid var(--me)}

/* ── State messages ── */
.state{display:flex;flex-direction:column;align-items:center;gap:10px;padding:40px 24px;color:var(--muted);font-size:12px;text-align:center}
.state-icon{font-size:26px;opacity:.35}
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ── Risk Findings links ── */
.rf-link{color:var(--text);text-decoration:none;font-weight:500}
.rf-link:hover{color:var(--accent-l);text-decoration:underline}
.cp-btn{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border:none;background:transparent;color:#94a3b8;cursor:pointer;border-radius:3px;padding:0;margin-left:5px;vertical-align:middle;flex-shrink:0;transition:color .15s,background .15s}
.cp-btn:hover{color:#DA291C;background:#fee2e2}
.cp-btn.ok{color:#22c55e}

/* ── Dashboard pie section ── */
.pie-section{display:flex;flex-direction:column;align-items:center;gap:14px;padding:20px 32px 16px;background:#ffffff;border-bottom:1px solid var(--border)}
.pie-donut{flex-shrink:0;display:flex;justify-content:center}
.pie-legend{display:grid;grid-template-columns:repeat(4,1fr);width:100%;max-width:860px;background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden}
.pi-row{display:flex;flex-direction:column;gap:6px;padding:20px 22px;cursor:pointer;transition:background .15s;border-right:1px solid var(--border)}
.pi-row:last-child{border-right:none}
.pi-row:hover{background:var(--card)}
.pi-topbar{height:3px;border-radius:2px;margin-bottom:6px}
.pi-cnt{font-size:40px;font-weight:900;line-height:1;letter-spacing:-2px}
.pi-name{font-size:13px;font-weight:700;color:var(--sub);line-height:1.3;margin-top:4px}
.pi-desc{font-size:10.5px;color:var(--muted);line-height:1.5}
/* legacy – keep in case referenced */
.dash-kpis{display:none}
.dk-val{font-size:42px;font-weight:900;line-height:1;letter-spacing:-2px}
.dk-red .dk-val{color:#ef4444}.dk-orange .dk-val{color:#f97316}.dk-amber .dk-val{color:#d97706}.dk-purple .dk-val{color:#8b5cf6}

/* ── Section view header ── */
.view-hdr{padding:16px 24px;display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--border)}
.vh-icon{display:none}
.vh-text{flex:1}
.vh-title{font-size:15px;font-weight:700;color:var(--text)}
.vh-sub{font-size:11px;color:var(--muted);margin-top:2px}
.vh-badge{font-size:12px;font-weight:800;padding:4px 14px;border-radius:7px;white-space:nowrap}
/* section-specific accents */
.vha-red{background:#fff5f5;border-bottom:1px solid var(--cr-bd)}.vha-red .vh-title{color:var(--cr)}.vha-red .vh-badge{background:var(--cr-bg);color:var(--cr);border:1px solid var(--cr-bd)}
.vha-orange{background:#fff8f2;border-bottom:1px solid var(--hi-bd)}.vha-orange .vh-title{color:var(--hi)}.vha-orange .vh-badge{background:var(--hi-bg);color:var(--hi);border:1px solid var(--hi-bd)}
.vha-amber{background:#fffbf0;border-bottom:1px solid rgba(217,119,6,.3)}.vha-amber .vh-title{color:var(--me)}.vha-amber .vh-badge{background:var(--me-bg);color:var(--me);border:1px solid rgba(217,119,6,.3)}
.vha-purple{background:#f8f6ff;border-bottom:1px solid rgba(109,40,217,.2)}.vha-purple .vh-title{color:#7c3aed}.vha-purple .vh-badge{background:rgba(109,40,217,.08);color:#7c3aed;border:1px solid rgba(109,40,217,.2)}

/* ── Alert description cell ── */
td.desc{font-size:11px;color:var(--sub);max-width:520px;white-space:normal;line-height:1.5;padding-top:7px;padding-bottom:7px}

/* ── Agent tip ── */
.agent-tip{font-size:10px;color:var(--accent-l);cursor:default;border-bottom:1px dashed var(--accent);padding-bottom:1px}
.agent-tip:hover{color:var(--accent)}

/* ── Footer ── */
.footer{text-align:center;padding:14px;font-size:10px;color:var(--muted);border-top:1px solid var(--border)}

/* ── App layout & sidebar ── */
.app-layout{display:flex;min-height:100vh}
.sidebar{width:214px;background:#111827;flex-shrink:0;position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}
.main{flex:1;min-width:0}
.top-bar{display:flex;align-items:center;justify-content:flex-end;padding:8px 20px;background:#fff;border-bottom:1px solid var(--border);gap:12px;position:sticky;top:0;z-index:100}
.tb-user{display:flex;align-items:center;gap:10px}
.tb-avatar{width:32px;height:32px;border-radius:50%;background:#DA291C;color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;letter-spacing:.03em;flex-shrink:0}
.tb-name{font-size:12px;font-weight:700;color:var(--text);line-height:1.2}
.tb-role-lbl{font-size:10px;color:var(--muted);line-height:1.2}
.tb-badge{font-size:9px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;background:#fef3c7;color:#92400e;border:1px solid #fde68a;border-radius:5px;padding:2px 7px}
.sb-brand{display:flex;align-items:center;gap:10px;padding:16px 14px;border-bottom:1px solid #1f2937}
.sb-logo{width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sb-logo svg{width:18px;height:18px;fill:none;stroke:#fff;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
.sb-name{font-size:14px;font-weight:700;color:#fff;letter-spacing:-.2px}
.sb-sect{padding:16px 16px 4px;font-size:9px;font-weight:700;letter-spacing:.14em;color:#4b5563;text-transform:uppercase}
.sb-item{display:flex;align-items:center;gap:9px;padding:8px 13px;margin:1px 8px;border-radius:7px;cursor:pointer;color:#9ca3af;font-size:12.5px;font-weight:500;transition:all .15s;user-select:none;white-space:nowrap}
.sb-item:hover{background:rgba(255,255,255,.07);color:#e5e7eb}
.sb-item.active{background:#DA291C;color:#fff;font-weight:600}
.sb-item svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.sb-sep{margin:8px 14px;border:none;border-top:1px solid #1f2937}
.sb-spacer{flex:1}
/* ── Views ── */
.view{display:none}.view.active{display:block}
/* ── Alerts dark section header ── */
.sec-hdr.dark{background:var(--surface);border-bottom:1px solid var(--border)}
.sec-hdr.dark .sec-title{color:var(--text)}
.sec-hdr.dark .sec-desc{color:var(--muted)}
/* ── Risk Findings view ── */
.rf-posture{display:flex;align-items:center;gap:28px;padding:20px 28px;background:#ffffff;border-bottom:1px solid var(--border)}
.rf-pos-num{font-size:60px;font-weight:900;line-height:1;letter-spacing:-3px;transition:color .4s}
.rf-pos-meta{display:flex;flex-direction:column;gap:3px}
.rf-pos-lbl{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:var(--muted)}
.rf-pos-band{font-size:17px;font-weight:700;letter-spacing:.06em;transition:color .4s}
.rf-pos-sub{font-size:10.5px;color:var(--muted)}
.rf-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
.rf-kpi{background:var(--surface);padding:13px 18px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
.rf-kpi-lbl{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:5px}
.rf-kpi-val{font-size:26px;font-weight:800;line-height:1;letter-spacing:-1px;color:var(--text)}
.rf-kpi-sub{font-size:10px;color:var(--muted);margin-top:3px}
.rf-body{padding:16px 20px}
/* ── Journey Snake Map ── */
.jmap-outer{padding:16px 16px 12px;display:flex;justify-content:center}
.jmap-svg{width:100%;max-width:1000px;overflow:visible}
@keyframes snake-flow{to{stroke-dashoffset:-26}}
@keyframes path-flow{to{stroke-dashoffset:-20}}

/* ── Report button + modal ── */
.rpt-btn{display:flex;align-items:center;gap:8px;margin:8px 10px 0;padding:10px 13px;border-radius:8px;cursor:pointer;background:linear-gradient(135deg,#c93428,#9e1f16);color:#fff;font-size:12px;font-weight:700;letter-spacing:.03em;border:none;width:calc(100% - 20px);transition:filter .15s}
.rpt-btn:hover{filter:brightness(1.15)}
.rpt-btn svg{width:14px;height:14px;fill:none;stroke:#fff;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal-box{background:#ffffff;border:1px solid var(--border);border-radius:16px;padding:28px 28px 22px;width:400px;max-width:92vw;box-shadow:0 24px 64px rgba(0,0,0,.15)}
.modal-title{font-size:16px;font-weight:800;color:var(--text);margin-bottom:6px}
.modal-sub{font-size:11px;color:var(--muted);margin-bottom:22px}
.modal-field{margin-bottom:14px}
.modal-label{font-size:10.5px;font-weight:700;color:var(--sub);letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px}
.modal-input{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:9px 12px;color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
.modal-input:focus{border-color:#DA291C}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
.modal-btn{padding:9px 18px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;border:none;font-family:inherit;transition:filter .15s}
.modal-btn.primary{background:#DA291C;color:#fff}
.modal-btn.primary:hover{filter:brightness(1.1)}
.modal-btn.primary:disabled{opacity:.5;cursor:not-allowed;filter:none}
.modal-btn.ghost{background:transparent;border:1px solid var(--border);color:var(--sub)}
.modal-btn.ghost:hover{border-color:var(--border2);color:var(--text)}
.modal-status{text-align:center;padding:16px 0 4px;font-size:12px;color:var(--muted);line-height:1.7;min-height:48px}
.modal-dl{display:flex;flex-direction:column;gap:8px;margin-top:12px}
.modal-dl a{display:flex;align-items:center;gap:8px;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--sub);text-decoration:none;font-size:12px;font-weight:600;transition:background .15s}
.modal-dl a:hover{background:var(--card)}
.modal-dl a svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round}
/* ── Login overlay ── */
.login-overlay{position:fixed;inset:0;z-index:2000;background:linear-gradient(135deg,#111827 0%,#1f2937 60%,#111827 100%);display:flex;align-items:center;justify-content:center}
.login-box{width:420px;max-width:92vw;background:#ffffff;border:1px solid #e5e7eb;border-radius:20px;padding:36px 36px 28px;box-shadow:0 32px 80px rgba(0,0,0,.35)}
.login-logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.login-logo-name{font-size:13px;font-weight:700;color:#374151;line-height:1.3;letter-spacing:.02em}
.login-title{font-size:20px;font-weight:800;color:#111827;margin-bottom:4px}
.login-sub{font-size:11.5px;color:#6b7280;margin-bottom:24px}
.login-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.login-field{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.login-label{font-size:10px;font-weight:700;color:#6b7280;letter-spacing:.1em;text-transform:uppercase}
.login-input{background:#f9fafb;border:1px solid #d1d5db;border-radius:8px;padding:9px 12px;color:#111827;font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
.login-input:focus{border-color:#DA291C}
.login-select{appearance:none;background:#f9fafb url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%236b7280'/%3E%3C/svg%3E") no-repeat right 10px center;border:1px solid #d1d5db;border-radius:8px;padding:9px 28px 9px 12px;color:#111827;font-size:13px;font-family:inherit;outline:none;width:100%;cursor:pointer;transition:border-color .15s}
.login-select:focus{border-color:#DA291C}
.login-btn{width:100%;margin-top:8px;padding:12px;border-radius:10px;background:#DA291C;color:#fff;font-size:13px;font-weight:700;border:none;cursor:pointer;letter-spacing:.04em;transition:filter .15s}
.login-btn:hover{filter:brightness(1.1)}
.login-err{font-size:11px;color:#ef4444;margin-top:8px;min-height:16px;text-align:center}
.lab-tabs-bar{display:flex;gap:0;padding:0 24px;border-bottom:1px solid var(--border);background:var(--bg);flex-wrap:wrap}
.lab-tab{padding:9px 20px;border:1px solid transparent;border-bottom:none;border-radius:7px 7px 0 0;background:transparent;font-size:12px;font-weight:700;color:var(--sub);cursor:pointer;transition:background .15s,color .15s,border-color .15s;letter-spacing:.04em;margin-bottom:-1px;position:relative}
.lab-tab:hover{background:var(--surface);color:var(--text)}
.lab-tab.active{background:var(--surface);color:var(--text);border-color:var(--border);border-bottom-color:var(--surface)}
.lab-tab[data-csp=aws].active{color:#FF9900;border-top-color:#FF9900;border-left-color:#FF9900;border-right-color:#FF9900}
.lab-tab[data-csp=azure].active{color:#0078D4;border-top-color:#0078D4;border-left-color:#0078D4;border-right-color:#0078D4}
.lab-tab[data-csp=gcp].active{color:#4285F4;border-top-color:#4285F4;border-left-color:#4285F4;border-right-color:#4285F4}
.cjmap-outer{padding:16px 16px 12px;display:flex;justify-content:center}
.cjmap-svg{width:100%;max-width:750px;overflow:visible}
.ai-overlay{position:fixed;inset:0;background:rgba(0,0,0,.48);z-index:2000;display:flex;align-items:center;justify-content:center;padding:16px}
.ai-panel{background:#fff;border-radius:16px;width:540px;max-width:100%;height:72vh;max-height:680px;display:flex;flex-direction:column;box-shadow:0 28px 72px rgba(0,0,0,.26);overflow:hidden}
.ai-hdr{padding:14px 18px 12px;border-bottom:1px solid #e2e8f0;display:flex;align-items:flex-start;justify-content:space-between;gap:10px;flex-shrink:0}
.ai-hdr-left{display:flex;flex-direction:column;gap:2px;min-width:0}
.ai-hdr-tag{font-size:9px;font-weight:900;letter-spacing:.14em;text-transform:uppercase;color:#DA291C}
.ai-hdr-title{font-size:13px;font-weight:700;color:#0f172a;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ai-hdr-sub{font-size:10px;color:#94a3b8}
.ai-close{width:28px;height:28px;border-radius:7px;border:none;background:#f1f5f9;font-size:16px;line-height:1;color:#64748b;cursor:pointer;flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:background .15s}
.ai-close:hover{background:#e2e8f0;color:#0f172a}
.ai-body{flex:1;overflow-y:auto;padding:14px 18px;display:flex;flex-direction:column;gap:10px}
.ai-msg{max-width:85%;padding:10px 14px;border-radius:12px;font-size:12.5px;line-height:1.6;white-space:pre-wrap;word-break:break-word}
.ai-msg.user{align-self:flex-end;background:#DA291C;color:#fff;border-bottom-right-radius:4px}
.ai-msg.assistant{align-self:flex-start;background:#f1f5f9;color:#0f172a;border-bottom-left-radius:4px}
.ai-msg.thinking{align-self:flex-start;background:#f8fafc;color:#94a3b8;font-style:italic;border:1px dashed #e2e8f0;border-bottom-left-radius:4px}
.ai-inv-btn.ai-ready{background:#16a34a!important;}
.ai-msg.fact{align-self:center;background:linear-gradient(135deg,#fff5f5,#fff);border:1.5px solid #DA291C33;border-radius:10px;color:#374151;font-size:12px;font-style:italic;padding:8px 14px;max-width:90%;text-align:center;margin-top:4px}
.ai-msg.fact::before{content:"☁️ Did you know? ";font-style:normal;font-weight:700;color:#DA291C}
.ai-feedback{display:flex;align-items:center;gap:6px;align-self:flex-start;margin-top:-4px;margin-left:2px}
.ai-fb-btn{background:none;border:1px solid #e2e8f0;border-radius:6px;padding:2px 7px;font-size:13px;cursor:pointer;line-height:1;color:#64748b;transition:background .15s,border-color .15s}
.ai-fb-btn:hover{background:#f1f5f9;border-color:#cbd5e1}
.ai-fb-btn.voted{border-color:#22c55e;background:#f0fdf4;color:#15803d}
.ai-fb-btn.voted-neg{border-color:#ef4444;background:#fef2f2;color:#dc2626}
.ai-fb-note{font-size:10px;color:#94a3b8;margin-left:2px}
@keyframes fg-arrow{0%,100%{transform:translateX(0)}50%{transform:translateX(5px)}}
.fg-arrow{display:inline-block;animation:fg-arrow 0.9s ease-in-out infinite;color:#DA291C;font-style:normal;margin-right:3px;font-size:13px}
#fg-inline{width:100%;max-width:clamp(380px,52vw,640px);margin-top:18px;opacity:0;transform:translateY(12px) scale(.97);transition:opacity .5s cubic-bezier(.22,1,.36,1),transform .5s cubic-bezier(.22,1,.36,1);pointer-events:none;position:relative}
#fg-inline.show{opacity:1;transform:translateY(0) scale(1);pointer-events:auto}
#fg-inline::before{content:'';position:absolute;top:-9px;left:50%;transform:translateX(-50%);width:0;height:0;border-left:10px solid transparent;border-right:10px solid transparent;border-bottom:10px solid #DA291C}
#fg-inline::after{content:'';position:absolute;top:-7px;left:50%;transform:translateX(-50%);width:0;height:0;border-left:9px solid transparent;border-right:9px solid transparent;border-bottom:9px solid #fff5f5}
.fg-bubble{background:linear-gradient(135deg,#fff5f5 0%,#fff 60%);border:1.5px solid #DA291C;border-radius:14px;padding:16px 20px 14px;box-shadow:0 8px 32px rgba(218,41,28,.13),0 2px 8px rgba(0,0,0,.06);position:relative;overflow:hidden}
.fg-bubble::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#DA291C,#ff6b5b,#DA291C)}
.fg-bubble-header{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.fg-bubble-icon{width:28px;height:28px;border-radius:50%;background:#DA291C;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.fg-bubble-label{font-size:10px;font-weight:800;letter-spacing:.1em;color:#DA291C;text-transform:uppercase}
.fg-bubble-src{font-size:9px;color:#94a3b8;margin-left:auto;font-style:italic}
.fg-bubble-fact{font-size:13px;font-weight:600;color:#0f172a;line-height:1.7;padding-left:2px}
.ai-footer{padding:10px 14px;border-top:1px solid #e2e8f0;display:flex;gap:8px;flex-shrink:0}
.mach-overlay{position:fixed;inset:0;background:rgba(15,23,42,.45);z-index:2000;display:flex;align-items:flex-end;justify-content:flex-end}
.mach-panel{background:#fff;width:480px;max-width:100vw;height:100vh;display:flex;flex-direction:column;box-shadow:-8px 0 40px rgba(0,0,0,.18);overflow:hidden}
.mach-hdr{padding:16px 18px 12px;border-bottom:1px solid #e2e8f0;display:flex;align-items:flex-start;gap:10px;flex-shrink:0}
.mach-hdr-icon{width:36px;height:36px;border-radius:8px;background:#f1f5f9;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.mach-title{font-size:13px;font-weight:800;color:#0f172a;word-break:break-all}
.mach-sub{font-size:10px;color:#94a3b8;margin-top:2px}
.mach-body{flex:1;overflow-y:auto;overflow-x:hidden;padding:14px 18px;display:flex;flex-direction:column;gap:12px;-webkit-overflow-scrolling:touch}
.mach-section{background:#f8fafc;border-radius:8px;overflow:hidden}
.mach-section-title{font-size:9px;font-weight:900;letter-spacing:.1em;text-transform:uppercase;color:#64748b;padding:6px 12px;background:#f1f5f9;border-bottom:1px solid #e2e8f0}
.mach-row{display:flex;align-items:baseline;gap:8px;padding:5px 12px;border-bottom:1px solid #f1f5f9}
.mach-row:last-child{border-bottom:none}
.mach-key{font-size:10px;font-weight:700;color:#64748b;min-width:120px;flex-shrink:0}
.mach-val{font-size:11px;color:#0f172a;word-break:break-all;font-family:monospace}
.ai-input{flex:1;padding:9px 12px;border:1px solid #e2e8f0;border-radius:9px;font-size:12.5px;outline:none;color:#0f172a;background:#fafafa;transition:border-color .15s}
.ai-input:focus{border-color:#DA291C;background:#fff}
.ai-send{padding:9px 16px;background:#DA291C;color:#fff;border:none;border-radius:9px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;transition:filter .15s}
.ai-send:hover{filter:brightness(1.1)}
.ai-send:disabled{opacity:.5;cursor:not-allowed;filter:none}
.ai-prompt-row{display:flex;gap:10px;width:100%}
.ai-prompt-btn{flex:1;padding:11px 8px;border:2px solid #DA291C;border-radius:10px;background:#fff;color:#DA291C;font-size:12px;font-weight:700;cursor:pointer;transition:background .15s,color .15s;letter-spacing:.03em}
.ai-prompt-btn:hover{background:#DA291C;color:#fff}
.ai-prompt-btn:disabled{opacity:.45;cursor:not-allowed;border-color:#cbd5e1;color:#94a3b8}
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
    <div style="font-size:8px;font-weight:500;color:#DA291C;letter-spacing:.06em;text-transform:uppercase;margin-left:1px">empowered by FortiCNAPP</div>
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
  <div class="sb-item" id="nav-asset-risk" onclick="nav('asset-risk')">
    <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="4" rx="1"/><rect x="2" y="10" width="20" height="4" rx="1"/><rect x="2" y="17" width="20" height="4" rx="1"/><circle cx="20" cy="5" r="2" fill="currentColor"/><circle cx="20" cy="12" r="2" fill="currentColor"/></svg>
    Correlated Risk / Asset
  </div>
  <div class="sb-sect">Risk Findings</div>
  <div class="sb-item" id="nav-vulns" onclick="nav('vulns')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    Internet Threat Exposure
  </div>
  <div class="sb-item" id="nav-identities" onclick="nav('identities')">
    <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
    Identities
  </div>
  <div class="sb-item" id="nav-compliance" onclick="nav('compliance')">
    <svg viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
    Critical Misconfigurations
  </div>
  <div class="sb-item" id="nav-secrets-all" onclick="nav('secrets-all')">
    <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    Secrets
  </div>
  <div class="sb-item" id="nav-risk" onclick="nav('risk')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r=".5" fill="currentColor"/></svg>
    Risk Findings Inventory
  </div>
  <div class="sb-sect">Operational Guidance</div>
  <div class="sb-item" id="nav-admin-settings" onclick="nav('admin-settings')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    Admin Settings
  </div>
  <!-- Generate Report button (alpha: live from cache) -->
  <div style="padding:0 0 6px">
    <a id="rpt-btn-link" href="/report" target="_blank" class="rpt-btn" style="display:flex;text-decoration:none">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      Generate Report
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
    <div style="font-size:16px;font-weight:800;letter-spacing:.2em;text-transform:uppercase;color:#DA291C;margin-bottom:4px">Cloud Security Posture Management Score</div>
    <div style="font-size:10px;color:#94a3b8;letter-spacing:.06em;text-transform:uppercase;margin-bottom:12px">Fortinet Rapid Cloud Assessment empowered by <a id="fg-link" href="https://community.fortinet.com/forticnapp-63" target="_blank" style="color:#DA291C;text-decoration:none;font-weight:700">FortiCNAPP</a> · last ${DAYS_BACK} days</div>

    <!-- Centering wrapper: responsive — fills available space up to a comfortable max -->
    <div style="width:100%;max-width:clamp(480px,58vw,740px);display:flex;flex-direction:column;align-items:center">
    <!-- Arc label positions (SVG units): URGENT≈(58,67)  ATTENTION≈(314,43)  PROACTIVE≈(396,180) -->
    <svg id="gauge-svg" viewBox="-88 -46 636 324" style="display:block;width:100%;overflow:visible">
      <defs>
        <linearGradient id="band-grad" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">
          <stop offset="0%"    stop-color="#ef4444"/>
          <stop offset="50%"   stop-color="#ef4444"/>
          <stop offset="50%"   stop-color="#f59e0b"/>
          <stop offset="97.5%" stop-color="#f59e0b"/>
          <stop offset="97.5%" stop-color="#22c55e"/>
          <stop offset="100%"  stop-color="#22c55e"/>
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
      <!-- Band divider ticks -->
      <line x1="200" y1="12" x2="200" y2="48"  stroke="white" stroke-width="3.5" stroke-linecap="round"/>
      <line x1="350" y1="156" x2="387" y2="143" stroke="white" stroke-width="3.5" stroke-linecap="round"/>
      <!-- Band labels removed — bubbles carry the labels -->
      <!-- Score number -->
      <text id="gauge-score" x="200" y="172" text-anchor="middle" font-size="58" font-weight="900"
            letter-spacing="-3" font-family="-apple-system,BlinkMacSystemFont,sans-serif" fill="#94a3b8">—</text>
      <!-- Scale endpoints -->

      <!-- ── URGENT bubble — left, tail centered on right edge → arc at ~(58,67) ── -->
      <g id="bubble-urgent" opacity="0.35" style="transition:opacity .4s,filter .4s">
        <polygon points="40,28 57,63 40,44" fill="#fef2f2" stroke="#fca5a5" stroke-width="1.3" stroke-linejoin="round"/>
        <rect x="-82" y="5" width="122" height="62" rx="9" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5"/>
        <line x1="40" y1="28" x2="40" y2="44" stroke="#fef2f2" stroke-width="3"/>
        <text x="-21" y="22" text-anchor="middle" font-size="11" font-weight="800" fill="#ef4444" letter-spacing=".06em" font-family="-apple-system,sans-serif">URGENT</text>
        <text x="-21" y="38" text-anchor="middle" font-size="8.5" fill="#7f1d1d" font-family="-apple-system,sans-serif">Critical gaps.</text>
        <text x="-21" y="52" text-anchor="middle" font-size="8.5" fill="#7f1d1d" font-family="-apple-system,sans-serif">Immediate action.</text>
      </g>

      <!-- ── ATTENTION bubble — upper-right of arc, tail on LEFT → arc at ~(314,43) ── -->
      <g id="bubble-attention" opacity="0.35" style="transition:opacity .4s,filter .4s">
        <polygon points="330,18 314,43 330,34" fill="#fffbeb" stroke="#fcd34d" stroke-width="1.3" stroke-linejoin="round"/>
        <rect x="330" y="-8" width="142" height="62" rx="9" fill="#fffbeb" stroke="#f59e0b" stroke-width="1.5"/>
        <line x1="330" y1="18" x2="330" y2="34" stroke="#fffbeb" stroke-width="3"/>
        <text x="401" y="10" text-anchor="middle" font-size="11" font-weight="800" fill="#b45309" letter-spacing=".06em" font-family="-apple-system,sans-serif">ATTENTION</text>
        <text x="401" y="26" text-anchor="middle" font-size="8.5" fill="#78350f" font-family="-apple-system,sans-serif">Gaps exist.</text>
        <text x="401" y="40" text-anchor="middle" font-size="8.5" fill="#78350f" font-family="-apple-system,sans-serif">Prioritize prompt action.</text>
      </g>

      <!-- ── PROACTIVE bubble — right, tail 20u → arc at ~(396,180). Left edge at x=416 ── -->
      <g id="bubble-proactive" opacity="0.35" style="transition:opacity .4s,filter .4s">
        <polygon points="416,172 398,180 416,188" fill="#f0fdf4" stroke="#86efac" stroke-width="1.3" stroke-linejoin="round"/>
        <rect x="416" y="149" width="118" height="62" rx="9" fill="#f0fdf4" stroke="#22c55e" stroke-width="1.5"/>
        <line x1="416" y1="172" x2="416" y2="188" stroke="#f0fdf4" stroke-width="3"/>
        <text x="475" y="166" text-anchor="middle" font-size="11" font-weight="800" fill="#15803d" letter-spacing=".06em" font-family="-apple-system,sans-serif">PROACTIVE</text>
        <text x="475" y="182" text-anchor="middle" font-size="8.5" fill="#14532d" font-family="-apple-system,sans-serif">Strong controls.</text>
        <text x="475" y="196" text-anchor="middle" font-size="8.5" fill="#14532d" font-family="-apple-system,sans-serif">Low risk.</text>
      </g>
      <!-- Objective tagline — anchored at x=200 (gauge arc center) -->
      <text x="200" y="248" text-anchor="middle" font-size="9.5" font-weight="600"
            letter-spacing=".08em" font-family="-apple-system,BlinkMacSystemFont,sans-serif"
            fill="#64748b" text-transform="uppercase">
        <tspan>THE OBJECTIVE IS TO ACHIEVE </tspan><tspan fill="#15803d" font-weight="800">PROACTIVE SECURITY</tspan>
      </text>
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
  <div class="footer">Fortinet Rapid Cloud Assessment empowered by FortiCNAPP &nbsp;·&nbsp; Auto-refresh every <span id="footer-interval">—</span> &nbsp;·&nbsp; <span id="countdown">—</span> &nbsp;·&nbsp; <span id="footer-time"></span></div>
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
  <div class="footer">Fortinet Rapid Cloud Assessment empowered by FortiCNAPP &nbsp;·&nbsp; Auto-refresh every <span class="footer-interval-ref">—</span> &nbsp;·&nbsp; <span id="footer-time-csp"></span></div>
</div><!-- /view-csp-scores -->

<!-- ═══ View: Critical Alerts ═══ -->
<div class="view" id="view-alerts">
  <div class="view-hdr vha-red">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">High Fidelity Alerts</div>
      <div class="vh-sub" id="sub-alerts">Active threats &amp; policy violations · last ${DAYS_BACK} days</div>
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
      <div class="vh-title">Internet Threat Exposure</div>
      <div class="vh-sub">Host CVEs · Risk Score ≥ 9.0 · Agentless scan &nbsp;<a class="agent-tip" href="https://docs.fortinet.com/document/forticnapp/latest/administration-guide/903770/agent-based-workload-security" target="_blank" style="text-decoration:none" title="Enable the FortiCNAPP agent for deeper in-memory &amp; runtime vulnerability detection">Agent available ↗</a></div>
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
      <div class="vh-title">Highest Permissive Identity without MFA Enabled</div>
      <div class="vh-sub">PASSWORD_LOGIN_NO_MFA · Admin or over-privileged · Priority 1</div>
    </div>
    <span class="vh-badge" id="cnt-i">—</span>
  </div>
  <div id="body-i"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Secrets ═══ -->
<div class="view" id="view-secrets-all">
  <div class="view-hdr vha-purple">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Discovered Secrets</div>
      <div class="vh-sub">High-permission secrets &amp; credentials detected on hosts</div>
    </div>
    <span class="vh-badge" id="cnt-sa">—</span>
  </div>
  <div id="body-sa"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: Asset Risk ═══ -->
<div class="view" id="view-asset-risk">
  <div class="view-hdr">
    <div class="vh-text">
      <div class="vh-title">Correlated Risk Findings per Asset</div>
      <div class="vh-sub">Hosts ranked by combined risk — CVEs &amp; secrets correlated per asset</div>
    </div>
    <span class="vh-badge" id="cnt-ar">—</span>
  </div>
  <div id="body-ar"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
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
  <div style="text-align:center;padding:24px 32px 16px;background:#fff;border-bottom:1px solid var(--border)">
    <div style="font-size:13px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#DA291C;margin-bottom:16px">Critical Risk Findings</div>
    <svg viewBox="0 0 220 220" width="240" height="240" style="display:block;margin:0 auto;overflow:visible">
      <circle cx="110" cy="110" r="80" fill="none" stroke="#e2e8f0" stroke-width="32"/>
      <g transform="rotate(-90,110,110)">
        <circle id="rf-pseg-a" cx="110" cy="110" r="80" fill="none" stroke="#ef4444" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-v" cx="110" cy="110" r="80" fill="none" stroke="#f97316" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-i" cx="110" cy="110" r="80" fill="none" stroke="#8b5cf6" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-c" cx="110" cy="110" r="80" fill="none" stroke="#f59e0b" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
        <circle id="rf-pseg-s" cx="110" cy="110" r="80" fill="none" stroke="#0ea5e9" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1)"/>
      </g>
      <text id="rf-pie-total" x="110" y="102" text-anchor="middle" dominant-baseline="middle" fill="#0f172a" font-size="42" font-weight="900" font-family="inherit" letter-spacing="-2">—</text>
      <text x="110" y="128" text-anchor="middle" fill="#94a3b8" font-size="8" font-weight="700" letter-spacing=".12em">CRITICAL RISK</text>
      <text x="110" y="140" text-anchor="middle" fill="#94a3b8" font-size="8" font-weight="700" letter-spacing=".12em">FINDINGS</text>
    </svg>
    <div style="display:flex;gap:20px;justify-content:center;margin-top:14px;flex-wrap:wrap;font-size:11px">
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('alerts')"><div style="width:9px;height:9px;border-radius:50%;background:#ef4444"></div><span style="color:#475569">Alerts</span><b id="rf-n-a" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('vulns')"><div style="width:9px;height:9px;border-radius:50%;background:#f97316"></div><span style="color:#475569">Exposure</span><b id="rf-n-v" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('identities')"><div style="width:9px;height:9px;border-radius:50%;background:#8b5cf6"></div><span style="color:#475569">Identities</span><b id="rf-n-i" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('compliance')"><div style="width:9px;height:9px;border-radius:50%;background:#f59e0b"></div><span style="color:#475569">Misconfigurations</span><b id="rf-n-c" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('secrets-all')"><div style="width:9px;height:9px;border-radius:50%;background:#0ea5e9"></div><span style="color:#475569">Secrets</span><b id="rf-n-s" style="margin-left:3px;color:#0f172a">—</b></div>
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
      <div class="vh-sub">Posture: <b id="lab-score">—</b> &nbsp;·&nbsp; <span id="lab-band-txt">—</span> &nbsp;·&nbsp; Fix findings to advance toward Proactive Security</div>
    </div>
  </div>

  <!-- ── Lab tab bar: Global | AWS | Azure | GCP ── -->
  <div class="lab-tabs-bar">
    <button class="lab-tab active" id="labtab-global" onclick="switchLabTab('global')">Global</button>
    <button class="lab-tab" id="labtab-aws" data-csp="aws" onclick="switchLabTab('aws')">AWS</button>
    <button class="lab-tab" id="labtab-azure" data-csp="azure" onclick="switchLabTab('azure')">Azure</button>
    <button class="lab-tab" id="labtab-gcp" data-csp="gcp" onclick="switchLabTab('gcp')">GCP</button>
  </div>

  <!-- Global (all-cloud) diagram — attack path graph -->
  <div id="lab-global-panel">
  <div class="jmap-outer">
  <svg class="jmap-svg" viewBox="0 0 900 380" preserveAspectRatio="xMidYMid meet">
    <defs>
      <filter id="jnd-shadow" x="-30%" y="-30%" width="160%" height="160%">
        <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="rgba(0,0,0,.22)"/>
      </filter>
    </defs>

    <!-- Passive resource nodes -->
    <circle cx="155" cy="130" r="14" fill="#e2e8f0"/>
    <circle cx="158" cy="258" r="13" fill="#e2e8f0"/>
    <circle cx="340" cy="192" r="16" fill="#e2e8f0"/>
    <circle cx="510" cy="190" r="14" fill="#e2e8f0"/>
    <circle cx="700" cy="165" r="15" fill="#e2e8f0"/>
    <circle cx="700" cy="230" r="13" fill="#e2e8f0"/>
    <circle cx="530" cy="72" r="12" fill="#e2e8f0"/>
    <circle cx="530" cy="312" r="12" fill="#e2e8f0"/>

    <!-- Static background tracks -->
    <g stroke="#dde3ed" stroke-width="2.5" stroke-linecap="round" fill="none">
      <line x1="98" y1="190" x2="190" y2="190"/>
      <line x1="266" y1="174" x2="392" y2="116"/>
      <line x1="266" y1="208" x2="392" y2="272"/>
      <line x1="470" y1="99" x2="582" y2="97"/>
      <line x1="470" y1="291" x2="582" y2="294"/>
      <line x1="656" y1="112" x2="775" y2="168"/>
      <line x1="655" y1="276" x2="775" y2="213"/>
    </g>
    <!-- Animated dot flow — stroke updated by JS via jsnake -->
    <g id="jsnake" stroke="#ef4444" stroke-width="3" stroke-linecap="round" fill="none" stroke-dasharray="5 15">
      <line x1="98" y1="190" x2="190" y2="190" style="animation:path-flow 1.1s linear infinite 0s"/>
      <line x1="266" y1="174" x2="392" y2="116" style="animation:path-flow 1.1s linear infinite .12s"/>
      <line x1="266" y1="208" x2="392" y2="272" style="animation:path-flow 1.1s linear infinite .22s"/>
      <line x1="470" y1="99" x2="582" y2="97" style="animation:path-flow 1.1s linear infinite .08s"/>
      <line x1="470" y1="291" x2="582" y2="294" style="animation:path-flow 1.1s linear infinite .2s"/>
      <line x1="656" y1="112" x2="775" y2="168" style="animation:path-flow 1.1s linear infinite .05s"/>
      <line x1="655" y1="276" x2="775" y2="213" style="animation:path-flow 1.1s linear infinite .28s"/>
    </g>

    <!-- Attacker entry node -->
    <circle cx="60" cy="190" r="38" fill="#ef4444" filter="url(#jnd-shadow)"/>
    <ellipse cx="60" cy="182" rx="10" ry="7" fill="white"/>
    <ellipse cx="60" cy="194" rx="12" ry="9" fill="white"/>
    <ellipse cx="60" cy="207" rx="9" ry="7" fill="white"/>
    <line x1="49" y1="186" x2="40" y2="181" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="49" y1="194" x2="38" y2="194" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="49" y1="202" x2="40" y2="207" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="71" y1="186" x2="80" y2="181" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="71" y1="194" x2="82" y2="194" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="71" y1="202" x2="80" y2="207" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="55" y1="163" x2="51" y2="155" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <line x1="65" y1="163" x2="69" y2="155" stroke="white" stroke-width="2" stroke-linecap="round"/>
    <text x="60" y="238" text-anchor="middle" font-size="8" font-weight="700" fill="#64748b" letter-spacing="1" font-family="-apple-system,sans-serif">Attacker</text>

    <!-- Node 3 — Internet Exposure (1st hop from Attacker) -->
    <circle id="jnd3" cx="230" cy="190" r="40" fill="#f97316" filter="url(#jnd-shadow)" style="cursor:pointer" onclick="nav('vulns')"/>
    <text x="230" y="183" text-anchor="middle" font-size="9.5" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Internet</text>
    <text x="230" y="196" text-anchor="middle" font-size="9.5" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Exposure</text>
    <text id="jnd3-cnt" x="230" y="214" text-anchor="middle" font-size="22" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>
    <circle cx="258" cy="162" r="11" fill="#FCD34D"/>
    <text x="258" y="167" text-anchor="middle" font-size="13" font-weight="900" fill="#92400E" style="pointer-events:none">!</text>

    <!-- Node 1 — Identities (upper branch) -->
    <circle id="jnd1" cx="430" cy="100" r="40" fill="#ef4444" filter="url(#jnd-shadow)" style="cursor:pointer" onclick="nav('identities')"/>
    <text x="430" y="93" text-anchor="middle" font-size="10" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Identities</text>
    <text id="jnd1-cnt" x="430" y="114" text-anchor="middle" font-size="22" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>
    <circle cx="458" cy="72" r="11" fill="#FCD34D"/>
    <text x="458" y="77" text-anchor="middle" font-size="13" font-weight="900" fill="#92400E" style="pointer-events:none">!</text>

    <!-- Node 2 — Alerts (lower branch) -->
    <circle id="jnd2" cx="430" cy="290" r="40" fill="#ef4444" filter="url(#jnd-shadow)" style="cursor:pointer" onclick="nav('alerts')"/>
    <text x="430" y="283" text-anchor="middle" font-size="9.5" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Crit. Alerts</text>
    <text id="jnd2-cnt" x="430" y="304" text-anchor="middle" font-size="22" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>
    <circle cx="458" cy="262" r="11" fill="#FCD34D"/>
    <text x="458" y="267" text-anchor="middle" font-size="13" font-weight="900" fill="#92400E" style="pointer-events:none">!</text>

    <!-- Node 4 — Compliance -->
    <circle id="jnd4" cx="620" cy="95" r="40" fill="#f59e0b" filter="url(#jnd-shadow)" style="cursor:pointer" onclick="nav('compliance')"/>
    <text x="620" y="88" text-anchor="middle" font-size="10" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Compliance</text>
    <text id="jnd4-cnt" x="620" y="109" text-anchor="middle" font-size="22" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>
    <circle cx="648" cy="67" r="11" fill="#FCD34D"/>
    <text x="648" y="72" text-anchor="middle" font-size="13" font-weight="900" fill="#92400E" style="pointer-events:none">!</text>

    <!-- Node 5 — Secrets -->
    <circle id="jnd5" cx="620" cy="295" r="40" fill="#eab308" filter="url(#jnd-shadow)" style="cursor:pointer" onclick="nav('secrets-all')"/>
    <text x="620" y="288" text-anchor="middle" font-size="10" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Secrets</text>
    <text id="jnd5-cnt" x="620" y="309" text-anchor="middle" font-size="22" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>
    <circle cx="648" cy="267" r="11" fill="#FCD34D"/>
    <text x="648" y="272" text-anchor="middle" font-size="13" font-weight="900" fill="#92400E" style="pointer-events:none">!</text>

    <!-- Goal — High Value Resources / Proactive Security -->
    <circle id="jnd6" cx="820" cy="190" r="50" fill="#22c55e" filter="url(#jnd-shadow)"/>
    <rect x="807" y="155" width="26" height="32" rx="3" fill="white" opacity="0.9"/>
    <line x1="812" y1="163" x2="828" y2="163" stroke="#22c55e" stroke-width="1.5"/>
    <line x1="812" y1="169" x2="828" y2="169" stroke="#22c55e" stroke-width="1.5"/>
    <line x1="812" y1="175" x2="823" y2="175" stroke="#22c55e" stroke-width="1.5"/>
    <text x="820" y="199" text-anchor="middle" font-size="8.5" font-weight="700" fill="white" font-family="-apple-system,sans-serif">Proactive</text>
    <text x="820" y="210" text-anchor="middle" font-size="8.5" font-weight="700" fill="white" font-family="-apple-system,sans-serif">Security</text>
    <text id="jnd6-cnt" x="820" y="226" text-anchor="middle" font-size="9.5" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif">—</text>
    <text x="820" y="252" text-anchor="middle" font-size="7.5" fill="#64748b" font-family="-apple-system,sans-serif">High Value Resources</text>

    <!-- Goal status pill -->
    <rect id="jph3" x="766" y="259" width="108" height="19" rx="9.5" fill="#94a3b8"/>
    <text id="jph3-txt" x="820" y="272" text-anchor="middle" font-size="8.5" font-weight="800" fill="white" letter-spacing="1" font-family="-apple-system,sans-serif">TARGET ≥ 90</text>

  </svg>
  </div>
  </div><!-- /lab-global-panel -->

  <!-- ── Per-CSP diagram (shared SVG, re-rendered per active tab) ── -->
  <div id="lab-csp-panel" style="display:none">
    <!-- CSP header row -->
    <div style="padding:14px 24px 0;display:flex;align-items:center;gap:10px">
      <span id="clab-csp-badge" style="font-size:10px;font-weight:900;letter-spacing:.14em;text-transform:uppercase;padding:3px 12px;border-radius:5px;color:#fff;background:#94a3b8">—</span>
      <span style="font-size:11px;color:var(--sub)">Posture: <b id="clab-score" style="color:#94a3b8">—</b> &nbsp;·&nbsp; <span id="clab-band-txt">—</span> &nbsp;·&nbsp; Fix findings to advance toward Proactive Security</span>
    </div>
    <!-- CSP snake diagram -->
    <div class="cjmap-outer">
    <svg class="cjmap-svg" viewBox="0 0 700 480" preserveAspectRatio="xMidYMid meet">
      <defs>
        <filter id="cjnd-shadow" x="-30%" y="-30%" width="160%" height="160%">
          <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="rgba(0,0,0,.22)"/>
        </filter>
        <filter id="cjph-shadow" x="-5%" y="-30%" width="115%" height="180%">
          <feDropShadow dx="1" dy="3" stdDeviation="3" flood-color="rgba(0,0,0,.18)"/>
        </filter>
      </defs>

      <!-- Phase chevron headers -->
      <polygon id="cjph1" points="0,4 350,4 374,27 350,50 0,50" fill="#ef4444" filter="url(#cjph-shadow)"/>
      <text x="175" y="32" text-anchor="middle" font-size="11" font-weight="800" fill="white" letter-spacing="2.5" font-family="-apple-system,sans-serif">CRITICAL</text>

      <polygon id="cjph2" points="350,4 700,4 700,50 350,50 374,27" fill="#94a3b8" filter="url(#cjph-shadow)"/>
      <text id="cjph2-txt" x="525" y="32" text-anchor="middle" font-size="10" font-weight="800" fill="white" letter-spacing="2" font-family="-apple-system,sans-serif">GOAL</text>

      <!-- Background snake (gray dashed) -->
      <path d="M250,155 L250,365 C250,435 550,435 550,365 L550,155"
        fill="none" stroke="#e2e8f0" stroke-width="10" stroke-dasharray="16,10" stroke-linecap="round" stroke-linejoin="round"/>

      <!-- Colored animated snake -->
      <path id="cjsnake" d="M250,155 L250,365 C250,435 550,435 550,365 L550,155"
        fill="none" stroke="#ef4444" stroke-width="5" stroke-dasharray="14,12" stroke-linecap="round" stroke-linejoin="round"
        style="animation:snake-flow 1.2s linear infinite"/>

      <!-- Direction arrows -->
      <polygon points="243,246 257,246 250,262" fill="#cbd5e1"/>
      <polygon points="388,425 402,431 388,437" fill="#cbd5e1"/>
      <polygon points="543,264 557,264 550,248" fill="#cbd5e1"/>

      <!-- Node 1 — Identities -->
      <circle id="cjnd1" cx="250" cy="155" r="58" fill="#ef4444" filter="url(#cjnd-shadow)" style="cursor:pointer" onclick="nav('identities')"/>
      <text x="250" y="135" text-anchor="middle" font-size="8.5" font-weight="700" fill="rgba(255,255,255,.65)" letter-spacing="2" font-family="-apple-system,sans-serif" style="pointer-events:none">STEP 1</text>
      <text x="250" y="153" text-anchor="middle" font-size="12" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Identities</text>
      <text id="cjnd1-cnt" x="250" y="180" text-anchor="middle" font-size="26" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>

      <!-- Node 2 — Alerts -->
      <circle id="cjnd2" cx="250" cy="365" r="58" fill="#ef4444" filter="url(#cjnd-shadow)" style="cursor:pointer" onclick="nav('alerts')"/>
      <text x="250" y="345" text-anchor="middle" font-size="8.5" font-weight="700" fill="rgba(255,255,255,.65)" letter-spacing="2" font-family="-apple-system,sans-serif" style="pointer-events:none">STEP 2</text>
      <text x="250" y="363" text-anchor="middle" font-size="11" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Critical Alerts</text>
      <text id="cjnd2-cnt" x="250" y="390" text-anchor="middle" font-size="26" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>

      <!-- Node 3 — Compliance -->
      <circle id="cjnd3" cx="550" cy="365" r="58" fill="#f59e0b" filter="url(#cjnd-shadow)" style="cursor:pointer" onclick="nav('compliance')"/>
      <text x="550" y="345" text-anchor="middle" font-size="8.5" font-weight="700" fill="rgba(255,255,255,.65)" letter-spacing="2" font-family="-apple-system,sans-serif" style="pointer-events:none">STEP 3</text>
      <text x="550" y="363" text-anchor="middle" font-size="12" font-weight="700" fill="white" font-family="-apple-system,sans-serif" style="pointer-events:none">Compliance</text>
      <text id="cjnd3-cnt" x="550" y="390" text-anchor="middle" font-size="26" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif" style="pointer-events:none">—</text>

      <!-- Goal — Proactive Security -->
      <circle id="cjnd-goal" cx="550" cy="155" r="58" fill="#22c55e" filter="url(#cjnd-shadow)"/>
      <text x="550" y="135" text-anchor="middle" font-size="8.5" font-weight="700" fill="rgba(255,255,255,.65)" letter-spacing="2" font-family="-apple-system,sans-serif">GOAL</text>
      <text x="550" y="153" text-anchor="middle" font-size="11" font-weight="700" fill="white" font-family="-apple-system,sans-serif">Proactive</text>
      <text x="550" y="167" text-anchor="middle" font-size="11" font-weight="700" fill="white" font-family="-apple-system,sans-serif">Security</text>
      <text id="cjnd-goal-cnt" x="550" y="192" text-anchor="middle" font-size="24" font-weight="900" fill="white" font-family="-apple-system,BlinkMacSystemFont,sans-serif">—</text>
    </svg>
    </div>
  </div>
</div>

<div class="view" id="view-admin-settings">
  <div class="view-hdr">
    <div class="vh-text">
      <div class="vh-title">Admin Settings</div>
      <div class="vh-sub">Configure dashboard behaviour</div>
    </div>
  </div>
  <div style="padding:24px 20px;max-width:520px">
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
          <option value="21">21 days (default)</option>
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
    {id:'rf-pseg-v',key:'v',n:(d.vulns||[]).length},
    {id:'rf-pseg-i',key:'i',n:(d.identities||[]).length},
    {id:'rf-pseg-c',key:'c',n:(d.compliance||[]).length},
    {id:'rf-pseg-s',key:'s',n:(d.secretsAll||[]).length},
  ];
  var total=segs.reduce(function(s,c){return s+c.n;},0);
  var C=502.65,GAP=7;
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
  if(err){state('body-v','',err);return}
  setKpi('kpi-v',rows.length);setCount('cnt-v',rows.length,true);
  if(!rows.length){state('body-v','','No CVEs with risk score \\u2265 9');return}
  const baseV='https://'+(_lastData?.account||'');
  setBody('body-v','<div class="tbl-wrap"><table><thead><tr><th>CVE / Vuln ID</th><th>Risk</th><th>Package</th><th>Host</th><th>Fix Version</th><th></th></tr></thead><tbody>'
    +rows.map(r=>{
      const fix=r.fixInfo?.fix_available===true||String(r.fixInfo?.fix_available)==='1'||r.fixInfo?.fix_available==='1';
      const fixVer=r.fixInfo?.fixed_version||'';
      const cveId=e(r.vulnId||r.cveId||'');
      return'<tr class="strip-cr">'
        +'<td class="m"><a class="rf-link" href="'+e(baseV)+'" target="_blank">'+e(r.vulnId||r.cveId||'\\u2014')+'</a><button class="cp-btn" data-cp="'+cveId+'">'+cpIcon+'</button></td>'
        +'<td class="r"><span class="risk-score">'+parseFloat(r.riskScore||0).toFixed(1)+'</span></td>'
        +'<td class="p">'+e(r.featureKey?.name||'—')+'</td>'
        +'<td class="m">'+e(r.evalCtx?.hostname||r.mid||'—')+'</td>'
        +'<td>'+(fix?'<span class="b b-ok" title="'+e(fixVer)+'">'+e(tr(fixVer,18)||'Fix \\u2713')+'</span>':'<span class="b b-nt">No fix</span>')+'</td>'
        +'<td><a href="https://www.fortiguard.com/threatintel-search?q='+cveId+'" target="_blank" style="font-size:10px;padding:2px 9px;border-radius:5px;background:#f97316;color:#fff;font-weight:700;white-space:nowrap;text-decoration:none;display:inline-block" title="FortiGuard Threat Intel">FortiGuard ↗</a></td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function renderCompliance(rows,err){
  if(err){state('body-c','',err);return}
  setKpi('kpi-c',rows.length);setCount('cnt-c',rows.length,true);
  if(!rows.length){state('body-c','','No critical compliance violations');return}
  const baseC='https://'+(_lastData?.account||'');
  setBody('body-c','<div class="tbl-wrap"><table><thead><tr><th>Policy ID</th><th>Cloud</th><th>Title</th><th>Description</th><th>Severity</th><th>Violations</th><th></th></tr></thead><tbody>'
    +rows.map(r=>'<tr class="'+strip(r.severity)+'">'
      +'<td class="m"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(r.alertId||'—')+'</a><button class="cp-btn" data-cp="'+e(r.alertId||'')+'">'+cpIcon+'</button></td>'
      +'<td>'+cloud(r.cloud)+'</td>'
      +'<td class="desc"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(r.title||'—')+'</a></td>'
      +'<td class="desc">'+e(r.description||'—')+'</td>'
      +'<td>'+sev(r.severity)+'</td>'
      +'<td class="r">'+e(r.violations||0)+'</td>'
      +'<td><button class="comp-det-btn" data-pid="'+e(r.alertId||'')+'" style="font-size:10px;padding:2px 9px;border-radius:5px;border:none;cursor:pointer;background:#f59e0b;color:#fff;font-weight:700" title="Non-compliant resources">Details</button></td>'
    +'</tr>').join('')+'</tbody></table></div>');
}

function renderIdentities(rows,err){
  if(err){state('body-i','',err);return}
  setKpi('kpi-i',rows.length);setCount('cnt-i',rows.length,true);
  if(!rows.length){state('body-i','','No high-permissive identities found');return}

  // Derive principal type and short name from PRINCIPAL_ID / NAME
  function identType(r){
    const pid=(r.PRINCIPAL_ID||'').toLowerCase();
    const nm=(r.NAME||'').toLowerCase();
    if(pid.includes(':root')||nm==='root')return{label:'Root Account',color:'#dc2626',bg:'#fef2f2',border:'#fecaca'};
    if(pid.includes('serviceaccount')||nm.includes('serviceaccount')||pid.includes('.iam.gserviceaccount.com'))return{label:'Service Account',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'};
    if(pid.includes(':assumed-role/')||pid.includes('/sts:'))return{label:'Assumed Role',color:'#b45309',bg:'#fffbeb',border:'#fde68a'};
    if(pid.includes(':role/')||nm.includes('role'))return{label:'IAM Role',color:'#0369a1',bg:'#f0f9ff',border:'#bae6fd'};
    if(pid.includes(':user/')||nm.includes('user'))return{label:'IAM User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
    const pt=(r.PROVIDER_TYPE||r.CLOUD_PROVIDER||'').toLowerCase();
    if(pt.includes('serviceprincipal')||pt.includes('aad'))return{label:'Service Principal',color:'#7c3aed',bg:'#f5f3ff',border:'#ddd6fe'};
    if(pt.includes('user'))return{label:'User',color:'#065f46',bg:'#ecfdf5',border:'#a7f3d0'};
    return{label:'Identity',color:'#475569',bg:'#f8fafc',border:'#e2e8f0'};
  }

  // Parse assigned-to from PRINCIPAL_ID path segments
  function assignedTo(r){
    const pid=r.PRINCIPAL_ID||'';
    // AWS: arn:aws:iam::ACCOUNT:role/NAME or arn:aws:iam::ACCOUNT:user/NAME
    const arnMatch=pid.match(/arn:[^:]+:[^:]+::[^:]*:(?:role|user|group|policy)\\/(.+)/i);
    if(arnMatch)return arnMatch[1];
    // GCP service account: name@project.iam.gserviceaccount.com
    const gcpMatch=pid.match(/^([^@]+)@([^.]+)/);
    if(gcpMatch)return gcpMatch[1]+' @ '+gcpMatch[2];
    // Azure: show last segment after /
    const azureMatch=pid.match(/\\/([^\\/]+)$/);
    if(azureMatch)return azureMatch[1];
    return r.NAME||pid;
  }

  const iHref='https://'+(_lastData?.account||'')+'/ui/insights';

  setBody('body-i','<div style="padding:8px 0">'
    +rows.map(r=>{
      const risks=r.METRICS?.risks??[];
      const isAdmin=risks.includes('ALLOWS_FULL_ADMIN');
      const noMfa=risks.includes('PASSWORD_LOGIN_NO_MFA')||r.MFA_ENABLED===false||r.MFA_ENABLED==='false';
      const riskSev=(r.METRICS?.risk_severity||'').toLowerCase();
      const riskScore=Math.round((r.METRICS?.risk_score||0)*100);
      const unused=r.ENTITLEMENT_COUNTS?.entitlements_unused_count??null;
      const total=r.ENTITLEMENT_COUNTS?.entitlements_total_count??null;
      const iName=r.NAME||r.PRINCIPAL_ID||'';
      const assigned=assignedTo(r);
      const type=identType(r);
      const provider=(r.PROVIDER_TYPE||r.CLOUD_PROVIDER||'').toUpperCase().replace(/_/g,' ');
      const keys=Array.isArray(r.ACCESS_KEYS)?r.ACCESS_KEYS:[];
      const activeKeys=keys.filter(k=>(k.active||k.status||'').toString().toLowerCase()==='true'||k.active===true);

      // Risk flag chips
      const RISK_LABELS={'ALLOWS_FULL_ADMIN':'Full Admin','PASSWORD_LOGIN_NO_MFA':'No MFA','UNUSED_ACCESS_KEY_90_DAYS':'Key Unused 90d','UNUSED_PERMISSION_90_DAYS':'Perms Unused 90d','HAS_CONSOLE_ACCESS':'Console Access','EXCESSIVE_PERMISSIONS':'Excessive Perms','CROSS_ACCOUNT_ACCESS':'Cross-Account'};
      const riskChips=risks.map(rk=>{
        const lbl=RISK_LABELS[rk]||(rk.replace(/_/g,' ').toLowerCase().replace(/\b\w/g,c=>c.toUpperCase()));
        const isRed=rk==='ALLOWS_FULL_ADMIN';
        const isAmber=rk==='PASSWORD_LOGIN_NO_MFA'||rk==='CROSS_ACCOUNT_ACCESS';
        const bg=isRed?'#fef2f2':isAmber?'#fffbeb':'#f8fafc';
        const col=isRed?'#dc2626':isAmber?'#b45309':'#475569';
        const brd=isRed?'#fecaca':isAmber?'#fde68a':'#e2e8f0';
        return'<span style="font-size:10px;font-weight:700;background:'+bg+';color:'+col+';border:1px solid '+brd+';border-radius:4px;padding:1px 7px">'+e(lbl)+'</span>';
      }).join('');

      return'<div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;margin:8px 16px;padding:14px 18px">'
        // Header row: type badge + name + cloud + score
        +'<div style="display:flex;align-items:flex-start;gap:10px;margin-bottom:8px">'
          +'<span style="font-size:10px;font-weight:700;background:'+type.bg+';color:'+type.color+';border:1px solid '+type.border+';border-radius:5px;padding:2px 8px;white-space:nowrap;flex-shrink:0">'+e(type.label)+'</span>'
          +'<div style="flex:1;min-width:0">'
            +'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">'
              +'<a class="rf-link" href="'+e(iHref)+'" target="_blank" style="font-weight:700;font-size:13px;color:#0f172a;text-decoration:none;word-break:break-all" title="'+e(r.PRINCIPAL_ID||'')+'">'+e(tr(iName,40))+'</a>'
              +'<button class="cp-btn" data-cp="'+e(iName)+'" title="Copy identity">'+cpIcon+'</button>'
            +'</div>'
            // Assigned-to line
            +(assigned&&assigned!==iName?'<div style="font-size:11px;color:#475569;margin-top:2px">Assigned to: <strong>'+e(assigned)+'</strong></div>':'')
            +(r.PRINCIPAL_ID&&r.PRINCIPAL_ID!==iName?'<div style="font-size:10px;color:#94a3b8;margin-top:1px;font-family:monospace;word-break:break-all">'+e(tr(r.PRINCIPAL_ID,60))+'</div>':'')
          +'</div>'
          +'<div style="text-align:right;flex-shrink:0">'
            +(riskScore?'<div style="font-size:18px;font-weight:900;color:'+(riskScore>=70?'#dc2626':riskScore>=40?'#f59e0b':'#475569')+'">'+riskScore+'</div><div style="font-size:9px;color:#94a3b8">risk</div>':'')
          +'</div>'
        +'</div>'
        // Meta row: provider, last used, unused entitlements, access keys
        +'<div style="display:flex;gap:12px;flex-wrap:wrap;font-size:10px;color:#64748b;margin-bottom:8px">'
          +(provider?'<span>☁️ '+e(provider)+'</span>':'')
          +(r.LAST_USED_TIME?'<span>Last used: '+fmtDate(r.LAST_USED_TIME)+'</span>':'<span style="color:#ef4444">Never used</span>')
          +(unused!==null&&total!==null?'<span>Unused perms: <strong style="color:#f59e0b">'+unused+' / '+total+'</strong></span>':'')
          +(activeKeys.length?'<span style="color:#dc2626">'+activeKeys.length+' active access key'+(activeKeys.length>1?'s':'')+'</span>':'')
        +'</div>'
        // Risk flag chips
        +(riskChips?'<div style="display:flex;gap:5px;flex-wrap:wrap">'+riskChips+'</div>':'')
        +(noMfa&&!risks.includes('PASSWORD_LOGIN_NO_MFA')?'<div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px"><span style="font-size:10px;font-weight:700;background:#fffbeb;color:#b45309;border:1px solid #fde68a;border-radius:4px;padding:1px 7px">No MFA</span></div>':'')
      +'</div>';
    }).join('')
    +'<div style="padding:10px 16px 4px;font-size:10px;color:#94a3b8;text-align:center">Showing up to 25 high-permissive identities — Full Admin &amp; High/Critical risk · sorted by privilege level then risk score</div>'
    +'</div>');
}

function renderSecretsAll(rows,err){
  const el=document.getElementById('t-sa');if(el)el.textContent=rows?rows.length:'—';
  setCount('cnt-sa',rows?rows.length:0,true);
  if(err){state('body-sa','',err);return}
  if(!rows||!rows.length){state('body-sa','','No secrets detected');return}
  // Group by SECRET_TYPE
  const groups={};
  rows.forEach(r=>{
    const cat=r.SECRET_TYPE||'Unknown';
    if(!groups[cat])groups[cat]=[];
    groups[cat].push(r);
  });
  const SECRET_TYPE_LABELS={'SSH_PRIVATE_KEY':'Moderate to High Permissive Access SSH Private Key','SSH_PRIVATE_KEYS':'Moderate to High Permissive Access SSH Private Key','RSA':'Moderate to High Permissive Access SSH Private Key (RSA)','ECDSA':'Moderate to High Permissive Access SSH Private Key (ECDSA)','ED25519':'Moderate to High Permissive Access SSH Private Key (ED25519)','AWS_SECRET_ACCESS_KEY':'Moderate to High Permissive Access AWS Secret Access Key','AWS_ACCESS_KEY':'Moderate to High Permissive Access AWS Secret Access Key','AWS_CREDENTIALS':'Moderate to High Permissive Access AWS Credentials','AWS_SECRET':'Moderate to High Permissive Access AWS Secret Access Key'};
  const displayCat=cat=>SECRET_TYPE_LABELS[cat]||SECRET_TYPE_LABELS[cat.toUpperCase()]||cat;
  const isHighRisk=cat=>{const l=cat.toLowerCase();return l.includes('key')||l.includes('token')||l.includes('password')||l.includes('credential');};
  const sortedGroups=Object.entries(groups).sort((a,b)=>{
    const ah=isHighRisk(a[0])?1:0,bh=isHighRisk(b[0])?1:0;
    if(ah!==bh)return bh-ah;
    return b[1].length-a[1].length;
  });
  const renderGroup=([cat,items])=>{
    const high=isHighRisk(cat);
    const hdrColor=high?'#ef4444':'#0ea5e9';
    const hdrBg=high?'#fef2f2':'#f0f9ff';
    const rowsHtml=items.map(r=>{
      const inContainer=r.IS_IN_CONTAINER===true||r.IS_IN_CONTAINER==='true'||r.IS_IN_CONTAINER===1;
      const containerLabel=inContainer?'<span class="b b-hi" title="'+e(r.CONTAINER_KEY||'')+'">'+e(r.CONTAINER_KEY?r.CONTAINER_KEY.slice(0,16):'Container')+'</span>':'<span style="color:#94a3b8">—</span>';
      const detectedAt=r.RECORD_CREATED_TIME?fmtDate(r.RECORD_CREATED_TIME):r.BATCH_END_TIME?fmtDate(r.BATCH_END_TIME):'—';
      const meta=(typeof r.SECRET_METADATA==='object'&&r.SECRET_METADATA)?r.SECRET_METADATA:{};
      const rawPerms=r.FILE_PERMISSIONS!=null?r.FILE_PERMISSIONS:meta.file_permissions;
      let dacHtml;
      if(rawPerms==null){
        dacHtml='<span style="color:#94a3b8">—</span>';
      }else{
        const oct=(rawPerms&0o777).toString(8).padStart(3,'0');
        const permissive=(rawPerms&0o377)!==0;
        const col=permissive?'#ef4444':'#22c55e';
        const plain=(function(o){
          const m={
            '777':'Everyone: read, write & execute',
            '776':'Owner+Group: read/write/execute · Others: read/write',
            '775':'Owner+Group: read/write/execute · Others: read/execute',
            '774':'Owner+Group: read/write/execute · Others: read-only',
            '755':'Owner: full · Others: read & execute',
            '750':'Owner: full · Group: read/execute · Others: none',
            '700':'Owner only: full access',
            '666':'Everyone: read & write (no execute)',
            '664':'Owner+Group: read/write · Others: read-only',
            '660':'Owner+Group: read/write · Others: none',
            '644':'Owner: read/write · Others: read-only',
            '640':'Owner: read/write · Group: read-only · Others: none',
            '600':'Owner: read/write · Others: none',
            '400':'Owner: read-only (recommended)',
            '444':'Everyone: read-only',
          };
          if(m[o])return m[o];
          const u=parseInt(o[0]),g=parseInt(o[1]),w=parseInt(o[2]);
          const bits=n=>(n&4?'r':'-')+(n&2?'w':'-')+(n&1?'x':'-');
          return'Owner: '+bits(u)+' · Group: '+bits(g)+' · World: '+bits(w);
        })(oct);
        dacHtml='<span style="font-size:11px;font-weight:600;color:'+col+'">'
          +'<code style="font-size:11px;font-weight:700;margin-right:5px">'+oct+'</code>'
          +e(plain)+'</span>';
      }
      return'<tr>'
        +'<td class="p">'+e(r.HOSTNAME||'—')+'<button class="cp-btn" data-cp="'+e(r.HOSTNAME||'')+'">'+cpIcon+'</button></td>'
        +'<td>'+containerLabel+'</td>'
        +'<td class="p"><code style="font-size:11px">'+e(r.FILE_PATH||'—')+'</code><button class="cp-btn" data-cp="'+e(r.FILE_PATH||'')+'">'+cpIcon+'</button></td>'
        +'<td>'+dacHtml+'</td>'
        +'<td class="m">'+detectedAt+'</td>'
        +'</tr>';
    }).join('');
    return'<div style="margin-bottom:18px">'
      +'<div style="display:flex;align-items:center;gap:8px;padding:7px 12px;background:'+hdrBg+';border-left:4px solid '+hdrColor+';border-radius:0 6px 6px 0;margin-bottom:4px">'
        +'<span style="font-weight:700;font-size:13px;color:'+hdrColor+'">'+e(displayCat(cat))+'</span>'
        +'<span style="background:'+hdrColor+';color:#fff;border-radius:10px;font-size:11px;font-weight:700;padding:1px 8px">'+items.length+'</span>'
      +'</div>'
      +'<div class="tbl-wrap"><table><thead><tr><th>Hostname</th><th>Container</th><th>File Path</th><th>Permissions</th><th>Detected</th></tr></thead><tbody>'
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
    const tags=r.evalCtx?.machineTags;
    const INET_KEY=/public.?ip|external.?ip|internet.?exp|public.?dns|public.?host/i;
    const IP_RE=/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    let ip=null;
    // Also check evalCtx top-level fields some providers populate
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

  // Factor 3 — CVE Internet Threat Exposure (per host, Medium weight: riskScore×10)
  (d.vulns||[]).forEach(r=>{
    const host=r.evalCtx?.hostname||r.evalCtx?.mid||'';
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
  if(!sorted.length){state('body-ar','','No significant host-level risk detected');return;}

  const medalColor=i=>i===0?'#ef4444':i===1?'#f97316':i===2?'#f59e0b':'#94a3b8';
  const barColor=s=>s>=60?'#ef4444':s>=30?'#f59e0b':'#22c55e';

  setBody('body-ar','<div style="padding:8px 0">'
    // Legend
    +'<div style="display:flex;gap:10px;flex-wrap:wrap;padding:4px 16px 10px;font-size:10px;font-weight:700">'
      +'<span style="background:#fef2f2;color:#dc2626;border:1px solid #fecaca;border-radius:4px;padding:2px 8px">CIEM +100</span>'
      +'<span style="background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe;border-radius:4px;padding:2px 8px">Secret +50</span>'
      +'<span style="background:#fff7ed;color:#ea580c;border:1px solid #fed7aa;border-radius:4px;padding:2px 8px">Threat Exp riskScore×10</span>'
      +(critMisconfig?'<span style="background:#fefce8;color:#ca8a04;border:1px solid #fde68a;border-radius:4px;padding:2px 8px">Misconfig +'+miscBoost+' ('+critMisconfig+' critical)</span>':'')
    +'</div>'
    +sorted.map((a,i)=>{
    const score=Math.round(a.risk/maxRisk*100);
    const color=barColor(score);
    const avgCveRisk=a.vulns.length?(' · avg '+( a.vulns.reduce((s,v)=>s+parseFloat(v.score||0),0)/a.vulns.length).toFixed(1)):'';
    return'<div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;margin:8px 16px;padding:14px 18px">'
      +'<div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">'
        +'<div style="font-size:20px;font-weight:900;color:'+medalColor(i)+';width:30px;text-align:center;flex-shrink:0">#'+(i+1)+'</div>'
        +'<div style="flex:1;min-width:0">'
          +'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">'
            +'<span style="font-weight:700;font-size:13px;color:#0f172a;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+e(a.name)+'</span>'
            +'<button class="cp-btn" data-cp="'+e(a.name)+'" title="Copy hostname" style="flex-shrink:0">'+cpIcon+'</button>'
            +'<button class="mach-inv-btn" data-hostname="'+e(a.name)+'" style="font-size:10px;padding:2px 9px;border-radius:5px;border:none;cursor:pointer;background:#6366f1;color:#fff;font-weight:700;flex-shrink:0">Details</button>'
          +'</div>'
          +(a.mid&&a.mid!==a.name?'<div style="font-size:10px;color:#94a3b8;margin-top:1px;font-family:monospace">'+e(a.mid)+'</div>':'')
        +'</div>'
        +'<div style="font-size:24px;font-weight:900;color:'+color+';flex-shrink:0">'+score+'</div>'
      +'</div>'
      +'<div style="background:#f1f5f9;border-radius:4px;height:6px;overflow:hidden;margin-bottom:10px">'
        +'<div style="height:6px;border-radius:4px;background:'+color+';width:'+score+'%"></div>'
      +'</div>'
      // Internet exposure flag + 4 factor badges
      +'<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">'
        +(a.internetExposed===true
          ?'<span style="font-size:10px;font-weight:700;background:#fef2f2;color:#dc2626;border:1px solid #fecaca;border-radius:5px;padding:2px 8px">🌐 Internet Exposed'+(a.publicIP?' · '+e(a.publicIP):'')+'</span>'
            +(a.publicIP?'<button class="geo-btn" data-ip="'+e(a.publicIP)+'" data-host="'+e(a.name)+'" style="font-size:10px;font-weight:700;background:#0ea5e9;color:#fff;border:none;border-radius:5px;padding:2px 9px;cursor:pointer">🌍 GeoIP</button>':'')
          :'<span style="font-size:10px;font-weight:700;background:#f8fafc;color:#64748b;border:1px solid #e2e8f0;border-radius:5px;padding:2px 8px">No Int Exp</span>')
        +(a.ciemSecrets.length?'<span title="'+e(a.ciemSecrets.join(', '))+'" style="font-size:10px;font-weight:700;background:#fef2f2;color:#dc2626;border:1px solid #fecaca;border-radius:5px;padding:2px 8px">CIEM: '+a.ciemSecrets.length+' high-perm cred'+(a.ciemSecrets.length>1?'s':'')+'</span>':'')
        +(a.genericSecrets.length?'<span style="font-size:10px;font-weight:700;background:#eff6ff;color:#2563eb;border:1px solid #bfdbfe;border-radius:5px;padding:2px 8px">Secret: '+a.genericSecrets.length+'</span>':'')
        +(a.vulns.length?'<span style="font-size:10px;font-weight:700;background:#fff7ed;color:#ea580c;border:1px solid #fed7aa;border-radius:5px;padding:2px 8px">Threat Exp: '+a.vulns.length+' CVE'+avgCveRisk+'</span>':'')
        +(a.miscRisk?'<span style="font-size:10px;font-weight:700;background:#fefce8;color:#ca8a04;border:1px solid #fde68a;border-radius:5px;padding:2px 8px">Misconfig: '+critMisconfig+' critical</span>':'')
      +'</div>'
    +'</div>';
  }).join('')
  +'<div style="padding:10px 16px 4px;font-size:10px;color:#94a3b8;text-align:center">CIEM &amp; Misconfig are account-wide · Threat Exposure and Secrets are per-host</div>'
  +'</div>');
}

function nav(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  document.getElementById('view-'+name).classList.add('active');
  document.getElementById('nav-'+name).classList.add('active');
  history.replaceState(null,'','#'+name);
}

let _lastData=null;
let _currentLabTab='global';

// Cloud Security Posture Score: higher = better posture (0–100).
// postureScore = 100 − mean(findingRiskScores).  No findings → 100.
// Alert: 95  |  CVE: riskScore×10  |  Compliance: 80  |  Identity: risk_score×100  |  Secret: 75
function calcPostureScore(d){
  const risks=[];
  (d.alerts||[]).forEach(()=>risks.push(95));
  (d.vulns||[]).forEach(r=>risks.push(Math.min(100,parseFloat(r.riskScore||0)*10)));
  (d.compliance||[]).forEach(()=>risks.push(80));
  (d.identities||[]).forEach(r=>risks.push(Math.min(100,(r.METRICS?.risk_score||0)*100)));
  (d.secretsAll||[]).forEach(()=>risks.push(75));
  return Math.max(0, Math.round(risks.length ? 100-risks.reduce((s,v)=>s+v,0)/risks.length : 100));
}
// 90–100 Green · 60–89 Orange · 0–59 Red  (higher = better posture)
function scoreColor(p){return p>=90?'#22c55e':p>=50?'#f59e0b':'#ef4444';}
function scoreBand(p){return p>=90?'Proactive Security':p>=50?'Some Attention Needed':'URGENT – Attention Needed';}

function renderRiskFindings(d){
  const p=calcPostureScore(d);
  const color=scoreColor(p);
  const band=scoreBand(p);
  const na=d.alerts?.length??0,nv=d.vulns?.length??0,nc=d.compliance?.length??0,ni=d.identities?.length??0,ns=(d.secretsAll||[]).length;
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
    {key:'Alert',     label:'High Fidelity Alerts',       color:'#ef4444', tab:'alerts',      items:(d.alerts||[]).map(r=>({title:r.alertName,     copyVal:r.alertName||r.alertId,   detail:r.alertType,score:95}))},
    {key:'CVE',       label:'Internet Threat Exposure',   color:'#f97316', tab:'vulns',       items:(d.vulns||[]).map(r=>({title:r.vulnId||r.cveId, copyVal:r.vulnId||r.cveId,        detail:(r.featureKey?.name||'')+' · '+(r.evalCtx?.hostname||''),score:parseFloat(r.riskScore||0)*10}))},
    {key:'Identity',  label:'Identities',                 color:'#8b5cf6', tab:'identities',  items:(d.identities||[]).map(r=>({title:r.NAME||r.PRINCIPAL_ID, copyVal:r.NAME||r.PRINCIPAL_ID, detail:(r.PROVIDER_TYPE||'')+' · No MFA',score:(r.METRICS?.risk_score||0)*100}))},
    {key:'Compliance',label:'Critical Misconfigurations', color:'#f59e0b', tab:'compliance',  items:(d.compliance||[]).map(r=>({title:r.title,     copyVal:r.alertId||r.title,       detail:(r.cloud||'').toUpperCase()+' · '+r.violations+' violations',score:80}))},
    {key:'Secret',    label:'Secrets Detected',           color:'#0ea5e9', tab:'secrets-all', items:(d.secretsAll||[]).map(r=>({title:r.SECRET_TYPE||'Secret', copyVal:r.HOSTNAME||r.SECRET_IDENTIFIER||r.SECRET_TYPE, detail:(r.HOSTNAME||'—')+' · '+tr(r.SECRET_IDENTIFIER||'',28),score:90}))},
  ].filter(g=>g.items.length);
  if(!groups.length){setBody('rf-table','<div class="state"><span>No risk findings</span></div>');return;}
  const rows=groups.map(g=>{
    const hdr='<tr style="background:#f8fafc;border-top:2px solid '+g.color+'">'
      +'<td colspan="3" style="padding:7px 12px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:'+g.color+'"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:'+g.color+';margin-right:6px;vertical-align:middle"></span>'+e(g.label)+'</td>'
      +'<td style="padding:7px 12px;text-align:right;font-size:11px;font-weight:700;color:'+g.color+'"><a href="#" data-tab="'+g.tab+'" onclick="nav(this.dataset.tab);return false;" style="color:inherit;text-decoration:none;border-bottom:1px dashed currentColor">'+g.items.length+' finding'+(g.items.length===1?'':'s')+' ↗</a></td>'
      +'</tr>';
    const detail=g.items.map((r,i)=>'<tr style="'+(i%2?'background:#fafafa':'')+'">'
      +'<td class="p" colspan="2" style="display:flex;align-items:center;gap:4px">'+e(tr(r.title,48))+'<button class="cp-btn" data-cp="'+e(r.copyVal||r.title)+'" title="Copy">'+cpIcon+'</button></td>'
      +'<td class="m">'+e(tr(r.detail,36))+'</td>'
      +'<td class="r"><span class="risk-score">'+Math.round(r.score)+'</span></td>'
    +'</tr>').join('');
    return hdr+detail;
  }).join('');
  setBody('rf-table','<div class="tbl-wrap"><table><thead><tr><th colspan="2">Finding</th><th>Detail</th><th>Risk Score</th></tr></thead><tbody>'+rows+'</tbody></table></div>');
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
// Option 3 — Hybrid Severity-Bucket model (logarithmic penalty, base 11)
// Buckets: CRITICAL(max -40) | HIGH(max -30) | MEDIUM(max -20) | LOW(max -10)
// penalty_b = max_b × log₁₁(1 + count_b)   score = 100 − Σ penalty_b
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
  // Identities — bucket by risk_score (0–1 scale)
  (d.identities||[]).filter(r=>cspOfIdentity(r)===csp).forEach(r=>{
    const rs=r.METRICS?.risk_score||0;
    if(rs>=0.8)C++;else if(rs>=0.5)H++;else if(rs>=0.2)M++;else L++;
  });
  if(C+H+M+L===0)return null;
  const log11=n=>Math.log(1+n)/Math.log(11);
  const penalty=40*log11(C)+30*log11(H)+20*log11(M)+10*log11(L);
  return Math.max(0,Math.round(100-Math.min(100,penalty)));
}
function cspBadgeColor(csp){return{aws:'#FF9900',azure:'#0078D4',gcp:'#4285F4'}[csp]||'#94a3b8';}

function renderCspLab(d,csp){
  const alerts=(d.alerts||[]).filter(r=>cspOfAlert(r)===csp);
  const compliance=(d.compliance||[]).filter(r=>(r.cloud||'')===csp);
  const identities=(d.identities||[]).filter(r=>cspOfIdentity(r)===csp);
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
  if(bandEl)bandEl.textContent=band;
  const nodes=[
    {nd:'cjnd1',cnt:'cjnd1-cnt',count:identities.length,activeClr:'#ef4444'},
    {nd:'cjnd2',cnt:'cjnd2-cnt',count:alerts.length,    activeClr:'#ef4444'},
    {nd:'cjnd3',cnt:'cjnd3-cnt',count:compliance.length,activeClr:'#f59e0b'},
  ];
  nodes.forEach(n=>{
    const el=document.getElementById(n.nd),ct=document.getElementById(n.cnt);
    if(ct)ct.textContent=n.count;
    if(el)el.setAttribute('fill',n.count>0?n.activeClr:'#22c55e');
  });
  const goal=document.getElementById('cjnd-goal');
  const goalCnt=document.getElementById('cjnd-goal-cnt');
  if(goal)goal.setAttribute('fill',color);
  // Show current band in goal node (not the score — counts in step nodes are findings, not score points)
  if(goalCnt){goalCnt.setAttribute('font-size','11');goalCnt.textContent=p>=90?'ACHIEVED':p>=50?'ATTENTION':'URGENT';}
  const ph2=document.getElementById('cjph2');
  const ph2txt=document.getElementById('cjph2-txt');
  if(ph2)ph2.setAttribute('fill',color);
  if(ph2txt){ph2txt.textContent=p>=90?'ACHIEVED':'TARGET ≥ 90';ph2txt.setAttribute('fill',p>=90?color:'#22c55e');}
  const snake=document.getElementById('cjsnake');
  if(snake)snake.setAttribute('stroke',color);
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

function renderLab(d){
  const p=calcPostureScore(d);
  const color=scoreColor(p);
  const band=scoreBand(p);
  const ls=document.getElementById('lab-score');ls.textContent=p;ls.style.color=color;
  document.getElementById('lab-band-txt').textContent=band;
  // ── Snake journey map: update SVG elements ──
  const nodes=[
    {nd:'jnd1',cnt:'jnd1-cnt',count:(d.identities||[]).length, activeClr:'#ef4444'},
    {nd:'jnd2',cnt:'jnd2-cnt',count:(d.alerts||[]).length,     activeClr:'#ef4444'},
    {nd:'jnd3',cnt:'jnd3-cnt',count:(d.vulns||[]).length,      activeClr:'#f97316'},
    {nd:'jnd4',cnt:'jnd4-cnt',count:(d.compliance||[]).length, activeClr:'#f59e0b'},
    {nd:'jnd5',cnt:'jnd5-cnt',count:(d.secretsAll||[]).length, activeClr:'#eab308'},
  ];
  nodes.forEach(n=>{
    const el=document.getElementById(n.nd), ct=document.getElementById(n.cnt);
    if(ct)ct.textContent=n.count;
    if(el)el.setAttribute('fill',n.count>0?n.activeClr:'#22c55e');
  });
  // Goal node
  const g6=document.getElementById('jnd6'),g6c=document.getElementById('jnd6-cnt');
  const ph3=document.getElementById('jph3'),ph3t=document.getElementById('jph3-txt');
  if(g6)g6.setAttribute('fill',color);
  if(g6c){g6c.setAttribute('font-size','11');g6c.textContent=p>=90?'ACHIEVED':p>=50?'ATTENTION':'URGENT';}
  if(ph3)ph3.setAttribute('fill',color);
  if(ph3t){ph3t.textContent=p>=90?'ACHIEVED':'TARGET ≥ 90';ph3t.setAttribute('fill',p>=90?color:'#22c55e');}
  // Snake path color tracks score band
  const snake=document.getElementById('jsnake');
  if(snake)snake.setAttribute('stroke',color);
}

async function load(){
  try{
    const d=await fetch('/api/data').then(r=>r.json());
    _lastData=d;
    renderAlerts(d.alerts,d.errors?.alerts);
    _preTriageAll(d.alerts);
    renderVulns(d.vulns,d.errors?.vulns);
    renderCompliance(d.compliance,d.errors?.compliance);
    renderIdentities(d.identities,d.errors?.identities);
    renderSecretsAll(d.secretsAll,d.errors?.secretsAll);
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
    document.getElementById('footer-time').textContent='Assessment window: last '+_db+' days';
    const _sa=document.getElementById('sub-alerts');
    if(_sa)_sa.textContent='Active threats & policy violations · last '+_db+' days';
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
  const band=p<50?'urgent':p<90?'attention':'proactive';
  ['urgent','attention','proactive'].forEach(b=>{
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
    const band=p>=90?'PROACTIVE':p>=50?'ATTENTION':'URGENT';
    const arc=document.getElementById('csp-arc-'+csp);
    const scoreEl=document.getElementById('csp-score-'+csp);
    const bandEl=document.getElementById('csp-band-'+csp);
    const labelEl=document.getElementById('csp-label-'+csp);
    const orgEl=document.getElementById('csp-org-'+csp);
    const subEl=document.getElementById('csp-sub-'+csp);
    if(arc){arc.setAttribute('stroke',color);arc.setAttribute('stroke-dasharray',(p/100*arcLen)+' '+arcLen);}
    if(scoreEl){scoreEl.textContent=p;scoreEl.setAttribute('fill',color);}
    if(bandEl){bandEl.textContent=band;bandEl.setAttribute('fill',color);}
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
  const btn=document.getElementById('rpt-btn-link');
  if(!btn||!user) return;
  const params=new URLSearchParams({customer:(user.company||'Customer'),author:(user.first||'')+(user.last?' '+user.last:'')});
  btn.href='/report?'+params.toString();
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
    const days=s.daysBack||21;
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
// Card cycle — show for 8s, hide, wait _fgFreqSec, repeat
function _fgRunCycle(){
  if(_fgCycleTimer)clearTimeout(_fgCycleTimer);
  if(_fgHideTimer)clearTimeout(_fgHideTimer);
  if(_fgEnabled)_fgShowCard();
  _fgHideTimer=setTimeout(function(){
    _fgHideCard();
    _fgCycleTimer=setTimeout(_fgRunCycle,_fgFreqSec*1000);
  },8000);
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
});

function closeMachPanel(){document.getElementById('mach-overlay').style.display='none';}

// ── GeoIP panel ───────────────────────────────────────────────────────────────
function closeGeoPanel(){document.getElementById('geo-overlay').style.display='none';}
document.getElementById('geo-overlay').addEventListener('click',function(ev){if(ev.target===this)closeGeoPanel();});

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
        <stop offset="0%"    stop-color="#ef4444"/>
        <stop offset="50%"   stop-color="#ef4444"/>
        <stop offset="50%"   stop-color="#f59e0b"/>
        <stop offset="97.5%" stop-color="#f59e0b"/>
        <stop offset="97.5%" stop-color="#22c55e"/>
        <stop offset="100%"  stop-color="#22c55e"/>
      </linearGradient>
    </defs>
    <path fill="none" stroke="#e2e8f0" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>
    <path id="garc" fill="none" stroke="url(#mg)" stroke-width="34" stroke-linecap="round" stroke-dasharray="0 550" d="M 25,205 A 175,175 0 0,1 375,205"/>
    <line x1="200" y1="10" x2="200" y2="44"  stroke="white" stroke-width="3" stroke-linecap="round"/>
    <line x1="350" y1="156" x2="383" y2="146" stroke="white" stroke-width="3" stroke-linecap="round"/>
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
  <span class="dot" id="ldot"></span>Fortinet Rapid Cloud Assessment empowered by FortiCNAPP<br>
  Last refresh: <span id="ltime">—</span>
</div>
<script>
function scoreColor(p){return p>=90?'#22c55e':p>=50?'#f59e0b':'#ef4444';}
function scoreBand(p){return p>=90?'Proactive Security':p>=50?'Some Attention Needed':'URGENT – Attention Needed';}
function calcScore(d){
  var risks=[];
  (d.alerts||[]).forEach(function(){risks.push(95);});
  (d.vulns||[]).forEach(function(r){risks.push(Math.min(100,parseFloat(r.riskScore||0)*10));});
  (d.compliance||[]).forEach(function(){risks.push(80);});
  (d.identities||[]).forEach(function(r){risks.push(Math.min(100,(r.METRICS&&r.METRICS.risk_score||0)*100));});
  (d.secretsAll||[]).forEach(function(){risks.push(75);});
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
    var mb=document.getElementById('m-band');if(mb){mb.textContent=scoreBand(p);mb.style.color=color;}
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
            --color-high: #CC4A1A;              /* Dark orange-red — distinct from Critical */
            --color-high-bg: #FDF0E8;
            --color-medium: #B7770D;            /* Amber */
            --color-medium-bg: #FEF9E7;
            --color-low: #2C5280;               /* Muted blue — informational/low risk */
            --color-low-bg: #EDF2F9;
            --color-success: #1E7A3E;
            --color-success-bg: #E8F5ED;
            --color-primary: #DA291C;           /* Fortinet Red — all primary accents */
            --color-primary-light: #F04030;
            --color-primary-dark: #000000;      /* Fortinet Black — all dark backgrounds */
            --color-text: #1A1A1A;
            --color-text-muted: #5A5A5A;
            --color-border: #D5D5D5;
            --color-bg-light: #F5F5F5;
            --color-bg-section: #FAFAFA;
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
            .pagebreak { page-break-after: always; clear: both; }
            .page-break-before { page-break-before: always; clear: both; }
            .no-print { display: none !important; }
            tbody tr:hover { background: transparent !important; }
            .section-card, .finding-row, .kpi-card, .decision-card, table {
                page-break-inside: avoid;
                break-inside: avoid;
            }
            section.pagebreak {
                page-break-before: always;
            }
            section.pagebreak:first-of-type {
                page-break-before: auto;
            }

            /* ── Tighten spacing for print — prevent large whitespace gaps ── */
            body { padding: 0 2rem; }
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

        /* ── Header ── */
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.2rem 2rem;
            background: var(--color-primary-dark);
            margin-bottom: 0;
        }
        header img { height: 42px; }

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
            font-weight: 700;
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
            border-radius: 8px;
            padding: 1.5rem 2rem;
            margin: 1.5rem auto 2rem;
        }
        .toc h3 { margin-top: 0; font-size: 1rem; color: var(--color-primary-dark); text-align: center; margin-bottom: 1.1rem; }
        .toc-cards { display: flex; gap: 0.75rem; flex-wrap: wrap; }
        .toc-card {
            flex: 1 1 calc(20% - 0.75rem);
            min-width: 140px;
            border: 1px solid var(--color-border);
            border-top: 3px solid var(--color-primary);
            border-radius: 8px;
            padding: 0.9rem 1rem;
            background: white;
            text-decoration: none;
            display: block;
            transition: box-shadow 0.15s;
        }
        .toc-card:hover { box-shadow: 0 4px 12px rgba(218,41,28,0.15); }
        .toc-card .tc-num {
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--color-primary);
            margin-bottom: 0.35rem;
        }
        .toc-card .tc-title {
            font-size: 0.88rem;
            font-weight: 700;
            color: var(--color-primary-dark);
            margin-bottom: 0.35rem;
            line-height: 1.3;
        }
        .toc-card .tc-sub {
            font-size: 0.72rem;
            color: var(--color-text-muted);
            line-height: 1.45;
        }

        /* ── KPI Cards ── */
        .kpi-grid { width: 100%; margin: 3rem 0; overflow: hidden; }
        .kpi-grid::after { content: ""; display: table; clear: both; }
        .kpi-card {
            float: left;
            width: 22%;
            margin-right: 4%;
            background: white;
            border-radius: 10px;
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
            padding: 0.18rem 0.6rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
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
            border-radius: 8px;
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
            border-radius: 6px;
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
            border-radius: 10px;
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
        .intro-card h4 { margin: 0 0 0.6rem; font-size: 0.95rem; color: var(--color-primary-dark); }
        .intro-card p { font-size: 0.8rem; color: var(--color-text-muted); line-height: 1.6; margin: 0; }

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
            border-radius: 8px;
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
            border-top: 1px solid var(--color-border);
            margin: 4rem 0 0;
            opacity: 0.5;
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
        .pagebreak { page-break-after: always; clear: both; }
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

function buildReportHtml(data, meta) {
  const customer = ((meta && meta.customer) || 'Customer').trim();
  const author   = ((meta && meta.author)   || 'Fortinet').trim();
  const dateStr  = new Date().toLocaleDateString('en-US', {weekday:'long',year:'numeric',month:'long',day:'numeric'});

  const alerts     = data.alerts     || [];
  const vulns      = data.vulns      || [];
  const compliance = data.compliance || [];
  const identities = data.identities || [];
  const secrets    = data.secrets    || [];
  const secretsAll = data.secretsAll || [];

  // Server-side scoring — mirrors client calcGlobalScoreFromCsp / calcCspScore exactly
  function _cspOfAlert(r) {
    const t = ((r.alertType||'')+(r.alertName||'')).toUpperCase();
    if (t.includes('AWS')||t.includes('CLOUDTRAIL')||t.includes('EC2')||t.includes('S3')) return 'aws';
    if (t.includes('AZURE')||t.includes('AZ_')) return 'azure';
    if (t.includes('GCP')||t.includes('GOOGLE')||t.includes('GKE')) return 'gcp';
    return null;
  }
  function _cspOfIdentity(r) {
    const p = ((r.PROVIDER_TYPE||r.CLOUD_PROVIDER||'')).toUpperCase();
    if (p.includes('AWS')) return 'aws';
    if (p.includes('AZURE')) return 'azure';
    if (p.includes('GCP')||p.includes('GOOGLE')) return 'gcp';
    return null;
  }
  function calcCspScoreReport(csp) {
    let C=0, H=0, M=0, L=0;
    (data.alerts||[]).filter(r=>_cspOfAlert(r)===csp).forEach(r=>{
      const s=(r.severity||'').toLowerCase();
      if(s==='critical')C++;else if(s==='high')H++;else M++;
    });
    (data.compliance||[]).filter(r=>(r.cloud||'')===csp).forEach(r=>{
      const s=(r.severity||'').toLowerCase();
      if(s==='critical')C++;else H++;
    });
    (data.identities||[]).filter(r=>_cspOfIdentity(r)===csp).forEach(r=>{
      const rs=(r.METRICS&&r.METRICS.risk_score)||0;
      if(rs>=0.8)C++;else if(rs>=0.5)H++;else if(rs>=0.2)M++;else L++;
    });
    if(C+H+M+L===0) return null;
    const log11 = n => Math.log(1+n)/Math.log(11);
    const penalty = 40*log11(C)+30*log11(H)+20*log11(M)+10*log11(L);
    return Math.max(0, Math.round(100-Math.min(100,penalty)));
  }
  const cspScores = { aws: calcCspScoreReport('aws'), azure: calcCspScoreReport('azure'), gcp: calcCspScoreReport('gcp') };
  const cspVals   = ['aws','azure','gcp'].map(c => cspScores[c] !== null ? cspScores[c] : 100);
  const score     = Math.round(cspVals.reduce((s,v)=>s+v,0)/cspVals.length);
  const sBand     = score>=90 ? 'Proactive Security' : score>=50 ? 'Attention Needed' : 'URGENT – Immediate Action Required';
  const sColor    = score>=90 ? '#22c55e' : score>=50 ? '#f59e0b' : '#ef4444';
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

  // ── Vuln rows
  const vulnRows = vulns.length ? vulns.map(function(r,i) {
    const rs  = parseFloat(r.riskScore||0);
    const pkg = (r.featureKey && r.featureKey.name) || '—';
    const ver = (r.featureKey && r.featureKey.version) || '';
    const fixVer = (r.fixInfo && r.fixInfo.fixed_version) || '';
    const fixCell = fixVer ? 'Update <strong>'+esc(pkg)+'</strong> to '+esc(fixVer) :
                    (r.fixInfo && r.fixInfo.fix_available) ? 'Vendor fix available — apply immediately' : 'No fix available yet — apply mitigating controls';
    const outcome = rs >= 10
      ? 'Full system compromise enabling ransomware deployment, data exfiltration, or lateral movement.'
      : 'Remote code execution enabling host compromise, data exfiltration, or privilege escalation.';
    return '<tr'+(i%2===1?' style="background:#FAFAFA;"':'')+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td><span class="badge badge-critical">Critical</span></td>'+
      '<td><strong>'+esc(r.vulnId||r.cveId||'—')+'</strong><br><small class="text-muted">'+esc((r.evalCtx&&r.evalCtx.imageId)?'Container':'Host')+'</small></td>'+
      '<td style="text-align:center"><span class="risk-chip'+(rs<10?' high':'')+'">'+rs.toFixed(1)+'</span></td>'+
      '<td class="med">'+esc((r.evalCtx&&r.evalCtx.hostname)||r.mid||'—')+'</td>'+
      '<td class="med"><strong>'+esc(pkg)+'</strong>'+(ver?'<br><small class="text-muted">'+esc(ver)+'</small>':'')+'</td>'+
      '<td class="wide">'+esc(outcome)+'</td>'+
      '<td class="med">'+fixCell+'</td>'+
      '<td><span class="badge badge-critical">Immediate</span></td>'+
      '</tr>';
  }).join('') : '<tr><td colspan="9" style="text-align:center;color:#999;padding:1.5rem">No critical CVEs</td></tr>';

  // ── Compliance rows
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
  const compRows = compliance.length ? compliance.map(function(r,i) {
    const isCrit = (r.severity||'').toLowerCase()==='critical';
    const bg = isCrit ? ' style="background:#FDECEA;"' : (i%2===1?' style="background:#FAFAFA;"':'');
    const svcArea = compServiceArea(r.title);
    const ctxRisk = 'Misconfigured or non-compliant control expands the attack surface, enabling unauthorized access or data exposure across '+((r.cloud||'cloud').toUpperCase())+' resources.';
    const bizImpact = 'Regulatory non-compliance, potential data breach, audit failure, and reputational risk.';
    const recFix = (r.description||'').slice(0,200) || 'Remediate the control violation per the policy guidance and re-evaluate in FortiCNAPP.';
    // Build resource URN sub-list from saved rows
    var resourceHtml = '';
    if (Array.isArray(r.resources) && r.resources.length) {
      // Detect which field is the URN/resource identifier (priority order)
      var urnKeys = ['URN','RESOURCE_ID','RESOURCE_KEY','RESOURCE_ARN','RESOURCE_IDENTIFIER','INSTANCE_ID','VM_ID','PRINCIPAL_ID','NAME'];
      var rows = r.resources;
      // Pick the first key that exists in the first row
      var firstRow = rows[0] || {};
      var urnKey = urnKeys.find(function(k){ return firstRow[k] !== undefined; }) || Object.keys(firstRow)[0] || '';
      // Secondary label key (e.g. region or type)
      var labelKeys = ['REGION','LOCATION','CLOUD','TYPE','RESOURCE_TYPE','SUBSCRIPTION_ID'];
      var labelKey = labelKeys.find(function(k){ return firstRow[k] !== undefined; }) || '';
      if (urnKey) {
        var shown = rows.slice(0, 50);
        resourceHtml = '<details style="margin-top:6px"><summary style="font-size:10px;font-weight:700;color:#DA291C;cursor:pointer;list-style:none">&#9660; '+rows.length+' Violating Resource'+(rows.length===1?'':'s')+'</summary>'+
          '<div style="max-height:200px;overflow-y:auto;margin-top:4px;border:1px solid #e5e7eb;border-radius:4px">'+
          '<table style="width:100%;font-size:9px;border-collapse:collapse">'+
          '<thead><tr style="background:#f1f5f9"><th style="padding:3px 6px;text-align:left;font-weight:700;color:#64748b">'+esc(urnKey)+'</th>'+
          (labelKey?'<th style="padding:3px 6px;text-align:left;font-weight:700;color:#64748b">'+esc(labelKey)+'</th>':'')+
          '</tr></thead><tbody>'+
          shown.map(function(row,ri){
            var urnVal = row[urnKey] !== undefined ? String(row[urnKey]) : '—';
            var lblVal = labelKey && row[labelKey] !== undefined ? String(row[labelKey]) : '';
            return '<tr style="'+(ri%2?'background:#f8fafc':'')+'">'
              +'<td style="padding:2px 6px;font-family:monospace;color:#1e293b;word-break:break-all">'+esc(urnVal)+'</td>'
              +(labelKey?'<td style="padding:2px 6px;color:#64748b">'+esc(lblVal)+'</td>':'')
              +'</tr>';
          }).join('')+
          (rows.length>50?'<tr><td colspan="2" style="padding:3px 6px;color:#94a3b8;font-style:italic">… and '+(rows.length-50)+' more</td></tr>':'')+
          '</tbody></table></div></details>';
      }
    }
    return '<tr'+bg+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td>'+sevBadge(r.severity)+'</td>'+
      '<td class="wide"><strong>'+esc(r.title||'—')+'</strong>'+resourceHtml+'</td>'+
      '<td class="med">'+cspBadge(r.cloud)+'<br><small class="text-muted">'+esc(r.alertId||'')+'</small></td>'+
      '<td class="med">'+svcArea+'</td>'+
      '<td class="wide">'+esc(ctxRisk)+'</td>'+
      '<td class="wide">'+esc(bizImpact)+'</td>'+
      '<td class="wide">'+esc(recFix)+'</td>'+
      '<td><span class="badge badge-critical">Immediate</span></td>'+
      '</tr>';
  }).join('') : '<tr><td colspan="9" style="text-align:center;color:#999;padding:1.5rem">No compliance findings</td></tr>';

  // ── Identity rows
  const idRows = identities.length ? identities.map(function(r,i) {
    const risks   = (r.METRICS && r.METRICS.risks) || [];
    const rs      = (r.METRICS && r.METRICS.risk_score) || 0;
    const isAdmin = risks.includes('ALLOWS_FULL_ADMIN');
    const noMfa   = risks.includes('PASSWORD_LOGIN_NO_MFA') || !r.MFA_ENABLED;
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
  }).join('') : '<tr><td colspan="7" style="text-align:center;color:#999;padding:1.5rem">No identity risks</td></tr>';

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
    alerts.length     ? '<a href="#alerts" class="toc-card"><div class="tc-num">01 — Alerts</div><div class="tc-title">Critical Alerts</div><div class="tc-sub">'+alerts.length+' open critical alert'+(alerts.length===1?'':'s')+'.</div></a>' : '',
    compliance.length ? '<a href="#compliance" class="toc-card"><div class="tc-num">02 — Compliance</div><div class="tc-title">Critical Non-Compliance</div><div class="tc-sub">'+compliance.length+' control failure'+(compliance.length===1?'':'s')+'.</div></a>' : '',
    vulns.length      ? '<a href="#vulnerabilities" class="toc-card"><div class="tc-num">03 — CVEs</div><div class="tc-title">Critical Vulnerabilities</div><div class="tc-sub">'+vulns.length+' CVE'+(vulns.length===1?'':'s')+' with risk score ≥ 9.</div></a>' : '',
    identities.length ? '<a href="#identity" class="toc-card"><div class="tc-num">04 — Identity</div><div class="tc-title">Identity Risk</div><div class="tc-sub">'+identities.length+' identity risk'+(identities.length===1?'':'s')+'.</div></a>' : '',
    secretsAll.length ? '<a href="#secrets-all" class="toc-card"><div class="tc-num">05 — Secrets</div><div class="tc-title">Discovered Secrets</div><div class="tc-sub">'+secretsAll.length+' secret'+(secretsAll.length===1?'':'s')+' detected across hosts.</div></a>' : '',
    '<a href="#next-steps" class="toc-card"><div class="tc-num">06 — Simulation</div><div class="tc-title">Exploit Simulation Layer</div><div class="tc-sub">'+nextSteps.length+' prioritised action'+(nextSteps.length===1?'':'s')+' to improve your posture.</div></a>',
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
    '<section id="compliance" class="pagebreak">\n<h2>2. Critical Non-Compliance Findings</h2>\n' +
    '<table class="exec-table"><thead><tr>' +
    '<th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:200px">Finding</th>' +
    '<th style="width:120px">Cloud Scope</th><th style="width:90px">Service Area</th>' +
    '<th style="width:180px">Contextual Risk</th><th style="width:180px">Business Impact</th>' +
    '<th style="width:180px">Recommended Fix</th><th style="width:70px">Priority</th>' +
    '</tr></thead><tbody>'+compRows+'</tbody></table>\n</section>'
  ) : '';

  const vulnSection = vulns.length ? (
    '<section id="vulnerabilities" class="pagebreak">\n<h2>3. Critical CVE Vulnerabilities</h2>\n' +
    '<table class="exec-table"><thead><tr>' +
    '<th class="narrow">#</th><th style="width:55px">Severity</th><th style="width:140px">Vulnerability (CVE)</th>' +
    '<th style="width:60px">Risk Score</th><th style="width:140px">Affected Resource</th>' +
    '<th style="width:130px">Package / Version</th><th style="width:200px">Attacker Outcome if Exploited</th>' +
    '<th style="width:130px">Recommended Fix</th><th style="width:65px">Priority</th>' +
    '</tr></thead><tbody>'+vulnRows+'</tbody></table>\n</section>'
  ) : '';

  const idSection = identities.length ? (
    '<section id="identity" class="pagebreak">\n<h2>4. Identity Risk</h2>\n' +
    '<table class="exec-table"><thead><tr>' +
    '<th style="width:160px">Identity</th><th style="width:80px">Privilege</th><th style="width:65px">MFA</th>' +
    '<th style="width:130px">Last Login</th><th style="width:100px">Idle Entitlements</th>' +
    '<th style="width:220px">Risk</th><th style="width:180px">Recommended Fix</th>' +
    '</tr></thead><tbody>'+idRows+'</tbody></table>\n</section>'
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
    '<section id="secrets-all" class="pagebreak">\n<h2>5. Secrets — Discovered Secrets</h2>\n' +
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
  '<header><span style="color:white;font-weight:700;font-size:15px;letter-spacing:.08em">FORTINET</span>' +
  '<span style="color:rgba(255,255,255,.55);font-size:11px">RAPID CLOUD ASSESSMENT</span></header>\n' +
  '<div class="report-cover">\n' +
  '  <div class="report-type">Rapid Cloud Assessment · Cloud Security Risk Findings</div>\n' +
  '  <h1>Cloud Security Posture Report</h1>\n' +
  '  <div class="subtitle">'+esc(customer)+'</div>\n' +
  (function(){
    const arcLen=550, fill=Math.round((score/100)*arcLen);
    function miniGauge(label, p, bgColor) {
      const arcL=314, f=Math.round((p/100)*arcL);
      const c=p>=90?'#22c55e':p>=50?'#f59e0b':'#ef4444';
      const band=p>=90?'PROACTIVE':p>=50?'ATTENTION':'URGENT';
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
      '<stop offset="50%"   stop-color="#ef4444"/>'+
      '<stop offset="50%"   stop-color="#f59e0b"/>'+
      '<stop offset="97.5%" stop-color="#f59e0b"/>'+
      '<stop offset="97.5%" stop-color="#22c55e"/>'+
      '<stop offset="100%" stop-color="#22c55e"/>'+
      '</linearGradient></defs>\n'+
      '    <path fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <path fill="none" stroke="url(#rg)" stroke-width="34" stroke-linecap="round" stroke-dasharray="'+fill+' '+arcLen+'" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <line x1="200" y1="32" x2="200" y2="62"  stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <line x1="350" y1="156" x2="383" y2="146" stroke="rgba(255,255,255,0.4)" stroke-width="2.5" stroke-linecap="round"/>\n'+
      '    <text x="200" y="165" text-anchor="middle" font-size="72" font-weight="900" letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="white">'+score+'</text>\n'+
      '    <text x="-8" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">0</text>\n'+
      '    <text x="408" y="212" text-anchor="middle" font-size="14" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.45)">100</text>\n'+
      '  </svg>\n'+
      '  <div style="text-align:center;font-size:.82rem;font-weight:700;letter-spacing:.08em;color:white;margin-top:2px;text-transform:uppercase">'+esc(sBand)+'</div>\n'+
      '  <div style="text-align:center;font-size:.68rem;font-weight:600;letter-spacing:.1em;color:rgba(255,255,255,0.55);margin-top:6px;text-transform:uppercase">The objective is to achieve <span style="color:#22c55e;font-weight:800">Proactive Security</span></div>\n'+
      '  <div style="display:flex;justify-content:center;gap:28px;margin-top:20px;flex-wrap:wrap">'+
        miniGauge('AWS',awsP,'#232F3E')+
        miniGauge('AZURE',azureP,'#0078D4')+
        miniGauge('GCP',gcpP,'#1a73e8')+
      '</div>\n'+
      '  </div>\n';
  })()+
  '  <div class="meta-row">\n' +
  '    <div class="meta-item"><strong>Prepared For</strong>'+esc(customer)+'</div>\n' +
  '    <div class="meta-item"><strong>Report Date</strong>'+dateStr+'</div>\n' +
  '    <div class="meta-item"><strong>Author</strong>'+esc(author)+'</div>\n' +
  '    <div class="meta-item"><strong>Classification</strong>Confidential</div>\n' +
  '  </div>\n</div>\n' +
  '<div class="toc"><h3>Discovered Risk Findings</h3><div class="toc-cards">\n      '+tocCards+'\n</div></div>\n' +
  '<section id="exec-summary" class="pagebreak">\n<h2>Executive Summary</h2>\n' +
  '<div class="kpi-grid">' +
  '<div class="kpi-card critical"><div class="kpi-number">'+alerts.length+'</div><div class="kpi-label">Critical Alerts</div></div>' +
  '<div class="kpi-card high"><div class="kpi-number">'+vulns.length+'</div><div class="kpi-label">Critical CVEs (Risk ≥ 9)</div></div>' +
  '<div class="kpi-card medium"><div class="kpi-number">'+compliance.length+'</div><div class="kpi-label">Non-Compliance Findings</div></div>' +
  '<div class="kpi-card info"><div class="kpi-number">'+identities.length+'</div><div class="kpi-label">Identity Risk Findings</div></div>' +
  (secrets.length ? '<div class="kpi-card info"><div class="kpi-number">'+secrets.length+'</div><div class="kpi-label">Moderate to High Permissive Access SSH Keys</div></div>' : '') +
  '</div>\n' +
  '<div class="section-summary"><div class="ss-title">Overall Risk Assessment</div>' +
  '<p>This assessment identified <strong style="color:#DA291C">'+total+' total findings</strong> across <strong>'+esc(customer)+'</strong>. ' +
  'The Cloud Security Posture Score is <strong style="color:'+sColor+'">'+score+'/100 — '+esc(sBand)+'</strong>.</p></div>\n' +
  '</section>\n' +
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
          if (d === 7 || d === 14 || d === 21 || d === 30) {
            dynamicDaysBack = d;
            res.writeHead(200, { 'Content-Type': 'application/json', ...CORS });
            res.end(JSON.stringify({ ok: true, daysBack: dynamicDaysBack }));
          } else {
            res.writeHead(400, { 'Content-Type': 'application/json', ...CORS });
            res.end(JSON.stringify({ error: 'daysBack must be 7, 14, 21, or 30' }));
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
        const data = await get(`https://ipinfo.io/${clean}/json`);
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
  } else if (req.url.startsWith('/report')) {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    const customer = (qs.get('customer') || 'Customer').trim();
    const author   = (qs.get('author')   || 'Fortinet').trim();
    if (!cache.fetchedAt) {
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', ...CORS, ...NO_CACHE });
      res.end('<body style="font-family:sans-serif;padding:2rem"><h2>⏳ Dashboard data not yet loaded</h2><p>Please wait a moment and try again.</p></body>');
      return;
    }
    const reportHtml = buildReportHtml(cache, { customer, author });
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
  console.log(`│  Fortinet Rapid Cloud Assessment empowered by FortiCNAPP — ${mode.padEnd(11)}│`);
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
