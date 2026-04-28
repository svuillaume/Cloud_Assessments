#!/usr/bin/env node
// Fortinet Rapid Cloud Assessment — Live Dashboard
// Usage:  node server.js   |   open http://localhost:8080
// No npm packages required.

'use strict';
const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');

const CONTACTS_CSV = path.join(__dirname, 'contacts.csv');
if (!fs.existsSync(CONTACTS_CSV)) {
  fs.writeFileSync(CONTACTS_CSV, 'Timestamp,FirstName,LastName,Company,Role,Email\n');
}

// ── CONFIG ────────────────────────────────────────────────────────────────────
const LW_ACCOUNT = process.env.LW_ACCOUNT || 'partner-demo.lacework.net';
const LW_KEY_ID  = process.env.LW_KEY_ID  || 'YOUR_KEY_ID';
const LW_SECRET  = process.env.LW_SECRET  || 'YOUR_SECRET_KEY';
const PORT       = Number(process.env.PORT) || 8080;
const INTERVAL   = 3600; // refresh interval (seconds) — 60 min
const DAYS_BACK  = 7;    // look-back window
const MOCK_FILE  = process.env.MOCK_FILE  || '';   // set to mock_data.json to skip API calls
// ─────────────────────────────────────────────────────────────────────────────

let token       = null;
let tokenExpiry = 0;
let cache = {
  alerts: [], vulns: [], compliance: [], identities: [],
  fetchedAt: null, errors: {}, account: LW_ACCOUNT,
  riskScore: 0,
  summary: { alerts: 0, vulns: 0, compliance: 0, identities: 0 },
};

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function request(method, hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const opts = {
      hostname, port: 443, path, method,
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
    req.setTimeout(12000, () => { req.destroy(); reject(new Error(`${method} ${path} timed out`)); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
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

async function post(path, body) {
  const tok = await ensureToken();
  const { status, body: resp } = await request(
    'POST', LW_ACCOUNT, `/api/v2/${path}`,
    { Authorization: `Bearer ${tok}` }, body,
  );
  if (status === 204) return [];
  if (status !== 200 && status !== 201)
    throw new Error(`POST ${path} → HTTP ${status}: ${JSON.stringify(resp).slice(0, 200)}`);
  return Array.isArray(resp?.data) ? resp.data : (Array.isArray(resp) ? resp : []);
}

async function get(path) {
  const tok = await ensureToken();
  const { status, body: resp } = await request(
    'GET', LW_ACCOUNT, `/api/v2/${path}`,
    { Authorization: `Bearer ${tok}` }, null,
  );
  if (status === 204) return null;
  if (status !== 200 && status !== 201)
    throw new Error(`GET ${path} → HTTP ${status}: ${JSON.stringify(resp).slice(0, 200)}`);
  return resp;
}



function timeFmt(d) { return d.toISOString().replace(/\.\d{3}Z$/, 'Z'); }

function timeFilter(days) {
  const end   = new Date();
  const start = new Date(Date.now() - (days || DAYS_BACK) * 86400000);
  // NOTE: Lacework v2 search uses singular "timeFilter" not "timeFilters"
  return { startTime: timeFmt(start), endTime: timeFmt(end) };
}

// ── 1. Alerts — POST /api/v2/Alerts/search ───────────────────────────────────

async function fetchAlerts() {
  const rows = await post('Alerts/search', {
    timeFilter: timeFilter(),
    filters: [{ field: 'severity', expression: 'eq', value: 'Critical' }],
    paging: { rows: 50 },
  });
  return rows
    .filter(r => (r.status || '').toLowerCase() !== 'closed')
    .sort((a, b) => new Date(b.startTime || 0) - new Date(a.startTime || 0))
    .slice(0, 10);
}

// ── 2. Vulns — POST /api/v2/Vulnerabilities/Hosts/search ─────────────────────
// riskScore >= 9 filtered client-side (not cveProps.cvssV3Score)

async function fetchVulns() {
  const rows = await post('Vulnerabilities/Hosts/search', {
    timeFilter: timeFilter(),
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

  // Step 2 — run each policy query to count violations
  const findings = [];
  const tf2 = timeFilter();
  for (const p of policies) {
    try {
      const rows = await post('Queries/execute', {
        query: { queryText: p.queryText },
        arguments: [
          { name: 'StartTimeRange', value: tf2.startTime },
          { name: 'EndTimeRange',   value: tf2.endTime   },
        ],
      });
      console.log(`  [compliance] ${p.policyId} → ${rows.length} rows`);
      if (rows.length) findings.push({
        alertId:     p.policyId,
        cloud:       policyCloud(p.queryId || p.policyId),
        title:       p.title || p.policyId,
        description: p.description || '—',
        severity:    'Critical',
        violations:  rows.length,
      });
    } catch (e) {
      console.log(`  [compliance] ${p.policyId} ERR: ${e.message.slice(0,80)}`);
      if (e.message.includes('429')) await new Promise(r => setTimeout(r, 5000));
    }
    if (findings.length >= 10) break;
    await new Promise(r => setTimeout(r, 1200));
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
  if (rows.length) console.log(`  [identities] sample: ${JSON.stringify(rows[0]).slice(0, 200)}`);

  // Filter: no MFA AND (admin OR high risk)
  return rows
    .filter(r => {
      const risks = r.METRICS?.risks ?? [];
      return risks.includes('PASSWORD_LOGIN_NO_MFA');
    })
    .sort((a, b) => {
      const aAdmin = (a.METRICS?.risks ?? []).includes('ALLOWS_FULL_ADMIN') ? 0 : 1;
      const bAdmin = (b.METRICS?.risks ?? []).includes('ALLOWS_FULL_ADMIN') ? 0 : 1;
      return aAdmin - bAdmin;
    })
    .slice(0, 10);
}

// ── 5. Secrets All — POST /api/v2/Queries/execute (LQL) ──────────────────────
// LW_HE_SECRETS_ALL dataset — all discovered secrets across hosts

async function fetchSecretsAll() {
  const tf = timeFilter();
  const queryText = `{source { LW_HE_SECRETS_ALL } return {HOSTNAME, MID, OS, SECRET_TYPE, SECRET_IDENTIFIER, END_TIME}}`;
  const rows = await post('Queries/execute', {
    query: { queryText },
    arguments: [
      { name: 'StartTimeRange', value: tf.startTime },
      { name: 'EndTimeRange',   value: tf.endTime   },
    ],
  });
  console.log(`  [secrets-all] total returned: ${rows.length}`);
  return rows;
}

// ── 6. Secrets SSH Keys — POST /api/v2/Queries/execute (LQL) ─────────────────
// LW_HE_SECRETS_SSH_PRIVATE_KEYS dataset — SSH private keys detected on hosts

async function fetchSecrets() {
  const tf = timeFilter();
  const queryText = `{source { LW_HE_SECRETS_SSH_PRIVATE_KEYS } return {HOSTNAME, FILE_PATH, SSH_KEY_TYPE}}`;
  const rows = await post('Queries/execute', {
    query: { queryText },
    arguments: [
      { name: 'StartTimeRange', value: tf.startTime },
      { name: 'EndTimeRange',   value: tf.endTime   },
    ],
  });
  console.log(`  [secrets-ssh] total returned: ${rows.length}`);
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

function buildHtml(account, intervalSec) {
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
/* ── Recommended Next Steps view ── */
.lab-steps{padding:16px 32px}
.lab-step{display:flex;align-items:flex-start;gap:18px;padding:20px 24px;margin-bottom:10px;background:var(--surface);border:1px solid var(--border);border-radius:10px;box-shadow:0 1px 3px rgba(15,23,42,.04)}
.lab-step-bar{width:4px;border-radius:3px;flex-shrink:0;align-self:stretch;min-height:40px}
.lab-step-n{font-size:13px;font-weight:700;color:var(--muted);min-width:20px;padding-top:1px}
.lab-step-title{font-size:14px;font-weight:600;color:var(--text);line-height:1.5}
.lab-step-sub{font-size:12px;color:var(--muted);margin-top:5px}

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
</style>
</head>
<body>

<!-- Login overlay -->
<div class="login-overlay" id="login-overlay">
  <div class="login-box">
    <div class="login-logo">
      <svg viewBox="0 0 100 100" width="36" height="36"><rect x="5" y="5" width="39" height="28" rx="9" fill="#c93428"/><rect x="56" y="5" width="39" height="28" rx="9" fill="#c93428"/><rect x="5" y="41" width="39" height="18" rx="5" fill="#c93428"/><rect x="56" y="41" width="39" height="18" rx="5" fill="#c93428"/><rect x="5" y="67" width="39" height="28" rx="9" fill="#c93428"/><rect x="56" y="67" width="39" height="28" rx="9" fill="#c93428"/></svg>
      <div class="login-logo-name">FortiCNAPP<br>Rapid Cloud Assessment</div>
    </div>
    <div class="login-title">Welcome</div>
    <div class="login-sub">Please identify yourself to access the dashboard</div>
    <div class="login-row">
      <div class="login-field">
        <div class="login-label">First Name</div>
        <input class="login-input" id="li-first" type="text" placeholder="Jane" autocomplete="given-name"/>
      </div>
      <div class="login-field">
        <div class="login-label">Last Name</div>
        <input class="login-input" id="li-last" type="text" placeholder="Smith" autocomplete="family-name"/>
      </div>
    </div>
    <div class="login-field">
      <div class="login-label">Company</div>
      <input class="login-input" id="li-company" type="text" placeholder="Acme Corp" autocomplete="organization"/>
    </div>
    <div class="login-field">
      <div class="login-label">Role</div>
      <select class="login-select" id="li-role">
        <option value="" disabled selected>Select your role…</option>
        <option>CISO / Security Leader</option>
        <option>Security Architect</option>
        <option>Cloud Engineer</option>
        <option>DevSecOps</option>
        <option>IT Manager</option>
        <option>Sales / PreSales</option>
        <option>Other</option>
      </select>
    </div>
    <div class="login-field">
      <div class="login-label">Email</div>
      <input class="login-input" id="li-email" type="email" placeholder="jane.smith@acme.com" autocomplete="email"/>
    </div>
    <button class="login-btn" onclick="submitLogin()">Access Dashboard</button>
    <div class="login-err" id="login-err"></div>
  </div>
</div>

<div class="app-layout">

<!-- Sidebar -->
<div class="sidebar">
  <div class="sb-brand">
    <div class="sb-logo">
      <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" width="36" height="36">
        <rect x="5" y="5"  width="39" height="28" rx="9" fill="#c93428"/>
        <rect x="56" y="5"  width="39" height="28" rx="9" fill="#c93428"/>
        <rect x="5" y="41" width="39" height="18" rx="5" fill="#c93428"/>
        <rect x="56" y="41" width="39" height="18" rx="5" fill="#c93428"/>
        <rect x="5" y="67" width="39" height="28" rx="9" fill="#c93428"/>
        <rect x="56" y="67" width="39" height="28" rx="9" fill="#c93428"/>
      </svg>
    </div>
    <div class="sb-name" style="font-size:12px;line-height:1.3">Rapid Cloud<br>Assessment</div>
  </div>
  <div class="sb-sect">Overview</div>
  <div class="sb-item active" id="nav-overview" onclick="nav('overview')">
    <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
    Dashboard
  </div>
  <div class="sb-sect">Threat Center</div>
  <div class="sb-item" id="nav-alerts" onclick="nav('alerts')">
    <svg viewBox="0 0 24 24"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
    Critical Alerts
  </div>
  <div class="sb-item" id="nav-vulns" onclick="nav('vulns')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    Vulnerabilities
  </div>
  <div class="sb-item" id="nav-compliance" onclick="nav('compliance')">
    <svg viewBox="0 0 24 24"><polyline points="9 11 12 14 22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
    Compliance
  </div>
  <div class="sb-item" id="nav-identities" onclick="nav('identities')">
    <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
    Identities
  </div>
  <div class="sb-item" id="nav-secrets-all" onclick="nav('secrets-all')">
    <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    Secrets
  </div>
  <div class="sb-item" id="nav-secrets-ssh" onclick="nav('secrets-ssh')">
    <svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
    SSH Key Types
  </div>
  <div class="sb-sect">Risk Center</div>
  <div class="sb-item" id="nav-risk" onclick="nav('risk')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r=".5" fill="currentColor"/></svg>
    Critical Risk Findings
  </div>
  <div class="sb-item" id="nav-lab" onclick="nav('lab')">
    <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
    Next Steps
  </div>
  <!-- Generate Report button (alpha: live from cache) -->
  <div style="padding:0 0 6px">
    <a id="rpt-btn-link" href="/report" target="_blank" class="rpt-btn" style="display:flex;text-decoration:none">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      Generate Report
    </a>
  </div>
  <!-- Sidebar meta -->
  <div style="padding:16px 14px;border-top:1px solid #1f2937;margin-top:auto">
    <span id="kpi-a" style="display:none"></span><span id="kpi-v" style="display:none"></span><span id="kpi-i" style="display:none"></span><span id="kpi-c" style="display:none"></span>
    <div style="font-size:10px;color:#6b7280;line-height:1.8;text-align:center">
      <div><b id="acct-lbl" style="color:#9ca3af">${account}</b></div>
      <div>Last refresh: <b id="fetched-at" style="color:#9ca3af">—</b></div>
      <div style="display:flex;align-items:center;justify-content:center;gap:5px"><div class="live-dot" id="live-dot"></div><span id="countdown">Initializing…</span></div>
    </div>
  </div>
</div>

<!-- Main content -->
<div class="main">

<div class="err-notice" id="err-bar"></div>

<!-- ═══ View: Dashboard ═══ -->
<div class="view active" id="view-overview">
  <div class="pie-section">
    <div style="text-align:center;line-height:1.3">
      <div style="font-size:15px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;color:#DA291C">Cloud Security Posture Score</div>
    </div>
    <svg id="gauge-svg" viewBox="0 0 400 230" style="display:block;width:100%;max-width:420px;overflow:visible;margin:0 auto">
      <defs>
        <!-- Gradient: Red→Orange→Green (higher score = better posture)
             Band boundaries: p=60→65.4%  p=90→97.5% of gradient width -->
        <linearGradient id="band-grad" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">
          <stop offset="0%"    stop-color="#ef4444"/>
          <stop offset="65.4%" stop-color="#ef4444"/>
          <stop offset="65.4%" stop-color="#f59e0b"/>
          <stop offset="97.5%" stop-color="#f59e0b"/>
          <stop offset="97.5%" stop-color="#22c55e"/>
          <stop offset="100%"  stop-color="#22c55e"/>
        </linearGradient>
      </defs>
      <!-- Grey background track -->
      <path fill="none" stroke="#e2e8f0" stroke-width="34" stroke-linecap="round"
            d="M 25,205 A 175,175 0 0,1 375,205"/>
      <!-- Coloured fill arc (gradient, grows with score) -->
      <path id="gauge-arc" fill="none" stroke="url(#band-grad)" stroke-width="34" stroke-linecap="round"
            stroke-dasharray="0 550" d="M 25,205 A 175,175 0 0,1 375,205"/>
      <!-- White divider ticks at band boundaries 60 / 90 -->
      <line x1="249" y1="55" x2="259" y2="22"  stroke="white" stroke-width="3" stroke-linecap="round"/>
      <line x1="350" y1="156" x2="383" y2="146" stroke="white" stroke-width="3" stroke-linecap="round"/>
      <text id="gauge-score" x="200" y="162" text-anchor="middle" font-size="64" font-weight="900"
            letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="#94a3b8">—</text>
      <!-- Scale labels at arc endpoints -->
      <text x="-8" y="212" text-anchor="middle" font-size="18" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="#94a3b8">0</text>
      <text x="408" y="212" text-anchor="middle" font-size="18" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="#94a3b8">100</text>
    </svg>
    <div class="rs-band" id="rs-band" style="display:none">—</div>
    <!-- Findings summary below gauge -->
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px 32px;margin-top:4px;font-size:12px;min-width:200px">
      <div style="display:flex;align-items:center;gap:7px;cursor:pointer" onclick="nav('alerts')"><div style="width:8px;height:8px;border-radius:50%;background:#ef4444;flex-shrink:0"></div><span style="color:#475569">Alerts</span><span style="margin-left:auto;color:#0f172a;font-weight:800;font-size:14px" id="ov-a">—</span></div>
      <div style="display:flex;align-items:center;gap:7px;cursor:pointer" onclick="nav('vulns')"><div style="width:8px;height:8px;border-radius:50%;background:#f97316;flex-shrink:0"></div><span style="color:#475569">CVEs</span><span style="margin-left:auto;color:#0f172a;font-weight:800;font-size:14px" id="ov-v">—</span></div>
      <div style="display:flex;align-items:center;gap:7px;cursor:pointer" onclick="nav('identities')"><div style="width:8px;height:8px;border-radius:50%;background:#8b5cf6;flex-shrink:0"></div><span style="color:#475569">Identities</span><span style="margin-left:auto;color:#0f172a;font-weight:800;font-size:14px" id="ov-i">—</span></div>
      <div style="display:flex;align-items:center;gap:7px;cursor:pointer" onclick="nav('compliance')"><div style="width:8px;height:8px;border-radius:50%;background:#d97706;flex-shrink:0"></div><span style="color:#475569">Compliance</span><span style="margin-left:auto;color:#0f172a;font-weight:800;font-size:14px" id="ov-c">—</span></div>
    </div>
  </div>
  <!-- Score legend — grey area, left-aligned -->
  <div style="padding:20px 28px 4px">
    <div style="max-width:280px;border-radius:10px;overflow:hidden;border:1px solid #dde2ea;font-family:-apple-system,Inter,sans-serif;box-shadow:0 1px 4px rgba(0,0,0,.05)">
      <div style="display:grid;grid-template-columns:1fr 68px;background:#eaecf2;padding:5px 12px;border-bottom:1px solid #dde2ea">
        <div style="font-size:10px;font-weight:700;color:#64748b;letter-spacing:.08em;padding-left:4px">POSTURE</div>
        <div style="font-size:10px;font-weight:700;color:#64748b;text-align:center;letter-spacing:.08em">COLOR</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 68px;padding:6px 12px;border-bottom:1px solid #e2e8f0;align-items:center;background:#ffffff">
        <div style="font-size:12px;color:#334155;padding-left:4px">Proactive Security</div>
        <div style="display:flex;align-items:center;justify-content:center;gap:4px"><div style="width:9px;height:9px;border-radius:50%;background:#22c55e;flex-shrink:0"></div><span style="font-size:11px;font-weight:600;color:#22c55e">Green</span></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 68px;padding:6px 12px;border-bottom:1px solid #e2e8f0;align-items:center;background:#ffffff">
        <div style="font-size:12px;color:#334155;padding-left:4px">Some Attention Needed</div>
        <div style="display:flex;align-items:center;justify-content:center;gap:4px"><div style="width:9px;height:9px;border-radius:50%;background:#f59e0b;flex-shrink:0"></div><span style="font-size:11px;font-weight:600;color:#f59e0b">Orange</span></div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 68px;padding:6px 12px;align-items:center;background:#ffffff">
        <div style="font-size:12px;color:#334155;padding-left:4px">URGENT – Attention Needed</div>
        <div style="display:flex;align-items:center;justify-content:center;gap:4px"><div style="width:9px;height:9px;border-radius:50%;background:#ef4444;flex-shrink:0"></div><span style="font-size:11px;font-weight:600;color:#ef4444">Red</span></div>
      </div>
    </div>
  </div>
  <div style="text-align:center;padding:10px 28px 4px;font-size:11px;font-weight:600;letter-spacing:.08em;color:#94a3b8;font-style:italic">Aiming towards a better, more secure cloud posture</div>
  <div class="footer">Fortinet Rapid Cloud Assessment &nbsp;·&nbsp; Auto-refresh every ${intervalSec}s &nbsp;·&nbsp; <span id="footer-time"></span></div>
</div><!-- /view-overview -->

<!-- ═══ View: Critical Alerts ═══ -->
<div class="view" id="view-alerts">
  <div class="view-hdr vha-red">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Critical Alerts</div>
      <div class="vh-sub">Active threats &amp; policy violations · last ${DAYS_BACK} days</div>
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
      <div class="vh-title">Critical Vulnerabilities</div>
      <div class="vh-sub">Host CVEs · Risk Score ≥ 9.0 · Agentless scan &nbsp;<span class="agent-tip" title="Enable the FortiCNAPP agent for deeper in-memory &amp; runtime vulnerability detection">Agent available</span></div>
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
      <div class="vh-title">Top Critical Non-Compliance</div>
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
      <div class="vh-sub">LW_HE_SECRETS_ALL · SSH keys, API tokens &amp; credentials detected on hosts</div>
    </div>
    <span class="vh-badge" id="cnt-sa">—</span>
  </div>
  <div id="body-sa"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
</div>

<!-- ═══ View: SSH Key Types ═══ -->
<div class="view" id="view-secrets-ssh">
  <div class="view-hdr vha-purple">
    <div class="vh-icon"></div>
    <div class="vh-text">
      <div class="vh-title">Discovered SSH Key Type</div>
      <div class="vh-sub">LW_HE_SECRETS_SSH_PRIVATE_KEYS · SSH private keys by algorithm — legacy ssh-rsa should be rotated</div>
    </div>
    <span class="vh-badge" id="cnt-ssh">—</span>
  </div>
  <div id="body-ssh"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
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
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('vulns')"><div style="width:9px;height:9px;border-radius:50%;background:#f97316"></div><span style="color:#475569">CVEs</span><b id="rf-n-v" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('identities')"><div style="width:9px;height:9px;border-radius:50%;background:#8b5cf6"></div><span style="color:#475569">Identities</span><b id="rf-n-i" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('compliance')"><div style="width:9px;height:9px;border-radius:50%;background:#f59e0b"></div><span style="color:#475569">Compliance</span><b id="rf-n-c" style="margin-left:3px;color:#0f172a">—</b></div>
      <div style="display:flex;align-items:center;gap:5px;cursor:pointer" onclick="nav('secrets-all')"><div style="width:9px;height:9px;border-radius:50%;background:#0ea5e9"></div><span style="color:#475569">Secrets</span><b id="rf-n-s" style="margin-left:3px;color:#0f172a">—</b></div>
    </div>
  </div>
  <div class="rf-kpis">
    <div class="rf-kpi"><div class="rf-kpi-lbl">Critical Alerts</div><div class="rf-kpi-val" id="rf-k-a">—</div><div class="rf-kpi-sub">Open &amp; unresolved</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">CVEs Risk ≥ 9</div><div class="rf-kpi-val" id="rf-k-v">—</div><div class="rf-kpi-sub">Critical host CVEs</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">Non-Compliance</div><div class="rf-kpi-val" id="rf-k-c">—</div><div class="rf-kpi-sub">Critical controls violated</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">Risky Identities</div><div class="rf-kpi-val" id="rf-k-i">—</div><div class="rf-kpi-sub">No MFA · Admin/over-privileged</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">Secrets Detected</div><div class="rf-kpi-val" id="rf-k-s">—</div><div class="rf-kpi-sub">Verify &amp; deprecate all</div></div>
  </div>
  <div class="rf-body">
    <div id="rf-table"><div class="state"><div class="spinner"></div><span>Loading…</span></div></div>
  </div>
</div>

<!-- ═══ View: Lab ═══ -->
<div class="view" id="view-lab">
  <div class="view-hdr">
    <div class="vh-text">
      <div class="vh-title">Recommended Next Steps</div>
      <div class="vh-sub">Posture: <b id="lab-score">—</b> &nbsp;·&nbsp; <span id="lab-band-txt">—</span></div>
    </div>
  </div>
  <div class="lab-steps" id="lab-actions"></div>
</div>

</div><!-- /main -->
</div><!-- /app-layout -->

<script>
const REFRESH=${intervalSec};
let cd=REFRESH;

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
function setKpi(id,n){document.getElementById(id).textContent=n;}
function setCount(id,n,bad){const el=document.getElementById(id);el.textContent=n;el.className='sec-count '+(n>0&&bad?'bad':'ok');}
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
function setBody(id,h){document.getElementById(id).innerHTML=h;}
function state(id,icon,msg){setBody(id,'<div class="state"><span class="state-icon">'+icon+'</span><span>'+e(msg)+'</span></div>');}

function renderAlerts(rows,err){
  if(err){state('body-a','',err);return}
  setKpi('kpi-a',rows.length);setCount('cnt-a',rows.length,true);
  if(!rows.length){state('body-a','','No open critical alerts');return}
  const baseA='https://'+(_lastData?.account||'');
  setBody('body-a','<div class="tbl-wrap"><table><thead><tr><th>Alert ID</th><th>Alert</th><th>Description</th><th>Status</th><th>Time</th></tr></thead><tbody>'
    +rows.map(r=>{
      const desc=(r.alertInfo?.description||'').replace(/\s+/g,' ').trim();
      const href=baseA+'/ui/investigation/alerts/'+r.alertId;
      return'<tr class="'+strip('critical')+'">'
        +'<td class="m"><a class="rf-link" href="'+e(href)+'" target="_blank">'+e(r.alertId||'\\u2014')+'</a></td>'
        +'<td class="p"><a class="rf-link" href="'+e(href)+'" target="_blank">'+e(r.alertName||'—')+'</a></td>'
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
  const baseV='https://'+(_lastData?.account||'')+'/ui/investigation/vulnerabilities/hosts';
  setBody('body-v','<div class="tbl-wrap"><table><thead><tr><th>CVE / Vuln ID</th><th>Risk</th><th>Package</th><th>Host</th><th>Fix Version</th></tr></thead><tbody>'
    +rows.map(r=>{
      const fix=r.fixInfo?.fix_available===true||String(r.fixInfo?.fix_available)==='1'||r.fixInfo?.fix_available==='1';
      const fixVer=r.fixInfo?.fixed_version||'';
      return'<tr class="strip-cr">'
        +'<td class="m"><a class="rf-link" href="'+e(baseV)+'" target="_blank">'+e(r.vulnId||r.cveId||'\\u2014')+'</a></td>'
        +'<td class="r"><span class="risk-score">'+parseFloat(r.riskScore||0).toFixed(1)+'</span></td>'
        +'<td class="p">'+e(r.featureKey?.name||'—')+'</td>'
        +'<td class="m">'+e(r.evalCtx?.hostname||r.mid||'—')+'</td>'
        +'<td>'+(fix?'<span class="b b-ok" title="'+e(fixVer)+'">'+e(tr(fixVer,18)||'Fix \\u2713')+'</span>':'<span class="b b-nt">No fix</span>')+'</td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function renderCompliance(rows,err){
  if(err){state('body-c','',err);return}
  setKpi('kpi-c',rows.length);setCount('cnt-c',rows.length,true);
  if(!rows.length){state('body-c','','No critical compliance violations');return}
  const baseC='https://'+(_lastData?.account||'')+'/ui/compliance';
  setBody('body-c','<div class="tbl-wrap"><table><thead><tr><th>Policy ID</th><th>Cloud</th><th>Title</th><th>Description</th><th>Severity</th><th>Violations</th></tr></thead><tbody>'
    +rows.map(r=>'<tr class="'+strip(r.severity)+'">'
      +'<td class="m"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(r.alertId||'—')+'</a></td>'
      +'<td>'+cloud(r.cloud)+'</td>'
      +'<td class="desc"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(r.title||'—')+'</a></td>'
      +'<td class="desc">'+e(r.description||'—')+'</td>'
      +'<td>'+sev(r.severity)+'</td>'
      +'<td class="r">'+e(r.violations||0)+'</td>'
    +'</tr>').join('')+'</tbody></table></div>');
}

function renderIdentities(rows,err){
  if(err){state('body-i','',err);return}
  setKpi('kpi-i',rows.length);setCount('cnt-i',rows.length,true);
  if(!rows.length){state('body-i','','No high-risk no-MFA identities found');return}
  setBody('body-i','<div class="tbl-wrap"><table><thead><tr><th>Identity</th><th>Cloud</th><th>Risk</th><th>Unused</th><th>MFA</th><th>Last Used</th></tr></thead><tbody>'
    +rows.map(r=>{
      const risks=r.METRICS?.risks??[];
      const isAdmin=risks.includes('ALLOWS_FULL_ADMIN');
      const riskSev=(r.METRICS?.risk_severity||'').toLowerCase();
      const unused=r.ENTITLEMENT_COUNTS?.entitlements_unused_count??'\\u2014';
      const iHref='https://'+(_lastData?.account||'')+'/ui/insights';
      return'<tr class="'+(isAdmin?'strip-cr':'strip-hi')+'">'
        +'<td class="p" title="'+e(r.NAME||r.PRINCIPAL_ID)+'"><a class="rf-link" href="'+e(iHref)+'" target="_blank">'+e(tr(r.NAME||r.PRINCIPAL_ID,28))+'</a></td>'
        +'<td><span class="b b-nt">'+e(r.PROVIDER_TYPE||'\\u2014')+'</span></td>'
        +'<td>'+(isAdmin?'<span class="tag-admin">FULL ADMIN</span>':sev(riskSev))+'</td>'
        +'<td class="r">'+unused+'</td>'
        +'<td><span class="tag-nomfa">NO MFA</span></td>'
        +'<td class="m">'+fmtDate(r.LAST_USED_TIME)+'</td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function renderSecretsAll(rows,err){
  const el=document.getElementById('t-sa');if(el)el.textContent=rows?rows.length:'—';
  setCount('cnt-sa',rows?rows.length:0,true);
  if(err){state('body-sa','',err);return}
  if(!rows||!rows.length){state('body-sa','','No secrets detected');return}
  setBody('body-sa','<div class="tbl-wrap"><table><thead><tr><th>Hostname</th><th>Instance ID</th><th>OS</th><th>Secret Type</th><th>Secret Identifier</th><th>Last Seen</th></tr></thead><tbody>'
    +rows.map((r,i)=>{
      const lastSeen=r.END_TIME?fmtDate(r.END_TIME):'—';
      return'<tr class="'+(i%2?'':'')+(r.SECRET_TYPE?.toLowerCase().includes('key')||r.SECRET_TYPE?.toLowerCase().includes('token')?'strip-cr':'strip-hi')+'">'
        +'<td class="p">'+e(r.HOSTNAME||'—')+'</td>'
        +'<td class="m"><small>'+e(r.MID||'—')+'</small></td>'
        +'<td>'+e(r.OS||'—')+'</td>'
        +'<td><span class="b b-cr">'+e(r.SECRET_TYPE||'—')+'</span></td>'
        +'<td class="p"><code style="font-size:11px">'+e(r.SECRET_IDENTIFIER||'—')+'</code></td>'
        +'<td class="m">'+lastSeen+'</td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function renderSecretsSsh(rows,err){
  setCount('cnt-ssh',rows?rows.length:0,true);
  if(err){state('body-ssh','',err);return}
  if(!rows||!rows.length){state('body-ssh','','No SSH private keys detected');return}
  setBody('body-ssh','<div class="tbl-wrap"><table><thead><tr><th>Hostname</th><th>File Path</th><th>SSH Key Type</th><th>Risk</th></tr></thead><tbody>'
    +rows.map((r,i)=>{
      const isRsa=(r.SSH_KEY_TYPE||'').toLowerCase()==='ssh-rsa';
      return'<tr class="'+(isRsa?'strip-cr':'')+(i%2&&!isRsa?'':'')+('">')
        +'<td class="p">'+e(r.HOSTNAME||'—')+'</td>'
        +'<td class="p"><code style="font-size:11px">'+e(r.FILE_PATH||'—')+'</code></td>'
        +'<td><span class="b '+(isRsa?'b-cr':'b-ok')+'">'+e(r.SSH_KEY_TYPE||'—')+'</span></td>'
        +'<td>'+(isRsa?'<span class="tag-nomfa">ROTATE NOW</span>':'<span class="b b-ok">OK</span>')+'</td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function nav(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  document.getElementById('view-'+name).classList.add('active');
  document.getElementById('nav-'+name).classList.add('active');
}

let _lastData=null;

// Cloud Security Posture Score (Rick Score): higher = better posture (0–100).
// postureScore = 100 − mean(findingRiskScores) − (secretCount × 0.5).  No findings → 100.
// CVE: riskScore×10  |  Identity: METRICS.risk_score×100  |  Alert: 95  |  Compliance: 80
// Secrets penalty: −0.5 pts per detected secret (applied after mean, excluded from mean pool)
function calcPostureScore(d){
  const risks=[];
  (d.alerts||[]).forEach(()=>risks.push(95));
  (d.vulns||[]).forEach(r=>risks.push(Math.min(100,parseFloat(r.riskScore||0)*10)));
  (d.compliance||[]).forEach(()=>risks.push(80));
  (d.identities||[]).forEach(r=>risks.push(Math.min(100,(r.METRICS?.risk_score||0)*100)));
  const secretPenalty=(d.secretsAll||[]).length*0.5;
  const base=risks.length ? 100-risks.reduce((s,v)=>s+v,0)/risks.length : 100;
  return Math.max(0, Math.round(base - secretPenalty));
}
// 90–100 Green · 60–89 Orange · 0–59 Red  (higher = better posture)
function scoreColor(p){return p>=90?'#22c55e':p>=60?'#f59e0b':'#ef4444';}
function scoreBand(p){return p>=90?'Proactive Security':p>=60?'Some Attention Needed':'URGENT – Attention Needed';}

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
    {key:'Alert',     label:'Critical Alerts',      color:'#ef4444', tab:'alerts',      items:(d.alerts||[]).map(r=>({title:r.alertName,detail:r.alertType,score:95,href:base+'/ui/investigation/alerts/'+r.alertId}))},
    {key:'CVE',       label:'Critical CVEs',         color:'#f97316', tab:'vulns',       items:(d.vulns||[]).map(r=>({title:r.vulnId,detail:(r.featureKey?.name||'')+' · '+(r.evalCtx?.hostname||''),score:parseFloat(r.riskScore||0)*10,href:base+'/ui/investigation/vulnerabilities/hosts'}))},
    {key:'Identity',  label:'Identity Risk',         color:'#8b5cf6', tab:'identities',  items:(d.identities||[]).map(r=>({title:r.NAME||r.PRINCIPAL_ID,detail:(r.PROVIDER_TYPE||'')+' · No MFA',score:(r.METRICS?.risk_score||0)*100,href:base+'/ui/insights'}))},
    {key:'Compliance',label:'Non-Compliance',        color:'#f59e0b', tab:'compliance',  items:(d.compliance||[]).map(r=>({title:r.title,detail:(r.cloud||'').toUpperCase()+' · '+r.violations+' violations',score:80,href:base+'/ui/compliance'}))},
    {key:'Secret',    label:'Secrets Detected',      color:'#0ea5e9', tab:'secrets-all', items:(d.secretsAll||[]).map(r=>({title:r.SECRET_TYPE||'Secret',detail:(r.HOSTNAME||'—')+' · '+tr(r.SECRET_IDENTIFIER||'',28),score:90,href:base+'/ui/investigation'}))},
  ].filter(g=>g.items.length);
  if(!groups.length){setBody('rf-table','<div class="state"><span>No risk findings</span></div>');return;}
  const rows=groups.map(g=>{
    const hdr='<tr style="background:#f8fafc;border-top:2px solid '+g.color+'">'
      +'<td colspan="3" style="padding:7px 12px;font-size:11px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:'+g.color+'"><span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:'+g.color+';margin-right:6px;vertical-align:middle"></span>'+e(g.label)+'</td>'
      +'<td style="padding:7px 12px;text-align:right;font-size:11px;font-weight:700;color:'+g.color+'"><a href="#" onclick="nav(\''+g.tab+'\');return false;" style="color:inherit;text-decoration:none;border-bottom:1px dashed currentColor">'+g.items.length+' finding'+(g.items.length===1?'':'s')+' ↗</a></td>'
      +'</tr>';
    const detail=g.items.map((r,i)=>'<tr style="'+(i%2?'background:#fafafa':'')+'">'
      +'<td class="p" colspan="2"><a class="rf-link" href="'+e(r.href)+'" target="_blank">'+e(tr(r.title,48))+' &#8599;</a></td>'
      +'<td class="m">'+e(tr(r.detail,36))+'</td>'
      +'<td class="r"><span class="risk-score">'+Math.round(r.score)+'</span></td>'
    +'</tr>').join('');
    return hdr+detail;
  }).join('');
  setBody('rf-table','<div class="tbl-wrap"><table><thead><tr><th colspan="2">Finding</th><th>Detail</th><th>Risk Score</th></tr></thead><tbody>'+rows+'</tbody></table></div>');
}

function renderLab(d){
  const p=calcPostureScore(d);
  const color=scoreColor(p);
  const band=scoreBand(p);
  const ls=document.getElementById('lab-score');ls.textContent=p;ls.style.color=color;
  document.getElementById('lab-band-txt').textContent=band;
  const actions=[];
  if((d.identities||[]).length) actions.push({cls:'p1',n:1,tab:'identities',text:'Fix '+d.identities.length+' High Permissive '+(d.identities.length===1?'identity':'identities')+' — enable MFA &amp; Apply Least Privilege Access',sub:'Priority 1 · Identity compromise is the #1 breach vector'});
  if((d.alerts||[]).length) actions.push({cls:'p2',n:actions.length+1,tab:'alerts',text:'Investigate '+d.alerts.length+' open critical alert'+(d.alerts.length===1?'':'s'),sub:'Threat Center · Some may indicate an active breach'});
  if((d.vulns||[]).length) actions.push({cls:'p3',n:actions.length+1,tab:'vulns',text:'Patch '+d.vulns.length+' critical CVE'+(d.vulns.length===1?'':'s')+' with risk score ≥ 9.0',sub:'Focus on internet-exposed hosts first'});
  if((d.compliance||[]).length) actions.push({cls:'p4',n:actions.length+1,tab:'compliance',text:'Remediate '+d.compliance.length+' non-compliant critical control'+(d.compliance.length===1?'':'s'),sub:'Compliance · Cloud misconfigurations'});
  if((d.secretsAll||[]).length) actions.push({cls:'p1',n:actions.length+1,tab:'secrets-all',text:'Verify &amp; Deprecate '+d.secretsAll.length+' discovered secret'+(d.secretsAll.length===1?'':'s')+' — rotate or revoke immediately',sub:'Secrets · SSH keys, API tokens &amp; credentials detected on hosts'});
  if(!actions.length) actions.push({cls:'p4',n:1,tab:'overview',text:'Security posture is excellent — keep monitoring',sub:'Cloud Security Posture Score: '+p+'/100'});
  const clrMap={p1:'var(--cr)',p2:'var(--hi)',p3:'var(--me)',p4:'var(--ok)'};
  document.getElementById('lab-actions').innerHTML=actions.map(a=>'<div class="lab-step"><div class="lab-step-bar" style="background:'+clrMap[a.cls]+'"></div><div class="lab-step-n">'+a.n+'</div><div><div class="lab-step-title"><a href="#" data-tab="'+a.tab+'" onclick="nav(this.dataset.tab);return false;" style="color:inherit;text-decoration:none;border-bottom:1px dashed currentColor;cursor:pointer">'+a.text+'</a></div><div class="lab-step-sub">'+e(a.sub)+'</div></div></div>').join('');
}

async function load(){
  try{
    const d=await fetch('/api/data').then(r=>r.json());
    _lastData=d;
    renderAlerts(d.alerts,d.errors?.alerts);
    renderVulns(d.vulns,d.errors?.vulns);
    renderCompliance(d.compliance,d.errors?.compliance);
    renderIdentities(d.identities,d.errors?.identities);
    renderSecretsAll(d.secretsAll,d.errors?.secretsAll);
    renderSecretsSsh(d.secrets,d.errors?.secrets);
    updateRiskScore(calcPostureScore(d));
    renderRiskFindings(d);
    renderLab(d);
    buildPie(d);
    document.getElementById('fetched-at').textContent=fmtDate(d.fetchedAt);
    document.getElementById('acct-lbl').textContent=d.account||'';
    const da=document.getElementById('dash-acct');if(da)da.textContent=d.account||'';
    document.getElementById('footer-time').textContent='Assessment window: last ${DAYS_BACK} days';
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

function updateRiskScore(p){
  const color=scoreColor(p);
  const arcLen=550;
  const fill=(p/100)*arcLen;
  const arc=document.getElementById('gauge-arc');
  if(arc){arc.setAttribute('stroke-dasharray',fill+' '+arcLen);}
  const gs=document.getElementById('gauge-score');
  if(gs){gs.textContent=p;gs.setAttribute('fill',color);}
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

(function checkLogin(){
  const s=sessionStorage.getItem('rca_user')||getCookie('rca_user');
  if(s){
    document.getElementById('login-overlay').style.display='none';
    try{wireReportBtn(JSON.parse(s));}catch(_){}
    load();
  }
})();

function submitLogin(){
  const first=document.getElementById('li-first').value.trim();
  const last=document.getElementById('li-last').value.trim();
  const company=document.getElementById('li-company').value.trim();
  const role=document.getElementById('li-role').value;
  const email=document.getElementById('li-email').value.trim();
  const err=document.getElementById('login-err');
  if(!first||!last){err.textContent='Please enter your first and last name.';return;}
  if(!company){err.textContent='Please enter your company name.';return;}
  if(!role){err.textContent='Please select your role.';return;}
  const emailInput=document.getElementById('li-email');
  if(!email||!emailInput.checkValidity()){err.textContent='Please enter a valid email address.';return;}
  err.textContent='';
  const user={first,last,company,role,email};
  const userJson=JSON.stringify(user);
  sessionStorage.setItem('rca_user',userJson);
  setCookie('rca_user',userJson,30);
  fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(user)}).catch(()=>{});
  document.getElementById('login-overlay').style.display='none';
  wireReportBtn(user);
  load();
}

document.getElementById('li-email').addEventListener('keydown',function(e){if(e.key==='Enter')submitLogin();});

setInterval(load,REFRESH*1000);
setInterval(()=>{
  cd=Math.max(0,cd-1);
  document.getElementById('countdown').textContent='Next refresh in '+cd+'s';
},1000);

</script>

</body>
</html>`;
}

const HTML = buildHtml(LW_ACCOUNT, INTERVAL);

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
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:10px;width:100%;max-width:340px;margin-top:20px}
.tile{background:#fff;border-radius:12px;padding:14px 12px;box-shadow:0 1px 4px rgba(0,0,0,.07);text-align:center}
.tile-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;margin-bottom:5px}
.tile-val{font-size:32px;font-weight:900;color:#0f172a;line-height:1}
.tile-a .tile-lbl{color:#ef4444}
.tile-v .tile-lbl{color:#f97316}
.tile-i .tile-lbl{color:#8b5cf6}
.tile-c .tile-lbl{color:#f59e0b}
.divider{width:100%;max-width:340px;border:none;border-top:1px solid #e2e8f0;margin:28px 0 20px}
.sec-title{font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:#64748b;width:100%;max-width:340px;margin-bottom:12px}
.steps{display:flex;flex-direction:column;gap:10px;width:100%;max-width:340px}
.step{background:#fff;border-radius:12px;padding:14px 16px;box-shadow:0 1px 4px rgba(0,0,0,.07);display:flex;gap:12px;align-items:flex-start}
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
  <svg viewBox="0 0 400 230" style="display:block;width:100%;overflow:visible">
    <defs>
      <linearGradient id="mg" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">
        <stop offset="0%"    stop-color="#ef4444"/>
        <stop offset="65.4%" stop-color="#ef4444"/>
        <stop offset="65.4%" stop-color="#f59e0b"/>
        <stop offset="97.5%" stop-color="#f59e0b"/>
        <stop offset="97.5%" stop-color="#22c55e"/>
        <stop offset="100%"  stop-color="#22c55e"/>
      </linearGradient>
    </defs>
    <path fill="none" stroke="#e2e8f0" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>
    <path id="garc" fill="none" stroke="url(#mg)" stroke-width="34" stroke-linecap="round" stroke-dasharray="0 550" d="M 25,205 A 175,175 0 0,1 375,205"/>
    <line x1="249" y1="55" x2="259" y2="22"  stroke="white" stroke-width="3" stroke-linecap="round"/>
    <line x1="350" y1="156" x2="383" y2="146" stroke="white" stroke-width="3" stroke-linecap="round"/>
    <text id="mscore" x="200" y="162" text-anchor="middle" font-size="64" font-weight="900" letter-spacing="-2" font-family="-apple-system,sans-serif" fill="#94a3b8">—</text>
    <text x="-8" y="212" text-anchor="middle" font-size="18" font-weight="700" font-family="-apple-system,sans-serif" fill="#94a3b8">0</text>
    <text x="408" y="212" text-anchor="middle" font-size="18" font-weight="700" font-family="-apple-system,sans-serif" fill="#94a3b8">100</text>
  </svg>
</div>
<div class="tiles">
  <div class="tile tile-a"><div class="tile-lbl">Critical Alerts</div><div class="tile-val" id="t-a">—</div></div>
  <div class="tile tile-v"><div class="tile-lbl">Critical CVEs</div><div class="tile-val" id="t-v">—</div></div>
  <div class="tile tile-i"><div class="tile-lbl">Risky Identities</div><div class="tile-val" id="t-i">—</div></div>
  <div class="tile tile-c"><div class="tile-lbl">Non-Compliance</div><div class="tile-val" id="t-c">—</div></div>
  <div class="tile tile-i" onclick="nav('secrets-all')" style="cursor:pointer"><div class="tile-lbl">Secrets</div><div class="tile-val" id="t-sa">—</div></div>
</div>
<hr class="divider">
<div class="sec-title">Recommended Next Steps</div>
<div class="steps" id="steps"></div>
<div class="meta">
  <span class="dot" id="ldot"></span><span id="lacct"></span><br>
  Last refresh: <span id="ltime">—</span>
</div>
<script>
function scoreColor(p){return p>=90?'#22c55e':p>=60?'#f59e0b':'#ef4444';}
function scoreBand(p){return p>=90?'Proactive Security':p>=60?'Some Attention Needed':'URGENT – Attention Needed';}
function calcScore(d){
  var risks=[];
  (d.alerts||[]).forEach(function(){risks.push(95);});
  (d.vulns||[]).forEach(function(r){risks.push(Math.min(100,parseFloat(r.riskScore||0)*10));});
  (d.compliance||[]).forEach(function(){risks.push(80);});
  (d.identities||[]).forEach(function(r){risks.push(Math.min(100,(r.METRICS&&r.METRICS.risk_score||0)*100));});
  var secretPenalty=(d.secretsAll||[]).length*0.5;
  var base=risks.length?100-risks.reduce(function(s,v){return s+v;},0)/risks.length:100;
  return Math.max(0,Math.round(base-secretPenalty));
}
function buildSteps(d,p){
  var items=[];
  if((d.identities||[]).length) items.push({color:'#ef4444',title:'Fix '+d.identities.length+' High Permissive '+(d.identities.length===1?'identity':'identities')+' — enable MFA & Apply Least Privilege Access',sub:'Priority 1 · Identity compromise is the #1 breach vector'});
  if((d.alerts||[]).length)     items.push({color:'#f97316',title:'Investigate '+d.alerts.length+' open critical alert'+(d.alerts.length===1?'':'s'),sub:'Threat Center · Some may indicate an active breach'});
  if((d.vulns||[]).length)      items.push({color:'#f59e0b',title:'Patch '+d.vulns.length+' critical CVE'+(d.vulns.length===1?'':'s')+' with risk score ≥ 9.0',sub:'Focus on internet-exposed hosts first'});
  if((d.compliance||[]).length) items.push({color:'#3b82f6',title:'Remediate '+d.compliance.length+' non-compliant critical control'+(d.compliance.length===1?'':'s'),sub:'Compliance · Cloud misconfigurations'});
  if(!items.length) items.push({color:'#22c55e',title:'Security posture is excellent — keep monitoring',sub:'Cloud Security Posture Score: '+p+'/100'});
  document.getElementById('steps').innerHTML=items.map(function(a,i){
    return '<div class="step"><div class="step-bar" style="background:'+a.color+'"></div><div class="step-n">'+(i+1)+'</div><div class="step-body"><div class="step-title">'+a.title+'</div><div class="step-sub">'+a.sub+'</div></div></div>';
  }).join('');
}
function refresh(){
  fetch('/api/data').then(function(r){return r.json();}).then(function(d){
    var p=calcScore(d);
    var color=scoreColor(p);
    document.getElementById('garc').setAttribute('stroke-dasharray',(p/100*550).toFixed(1)+' 550');
    var ms=document.getElementById('mscore');if(ms){ms.textContent=p;ms.setAttribute('fill',color);}
    document.getElementById('t-a').textContent=(d.alerts||[]).length;
    document.getElementById('t-v').textContent=(d.vulns||[]).length;
    document.getElementById('t-i').textContent=(d.identities||[]).length;
    document.getElementById('t-c').textContent=(d.compliance||[]).length;
    buildSteps(d,p);
    document.getElementById('ldot').className='dot ok';
    document.getElementById('lacct').textContent=d.account||'';
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

  // Server-side posture score (mirrors client calcPostureScore)
  function calcScore(d) {
    const r = [];
    (d.alerts||[]).forEach(() => r.push(95));
    (d.vulns||[]).forEach(v => r.push(Math.min(100, parseFloat(v.riskScore||0)*10)));
    (d.compliance||[]).forEach(() => r.push(80));
    (d.identities||[]).forEach(i => r.push(Math.min(100, (i.METRICS && i.METRICS.risk_score||0)*100)));
    const secretPenalty = (d.secretsAll||[]).length * 0.5;
    const base = r.length ? 100 - r.reduce((s,v) => s+v, 0) / r.length : 100;
    return Math.max(0, Math.round(base - secretPenalty));
  }
  const score  = calcScore(data);
  const sBand  = score>=90 ? 'Proactive Security' : score>=60 ? 'Some Attention Needed' : 'URGENT – Attention Needed';
  const sColor = score>=90 ? '#22c55e' : score>=60 ? '#f59e0b' : '#ef4444';
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
    return '<tr'+bg+'>'+
      '<td class="narrow">'+(i+1)+'</td>'+
      '<td>'+sevBadge(r.severity)+'</td>'+
      '<td class="wide"><strong>'+esc(r.title||'—')+'</strong></td>'+
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

  // ── Build HTML ──────────────────────────────────────────────────────────────
  const tocCards = [
    alerts.length     ? '<a href="#alerts" class="toc-card"><div class="tc-num">01 — Alerts</div><div class="tc-title">Critical Alerts</div><div class="tc-sub">'+alerts.length+' open critical alert'+(alerts.length===1?'':'s')+'.</div></a>' : '',
    compliance.length ? '<a href="#compliance" class="toc-card"><div class="tc-num">02 — Compliance</div><div class="tc-title">Critical Non-Compliance</div><div class="tc-sub">'+compliance.length+' control failure'+(compliance.length===1?'':'s')+'.</div></a>' : '',
    vulns.length      ? '<a href="#vulnerabilities" class="toc-card"><div class="tc-num">03 — CVEs</div><div class="tc-title">Critical Vulnerabilities</div><div class="tc-sub">'+vulns.length+' CVE'+(vulns.length===1?'':'s')+' with risk score ≥ 9.</div></a>' : '',
    identities.length ? '<a href="#identity" class="toc-card"><div class="tc-num">04 — Identity</div><div class="tc-title">Identity Risk</div><div class="tc-sub">'+identities.length+' identity risk'+(identities.length===1?'':'s')+'.</div></a>' : '',
    secretsAll.length ? '<a href="#secrets-all" class="toc-card"><div class="tc-num">05 — Secrets</div><div class="tc-title">Discovered Secrets</div><div class="tc-sub">'+secretsAll.length+' secret'+(secretsAll.length===1?'':'s')+' detected across hosts.</div></a>' : '',
    secrets.length    ? '<a href="#secrets" class="toc-card"><div class="tc-num">06 — SSH Keys</div><div class="tc-title">SSH Key Type</div><div class="tc-sub">'+secrets.length+' SSH private key'+(secrets.length===1?'':'s')+' detected.</div></a>' : '',
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

  function inferCsp(hostname) {
    const h = (hostname || '').toLowerCase();
    if (/^ip-\d+|^i-[0-9a-f]{8,17}$|ec2|\.aws\.|amazon/.test(h)) return 'AWS';
    if (/azure|-vm$|azurevm|msft/.test(h)) return 'Azure';
    if (/gcp|google|^instance-[0-9]/.test(h)) return 'GCP';
    return 'Unknown';
  }
  function permRisk(path) {
    const p = path || '';
    if (/\\/. test(p) || (p.length > 2 && p[1] === ':')) return 'Windows — restrict to owner account; remove Users/Everyone ACE';
    if (p.startsWith('/tmp/')) return 'Linux /tmp — CRITICAL: world-readable directory; move immediately';
    if (p.startsWith('/etc/')) return 'Linux /etc — root:root 600 required; no world/group read';
    if (p.startsWith('/root/')) return 'Linux /root — root:root 600; accessible only by root';
    if (p.startsWith('/home/')) return 'Linux /home — owner:owner 600; no group or world permissions';
    if (/\.(pem|key|p12|pfx|crt)$/.test(p)) return 'Key/cert file — 600 (owner read-only); never world or group readable';
    return 'Linux/Unix — verify 600 (owner read-only); audit with: stat -c "%a %U %G" &lt;path&gt;';
  }
  function secretRec(keyType) {
    return (keyType || '').toLowerCase() === 'ssh-rsa'
      ? 'Upgrade to ssh-ed25519 — stronger, faster, and immune to RSA timing attacks'
      : '—';
  }
  function isRsaRisk(keyType) { return (keyType || '').toLowerCase() === 'ssh-rsa'; }

  const secretRows = secrets.length ? secrets.map(function(r, i) {
    const risky = isRsaRisk(r.SSH_KEY_TYPE);
    const bg = risky ? ' style="background:#FDECEA;"' : (i % 2 ? ' style="background:#FAFAFA;"' : '');
    return '<tr'+bg+'>' +
      '<td><strong>'+esc(r.HOSTNAME||'—')+'</strong></td>' +
      '<td><span class="badge '+(inferCsp(r.HOSTNAME)==='AWS'?'badge-aws':inferCsp(r.HOSTNAME)==='Azure'?'badge-azure':inferCsp(r.HOSTNAME)==='GCP'?'badge-gcp':'badge-high')+'">'+esc(inferCsp(r.HOSTNAME))+'</span></td>' +
      '<td class="wide"><code style="font-size:0.8rem">'+esc(r.FILE_PATH||'—')+'</code></td>' +
      '<td><span class="badge '+(risky?'badge-critical':'badge-mfa-on')+'">'+esc(r.SSH_KEY_TYPE||'—')+'</span></td>' +
      '<td class="wide">'+esc(permRisk(r.FILE_PATH))+'</td>' +
      '<td class="wide">'+esc(secretRec(r.SSH_KEY_TYPE))+'</td>' +
      '</tr>';
  }).join('') : '';

  const rsaCount = secrets.filter(r => isRsaRisk(r.SSH_KEY_TYPE)).length;
  const secretSummary = secrets.length === 0 ? '' :
    '<div class="section-summary"><div class="ss-title">&#9650; Risk Summary — Secrets Posture</div>' +
    (rsaCount > 0
      ? '<p><strong style="color:#DA291C;">&#9888; Key Algorithm Risk:</strong> '+rsaCount+' of '+secrets.length+' detected SSH key'+(secrets.length===1?'':'s')+' use the legacy <code>ssh-rsa</code> algorithm. Migrate to <code>ssh-ed25519</code> — run <code>ssh-keygen -t ed25519</code> to generate replacements, then rotate and revoke legacy keys.</p>'
      : '<p><strong style="color:#1E7A3E;">&#10003; No algorithm risk.</strong> All '+secrets.length+' detected key'+(secrets.length===1?'':'s')+' use modern algorithms. Verify file permissions are 600 (owner read-only) and rotate on a scheduled basis.</p>'
    ) + '</div>';

  const secretSection = secrets.length ? (
    '<section id="secrets" class="pagebreak">\n<h2>6. Secrets — Discovered SSH Key Type</h2>\n' +
    '<table class="exec-table"><thead><tr>' +
    '<th style="width:160px">Hostname</th><th style="width:70px">CSP</th>' +
    '<th style="width:200px">File Path</th><th style="width:100px">SSH Key Type</th>' +
    '<th style="width:200px">Permission Risk</th><th style="width:200px">Recommendation</th>' +
    '</tr></thead><tbody>'+secretRows+'</tbody></table>\n' +
    secretSummary + '\n</section>'
  ) : '';

  return '<!DOCTYPE html>\n<html lang="en">\n<head>\n' +
  '  <meta charset="UTF-8">\n' +
  '  <meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
  '  <title>Rapid Cloud Assessment – '+esc(customer)+'</title>\n' +
  '  <style type="text/css">\n' + REPORT_CSS + '\n' +
  '    .alpha-banner{background:#f59e0b;color:#000;padding:6px 20px;font-size:11px;font-weight:700;text-align:center;letter-spacing:.06em}\n' +
  '  </style>\n</head>\n<body>\n' +
  '<div class="alpha-banner no-print">⚠ ALPHA — Generated live from RCA UI dashboard data · '+new Date().toISOString()+'</div>\n' +
  '<header><span style="color:white;font-weight:700;font-size:15px;letter-spacing:.08em">FORTINET</span>' +
  '<span style="color:rgba(255,255,255,.55);font-size:11px">RAPID CLOUD ASSESSMENT</span></header>\n' +
  '<div class="report-cover">\n' +
  '  <div class="report-type">Rapid Cloud Assessment · Cloud Security Risk Findings</div>\n' +
  '  <h1>Cloud Security Posture Report</h1>\n' +
  '  <div class="subtitle">'+esc(customer)+'</div>\n' +
  (function(){
    const arcLen=550, fill=Math.round((score/100)*arcLen);
    return '  <div style="margin:1rem auto 0;max-width:340px;width:100%">\n'+
      '  <svg viewBox="0 0 400 240" style="display:block;width:100%;overflow:visible">\n'+
      '    <defs><linearGradient id="rg" gradientUnits="userSpaceOnUse" x1="25" y1="0" x2="375" y2="0">'+
      '<stop offset="0%" stop-color="#ef4444"/>'+
      '<stop offset="65.4%" stop-color="#ef4444"/>'+
      '<stop offset="65.4%" stop-color="#f59e0b"/>'+
      '<stop offset="97.5%" stop-color="#f59e0b"/>'+
      '<stop offset="97.5%" stop-color="#22c55e"/>'+
      '<stop offset="100%" stop-color="#22c55e"/>'+
      '</linearGradient></defs>\n'+
      '    <path fill="none" stroke="rgba(255,255,255,0.18)" stroke-width="34" stroke-linecap="round" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <path fill="none" stroke="url(#rg)" stroke-width="34" stroke-linecap="round" stroke-dasharray="'+fill+' '+arcLen+'" d="M 25,205 A 175,175 0 0,1 375,205"/>\n'+
      '    <line x1="249" y1="55" x2="259" y2="22" stroke="rgba(255,255,255,0.5)" stroke-width="3" stroke-linecap="round"/>\n'+
      '    <line x1="350" y1="156" x2="383" y2="146" stroke="rgba(255,255,255,0.5)" stroke-width="3" stroke-linecap="round"/>\n'+
      '    <text x="200" y="165" text-anchor="middle" font-size="72" font-weight="900" letter-spacing="-2" font-family="-apple-system,Inter,sans-serif" fill="white">'+score+'</text>\n'+
      '    <text x="-8" y="212" text-anchor="middle" font-size="16" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.55)">0</text>\n'+
      '    <text x="408" y="212" text-anchor="middle" font-size="16" font-weight="700" font-family="-apple-system,Inter,sans-serif" fill="rgba(255,255,255,0.55)">100</text>\n'+
      '  </svg>\n'+
      '  <div style="text-align:center;font-size:.82rem;font-weight:700;letter-spacing:.08em;color:white;margin-top:4px;text-transform:uppercase">'+esc(sBand)+'</div>\n'+
      '  </div>\n';
  })()+
  '  <div class="meta-row">\n' +
  '    <div class="meta-item"><strong>Prepared For</strong>'+esc(customer)+'</div>\n' +
  '    <div class="meta-item"><strong>Report Date</strong>'+dateStr+'</div>\n' +
  '    <div class="meta-item"><strong>Author</strong>'+esc(author)+'</div>\n' +
  '    <div class="meta-item"><strong>Classification</strong>Confidential</div>\n' +
  '    <div class="meta-item"><strong>Status</strong><span style="color:#f59e0b;font-weight:700">ALPHA</span></div>\n' +
  '  </div>\n</div>\n' +
  '<div class="toc"><h3>Discovered Risk Findings</h3><div class="toc-cards">\n      '+tocCards+'\n</div></div>\n' +
  '<section id="exec-summary" class="pagebreak">\n<h2>Executive Summary</h2>\n' +
  '<div class="kpi-grid">' +
  '<div class="kpi-card critical"><div class="kpi-number">'+alerts.length+'</div><div class="kpi-label">Critical Alerts</div></div>' +
  '<div class="kpi-card high"><div class="kpi-number">'+vulns.length+'</div><div class="kpi-label">Critical CVEs (Risk ≥ 9)</div></div>' +
  '<div class="kpi-card medium"><div class="kpi-number">'+compliance.length+'</div><div class="kpi-label">Non-Compliance Findings</div></div>' +
  '<div class="kpi-card info"><div class="kpi-number">'+identities.length+'</div><div class="kpi-label">Identity Risk Findings</div></div>' +
  (secrets.length ? '<div class="kpi-card info"><div class="kpi-number">'+secrets.length+'</div><div class="kpi-label">SSH Keys Detected</div></div>' : '') +
  '</div>\n' +
  '<div class="section-summary"><div class="ss-title">Overall Risk Assessment</div>' +
  '<p>This assessment identified <strong style="color:#DA291C">'+total+' total findings</strong> across <strong>'+esc(customer)+'</strong>. ' +
  'The Cloud Security Posture Score is <strong style="color:'+sColor+'">'+score+'/100 — '+esc(sBand)+'</strong>.</p></div>\n' +
  '</section>\n' +
  alertSection + '\n' + compSection + '\n' + vulnSection + '\n' + idSection + '\n' + secretsAllSection + '\n' + secretSection + '\n' +
  '<footer><p>RAPID CLOUD ASSESSMENT REPORT — Powered by FortiCNAPP · Prepared for '+esc(customer)+' · '+dateStr+'</p>' +
  '<p style="opacity:.55;font-size:.72rem;margin-top:.4rem">Confidential — for named recipient only. Alpha feature — generated from live dashboard cache.</p>' +
  '</footer>\n</body>\n</html>';
}


// ── HTTP server ───────────────────────────────────────────────────────────────

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

http.createServer((req, res) => {
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
        const { first, last, company, role, email } = JSON.parse(body);
        const ts = new Date().toISOString();
        const row = [ts, first, last, company, role, email]
          .map(v => `"${(v||'').replace(/"/g,'""')}"`)
          .join(',') + '\n';
        fs.appendFileSync(CONTACTS_CSV, row);
        console.log(`[register] ${first} ${last} <${email}> — ${company} (${role})`);
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

  if (req.url === '/api/data') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', ...CORS });
    res.end(JSON.stringify(cache));
  } else if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...CORS });
    res.end('OK');
  } else if (req.url === '/mobile') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS });
    res.end(MOBILE_HTML);
  } else if (req.url === '/desktop') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS });
    res.end(HTML);
  } else if (req.url.startsWith('/report')) {
    const qs = new URL(req.url, 'http://localhost').searchParams;
    const customer = (qs.get('customer') || 'Customer').trim();
    const author   = (qs.get('author')   || 'Fortinet').trim();
    if (!cache.fetchedAt) {
      res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', ...CORS });
      res.end('<body style="font-family:sans-serif;padding:2rem"><h2>⏳ Dashboard data not yet loaded</h2><p>Please wait a moment and try again.</p></body>');
      return;
    }
    const reportHtml = buildReportHtml(cache, { customer, author });
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS });
    res.end(reportHtml);
  } else if (isMobile && req.url === '/') {
    res.writeHead(302, { Location: '/mobile', ...CORS });
    res.end();
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS });
    res.end(HTML);
  }
}).listen(PORT, () => {
  const mode = MOCK_FILE ? 'MOCK' : 'LIVE';
  console.log('\n┌──────────────────────────────────────────────────┐');
  console.log(`│  Fortinet Rapid Cloud Assessment — ${mode.padEnd(11)}│`);
  console.log('├──────────────────────────────────────────────────┤');
  console.log(`│  Account  : ${LW_ACCOUNT.padEnd(37)}│`);
  if (MOCK_FILE) {
    console.log(`│  Mock     : ${MOCK_FILE.padEnd(37)}│`);
  } else {
    console.log(`│  Refresh  : every ${String(INTERVAL + 's').padEnd(32)}│`);
  }
  console.log(`│  Open     : http://localhost:${String(PORT).padEnd(21)}│`);
  console.log('└──────────────────────────────────────────────────┘\n');

  if (MOCK_FILE) {
    // Mock mode — load snapshot once, never call the API
    try {
      const fs = require('fs');
      const raw = fs.readFileSync(MOCK_FILE, 'utf8');
      cache = { ...cache, ...JSON.parse(raw) };
      console.log(`[mock] Loaded ${MOCK_FILE} (${raw.length} bytes) — no API calls will be made\n`);
    } catch (e) {
      console.error(`[mock] Failed to load ${MOCK_FILE}:`, e.message);
    }
  } else {
    refreshData().catch(e => console.error('[startup]', e.message));
    setInterval(() => refreshData().catch(e => console.error('[refresh]', e.message)), INTERVAL * 1000);
  }
});
