#!/usr/bin/env node
// FortiCNAPP Rapid Cloud Assessment — Live Dashboard
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
// compliance policies and count returned rows as violations.

function policyCloud(id) {
  const u = (id || '').toUpperCase();
  if (u.includes('AWS')) return 'aws';
  if (u.includes('AZURE') || u.includes('AZ_')) return 'azure';
  if (u.includes('GCP') || u.includes('GOOGLE')) return 'gcp';
  return 'cloud';
}

async function fetchCompliance() {
  // Step 1 — get Critical compliance policy definitions
  let policies = [];
  try {
    const resp = await get('Policies');
    const all  = Array.isArray(resp?.data) ? resp.data : [];
    const sevOk = s => ['critical','high'].includes((s||'').toLowerCase());
    policies = all.filter(p =>
      p.policyType === 'Compliance' && sevOk(p.severity) &&
      p.enabled !== false && p.queryText,
    )
    // Critical first, then High; cap at 15
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

  // Step 2 — execute sequentially to stay within rate limits
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
        cloud:      policyCloud(p.queryId || p.policyId),
        id:         p.policyId,
        title:      p.title || p.policyId,
        severity:   'Critical',
        violations: rows.length,
      });
    } catch (e) {
      console.log(`  [compliance] ${p.policyId} ERR: ${e.message.slice(0,80)}`);
      if (e.message.includes('429')) await new Promise(r => setTimeout(r, 5000));
    }
    if (findings.length >= 10) break;
    await new Promise(r => setTimeout(r, 1200)); // throttle: 1.2s between queries
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
  const [a, v, i] = await Promise.allSettled([
    fetchAlerts(),
    fetchVulns(),
    fetchIdentities(),
  ]);

  function unwrap(res, key) {
    if (res.status === 'fulfilled') return res.value;
    errors[key] = res.reason?.message ?? String(res.reason);
    console.error(`  [${key}] ERROR: ${errors[key]}`);
    return [];
  }

  const alerts     = unwrap(a, 'alerts');
  const vulns      = unwrap(v, 'vulns');
  const identities = unwrap(i, 'identities');

  // Publish fast data right away; compliance will update the cache when ready
  cache = {
    ...cache,
    alerts, vulns, identities,
    fetchedAt: new Date().toISOString(),
    errors,
    account: LW_ACCOUNT,
    riskScore: calcRiskScore(alerts, vulns, identities),
    summary: { alerts: alerts.length, vulns: vulns.length, compliance: cache.compliance?.length ?? 0, identities: identities.length },
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
  --bg:#0c1422;--surface:#111d2e;--card:#131f30;--card2:#162336;
  --border:#1c2f46;--border2:#243a58;
  --text:#dde4ef;--sub:#8ba0bc;--muted:#4a6280;
  --accent:#0d9488;--accent-l:#14b8a6;--accent-dim:rgba(13,148,136,.15);
  --cr:#ef4444;--cr-bg:rgba(239,68,68,.12);--cr-bd:rgba(239,68,68,.3);
  --hi:#f97316;--hi-bg:rgba(249,115,22,.12);--hi-bd:rgba(249,115,22,.3);
  --me:#f59e0b;--me-bg:rgba(245,158,11,.12);
  --ok:#22c55e;--ok-bg:rgba(34,197,94,.12);--ok-bd:rgba(34,197,94,.3);
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,'Inter',BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;line-height:1.55;-webkit-font-smoothing:antialiased}
::-webkit-scrollbar{width:4px;height:4px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:#1e3050;border-radius:2px}

/* ── Report header ── */
.rpt-header{background:linear-gradient(135deg,#0d1b2e 0%,#152640 100%);border-bottom:1px solid #1e3450;padding:18px 28px;--text:#dde4ef;--sub:#8ba0bc;--muted:#4e6480;--border2:#223550;--ok:#34d399;--cr:#f87171;--hi:#fb923c;--me:#facc15}
.rpt-top{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:0}
.rpt-brand{display:flex;align-items:center;gap:14px}
.logo{width:46px;height:46px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.logo svg{width:24px;height:24px;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.rpt-title{font-size:20px;font-weight:700;color:#fff;letter-spacing:-.3px}
.rpt-sub{font-size:11px;color:var(--accent-l);text-transform:uppercase;letter-spacing:.12em;margin-top:2px}
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
.tbl-wrap{overflow-x:auto;max-height:380px;overflow-y:auto}
table{width:100%;border-collapse:collapse;font-size:11.5px}
thead{position:sticky;top:0;z-index:2}
thead th{text-align:left;padding:7px 14px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--card);border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:hover{background:rgba(99,102,241,.04)}
tbody tr:last-child{border-bottom:none}
td{padding:8px 14px;vertical-align:middle;color:var(--sub)}
td.p{color:var(--text);font-weight:500;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.m{font-family:'SFMono-Regular',Consolas,monospace;font-size:10.5px;color:var(--muted);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.r{text-align:right;padding-right:16px}

/* ── Badges ── */
.b{display:inline-flex;align-items:center;gap:4px;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.b::before{content:'';width:5px;height:5px;border-radius:50%;background:currentColor;flex-shrink:0}
.b-cr{color:var(--cr);background:var(--cr-bg);border-color:var(--cr-bd)}
.b-hi{color:var(--hi);background:var(--hi-bg);border-color:var(--hi-bd)}
.b-me{color:var(--me);background:var(--me-bg)}
.b-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-bd)}
.b-nt{color:var(--muted);background:rgba(78,100,128,.15)}
.risk-score{font-size:13px;font-weight:800;color:var(--cr)}
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
.pie-section{display:flex;flex-direction:column;align-items:center;gap:28px;padding:36px 40px 28px;background:linear-gradient(180deg,#060e1b 0%,#0c1422 100%);border-bottom:1px solid #1a2e46}
.pie-donut{flex-shrink:0;display:flex;justify-content:center}
.pie-legend{display:grid;grid-template-columns:repeat(4,1fr);width:100%;max-width:860px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);border-radius:14px;overflow:hidden}
.pi-row{display:flex;flex-direction:column;gap:6px;padding:20px 22px;cursor:pointer;transition:background .15s;border-right:1px solid rgba(255,255,255,.05)}
.pi-row:last-child{border-right:none}
.pi-row:hover{background:rgba(255,255,255,.05)}
.pi-topbar{height:3px;border-radius:2px;margin-bottom:6px}
.pi-cnt{font-size:40px;font-weight:900;line-height:1;letter-spacing:-2px}
.pi-name{font-size:13px;font-weight:700;color:#b8cce0;line-height:1.3;margin-top:4px}
.pi-desc{font-size:10.5px;color:#3a5570;line-height:1.5}
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
.vha-red{background:linear-gradient(135deg,#160d0d,#1a0f0f);border-bottom:1px solid var(--cr-bd)}.vha-red .vh-title{color:var(--cr)}.vha-red .vh-badge{background:var(--cr-bg);color:var(--cr);border:1px solid var(--cr-bd)}
.vha-orange{background:linear-gradient(135deg,#160f08,#1a1108);border-bottom:1px solid var(--hi-bd)}.vha-orange .vh-title{color:var(--hi)}.vha-orange .vh-badge{background:var(--hi-bg);color:var(--hi);border:1px solid var(--hi-bd)}
.vha-amber{background:linear-gradient(135deg,#141006,#181208);border-bottom:1px solid rgba(245,158,11,.3)}.vha-amber .vh-title{color:var(--me)}.vha-amber .vh-badge{background:var(--me-bg);color:var(--me);border:1px solid rgba(245,158,11,.3)}
.vha-purple{background:linear-gradient(135deg,#0f0d16,#120f1a);border-bottom:1px solid rgba(139,92,246,.3)}.vha-purple .vh-title{color:#a78bfa}.vha-purple .vh-badge{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.3)}

/* ── Alert description cell ── */
td.desc{font-size:11px;color:var(--sub);max-width:340px;white-space:normal;line-height:1.45;padding-top:7px;padding-bottom:7px}

/* ── Agent tip ── */
.agent-tip{font-size:10px;color:var(--accent-l);cursor:default;border-bottom:1px dashed var(--accent);padding-bottom:1px}
.agent-tip:hover{color:var(--accent)}

/* ── Footer ── */
.footer{text-align:center;padding:14px;font-size:10px;color:var(--muted);border-top:1px solid var(--border)}

/* ── App layout & sidebar ── */
.app-layout{display:flex;min-height:100vh}
.sidebar{width:214px;background:#07101f;flex-shrink:0;position:sticky;top:0;height:100vh;overflow-y:auto;display:flex;flex-direction:column}
.main{flex:1;min-width:0}
.sb-brand{display:flex;align-items:center;gap:10px;padding:16px 14px;border-bottom:1px solid #172540}
.sb-logo{width:36px;height:36px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.sb-logo svg{width:18px;height:18px;fill:none;stroke:#fff;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round}
.sb-name{font-size:14px;font-weight:700;color:#fff;letter-spacing:-.2px}
.sb-sect{padding:16px 16px 4px;font-size:9px;font-weight:700;letter-spacing:.14em;color:#243b56;text-transform:uppercase}
.sb-item{display:flex;align-items:center;gap:9px;padding:8px 13px;margin:1px 8px;border-radius:7px;cursor:pointer;color:#5a7ea0;font-size:12.5px;font-weight:500;transition:all .15s;user-select:none;white-space:nowrap}
.sb-item:hover{background:rgba(255,255,255,.06);color:#c0d4ec}
.sb-item.active{background:#1a3d72;color:#fff;font-weight:600}
.sb-item svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.sb-sep{margin:8px 14px;border:none;border-top:1px solid #162136}
.sb-spacer{flex:1}
/* ── Views ── */
.view{display:none}.view.active{display:block}
/* ── Alerts dark section header ── */
.sec-hdr.dark{background:linear-gradient(135deg,#0d1b2e 0%,#152640 100%);border-bottom:1px solid #1e3450}
.sec-hdr.dark .sec-title{color:#dde4ef}
.sec-hdr.dark .sec-desc{color:#4a6280}
/* ── Risk Findings view ── */
.rf-posture{display:flex;align-items:center;gap:28px;padding:20px 28px;background:linear-gradient(135deg,#0d1b2e 0%,#152640 100%);border-bottom:1px solid #1e3450}
.rf-pos-num{font-size:60px;font-weight:900;line-height:1;letter-spacing:-3px;transition:color .4s}
.rf-pos-meta{display:flex;flex-direction:column;gap:3px}
.rf-pos-lbl{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:#2e4a68}
.rf-pos-band{font-size:17px;font-weight:700;letter-spacing:.06em;transition:color .4s}
.rf-pos-sub{font-size:10.5px;color:#3e5c7a}
.rf-kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border-bottom:1px solid var(--border)}
.rf-kpi{background:var(--surface);padding:13px 18px;box-shadow:0 1px 3px rgba(15,23,42,.05)}
.rf-kpi-lbl{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:5px}
.rf-kpi-val{font-size:26px;font-weight:800;line-height:1;letter-spacing:-1px;color:var(--text)}
.rf-kpi-sub{font-size:10px;color:var(--muted);margin-top:3px}
.rf-body{padding:16px 20px}
/* ── Recommended Next Steps view ── */
.lab-steps{padding:0 28px}
.lab-step{display:flex;align-items:flex-start;gap:16px;padding:18px 0;border-bottom:1px solid var(--border)}
.lab-step:last-child{border-bottom:none}
.lab-step-bar{width:3px;border-radius:2px;flex-shrink:0;align-self:stretch;min-height:36px}
.lab-step-n{font-size:12px;font-weight:700;color:var(--muted);min-width:18px;padding-top:2px}
.lab-step-title{font-size:13.5px;font-weight:600;color:var(--text);line-height:1.4}
.lab-step-sub{font-size:11px;color:var(--muted);margin-top:4px}
.lab-split{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid var(--border)}
.lab-pane{padding:22px 26px}
.lab-pane+.lab-pane{border-left:1px solid var(--border)}
.lab-pane-title{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.13em;color:var(--muted);margin-bottom:14px}

/* ── Report button + modal ── */
.rpt-btn{display:flex;align-items:center;gap:8px;margin:8px 10px 0;padding:10px 13px;border-radius:8px;cursor:pointer;background:linear-gradient(135deg,#c93428,#9e1f16);color:#fff;font-size:12px;font-weight:700;letter-spacing:.03em;border:none;width:calc(100% - 20px);transition:filter .15s}
.rpt-btn:hover{filter:brightness(1.15)}
.rpt-btn svg{width:14px;height:14px;fill:none;stroke:#fff;stroke-width:2.2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:1000;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal-box{background:#0e1a2e;border:1px solid #1e3450;border-radius:16px;padding:28px 28px 22px;width:400px;max-width:92vw;box-shadow:0 24px 64px rgba(0,0,0,.6)}
.modal-title{font-size:16px;font-weight:800;color:#dde4ef;margin-bottom:6px}
.modal-sub{font-size:11px;color:#3e5c7a;margin-bottom:22px}
.modal-field{margin-bottom:14px}
.modal-label{font-size:10.5px;font-weight:700;color:#5a7ea0;letter-spacing:.06em;text-transform:uppercase;margin-bottom:5px}
.modal-input{width:100%;background:#081016;border:1px solid #1e3450;border-radius:8px;padding:9px 12px;color:#dde4ef;font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
.modal-input:focus{border-color:#c93428}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}
.modal-btn{padding:9px 18px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;border:none;font-family:inherit;transition:filter .15s}
.modal-btn.primary{background:linear-gradient(135deg,#c93428,#9e1f16);color:#fff}
.modal-btn.primary:hover{filter:brightness(1.15)}
.modal-btn.primary:disabled{opacity:.5;cursor:not-allowed;filter:none}
.modal-btn.ghost{background:transparent;border:1px solid #1e3450;color:#5a7ea0}
.modal-btn.ghost:hover{border-color:#2e5070;color:#8ba0bc}
.modal-status{text-align:center;padding:16px 0 4px;font-size:12px;color:#5a7ea0;line-height:1.7;min-height:48px}
.modal-dl{display:flex;flex-direction:column;gap:8px;margin-top:12px}
.modal-dl a{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#0a1826;border:1px solid #1e3450;border-radius:8px;color:#c0d4ec;text-decoration:none;font-size:12px;font-weight:600;transition:background .15s}
.modal-dl a:hover{background:#101e30}
.modal-dl a svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round}
/* ── Login overlay ── */
.login-overlay{position:fixed;inset:0;z-index:2000;background:linear-gradient(135deg,#040c18 0%,#071525 60%,#0a1e36 100%);display:flex;align-items:center;justify-content:center}
.login-box{width:420px;max-width:92vw;background:#0c1826;border:1px solid #1a3050;border-radius:20px;padding:36px 36px 28px;box-shadow:0 32px 80px rgba(0,0,0,.7)}
.login-logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.login-logo-name{font-size:13px;font-weight:700;color:#8aa8c8;line-height:1.3;letter-spacing:.02em}
.login-title{font-size:20px;font-weight:800;color:#d8e8f4;margin-bottom:4px}
.login-sub{font-size:11.5px;color:#2e4d6e;margin-bottom:24px}
.login-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.login-field{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.login-label{font-size:10px;font-weight:700;color:#3a6090;letter-spacing:.1em;text-transform:uppercase}
.login-input{background:#070f1c;border:1px solid #1a3050;border-radius:8px;padding:9px 12px;color:#d0dce8;font-size:13px;font-family:inherit;outline:none;transition:border-color .15s}
.login-input:focus{border-color:#c93428}
.login-select{appearance:none;background:#070f1c url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%233a6090'/%3E%3C/svg%3E") no-repeat right 10px center;border:1px solid #1a3050;border-radius:8px;padding:9px 28px 9px 12px;color:#d0dce8;font-size:13px;font-family:inherit;outline:none;width:100%;cursor:pointer;transition:border-color .15s}
.login-select:focus{border-color:#c93428}
.login-btn{width:100%;margin-top:8px;padding:12px;border-radius:10px;background:linear-gradient(135deg,#c93428,#9e1f16);color:#fff;font-size:13px;font-weight:700;border:none;cursor:pointer;letter-spacing:.04em;transition:filter .15s}
.login-btn:hover{filter:brightness(1.15)}
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
  <div class="sb-sect">Risk Center</div>
  <div class="sb-item" id="nav-risk" onclick="nav('risk')">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r=".5" fill="currentColor"/></svg>
    Critical Risk Findings
  </div>
  <div class="sb-item" id="nav-lab" onclick="nav('lab')">
    <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
    Recommended Next Steps
  </div>
  <!-- Generate Report button -->
  <div style="padding:0 0 6px">
    <a href="https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html" target="_blank" rel="noopener" class="rpt-btn" style="display:flex;text-decoration:none">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      Generate Report
    </a>
  </div>
  <!-- Sidebar gauge + meta -->
  <div style="padding:16px 14px;border-top:1px solid #172540;margin-top:auto">
    <div style="display:flex;flex-direction:column;align-items:center;gap:6px">
      <div style="font-size:9px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#243b56">Security Posture</div>
      <svg id="gauge-svg" viewBox="0 0 200 168" width="160" height="134" style="overflow:visible;display:block">
        <defs>
          <filter id="glow-f" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="2.5" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <g id="gauge-ticks"></g>
        <text id="gauge-txt" x="100" y="112" text-anchor="middle" font-size="14" font-weight="800" letter-spacing="2" fill="white" font-family="-apple-system,Inter,sans-serif">—</text>
        <text x="100" y="128" text-anchor="middle" font-size="9" font-weight="600" letter-spacing="2.5" fill="rgba(255,255,255,0.28)" font-family="-apple-system,Inter,sans-serif">POSTURE</text>
      </svg>
      <div class="rs-band" id="rs-band" style="display:none">—</div>
    </div>
    <div style="margin-top:12px;font-size:10px;color:#2e4d6e;line-height:1.8;text-align:center">
      <div><b id="acct-lbl" style="color:#5a7ea0">${account}</b></div>
      <div>Last refresh: <b id="fetched-at" style="color:#5a7ea0">—</b></div>
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
    <!-- Single large centered donut chart -->
    <div class="pie-donut">
      <svg viewBox="0 0 220 220" width="360" height="360">
        <circle cx="110" cy="110" r="80" fill="none" stroke="#162438" stroke-width="32"/>
        <g transform="rotate(-90,110,110)">
          <circle id="pseg-a" cx="110" cy="110" r="80" fill="none" stroke="#b85555" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1);filter:drop-shadow(0 0 4px rgba(184,85,85,.45))"/>
          <circle id="pseg-v" cx="110" cy="110" r="80" fill="none" stroke="#b87030" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1);filter:drop-shadow(0 0 4px rgba(184,112,48,.45))"/>
          <circle id="pseg-i" cx="110" cy="110" r="80" fill="none" stroke="#7b65c0" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1);filter:drop-shadow(0 0 4px rgba(123,101,192,.45))"/>
          <circle id="pseg-c" cx="110" cy="110" r="80" fill="none" stroke="#a07818" stroke-width="32" stroke-linecap="butt" stroke-dasharray="0 502.65" stroke-dashoffset="0" style="transition:stroke-dasharray 1.4s cubic-bezier(.22,1,.36,1),stroke-dashoffset 1.4s cubic-bezier(.22,1,.36,1);filter:drop-shadow(0 0 4px rgba(160,120,24,.45))"/>
        </g>
        <text id="pie-total" x="110" y="100" text-anchor="middle" dominant-baseline="middle" fill="#d0dce8" font-size="40" font-weight="900" font-family="inherit" letter-spacing="-2">—</text>
        <text x="110" y="127" text-anchor="middle" fill="#2a4260" font-size="8.5" font-weight="700" letter-spacing=".12em">CRITICAL RISK</text>
        <text x="110" y="139" text-anchor="middle" fill="#2a4260" font-size="8.5" font-weight="700" letter-spacing=".12em">FINDINGS</text>
      </svg>
    </div>
    <!-- 4-column legend grid below -->
    <div class="pie-legend">
      <div class="pi-row" onclick="nav('alerts')">
        <div class="pi-topbar" style="background:#b85555"></div>
        <div class="pi-cnt" style="color:#b85555"><span id="kpi-a">—</span></div>
        <div class="pi-name">Critical Alerts</div>
        <div class="pi-desc">Active threats &amp; policy violations requiring immediate action</div>
      </div>
      <div class="pi-row" onclick="nav('vulns')">
        <div class="pi-topbar" style="background:#b87030"></div>
        <div class="pi-cnt" style="color:#b87030"><span id="kpi-v">—</span></div>
        <div class="pi-name">Critical CVEs</div>
        <div class="pi-desc">Known exploitable weaknesses on running hosts</div>
      </div>
      <div class="pi-row" onclick="nav('identities')">
        <div class="pi-topbar" style="background:#7b65c0"></div>
        <div class="pi-cnt" style="color:#7b65c0"><span id="kpi-i">—</span></div>
        <div class="pi-name">Risky Identities</div>
        <div class="pi-desc">Overprivileged roles &amp; lateral movement exposure</div>
      </div>
      <div class="pi-row" onclick="nav('compliance')">
        <div class="pi-topbar" style="background:#a07818"></div>
        <div class="pi-cnt" style="color:#a07818"><span id="kpi-c">—</span></div>
        <div class="pi-name">Compliance Violations</div>
        <div class="pi-desc">Governance gaps &amp; audit exposure across cloud policies</div>
      </div>
    </div>
  </div>
  <div style="text-align:center;padding:10px 28px 4px;font-size:11px;font-weight:600;letter-spacing:.08em;color:#2e4d6e;font-style:italic">Aiming towards a better, more secure cloud posture</div>
  <div class="footer">FortiCNAPP Rapid Cloud Assessment &nbsp;·&nbsp; Auto-refresh every ${intervalSec}s &nbsp;·&nbsp; <span id="footer-time"></span></div>
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

<!-- ═══ View: Risk Findings ═══ -->
<div class="view" id="view-risk">
  <div class="rf-posture">
    <div class="rf-pos-num" id="rf-num">—</div>
    <div class="rf-pos-meta">
      <div class="rf-pos-lbl">Security Posture Score</div>
      <div class="rf-pos-band" id="rf-band">—</div>
      <div class="rf-pos-sub">Higher is better &nbsp;·&nbsp; 0–100 scale</div>
    </div>
  </div>
  <div class="rf-kpis">
    <div class="rf-kpi"><div class="rf-kpi-lbl">Critical Alerts</div><div class="rf-kpi-val" id="rf-k-a">—</div><div class="rf-kpi-sub">Open &amp; unresolved</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">CVEs Risk ≥ 9</div><div class="rf-kpi-val" id="rf-k-v">—</div><div class="rf-kpi-sub">Critical host CVEs</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">Non-Compliance</div><div class="rf-kpi-val" id="rf-k-c">—</div><div class="rf-kpi-sub">Critical controls violated</div></div>
    <div class="rf-kpi"><div class="rf-kpi-lbl">Risky Identities</div><div class="rf-kpi-val" id="rf-k-i">—</div><div class="rf-kpi-sub">No MFA · Admin/over-privileged</div></div>
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
  <div class="lab-split">
    <div class="lab-pane">
      <div class="lab-pane-title">Top Critical CVEs</div>
      <div id="lab-vulns"><div class="state"><div class="spinner"></div></div></div>
    </div>
    <div class="lab-pane">
      <div class="lab-pane-title">Top Risky Identities</div>
      <div id="lab-idents"><div class="state"><div class="spinner"></div></div></div>
    </div>
  </div>
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
    {id:'pseg-a',n:(d.alerts||[]).length},
    {id:'pseg-v',n:(d.vulns||[]).length},
    {id:'pseg-i',n:(d.identities||[]).length},
    {id:'pseg-c',n:(d.compliance||[]).length},
  ];
  var total=segs.reduce(function(s,c){return s+c.n;},0);
  var C=502.65,GAP=7;
  var active=segs.filter(function(s){return s.n>0;}).length||1;
  var usable=C-GAP*active;
  var cum=0;
  segs.forEach(function(seg){
    var el=document.getElementById(seg.id);if(!el)return;
    var len=total===0?0:(seg.n/total)*usable;
    (function(e,l,o){
      requestAnimationFrame(function(){
        e.setAttribute('stroke-dasharray',l.toFixed(1)+' '+(C-l).toFixed(1));
        e.setAttribute('stroke-dashoffset',(-o).toFixed(1));
      });
    })(el,len,cum);
    if(seg.n>0)cum+=len+GAP;
  });
  var ct=document.getElementById('pie-total');
  if(ct)ct.textContent=total||'0';
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
        +'<td class="p" title="'+e(r.alertName)+'"><a class="rf-link" href="'+e(href)+'" target="_blank">'+e(tr(r.alertName,32))+'</a></td>'
        +'<td class="desc">'+e(tr(desc,160))+'</td>'
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
        +'<td class="p" title="'+e(r.featureKey?.name)+'">'+e(tr(r.featureKey?.name,22))+'</td>'
        +'<td class="m">'+e(tr(r.evalCtx?.hostname||r.mid||'\\u2014',20))+'</td>'
        +'<td>'+(fix?'<span class="b b-ok" title="'+e(fixVer)+'">'+e(tr(fixVer,18)||'Fix \\u2713')+'</span>':'<span class="b b-nt">No fix</span>')+'</td>'
      +'</tr>';
    }).join('')+'</tbody></table></div>');
}

function renderCompliance(rows,err){
  if(err){state('body-c','',err);return}
  setKpi('kpi-c',rows.length);setCount('cnt-c',rows.length,true);
  if(!rows.length){state('body-c','','No critical compliance violations');return}
  const baseC='https://'+(_lastData?.account||'')+'/ui/compliance';
  setBody('body-c','<div class="tbl-wrap"><table><thead><tr><th>Cloud</th><th>Rule ID</th><th>Title</th><th>Severity</th><th>Violations</th></tr></thead><tbody>'
    +rows.map(r=>'<tr class="'+strip(r.severity)+'">'
      +'<td>'+cloud(r.cloud)+'</td>'
      +'<td class="m"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(tr(r.id,18))+'</a></td>'
      +'<td class="p" title="'+e(r.title)+'"><a class="rf-link" href="'+e(baseC)+'" target="_blank">'+e(tr(r.title,38))+'</a></td>'
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

function nav(name){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  document.getElementById('view-'+name).classList.add('active');
  document.getElementById('nav-'+name).classList.add('active');
}

let _lastData=null;

function renderRiskFindings(d){
  const p=Math.max(0,100-(d.riskScore??0));
  const color=p>=90?'var(--ok)':p>=50?'var(--me)':'var(--cr)';
  const band=p>=90?'OPTIMIZING':p>=50?'MATURING':'BUILDING';
  const rn=document.getElementById('rf-num');rn.textContent=p;rn.style.color=color;
  const rb=document.getElementById('rf-band');rb.textContent=band;rb.style.color=color;
  document.getElementById('rf-k-a').textContent=d.alerts?.length??0;
  document.getElementById('rf-k-v').textContent=d.vulns?.length??0;
  document.getElementById('rf-k-c').textContent=d.compliance?.length??0;
  document.getElementById('rf-k-i').textContent=d.identities?.length??0;
  const base='https://'+d.account;
  const items=[];
  (d.alerts||[]).forEach(r=>items.push({cat:'Alert',title:r.alertName,detail:r.alertType,score:95,href:base+'/ui/investigation/alerts/'+r.alertId}));
  (d.vulns||[]).forEach(r=>items.push({cat:'CVE',title:r.vulnId,detail:(r.featureKey?.name||'')+' · '+(r.evalCtx?.hostname||''),score:parseFloat(r.riskScore||0)*10,href:base+'/ui/investigation/vulnerabilities/hosts'}));
  (d.compliance||[]).forEach(r=>items.push({cat:'Compliance',title:r.title,detail:(r.cloud||'').toUpperCase()+' · '+r.violations+' violations',score:80,href:base+'/ui/compliance'}));
  (d.identities||[]).forEach(r=>items.push({cat:'Identity',title:r.NAME||r.PRINCIPAL_ID,detail:(r.PROVIDER_TYPE||'')+' · No MFA',score:(r.METRICS?.risk_score||0)*100,href:base+'/ui/insights'}));
  items.sort((a,b)=>b.score-a.score);
  if(!items.length){setBody('rf-table','<div class="state"><span>No risk findings</span></div>');return;}
  setBody('rf-table','<div class="tbl-wrap"><table><thead><tr><th>Category</th><th>Finding</th><th>Detail</th><th>Risk Score</th></tr></thead><tbody>'
    +items.slice(0,25).map(r=>'<tr>'
      +'<td><span class="b b-nt">'+e(r.cat)+'</span></td>'
      +'<td class="p"><a class="rf-link" href="'+e(r.href)+'" target="_blank" title="Open in FortiCNAPP">'+e(tr(r.title,42))+' &#8599;</a></td>'
      +'<td class="m">'+e(tr(r.detail,38))+'</td>'
      +'<td class="r"><span class="risk-score">'+Math.round(r.score)+'</span></td>'
    +'</tr>').join('')+'</tbody></table></div>');
}

function renderLab(d){
  const p=Math.max(0,100-(d.riskScore??0));
  const color=p>=90?'var(--ok)':p>=50?'var(--me)':'var(--cr)';
  const band=p>=90?'OPTIMIZING':p>=50?'MATURING':'BUILDING';
  const ls=document.getElementById('lab-score');ls.textContent=p;ls.style.color=color;
  document.getElementById('lab-band-txt').textContent=band;
  const actions=[];
  if((d.identities||[]).length) actions.push({cls:'p1',n:1,tab:'identities',text:'Fix '+d.identities.length+' risky identit'+(d.identities.length===1?'y':'ies')+' — enable MFA &amp; remove over-provisioned access',sub:'Priority 1 · Identity compromise is the #1 breach vector'});
  if((d.alerts||[]).length) actions.push({cls:'p2',n:actions.length+1,tab:'alerts',text:'Investigate '+d.alerts.length+' open critical alert'+(d.alerts.length===1?'':'s'),sub:'Threat Center · Some may indicate an active breach'});
  if((d.vulns||[]).length) actions.push({cls:'p3',n:actions.length+1,tab:'vulns',text:'Patch '+d.vulns.length+' critical CVE'+(d.vulns.length===1?'':'s')+' with risk score ≥ 9.0',sub:'Focus on internet-exposed hosts first'});
  if((d.compliance||[]).length) actions.push({cls:'p4',n:actions.length+1,tab:'compliance',text:'Remediate '+d.compliance.length+' non-compliant critical control'+(d.compliance.length===1?'':'s'),sub:'Compliance · Cloud misconfigurations'});
  if(!actions.length) actions.push({cls:'p4',n:1,tab:'overview',text:'Security posture is excellent — keep monitoring',sub:'Posture score: '+p+'/100'});
  const clrMap={p1:'var(--cr)',p2:'var(--hi)',p3:'var(--me)',p4:'var(--ok)'};
  document.getElementById('lab-actions').innerHTML=actions.map(a=>'<div class="lab-step"><div class="lab-step-bar" style="background:'+clrMap[a.cls]+'"></div><div class="lab-step-n">'+a.n+'</div><div><div class="lab-step-title"><a href="#" data-tab="'+a.tab+'" onclick="nav(this.dataset.tab);return false;" style="color:inherit;text-decoration:none;border-bottom:1px dashed currentColor;cursor:pointer">'+a.text+'</a></div><div class="lab-step-sub">'+e(a.sub)+'</div></div></div>').join('');
  const tv=d.vulns||[];
  document.getElementById('lab-vulns').innerHTML=tv.length?'<div class="tbl-wrap"><table><thead><tr><th>CVE</th><th>Host</th><th>Risk</th></tr></thead><tbody>'
    +tv.slice(0,6).map(r=>'<tr><td class="m">'+e(tr(r.vulnId,20))+'</td><td class="p">'+e(tr(r.evalCtx?.hostname||'\\u2014',18))+'</td><td class="r"><span class="risk-score">'+parseFloat(r.riskScore||0).toFixed(1)+'</span></td></tr>').join('')
    +'</tbody></table></div>':'<div class="state"><span>No critical CVEs</span></div>';
  const ti=d.identities||[];
  document.getElementById('lab-idents').innerHTML=ti.length?'<div class="tbl-wrap"><table><thead><tr><th>Identity</th><th>Cloud</th><th>MFA</th></tr></thead><tbody>'
    +ti.slice(0,6).map(r=>'<tr><td class="p">'+e(tr(r.NAME||r.PRINCIPAL_ID,22))+'</td><td class="m">'+e(r.PROVIDER_TYPE||'\\u2014')+'</td><td><span class="tag-nomfa">NO MFA</span></td></tr>').join('')
    +'</tbody></table></div>':'<div class="state"><span>No risky identities</span></div>';
}

async function load(){
  try{
    const d=await fetch('/api/data').then(r=>r.json());
    _lastData=d;
    renderAlerts(d.alerts,d.errors?.alerts);
    renderVulns(d.vulns,d.errors?.vulns);
    renderCompliance(d.compliance,d.errors?.compliance);
    renderIdentities(d.identities,d.errors?.identities);
    updateRiskScore(d.riskScore??0);
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

(function initGauge(){
  const NS='http://www.w3.org/2000/svg';
  const CX=100,CY=116,R=78,N=36;
  const START=225,SWEEP=270;
  const g=document.getElementById('gauge-ticks');
  for(let i=0;i<=N;i++){
    const deg=START-(i/N)*SWEEP;
    const rad=deg*Math.PI/180;
    const maj=i%6===0;
    const r0=maj?R-13:R-8;
    const ln=document.createElementNS(NS,'line');
    ln.setAttribute('x1',(CX+r0*Math.cos(rad)).toFixed(2));
    ln.setAttribute('y1',(CY-r0*Math.sin(rad)).toFixed(2));
    ln.setAttribute('x2',(CX+R*Math.cos(rad)).toFixed(2));
    ln.setAttribute('y2',(CY-R*Math.sin(rad)).toFixed(2));
    ln.setAttribute('stroke','#1e3450');
    ln.setAttribute('stroke-width',maj?'2.5':'1.5');
    ln.setAttribute('stroke-linecap','round');
    ln.setAttribute('class','gtick');
    g.appendChild(ln);
  }
})();

function updateRiskScore(riskScore){
  const p=Math.max(0,100-riskScore);
  // green=great → red=poor
  const color=p>=90?'#22c55e':p>=50?'#f59e0b':'#ef4444';
  const band=p>=90?'OPTIMIZING':p>=50?'MATURING':'BUILDING';
  document.getElementById('rs-band').textContent=band+' POSTURE';
  const t=document.getElementById('gauge-txt');t.textContent=band;t.setAttribute('fill',color);
  const N=36,fill=Math.round(p/100*N);
  document.querySelectorAll('.gtick').forEach((tk,i)=>{
    const lit=i<=fill;
    tk.setAttribute('stroke',lit?color:'#1e3450');
    if(lit)tk.setAttribute('filter','url(#glow-f)');else tk.removeAttribute('filter');
  });
}

// ── Login ─────────────────────────────────────────────────────────────────────
(function checkLogin(){
  const s=sessionStorage.getItem('rca_user');
  if(s){
    document.getElementById('login-overlay').style.display='none';
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
  sessionStorage.setItem('rca_user',JSON.stringify(user));
  fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(user)}).catch(()=>{});
  document.getElementById('login-overlay').style.display='none';
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
  if (req.url === '/api/data') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache', ...CORS });
    res.end(JSON.stringify(cache));
  } else if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...CORS });
    res.end('OK');
  } else {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...CORS });
    res.end(HTML);
  }
}).listen(PORT, () => {
  const mode = MOCK_FILE ? 'MOCK' : 'LIVE';
  console.log('\n┌──────────────────────────────────────────────────┐');
  console.log(`│  FortiCNAPP Rapid Cloud Assessment — ${mode.padEnd(11)}│`);
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
