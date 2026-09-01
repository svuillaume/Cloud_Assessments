#!/usr/bin/env node
// RCA Report — a small local admin console with two actions: Deploy RCA and Decommission
// RCA, plus a live health pill (top-right: HEALTHY / NOT DEPLOYED / UNREACHABLE) and a
// real-time pipeline view of each workflow step while a run is in flight. Deliberately NOT
// part of the customer-facing dashboard (server.js) and NOT deployed into the EKS cluster it
// manages — see k8s/README.md's "RCA Report control panel" section for why: the dashboard's
// @fortinet.com email gate isn't real access control, and a page tearing down the very pod
// serving it couldn't show a final "done" status. This runs locally instead, and shells out
// to the `gh` CLI (reusing whatever `gh auth login` session is already active on this
// machine — the same one used manually throughout this repo's deploy work) rather than
// holding its own GitHub token.
//
// Health is inferred from GitHub Actions history (whichever of rca-deploy.yml/
// rca-teardown.yml most recently succeeded), then — only when that points at "deployed" —
// confirmed with a real server-side HTTPS request to the app's own /health endpoint
// (rejectUnauthorized:false, since it's the app's own self-signed cert, same trust decision
// a browser makes clicking through the "unsafe cert" warning). CI success alone doesn't mean
// the app is actually reachable right now, so both signals matter.
//
// Usage:
//   node k8s/rca_control_panel.cjs
//   PORT=4100 node k8s/rca_control_panel.cjs         # default 4321
//   HOST=0.0.0.0 node k8s/rca_control_panel.cjs       # default 127.0.0.1 (localhost-only)
//
// .cjs, not .js — an unrelated ancestor directory's package.json (outside this repo) sets
// "type": "module", which would otherwise force Node to parse this CommonJS file as ESM and
// fail on `require()`. .cjs is Node's own documented override for exactly this situation.
//
// Requires: `gh` CLI installed and authenticated (`gh auth status`) with `workflow` scope.
'use strict';

const http = require('http');
const https = require('https');
const { execFile } = require('child_process');
const { URL } = require('url');

const REPO = process.env.REPO || 'svuillaume/Cloud_Assessments';
const PORT = Number(process.env.PORT) || 4321;
const HOST = process.env.HOST || '127.0.0.1';

// GitHub always lists every step of a job upfront (queued ones included, with status
// "pending"), so the frontend can render a stable, live-filling pipeline straight from this
// list — no need to hardcode a step list per workflow. Only the bookkeeping steps GitHub adds
// automatically are filtered out here; everything the workflow YAML itself names is real
// signal and passed through as-is.
const NOISE_STEPS = new Set(['Set up job', 'Complete job']);
function isNoiseStep(name) {
  return NOISE_STEPS.has(name) || name.startsWith('Post ');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function gh(args) {
  return new Promise((resolve, reject) => {
    execFile('gh', args, { maxBuffer: 1024 * 1024 * 20 }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(stderr || err.message));
      } else {
        resolve(stdout);
      }
    });
  });
}

// gh workflow run doesn't print a run ID — dispatch, then poll the workflow's recent runs
// for one created after we fired, same trick used manually throughout this session.
async function dispatchAndFindRun(workflow, extraArgs) {
  const before = Date.now() - 5000; // small buffer for clock skew between here and GitHub
  await gh(['workflow', 'run', workflow, '-R', REPO, ...extraArgs]);
  for (let i = 0; i < 15; i++) {
    await sleep(1500);
    const out = await gh([
      'run', 'list', '-R', REPO,
      '--workflow', workflow,
      '--limit', '5',
      '--json', 'databaseId,createdAt,event',
    ]);
    const runs = JSON.parse(out).filter((r) => r.event === 'workflow_dispatch');
    const fresh = runs.find((r) => new Date(r.createdAt).getTime() >= before);
    if (fresh) return fresh.databaseId;
  }
  throw new Error('Triggered the workflow but could not locate the new run — check the Actions tab directly.');
}

async function getRunStatus(runId) {
  const out = await gh(['run', 'view', String(runId), '-R', REPO, '--json', 'status,conclusion,url,jobs']);
  const data = JSON.parse(out);
  const job = data.jobs && data.jobs[0];
  const steps = (job ? job.steps : [])
    .filter((s) => !isNoiseStep(s.name))
    .map((s) => ({ name: s.name, status: s.status, conclusion: s.conclusion || null }));
  return { status: data.status, conclusion: data.conclusion, url: data.url, steps };
}

async function getDeployFqdn(runId) {
  const out = await gh(['run', 'view', String(runId), '-R', REPO, '--log']);
  // GitHub echoes the step's *script source* into the log before running it — that source
  // line literally contains the unexpanded `https://$NODE_ADDR:30443` text and would match a
  // naive regex before the real runtime output does (confirmed live: this returned the
  // literal string "$NODE_ADDR" instead of an address on a genuinely successful run). The
  // negative lookahead skips any match where the character right after "https://" is "$" —
  // a real resolved address never starts with one.
  const m = out.match(/Reachable at (https:\/\/(?!\$)\S+)/);
  return m ? m[1] : null;
}

async function lastSuccessfulRun(workflow) {
  const out = await gh([
    'run', 'list', '-R', REPO,
    '--workflow', workflow,
    '--status', 'success',
    '--limit', '1',
    '--json', 'databaseId,createdAt',
  ]);
  const runs = JSON.parse(out);
  return runs[0] || null;
}

// FortiCNAPP credentials, pushed straight to GitHub's encrypted secret store — same fields
// rca_update_secrets.sh manages, just driven from the Deploy button instead of a local .env
// file. `mask: true` fields render as <input type="password"> client-side so a pasted key/
// secret is hidden immediately, same as any password field.
const LW_SECRET_FIELDS = [
  { name: 'LW_ACCOUNT', label: 'FortiCNAPP Account', placeholder: 'your-tenant.lacework.net', mask: false },
  { name: 'LW_KEY_ID', label: 'API Key ID', placeholder: 'FORTINET_XXXXXXXX', mask: true },
  { name: 'LW_SECRET', label: 'API Secret', placeholder: '_xxxxxxxx', mask: true },
  { name: 'LW_SUBACCOUNT', label: 'Subaccount (optional)', placeholder: 'leave blank if not used', mask: false },
];

async function setSecret(name, value) {
  await gh(['secret', 'set', name, '-b', value, '-R', REPO]);
}

// gh exits non-zero when asked to delete a secret that doesn't exist — that's not a real
// failure for this tool's purposes (nothing to remove), so it resolves false instead of
// rejecting; any other error still propagates.
async function deleteSecret(name) {
  try {
    await gh(['secret', 'delete', name, '-R', REPO]);
    return true;
  } catch (err) {
    if (/not found|no secret/i.test(err.message)) return false;
    throw err;
  }
}

// self-signed cert (SELF_SIGNED=true, entrypoint.sh) — rejectUnauthorized:false is
// deliberate here, same trust decision a browser makes when you click through the "unsafe
// cert" warning, just made server-side so this check doesn't depend on the browser having
// visited (and trusted) that origin already.
function checkHealth(fqdn) {
  return new Promise((resolve) => {
    let settled = false;
    const req = https.get(`${fqdn}/health`, { rejectUnauthorized: false, timeout: 6000 }, (res) => {
      settled = true;
      resolve(res.statusCode >= 200 && res.statusCode < 300);
      res.resume();
    });
    req.on('error', () => { if (!settled) resolve(false); });
    req.on('timeout', () => { req.destroy(); if (!settled) resolve(false); });
  });
}

// "Deployed" is inferred from GitHub Actions history, not a live cluster query (this tool
// deliberately has no kubectl/AWS access of its own — only `gh`) — whichever of the two
// workflows most recently completed successfully wins. If that's a deploy, actually reach out
// to the app's /health endpoint to distinguish "deployed and healthy" from "deployed per CI
// but not actually reachable" (SG rule missing, pod crash-looping, etc.) — CI success alone
// doesn't guarantee that.
async function getAppHealth() {
  const [deploy, teardown] = await Promise.all([
    lastSuccessfulRun('rca-deploy.yml'),
    lastSuccessfulRun('rca-teardown.yml'),
  ]);
  const deployAt = deploy ? new Date(deploy.createdAt).getTime() : -1;
  const teardownAt = teardown ? new Date(teardown.createdAt).getTime() : -1;

  if (!deploy || teardownAt > deployAt) {
    return { state: 'not-deployed' };
  }
  const fqdn = await getDeployFqdn(deploy.databaseId);
  if (!fqdn) return { state: 'unknown' };
  const healthy = await checkHealth(fqdn);
  return { state: healthy ? 'healthy' : 'unreachable', fqdn };
}

function sendJson(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) });
  res.end(data);
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 1e5) req.destroy();
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

const PAGE_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Cloud Assessment — Report Generation</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e12;
    --surface: #12181f;
    --surface-2: #1a222b;
    --line: #232d38;
    --text: #eef2f6;
    --text-dim: #7c8a99;
    --text-faint: #4b5866;
    --deploy: #3ddc84;
    --deploy-dim: #1d5c3d;
    --decom: #ff5a5f;
    --decom-dim: #6b2224;
    --amber: #f5b83d;
    --mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }
  * { box-sizing: border-box; }
  ::selection { background: var(--deploy-dim); color: var(--text); }
  body {
    margin: 0; background: var(--bg); color: var(--text); font: 15px/1.6 var(--sans);
    background-image:
      radial-gradient(circle at 15% 0%, rgba(61,220,132,0.06), transparent 45%),
      radial-gradient(circle at 85% 15%, rgba(255,90,95,0.05), transparent 40%);
    background-attachment: fixed;
  }
  main { max-width: 640px; margin: 0 auto; padding: 40px 24px 80px; animation: fade-up .4s ease both; }
  @keyframes fade-up { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }

  .brand { position: fixed; top: 20px; left: 24px; z-index: 20; }
  .brand-logo { height: 22px; width: auto; color: var(--text); display: block; }

  header { display: flex; flex-direction: column; align-items: center; text-align: center; gap: 14px; margin-bottom: 34px; }
  h1 { font: 700 22px/1.4 var(--mono); margin: 0; letter-spacing: -0.01em; }

  .status-pill { display: inline-flex; align-items: center; gap: 7px; padding: 5px 12px 5px 10px;
                 border: 1px solid var(--line); border-radius: 999px; background: var(--surface);
                 font: 500 11px var(--mono); text-transform: uppercase; letter-spacing: .05em; color: var(--text-dim); }
  .led { width: 7px; height: 7px; border-radius: 50%; background: var(--text-faint); flex: none; }
  .led.checking { background: var(--text-dim); animation: breathe 1.2s ease-in-out infinite; }
  .led.healthy { background: var(--deploy); box-shadow: 0 0 8px var(--deploy); animation: breathe 2.4s ease-in-out infinite; }
  .led.down { background: var(--decom); box-shadow: 0 0 6px var(--decom); }
  .status-pill.healthy { color: var(--deploy); border-color: var(--deploy-dim); }
  .status-pill.down { color: var(--decom); border-color: var(--decom-dim); }

  .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  @media (max-width: 520px) { .actions { grid-template-columns: 1fr; } }

  button.tile {
    all: unset; cursor: pointer; box-sizing: border-box;
    background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
    padding: 20px; display: flex; flex-direction: column; gap: 10px;
    transition: border-color .15s, transform .1s, box-shadow .2s;
  }
  button.tile:hover:not(:disabled) { transform: translateY(-1px); }
  button.tile:active:not(:disabled) { transform: translateY(0); }
  button.tile:focus-visible { outline: 2px solid var(--text-dim); outline-offset: 2px; }
  button.tile:disabled { opacity: .4; cursor: not-allowed; }
  #btn-deploy:hover:not(:disabled) { border-color: var(--deploy); box-shadow: 0 0 0 1px var(--deploy), 0 0 24px -8px var(--deploy); }
  #btn-decommission:hover:not(:disabled) { border-color: var(--decom); box-shadow: 0 0 0 1px var(--decom), 0 0 24px -8px var(--decom); }
  .tile-icon { width: 20px; height: 20px; }
  #btn-deploy .tile-icon { color: var(--deploy); }
  #btn-decommission .tile-icon { color: var(--decom); }
  .tile-label { font: 600 14px var(--mono); letter-spacing: .01em; }
  .tile-desc { font: 12px/1.5 var(--sans); color: var(--text-dim); }

  .pipeline-wrap { max-height: 0; overflow: hidden; transition: max-height .4s ease; }
  .pipeline-wrap.open { max-height: 900px; }
  .pipeline { margin-top: 28px; padding-top: 24px; border-top: 1px solid var(--line); }
  .pipeline-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
  .pipeline-title { font: 600 12px var(--mono); text-transform: uppercase; letter-spacing: .08em; color: var(--text-dim); }
  .pipeline-link { font: 12px var(--mono); color: var(--text-dim); text-decoration: none; }
  .pipeline-link:hover { color: var(--text); }

  .steps { position: relative; padding-left: 28px; }
  .conduit { position: absolute; left: 9px; top: 6px; bottom: 6px; width: 2px; background: var(--line); border-radius: 1px; overflow: hidden; }
  .conduit-fill { width: 100%; height: 0%; background: linear-gradient(var(--fill-color, var(--deploy)), var(--fill-color, var(--deploy))); transition: height .5s cubic-bezier(.4,0,.2,1); box-shadow: 0 0 10px var(--fill-color, var(--deploy)); }

  .step { position: relative; padding: 0 0 20px; }
  .step:last-child { padding-bottom: 0; }
  .step-node { position: absolute; left: -28px; top: 1px; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; }
  .step-node .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--text-faint); transition: background .2s, box-shadow .2s; }
  .step.done .step-node .dot { background: var(--fill-color, var(--deploy)); }
  .step.running .step-node .dot { background: var(--amber); box-shadow: 0 0 8px var(--amber); animation: breathe 1s ease-in-out infinite; }
  .step.failed .step-node .dot { background: var(--decom); box-shadow: 0 0 8px var(--decom); }
  .step.skipped .step-node .dot { background: var(--text-faint); opacity: .4; }

  .step-row { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
  .step-name { font: 13px var(--mono); color: var(--text-faint); transition: color .2s; }
  .step.done .step-name, .step.running .step-name, .step.failed .step-name { color: var(--text); }
  .step-state { font: 11px var(--mono); color: var(--text-faint); flex: none; text-transform: uppercase; letter-spacing: .04em; }
  .step.running .step-state { color: var(--amber); }
  .step.failed .step-state { color: var(--decom); }
  .step.done .step-state { color: var(--fill-color, var(--deploy)); }

  @keyframes breathe { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }

  .result { margin-top: 20px; padding: 16px 18px; border-radius: 10px; border: 1px solid var(--line);
            background: var(--surface); animation: fade-up .3s ease both; }
  .result.success { border-color: var(--deploy-dim); background: linear-gradient(180deg, rgba(61,220,132,.07), transparent); }
  .result.success.decom { border-color: var(--decom-dim); background: linear-gradient(180deg, rgba(255,90,95,.07), transparent); }
  .result.error { border-color: var(--decom-dim); background: linear-gradient(180deg, rgba(255,90,95,.08), transparent); }
  .result-title { font: 600 13px var(--mono); margin-bottom: 4px; }
  .result.success .result-title { color: var(--deploy); }
  .result.success.decom .result-title { color: var(--decom); }
  .result.error .result-title { color: var(--decom); }
  .fqdn-row { display: flex; align-items: center; gap: 8px; margin-top: 10px; }
  .fqdn-row a { font: 13px var(--mono); color: var(--text); text-decoration: none; word-break: break-all; }
  .fqdn-row a:hover { text-decoration: underline; }
  .copy-btn { all: unset; cursor: pointer; font: 11px var(--mono); color: var(--text-dim); border: 1px solid var(--line);
              border-radius: 6px; padding: 3px 8px; flex: none; }
  .copy-btn:hover { color: var(--text); border-color: var(--text-dim); }

  .modal-overlay { position: fixed; inset: 0; background: rgba(4,6,8,.72); display: flex;
                   align-items: center; justify-content: center; padding: 20px; z-index: 10; }
  .modal-overlay[hidden] { display: none; }
  .modal { width: 100%; max-width: 420px; background: var(--surface); border: 1px solid var(--line);
           border-radius: 12px; padding: 24px; animation: fade-up .2s ease both; }
  .modal-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px; }
  .modal-title { font: 600 14px var(--mono); }
  .modal-close { all: unset; cursor: pointer; color: var(--text-dim); font-size: 20px; line-height: 1; padding: 2px 6px; }
  .modal-close:hover { color: var(--text); }
  .modal-hint { margin: 0 0 18px; font: 12px/1.5 var(--sans); color: var(--text-dim); }
  .field { display: block; margin-bottom: 14px; }
  .field span { display: block; font: 500 11px var(--mono); text-transform: uppercase; letter-spacing: .04em;
                color: var(--text-dim); margin-bottom: 6px; }
  .field input { width: 100%; box-sizing: border-box; background: var(--surface-2); border: 1px solid var(--line);
                 border-radius: 8px; padding: 9px 10px; color: var(--text); font: 13px var(--mono); }
  .field input:focus { outline: none; border-color: var(--deploy); }
  .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
  .btn-secondary, .btn-primary { all: unset; box-sizing: border-box; cursor: pointer; font: 600 12px var(--mono);
                                  padding: 8px 16px; border-radius: 8px; border: 1px solid var(--line); }
  .btn-secondary { color: var(--text-dim); }
  .btn-secondary:hover { color: var(--text); border-color: var(--text-dim); }
  .btn-primary { color: #06110b; background: var(--deploy); border-color: var(--deploy); }
  .btn-primary:hover { filter: brightness(1.08); }
  .btn-primary:disabled, .btn-secondary:disabled { opacity: .5; cursor: not-allowed; }
  .cred-error { margin-top: 12px; font: 12px var(--mono); color: var(--decom); }


  @media (prefers-reduced-motion: reduce) {
    * { animation-duration: .001ms !important; transition-duration: .001ms !important; }
  }
</style>
</head>
<body>
<div class="brand"><svg class="brand-logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 487.6 55" aria-label="Fortinet"><path fill="currentColor" d="M279.9 11.7V0h13.4v54.8h-13.4V11.7zM220.9 0h51.7v11.8h-24.3v43.1H235V11.8h-14.1V0zm266.7 0v11.8h-24.3v43.1H450V11.8h-14.1V0h51.7zM0 0h58v11.8H13.4v11.7h38v11.8h-38v19.5H0V0zm374.5 0h54v11.8h-40.6v9.8h33.3v11.8h-33.3v9.8h41.3V55h-54.7V0zm-10.3 15.5v39.3h-13.4V15.5c0-2.1-1.6-3.7-3.7-3.7h-30v43.1h-13.4V0h45c8.5 0 15.5 7 15.5 15.5zM200.3 0h-45.7v54.8H168V35.3h30c1.6.1 2.9 1.4 2.9 3v16.6h13.4V38.1c0-2.9-1.6-5.4-4-6.8 2.9-2.7 4.7-6.6 4.7-10.8v-5.8c.1-8.1-6.5-14.7-14.7-14.7zm1.4 20.5c0 1.6-1.3 3-3 3H168V11.8h30.7c1.6 0 3 1.3 3 3v5.7z"/><path fill="#da291c" d="M144.2 20.4v14.2H122V20.4h22.2zM93.9 54.8H116V40.6H93.9v14.2zm50.3-42.9c0-6.6-5.3-11.9-11.9-11.9h-10.2v14.2h22.1v-2.3zM93.9 0v14.2H116V0H93.9zM65.7 20.4v14.2h22.1V20.4H65.7zM122 54.8h10.2c6.6 0 11.9-5.3 11.9-11.9v-2.3H122v14.2zM65.7 42.9c0 6.6 5.3 11.9 11.9 11.9h10.2V40.6H65.7v2.3zm0-31v2.3h22.1V0H77.6C71 0 65.7 5.3 65.7 11.9z"/></svg></div>
<main>
  <header>
    <h1>Security Cloud Assessment<br>Report Generation</h1>
    <span class="status-pill" id="status-pill">
      <span class="led checking" id="led"></span>
      <span id="health-text">checking</span>
    </span>
  </header>

  <div class="actions">
    <button class="tile" id="btn-deploy">
      <svg class="tile-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5"/><path d="M5 12l7-7 7 7"/></svg>
      <span class="tile-label">Deploy RCA</span>
      <span class="tile-desc">Apply the latest built image to <code>eks_samv</code></span>
    </button>
    <button class="tile" id="btn-decommission">
      <svg class="tile-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v10"/><path d="M18.4 6.6a9 9 0 1 1-12.8 0"/></svg>
      <span class="tile-label">Decommission RCA</span>
      <span class="tile-desc">Remove Deployment, Service, Secret, PVC</span>
    </button>
  </div>


  <div class="modal-overlay" id="cred-modal" hidden>
    <div class="modal">
      <div class="modal-head">
        <span class="modal-title">FortiCNAPP Credentials</span>
        <button class="modal-close" id="cred-close" type="button" aria-label="Close">&times;</button>
      </div>
      <p class="modal-hint">Pushed straight to GitHub Secrets on this repo before deploying. Leave a field blank to keep its current value.</p>
      <form id="cred-form">
        ${LW_SECRET_FIELDS.map((f) => `<label class="field">
          <span>${f.label}</span>
          <input type="${f.mask ? 'password' : 'text'}" name="${f.name}" placeholder="${f.placeholder}" autocomplete="off">
        </label>`).join('\n        ')}
        <div id="cred-error" class="cred-error" hidden></div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" id="cred-cancel">Cancel</button>
          <button type="submit" class="btn-primary" id="cred-submit">Save &amp; Deploy</button>
        </div>
      </form>
    </div>
  </div>

  <div class="pipeline-wrap" id="pipeline-wrap">
    <div class="pipeline">
      <div class="pipeline-head">
        <span class="pipeline-title" id="pipeline-title">Pipeline</span>
        <a href="#" id="run-link" class="pipeline-link" target="_blank">view on GitHub &rarr;</a>
      </div>
      <div class="steps" id="steps">
        <div class="conduit"><div class="conduit-fill" id="conduit-fill"></div></div>
      </div>
      <div id="result-slot"></div>
    </div>
  </div>

</main>
<script>
const btnDeploy = document.getElementById('btn-deploy');
const btnDecommission = document.getElementById('btn-decommission');
const pipelineWrap = document.getElementById('pipeline-wrap');
const pipelineTitle = document.getElementById('pipeline-title');
const runLink = document.getElementById('run-link');
const stepsEl = document.getElementById('steps');
const conduitFill = document.getElementById('conduit-fill');
const resultSlot = document.getElementById('result-slot');
const led = document.getElementById('led');
const statusPill = document.getElementById('status-pill');
const healthText = document.getElementById('health-text');

let polling = null;
let healthPollTimer = null;
let lastDeletedSecrets = [];
const ACCENT = { deploy: '#3ddc84', decommission: '#ff5a5f' };

const credModal = document.getElementById('cred-modal');
const credForm = document.getElementById('cred-form');
const credClose = document.getElementById('cred-close');
const credCancel = document.getElementById('cred-cancel');
const credSubmit = document.getElementById('cred-submit');
const credError = document.getElementById('cred-error');

function openCredModal() {
  credError.hidden = true;
  credForm.reset();
  credModal.hidden = false;
}
function closeCredModal() {
  credModal.hidden = true;
}
credClose.addEventListener('click', closeCredModal);
credCancel.addEventListener('click', closeCredModal);
credModal.addEventListener('click', (e) => { if (e.target === credModal) closeCredModal(); });

credForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  credError.hidden = true;
  credSubmit.disabled = true;
  credSubmit.textContent = 'Saving…';
  const data = Object.fromEntries(new FormData(credForm).entries());
  try {
    const res = await fetch('/api/credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const result = await res.json();
    if (result.error) throw new Error(result.error);
    closeCredModal();
    trigger('deploy', '/api/deploy', 'Deploying');
  } catch (err) {
    credError.textContent = err.message;
    credError.hidden = false;
  } finally {
    credSubmit.disabled = false;
    credSubmit.textContent = 'Save & Deploy';
  }
});

function setButtonsDisabled(disabled) {
  btnDeploy.disabled = disabled;
  btnDecommission.disabled = disabled;
}

async function checkAppHealth() {
  led.className = 'led checking';
  statusPill.className = 'status-pill';
  healthText.textContent = 'checking';
  let data;
  try {
    const res = await fetch('/api/health');
    data = await res.json();
  } catch (e) {
    led.className = 'led down';
    statusPill.className = 'status-pill down';
    healthText.textContent = 'unknown';
    return;
  }
  const LABEL = { healthy: 'healthy', 'not-deployed': 'not deployed', unreachable: 'unreachable', unknown: 'unknown' };
  const isUp = data.state === 'healthy';
  led.className = 'led ' + (isUp ? 'healthy' : 'down');
  statusPill.className = 'status-pill ' + (isUp ? 'healthy' : 'down');
  healthText.textContent = LABEL[data.state] || 'unknown';
}

function renderSteps(kind, steps) {
  stepsEl.querySelectorAll('.step').forEach((n) => n.remove());
  const accent = ACCENT[kind];
  stepsEl.style.setProperty('--fill-color', accent);
  if (!steps || !steps.length) return;
  let doneCount = 0;
  steps.forEach((s) => {
    const state = s.status === 'completed'
      ? (s.conclusion === 'success' ? 'done' : s.conclusion === 'skipped' ? 'skipped' : 'failed')
      : (s.status === 'in_progress' ? 'running' : 'pending');
    if (state === 'done') doneCount++;
    const row = document.createElement('div');
    row.className = 'step ' + state;
    row.style.setProperty('--fill-color', accent);
    const label = { done: 'done', running: 'running', failed: 'failed', skipped: 'skipped', pending: 'queued' }[state];
    row.innerHTML = '<div class="step-node"><span class="dot"></span></div>' +
      '<div class="step-row"><span class="step-name"></span><span class="step-state">' + label + '</span></div>';
    row.querySelector('.step-name').textContent = s.name;
    stepsEl.appendChild(row);
  });
  const pct = steps.length ? Math.round((doneCount / steps.length) * 100) : 0;
  conduitFill.style.setProperty('--fill-color', accent);
  conduitFill.style.height = pct + '%';
}

function renderResult(kind, outcome, message, fqdn) {
  resultSlot.innerHTML = '';
  if (!outcome) return;
  const box = document.createElement('div');
  box.className = 'result ' + (outcome === 'success' ? 'success' + (kind === 'decommission' ? ' decom' : '') : 'error');
  const title = document.createElement('div');
  title.className = 'result-title';
  title.textContent = message;
  box.appendChild(title);
  if (fqdn) {
    const row = document.createElement('div');
    row.className = 'fqdn-row';
    row.innerHTML = '<a href="' + fqdn + '" target="_blank"></a><button class="copy-btn" type="button">copy</button>';
    row.querySelector('a').textContent = fqdn;
    row.querySelector('a').href = fqdn;
    const copyBtn = row.querySelector('.copy-btn');
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(fqdn).then(() => {
        copyBtn.textContent = 'copied';
        setTimeout(() => { copyBtn.textContent = 'copy'; }, 1400);
      });
    });
    box.appendChild(row);
  }
  resultSlot.appendChild(box);
}

async function poll(kind, runId) {
  let data;
  try {
    const res = await fetch('/api/status?workflow=' + encodeURIComponent(kind) + '&runId=' + runId);
    data = await res.json();
  } catch (e) {
    return; // transient network hiccup — keep polling, next tick will retry
  }
  if (data.error) {
    clearInterval(polling);
    setButtonsDisabled(false);
    renderResult(kind, 'error', data.error);
    checkAppHealth();
    return;
  }
  renderSteps(kind, data.steps);
  if (data.status !== 'completed') return;

  clearInterval(polling);
  setButtonsDisabled(false);
  if (data.conclusion === 'success') {
    if (kind === 'deploy') {
      renderResult(kind, 'success', data.fqdn ? 'Deployed' : 'Deployed — no URL found in the run log, check manually', data.fqdn);
    } else {
      const secretsMsg = lastDeletedSecrets.length
        ? 'Decommissioned — GitHub secrets removed: ' + lastDeletedSecrets.join(', ')
        : 'Decommissioned — no matching GitHub secrets found';
      renderResult(kind, 'success', secretsMsg);
    }
  } else {
    renderResult(kind, 'error', 'Run failed (' + data.conclusion + ')');
  }
  checkAppHealth();
}

async function trigger(kind, endpoint, label, confirmMsg) {
  if (confirmMsg && !confirm(confirmMsg)) return;
  setButtonsDisabled(true);
  pipelineWrap.classList.add('open');
  pipelineTitle.textContent = label;
  resultSlot.innerHTML = '';
  stepsEl.querySelectorAll('.step').forEach((n) => n.remove());
  conduitFill.style.height = '0%';
  runLink.hidden = true;
  try {
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    if (kind === 'decommission') lastDeletedSecrets = data.deletedSecrets || [];
    runLink.href = data.url;
    runLink.hidden = false;
    polling = setInterval(() => poll(kind, data.runId), 3000);
    poll(kind, data.runId);
  } catch (e) {
    setButtonsDisabled(false);
    renderResult(kind, 'error', e.message);
  }
}

btnDeploy.addEventListener('click', openCredModal);
btnDecommission.addEventListener('click', () =>
  trigger('decommission', '/api/decommission', 'Decommissioning',
    'This deletes the Deployment, Service, Secret, PVC, and the FortiCNAPP GitHub Secrets (LW_ACCOUNT, LW_KEY_ID, LW_SECRET, LW_SUBACCOUNT). Continue?')
);

checkAppHealth();
healthPollTimer = setInterval(checkAppHealth, 20000);
</script>
</body>
</html>
`;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(PAGE_HTML);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/health') {
      const health = await getAppHealth();
      return sendJson(res, 200, health);
    }

    if (req.method === 'POST' && url.pathname === '/api/credentials') {
      const body = await readJsonBody(req);
      const updated = [];
      for (const { name } of LW_SECRET_FIELDS) {
        const val = typeof body[name] === 'string' ? body[name].trim() : '';
        if (!val) continue; // blank field = keep whatever's already stored
        await setSecret(name, val);
        updated.push(name);
      }
      return sendJson(res, 200, { updated });
    }

    if (req.method === 'POST' && url.pathname === '/api/deploy') {
      await readJsonBody(req);
      const runId = await dispatchAndFindRun('rca-deploy.yml', ['-f', 'image_tag=latest']);
      const status = await getRunStatus(runId);
      return sendJson(res, 200, { runId, url: status.url });
    }

    if (req.method === 'POST' && url.pathname === '/api/decommission') {
      await readJsonBody(req);
      const runId = await dispatchAndFindRun('rca-teardown.yml', ['-f', 'mode=full']);
      const status = await getRunStatus(runId);
      // Best-effort: the k8s teardown itself doesn't depend on these, so one failing to
      // delete (or not existing) shouldn't fail the whole decommission response.
      const deletedSecrets = [];
      for (const { name } of LW_SECRET_FIELDS) {
        try {
          if (await deleteSecret(name)) deletedSecrets.push(name);
        } catch { /* leave it — surfaced nowhere, but doesn't block the response */ }
      }
      return sendJson(res, 200, { runId, url: status.url, deletedSecrets });
    }

    if (req.method === 'GET' && url.pathname === '/api/status') {
      const workflow = url.searchParams.get('workflow') === 'deploy' ? 'rca-deploy.yml' : 'rca-teardown.yml';
      const runId = url.searchParams.get('runId');
      if (!runId) return sendJson(res, 400, { error: 'missing runId' });
      const status = await getRunStatus(runId);
      const payload = { status: status.status, conclusion: status.conclusion, url: status.url, steps: status.steps };
      if (workflow === 'rca-deploy.yml' && status.status === 'completed' && status.conclusion === 'success') {
        payload.fqdn = await getDeployFqdn(runId);
      }
      return sendJson(res, 200, payload);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  } catch (err) {
    sendJson(res, 500, { error: err.message });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`RCA Report control panel: http://${HOST}:${PORT}  (repo: ${REPO})`);
});
