#!/usr/bin/env node
// RCA Report — a small local admin page with two buttons: Deploy RCA and Decommission RCA.
// Deliberately NOT part of the customer-facing dashboard (server.js) and NOT deployed into
// the EKS cluster it manages — see k8s/README.md's "RCA Report control panel" section for
// why: the dashboard's @fortinet.com email gate isn't real access control, and a page
// tearing down the very pod serving it couldn't show a final "done" status. This runs
// locally instead, and shells out to the `gh` CLI (reusing whatever `gh auth login` session
// is already active on this machine — the same one used manually throughout this repo's
// deploy work) rather than holding its own GitHub token.
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
const { execFile } = require('child_process');
const { URL } = require('url');

const REPO = process.env.REPO || 'svuillaume/Cloud_Assessments';
const PORT = Number(process.env.PORT) || 4321;
const HOST = process.env.HOST || '127.0.0.1';

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
  const out = await gh(['run', 'view', String(runId), '-R', REPO, '--json', 'status,conclusion,url']);
  return JSON.parse(out);
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
<title>RCA Report</title>
<style>
  :root { --bg:#0b0d10; --panel:#151a1f; --border:#262d35; --text:#f1f3f5; --text2:#98a2ad;
          --red:#ee3124; --green:#2fb673; --amber:#e0a52b; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  header { padding:28px 32px 8px; }
  header h1 { margin:0; font-size:22px; font-weight:650; letter-spacing:-0.01em; }
  header p { margin:6px 0 0; color:var(--text2); font-size:13px; }
  main { max-width:720px; margin:0 auto; padding:24px 32px 60px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:12px; padding:24px; margin-bottom:20px; }
  .actions { display:flex; gap:14px; flex-wrap:wrap; }
  button { font:inherit; font-weight:600; font-size:14px; border:none; border-radius:8px; padding:12px 20px; cursor:pointer; transition:opacity .15s; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  button:not(:disabled):hover { opacity:.88; }
  #btn-deploy { background:var(--green); color:#04120a; }
  #btn-decommission { background:var(--red); color:#fff; }
  .status-row { display:flex; align-items:center; gap:10px; margin-top:18px; font-size:14px; }
  .dot { width:9px; height:9px; border-radius:50%; background:var(--text2); flex:none; }
  .dot.running { background:var(--amber); animation:pulse 1.2s infinite; }
  .dot.ok { background:var(--green); }
  .dot.err { background:var(--red); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.35} }
  .fqdn-box { margin-top:16px; padding:16px; background:#0e2a1c; border:1px solid #1f5c3d; border-radius:8px; }
  .fqdn-box a { color:var(--green); font-weight:600; word-break:break-all; }
  .muted { color:var(--text2); font-size:13px; }
  .run-link { color:#7aa7ff; text-decoration:none; }
  .run-link:hover { text-decoration:underline; }
</style>
</head>
<body>
<header>
  <h1>RCA Report</h1>
  <p>Deploy or decommission the RCA dashboard on <code>eks_samv</code> via GitHub Actions — repo: <code id="repo"></code></p>
</header>
<main>
  <div class="card">
    <div class="actions">
      <button id="btn-deploy">Deploy RCA</button>
      <button id="btn-decommission">Decommission RCA</button>
    </div>
    <div class="status-row" id="status-row" hidden>
      <span class="dot" id="status-dot"></span>
      <span id="status-text"></span>
      <a href="#" id="run-link" class="run-link" target="_blank" hidden>view run &rarr;</a>
    </div>
    <div class="fqdn-box" id="fqdn-box" hidden>
      Dashboard is live at <a id="fqdn-link" href="#" target="_blank"></a>
    </div>
  </div>
  <p class="muted">Runs locally against your <code>gh</code> CLI session — no credentials stored in this page or sent to your browser beyond what you see here.</p>
</main>
<script>
const repoEl = document.getElementById('repo');
const btnDeploy = document.getElementById('btn-deploy');
const btnDecommission = document.getElementById('btn-decommission');
const statusRow = document.getElementById('status-row');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');
const runLink = document.getElementById('run-link');
const fqdnBox = document.getElementById('fqdn-box');
const fqdnLink = document.getElementById('fqdn-link');

let polling = null;

function setButtonsDisabled(disabled) {
  btnDeploy.disabled = disabled;
  btnDecommission.disabled = disabled;
}

function setStatus(kind, text, url) {
  statusRow.hidden = false;
  statusDot.className = 'dot' + (kind ? ' ' + kind : '');
  statusText.textContent = text;
  if (url) {
    runLink.href = url;
    runLink.hidden = false;
  } else {
    runLink.hidden = true;
  }
}

async function poll(kind, runId) {
  const res = await fetch('/api/status?workflow=' + encodeURIComponent(kind) + '&runId=' + runId);
  const data = await res.json();
  if (data.error) {
    setStatus('err', data.error);
    setButtonsDisabled(false);
    clearInterval(polling);
    return;
  }
  if (data.status !== 'completed') {
    setStatus('running', 'Running…', data.url);
    return;
  }
  clearInterval(polling);
  setButtonsDisabled(false);
  if (data.conclusion === 'success') {
    if (kind === 'deploy') {
      setStatus('ok', 'Deployed', data.url);
      if (data.fqdn) {
        fqdnBox.hidden = false;
        fqdnLink.href = data.fqdn;
        fqdnLink.textContent = data.fqdn;
      } else {
        setStatus('ok', 'Deployed (no URL found in the run log — check manually)', data.url);
      }
    } else {
      fqdnBox.hidden = true;
      setStatus('ok', 'Decommissioned', data.url);
    }
  } else {
    setStatus('err', 'Run failed (' + data.conclusion + ')', data.url);
  }
}

async function trigger(kind, endpoint, confirmMsg) {
  if (confirmMsg && !confirm(confirmMsg)) return;
  setButtonsDisabled(true);
  fqdnBox.hidden = true;
  setStatus('running', 'Triggering…');
  try {
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    setStatus('running', 'Running…', data.url);
    polling = setInterval(() => poll(kind, data.runId), 4000);
  } catch (e) {
    setStatus('err', e.message);
    setButtonsDisabled(false);
  }
}

btnDeploy.addEventListener('click', () => trigger('deploy', '/api/deploy'));
btnDecommission.addEventListener('click', () =>
  trigger('decommission', '/api/decommission', 'This deletes the Deployment, Service, Secret, and PVC. Continue?')
);

fetch('/api/repo').then((r) => r.json()).then((d) => { repoEl.textContent = d.repo; });
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

    if (req.method === 'GET' && url.pathname === '/api/repo') {
      return sendJson(res, 200, { repo: REPO });
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
      return sendJson(res, 200, { runId, url: status.url });
    }

    if (req.method === 'GET' && url.pathname === '/api/status') {
      const workflow = url.searchParams.get('workflow') === 'deploy' ? 'rca-deploy.yml' : 'rca-teardown.yml';
      const runId = url.searchParams.get('runId');
      if (!runId) return sendJson(res, 400, { error: 'missing runId' });
      const status = await getRunStatus(runId);
      const payload = { status: status.status, conclusion: status.conclusion, url: status.url };
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
