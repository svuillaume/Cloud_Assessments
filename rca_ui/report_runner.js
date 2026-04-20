#!/usr/bin/env node
// Report Runner — runs alongside the Docker dashboard on port 8081
// Usage: node report_runner.js
'use strict';

const http   = require('http');
const { spawn } = require('child_process');
const path   = require('path');
const fs     = require('fs');
const os     = require('os');

const PORT       = 8081;
const SCRIPT_DIR = path.join(os.homedir(), 'rapid_ass_newfeature/extensible-reporting');
const SCRIPT     = path.join(SCRIPT_DIR, 'lw_report_gen.py');
const OUT_DIR    = path.join(os.homedir(), 'Downloads');

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

let running = false;
let lastJob = null;

function runScript(args) {
  return new Promise((resolve, reject) => {
    console.log('[run]', 'python3', args.join(' '));
    const proc = spawn('python3', [SCRIPT, ...args], {
      cwd: SCRIPT_DIR,
      env: { ...process.env },
    });
    let out = '';
    proc.stdout.on('data', d => { out += d.toString(); process.stdout.write(d); });
    proc.stderr.on('data', d => { out += d.toString(); process.stderr.write(d); });
    proc.on('close', code => {
      if (code === 0) resolve(out);
      else reject(new Error(`Exit ${code}: ${out.slice(-400)}`));
    });
  });
}

http.createServer(async (req, res) => {
  Object.entries(CORS).forEach(([k, v]) => res.setHeader(k, v));

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // POST /run-report  {author, customer}
  if (req.method === 'POST' && req.url === '/run-report') {
    if (running) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Report already running — please wait' }));
      return;
    }
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      let p = {};
      try { p = JSON.parse(body); } catch (_) {}
      const author   = (p.author   || 'Fortinet').trim();
      const customer = (p.customer || 'Customer').trim();
      const ts   = new Date().toISOString().slice(0, 10).replace(/-/g, '');
      const safe = customer.replace(/[^a-zA-Z0-9_-]/g, '_');
      const base = path.join(OUT_DIR, `${safe}_RCA_${ts}`);
      const htmlFile = `${safe}_RCA_${ts}.html`;
      const pdfFile  = `${safe}_RCA_${ts}.pdf`;

      running = true;
      console.log(`\n[report] author="${author}" customer="${customer}"`);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      try {
        // Phase 1: HTML (fresh API data, creates local cache)
        await runScript([
          '--author', author, '--customer', customer,
          '--report-format', 'html',
          '--report-path', base + '.html',
        ]);
        // Phase 2: PDF (reuse cached data from phase 1)
        await runScript([
          '--author', author, '--customer', customer,
          '--report-format', 'pdf',
          '--report-path', base + '.pdf',
          '--cache-data',
        ]);
        lastJob = { html: htmlFile, pdf: pdfFile, ts: new Date().toISOString() };
        console.log(`[report] done → ${htmlFile} + ${pdfFile}\n`);
        res.end(JSON.stringify({ ok: true, html: htmlFile, pdf: pdfFile }));
      } catch (e) {
        console.error('[report] ERROR:', e.message.slice(0, 200));
        res.end(JSON.stringify({ ok: false, error: e.message.slice(0, 400) }));
      } finally {
        running = false;
      }
    });
    return;
  }

  // GET /download/:filename  — stream a generated report file
  if (req.method === 'GET' && req.url.startsWith('/download/')) {
    const filename = decodeURIComponent(req.url.slice('/download/'.length)).replace(/\.\./g, '');
    const filepath = path.join(OUT_DIR, filename);
    if (!fs.existsSync(filepath)) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(filename).toLowerCase();
    const ct  = ext === '.pdf' ? 'application/pdf' : 'text/html; charset=utf-8';
    res.writeHead(200, {
      'Content-Type': ct,
      'Content-Disposition': `attachment; filename="${filename}"`,
    });
    fs.createReadStream(filepath).pipe(res);
    return;
  }

  // GET /status  — check if a job is running
  if (req.url === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ running, lastJob }));
    return;
  }

  res.writeHead(404); res.end('Not found');

}).listen(PORT, () => {
  console.log(`\n┌──────────────────────────────────────────────┐`);
  console.log(`│   Report Runner  →  http://localhost:${PORT}      │`);
  console.log(`│   Script : ${path.basename(SCRIPT).padEnd(35)}│`);
  console.log(`│   Output : ${SCRIPT_DIR.replace(os.homedir(), '~').slice(-35).padEnd(35)}│`);
  console.log(`└──────────────────────────────────────────────┘\n`);
  console.log('Waiting for requests on http://localhost:8081/run-report\n');
});
