import os
import sys
import shutil
import threading
import time
import random
import logging
import logzero

_FRAMES = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

_STATS = [
    # FortiCNAPP product insights
    'FortiCNAPP is agentless — zero software to deploy on workloads',
    'FortiCNAPP Risk Score weights CVSS, blast radius & live exploit code',
    'FortiCNAPP scans AWS, Azure & GCP from a single unified console',
    'FortiCNAPP CIEM shows exactly which permissions went unused in 90 days',
    'FortiCNAPP detects secrets in running containers, configs & IaC',
    'FortiCNAPP maps every finding to CIS, NIST, PCI-DSS & SOC2',
    'FortiCNAPP composite alerts correlate multiple signals into one finding',
    'FortiCNAPP baselines normal behaviour across 90 days of cloud activity',
    'FortiCNAPP scans IaC templates pre-deployment — fix before it ships',
    'FortiCNAPP CIEM can generate right-sized permission recommendations',
    'FortiCNAPP Risk Score ≥ 9 = top 5% most dangerous CVEs in your env',
    'FortiCNAPP integrates with Jira, Slack, and SIEM/SOAR platforms',
    'FortiCNAPP detects lateral movement paths across cloud accounts',
    'FortiCNAPP agentless scanning completes in minutes, not hours',
    'FortiCNAPP correlates compliance, vulns & identity in one risk view',
    'FortiCNAPP behavioral analytics detect anomalies no signature can catch',
    'FortiCNAPP shows the blast radius of every misconfiguration',
    'FortiCNAPP secret scanning covers SSH keys, API tokens & cloud creds',
    'FortiCNAPP CSPM tracks drift from secure baseline in real time',
    'FortiCNAPP unifies CSPM + CWPP + CIEM + secrets in one platform',
    'FortiCNAPP is private by design — all scanning runs in your cloud env',
    # Cloud security industry facts
    '<1% of cloud permissions are actually used  — Gartner',
    'Avg time to exploit a disclosed CVE: 12 days',
    'MFA blocks 99.9% of automated account attacks  — Microsoft',
    '194 days avg to detect a breach  — IBM',
    'Cloud misconfiguration: #1 cloud breach vector',
    '80%+ of cloud workloads are over-privileged',
    '60% of breaches involve unpatched vulnerabilities',
    'Containers running as root: 60% of deployments  — Sysdig',
    'Shadow IT: 10× more SaaS than IT knows  — Gartner',
    '45% of breaches now involve cloud assets  — Verizon',
]


def _get_console_handler():
    for h in logging.getLogger().handlers:
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            return h
    return None


class Spinner:

    def __init__(self, message='Generating report'):
        self.message = message
        self._stop = threading.Event()
        self._thread = None
        self._saved_stdout = None
        self._devnull = None
        self._console_handler = None
        self._saved_handler_level = None

    def _run(self):
        i = 0
        tick = 0
        acronym = random.choice(_STATS)
        while not self._stop.is_set():
            frame = _FRAMES[i % len(_FRAMES)]
            cols = shutil.get_terminal_size((120, 20)).columns
            line = f'  {frame}  {self.message}  ·  {acronym}   '
            if len(line) > cols:
                line = line[:cols - 3] + '   '
            sys.__stdout__.write(f'\r{line}')
            sys.__stdout__.flush()
            time.sleep(0.08)
            i += 1
            tick += 1
            if tick >= 40:
                acronym = random.choice(_STATS)
                tick = 0

    def start(self):
        self._devnull = open(os.devnull, 'w')
        self._saved_stdout = sys.stdout
        sys.stdout = self._devnull

        self._console_handler = _get_console_handler()
        if self._console_handler:
            self._saved_handler_level = self._console_handler.level
            self._console_handler.setLevel(logging.CRITICAL + 1)

        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, success=True):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)

        sys.stdout = self._saved_stdout
        if self._console_handler and self._saved_handler_level is not None:
            self._console_handler.setLevel(self._saved_handler_level)
        if self._devnull:
            self._devnull.close()

        mark = '✓' if success else '✗'
        suffix = 'done!' if success else 'failed — check lw_report_gen.log for details.'
        sys.__stdout__.write(f'\r  {mark}  {self.message} — {suffix}                    \n')
        sys.__stdout__.flush()
