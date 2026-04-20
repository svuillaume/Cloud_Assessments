# Scoring Guide

This repository contains two scoring systems: the **Live Dashboard risk score** and the **CSA Report posture score**.

---

## Part 1 — Dashboard Risk Score (server.js)

### Score Bands

| Band            | Range | Color  |
|-----------------|-------|--------|
| EMERGING        | < 40  | Red    |
| STEADY          | 40–59 | Orange |
| HIGH PERFORMING | 60–79 | Yellow |
| OUTSTANDING     | ≥ 80  | Green  |

### Formula

```
topIdent = max(identity.METRICS.risk_score) × 100   # Lacework 0-1 → 0-100  (60%)
topCve   = max(vuln.riskScore) × 10                 # CVSS 0-10 → 0-100     (25%)
alertPts = min(criticalAlerts × 3, 15)              # urgency boost           (15%)

riskScore = min(100, round(topIdent × 0.60 + topCve × 0.25 + alertPts))
```

| Input | Source field | Weight | Rationale |
|-------|-------------|--------|-----------|
| Highest identity risk | `METRICS.risk_score` | **60%** | Priority 1 — majority of breaches start with compromised identity |
| Highest CVE risk | `vuln.riskScore` (CVSS) | 25% | Attack surface / exploitability signal |
| Critical alert count | alert count × 3 | capped 15 pt | Urgency: active unresolved threats |

---

## Part 2 — CSA Report Posture Score (lw_report_gen.py)

### Global Cloud Security Posture Score

**Range:** 0 – 10

```
posture_score = max(10.0 − (p_comp + p_vuln + p_admin + p_alerts + p_secrets), 0)
```

| Variable | Formula | Max penalty | Saturation point |
|---|---|---|---|
| `p_comp`    | `min(critical_compliance / 10, 1) × 1.5` | 1.5 pts | 10 critical findings |
| `p_vuln`    | `min(critical_vulns / 15, 1) × 2.5`      | 2.5 pts | 15 critical CVEs     |
| `p_admin`   | `min(admin_no_mfa / 30, 1) × 2.5`        | 2.5 pts | 30 admin w/o MFA     |
| `p_alerts`  | `min(critical_alerts / 10, 1) × 1.5`     | 1.5 pts | 10 critical alerts   |
| `p_secrets` | `min(_sc / 3, 1) × 2.0`                  | 2.0 pts | 3 risky secrets      |

### Per-CSP Gauge Scores (AWS / Azure / GCP)

```
score_csp = max(10.0 − (min(cc / 10, 1) × 6.0) − (min(ac / 30, 1) × 4.0), 0)
```

| Score | Label | Colour |
|---|---|---|
| ≤ 3.0 | CRITICAL | Red |
| 3.1 – 5.0 | POOR | Red |
| 5.1 – 6.0 | AT RISK | Red |
| 6.1 – 7.9 | MODERATE | Blue |
| 8.0 – 8.9 | GOOD | Green |
| ≥ 9.0 | EXCELLENT | Green |

### `_sc` — Risky Secrets

`_sc` counts secrets in paths where `chmod 600` is **not** the secure default (e.g. `/var/`, `/tmp/`, Windows paths). Secrets in `/home/`, `/root/`, `/etc/` give `_sc = 0` and no penalty.
