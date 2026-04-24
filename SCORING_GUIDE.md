# Scoring Guide

Both tools share the same three-stage maturity model. The Dashboard works on a 0–100 posture scale; the CSA Report works on a 0–10 scale. The bands map 1:1.

| Stage      | Dashboard Posture (0–100) | CSA Score (0–10) | Color  |
|------------|--------------------------|-----------------|--------|
| BUILDING   | 0 – 49                   | 0.0 – 4.9       | Red    |
| MATURING   | 50 – 89                  | 5.0 – 8.9       | Orange |
| OPTIMIZING | 90 – 100                 | 9.0 – 10.0      | Green  |

---

## Dashboard Risk Score (source of truth)

`posture = 100 − riskScore`  →  stage derived from posture %

### Formula

```
topIdent = max(identity.METRICS.risk_score) × 100   # Lacework 0-1 → 0-100  (60%)
topCve   = max(vuln.riskScore) × 10                 # CVSS 0-10 → 0-100     (25%)
alertPts = min(criticalAlerts × 3, 15)              # urgency boost          (15%)

riskScore = min(100, round(topIdent × 0.60 + topCve × 0.25 + alertPts))
```

| Input | Source field | Weight | Rationale |
|-------|-------------|--------|-----------|
| Highest identity risk | `METRICS.risk_score` | **60%** | Majority of breaches start with compromised identity |
| Highest CVE risk | `vuln.riskScore` (CVSS) | **25%** | Attack surface / exploitability signal |
| Critical alert count | alert count × 3, capped 15 pt | **15%** | Urgency: active unresolved threats |

---

## CSA Report Posture Score

```
posture_score = max(10.0 − (p_comp + p_vuln + p_admin + p_alerts + p_secrets), 0)
```

| Variable | Formula | Max penalty | Saturates at |
|----------|---------|-------------|-------------|
| `p_comp`    | `min(critical_compliance / 10, 1) × 1.5` | 1.5 pts | 10 critical findings |
| `p_vuln`    | `min(critical_vulns / 15, 1) × 2.5`      | 2.5 pts | 15 critical CVEs     |
| `p_admin`   | `min(admin_no_mfa / 30, 1) × 2.5`        | 2.5 pts | 30 admin w/o MFA     |
| `p_alerts`  | `min(critical_alerts / 10, 1) × 1.5`     | 1.5 pts | 10 critical alerts   |
| `p_secrets` | `min(_sc / 3, 1) × 2.0`                  | 2.0 pts | 3 risky secrets      |

### Per-CSP Gauge (AWS / Azure / GCP)

```
score_csp = max(10.0 − (min(cc / 10, 1) × 6.0) − (min(ac / 30, 1) × 4.0), 0)
```

| Score (0–10) | Stage      | Color  |
|-------------|------------|--------|
| 0.0 – 4.9   | BUILDING   | Red    |
| 5.0 – 8.9   | MATURING   | Orange |
| 9.0 – 10.0  | OPTIMIZING | Green  |

### `_sc` — Risky Secrets

`_sc` counts secrets in paths where `chmod 600` is **not** the secure default (e.g. `/var/`, `/tmp/`, Windows paths). Secrets in `/home/`, `/root/`, `/etc/` give `_sc = 0` and no penalty.
