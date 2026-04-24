<div align="center">

Both tools share the **same risk score model** on a unified **0–10 scale** — lower is better.

</div>

## Risk Score Model

| Score (0–10) | Security Posture | Color |
|:------------:|------------------|:-----:|
| 0.0 – 1.9 | Priority Attention Recommended | 🔴 Red |
| 2.0 – 4.9 | Improvement Opportunities Identified | 🟠 Orange |
| 5.0 – 7.9 | Stable Security Posture | 🔵 Blue |
| 8.0 – 10.0 | Strong Security Posture | 🟢 Green |

### Guidance

- **Red** — Immediate focus is recommended to address higher-risk findings quickly.
- **Orange** — Meaningful opportunities exist to strengthen controls and reduce risk.
- **Blue** — Good overall posture with areas to continue improving.
- **Green** — Strong controls and mature security practices are in place.

> 📐 **Higher score = better posture.** A score of 10 means no penalty-triggering findings. A score of 0 means all inputs are fully saturated.

---

## Formula

```
posture = 10
        − min(alerts      / 8, 1) × 2.5
        − min(CVEs        / 5, 1) × 2.5
        − min(violations  / 3, 1) × 2.5
        − min(admins_noMFA/ 8, 1) × 2.5
```

Each category contributes equally (max 2.5 pts). Total max penalty = 10 → minimum score = 0.

| Input | Saturates at | Max deduction |
|-------|:------------:|:-------------:|
| Critical alerts | 20 | −2.5 |
| Critical CVEs (risk ≥ 9) | 20 | −2.5 |
| Compliance violations | 20 | −2.5 |
| Admins without MFA | 20 | −2.5 |

**Per-CSP gauge** (AWS / Azure / GCP) uses only the two signals available per provider:

```
score_csp = 10
          − min(violations / 20, 1) × 5.0
          − min(admins_noMFA / 20, 1) × 5.0
```

---

## Per-CSP Gauge (AWS / Azure / GCP) — CSA Report

Each cloud provider gets its own gauge using only the signals available per-provider:

```
posture_csp  = max(10.0 − (min(cc / 10, 1) × 6.0) − (min(ac / 30, 1) × 4.0), 0)
risk_csp     = 10 − posture_csp
```

- `cc` → critical compliance findings for that CSP
- `ac` → admin accounts without MFA for that CSP

---

## `_sc` — Risky Secrets (CSA Report)

The `_sc` counter only penalizes secrets in **insecure default locations**:

| Path pattern | Counted? | Reason |
|-------------|:--------:|--------|
| `/var/…` | ✅ | World-readable by default |
| `/tmp/…` | ✅ | Ephemeral and shared |
| `C:\Users\Public\…` | ✅ | Shared by default |
| `/home/…` | ❌ | Per-user, restrictive umask |
| `/root/…` | ❌ | Root-only access |
| `/etc/…` | ❌ | Typically `chmod 600` for sensitive files |

---

## Worked Example

A tenant with 4 compliance findings, 20 critical CVEs, 12 admins without MFA, 2 alerts, 1 risky secret:

```
p_comp    = min(4/10, 1)  × 1.5 = 0.60
p_vuln    = min(20/15, 1) × 2.5 = 2.50  (saturated)
p_admin   = min(12/30, 1) × 2.5 = 1.00
p_alerts  = min(2/10, 1)  × 1.5 = 0.30
p_secrets = min(1/3, 1)   × 2.0 = 0.67
total penalty                    = 5.07

CSA risk_score  = 5.07   →  🟠 Improvement Opportunities Identified
Dashboard risk  = min(10, 4.40 / 8 × 10) = 5.5  →  🟠 Improvement Opportunities Identified
```
*(Dashboard excludes p_secrets: 0.60 + 2.50 + 1.00 + 0.30 = 4.40)*

---

<div align="center">

[← Back to README](README.md) · [📝 Changelog](CHANGELOG.md) · [📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
