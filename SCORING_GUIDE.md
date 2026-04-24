<div align="center">

Both tools share the same three-stage maturity model on a unified **0–10 scale**.

| Stage      | Score (0–10) | Color  |
|------------|-------------|--------|
| BUILDING   | 0.0 – 4.9   | Red    |
| MATURING   | 5.0 – 8.9   | Orange |
| OPTIMIZING | 9.0 – 10.0  | Green  |

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

> 💡 **Why two?** The dashboard needs a fast "how bad is it right now?" number. The report needs a balanced, multi-dimensional score suitable for leadership.

---

## 🖥️ Part 1 — Dashboard Risk Score (`server.js`)

The dashboard reduces the whole environment to a **single 0–100 risk number**, then converts it into a friendlier posture % and maturity stage.

### 🏷️ Score bands (Maturity Model)

| Stage | Maturity % | Risk (0–100) | Color | What it means |
|-------|:---------:|:-----------:|:-----:|---------------|
| 🔴 **BUILDING** | 0 – 49 | 50 – 100 | Red | Security basics need significant work |
| 🟠 **MATURING** | 50 – 89 | 11 – 50 | Orange | Good progress, meaningful gaps remain |
| 🟢 **OPTIMIZING** | 90 – 100 | 0 – 10 | Green | Mature, well-run posture |

> 📐 **Relationship:** `posture % = 100 − riskScore`. The maturity stage is derived from the posture %.

### 🧮 Formula

```text
topIdent  = max(identity.METRICS.risk_score) × 100   # Lacework 0–1 normalized to 0–100
topCve    = max(vuln.riskScore) × 10                 # CVSS 0–10 normalized to 0–100
alertPts  = min(criticalAlerts × 3, 15)              # urgency boost, capped at 15

riskScore = min(100, round(
              topIdent  × 0.60
            + topCve    × 0.25
            + alertPts
          ))
```

### ⚖️ Weights & rationale

| Input | Source field | Weight | Why this weight? |
|-------|-------------|:------:|------------------|
| 🪪 **Highest identity risk** | `METRICS.risk_score` | **60%** | Most breaches start with a compromised identity — it's the #1 priority signal |
| 🐛 **Highest CVE risk** | `vuln.riskScore` (CVSS) | **25%** | Represents attack surface and exploitability |
| 🚨 **Critical alert count** | `criticalAlerts × 3` | **capped at 15 pts** | Urgency boost for active, unresolved threats |

> 💡 **Key design choices**
> - Identity and CVE inputs use the **worst single finding**, not an average — one critical hole sinks the score, as it should.
> - Alerts are an **additive boost**, not a weighted average — they reflect urgency, not baseline posture.
> - The total is **clamped to 100** so the score always fits the band table above.

---

## 📄 Part 2 — CSA Report Posture Score (`lw_report_gen.py`)

The CSA report uses a **0–10 posture scale** (higher = better) — the standard executive-friendly format. Five penalty dimensions subtract from a starting 10.

### 🌐 Global posture score

```text
posture_score = max(
  10.0 − (p_comp + p_vuln + p_admin + p_alerts + p_secrets),
  0
)
```

Each `p_*` is a penalty that saturates — past the saturation point, more findings don't make it worse (there's no "−100 posture").

| Variable | Formula | Max penalty | Saturation point | What it measures |
|----------|---------|:-----------:|:----------------:|------------------|
| `p_comp` | `min(critical_compliance / 10, 1) × 1.5` | **1.5 pts** | 10 critical findings | Compliance violations |
| `p_vuln` | `min(critical_vulns / 15, 1) × 2.5` | **2.5 pts** | 15 critical CVEs | Vulnerability exposure |
| `p_admin` | `min(admin_no_mfa / 30, 1) × 2.5` | **2.5 pts** | 30 admins without MFA | Identity hygiene |
| `p_alerts` | `min(critical_alerts / 10, 1) × 1.5` | **1.5 pts** | 10 critical alerts | Active threats |
| `p_secrets` | `min(_sc / 3, 1) × 2.0` | **2.0 pts** | 3 risky secrets | Secret sprawl |
| **Total possible** | — | **10.0 pts** | — | Full penalty → score of `0` |

> 📐 **Weight distribution:** Vulnerabilities and identity (admin/MFA) carry the heaviest weight at 2.5 pts each, reflecting their outsized contribution to real-world breaches.

### ☁️ Per-CSP gauge scores (AWS / Azure / GCP)

Each cloud provider gets its own gauge, scored on only two inputs — compliance findings and admin MFA gaps — because those are the signals consistently available across CSPs.

```text
score_csp = max(
  10.0
  − (min(cc / 10, 1) × 6.0)       # compliance penalty, up to −6.0
  − (min(ac / 30, 1) × 4.0),      # admin-no-MFA penalty, up to −4.0
  0
)
```

- `cc` → critical compliance findings for that CSP
- `ac` → admin accounts without MFA for that CSP

### 🎨 Score labels & colors

| Score | Label | Color | Typical message |
|:-----:|-------|:-----:|-----------------|
| **≤ 3.0** | CRITICAL | 🔴 Red | Immediate action required |
| **3.1 – 5.0** | POOR | 🔴 Red | Major gaps across several dimensions |
| **5.1 – 6.0** | AT RISK | 🔴 Red | Notable exposure — prioritize remediation |
| **6.1 – 7.9** | MODERATE | 🔵 Blue | Workable posture with known weak spots |
| **8.0 – 8.9** | GOOD | 🟢 Green | Solid posture, minor polish needed |
| **≥ 9.0** | EXCELLENT | 🟢 Green | Best-practice posture |

### 🔐 `_sc` — risky secrets explained

The `_sc` counter only penalizes secrets stored in **insecure default locations** — places where `chmod 600` is *not* automatically applied.

| Path pattern | Counted in `_sc`? | Reason |
|-------------|:-----------------:|--------|
| `/var/…` | ✅ Yes | World-readable by default |
| `/tmp/…` | ✅ Yes | Ephemeral and shared |
| `C:\Users\Public\…` and similar Windows paths | ✅ Yes | Shared by default |
| `/home/…` | ❌ No | Per-user, restrictive umask |
| `/root/…` | ❌ No | Root-only access |
| `/etc/…` | ❌ No | Typically `chmod 600` for sensitive files |

> 💡 Secrets in "secure default" paths contribute `_sc = 0` — no penalty, even if they exist. The intent is to flag **misplacement**, not presence.

---

## 🧪 Worked examples

### Example A — Dashboard Risk Score

A tenant with:
- Top identity risk: `0.80` (Lacework 0–1 scale)
- Top CVE risk: `9.8` (CVSS)
- Critical alerts: `7`

```text
topIdent  = 0.80 × 100   = 80
topCve    = 9.8  × 10    = 98
alertPts  = min(7 × 3, 15) = 15

riskScore = round(80 × 0.60 + 98 × 0.25 + 15)
          = round(48 + 24.5 + 15)
          = 88  →  clamped to 88

posture % = 100 − 88 = 12%  →  Stage: 🔴 BUILDING
```

### Example B — CSA Posture Score

A tenant with:
- 4 critical compliance findings
- 20 critical CVEs
- 12 admins without MFA
- 2 critical alerts
- 1 risky secret

```text
p_comp    = min(4/10, 1)  × 1.5 = 0.60
p_vuln    = min(20/15, 1) × 2.5 = 2.50   (saturated)
p_admin   = min(12/30, 1) × 2.5 = 1.00
p_alerts  = min(2/10, 1)  × 1.5 = 0.30
p_secrets = min(1/3, 1)   × 2.0 = 0.67
total penalty                    = 5.07

posture_score = max(10.0 − 5.07, 0) = 4.93  →  POOR 🔴
```

### Example C — Per-CSP Gauge (AWS)

- `cc = 7` compliance findings
- `ac = 5` admins without MFA

```text
penalty = (min(7/10, 1) × 6.0) + (min(5/30, 1) × 4.0)
        = (0.7 × 6.0) + (0.167 × 4.0)
        = 4.2 + 0.67
        = 4.87

score_aws = max(10.0 − 4.87, 0) = 5.13  →  AT RISK 🔴
```

---

<div align="center">

[← Back to README](README.md) · [📝 Changelog](CHANGELOG.md) · [📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
