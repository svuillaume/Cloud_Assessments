<div align="center">

# Fortinet Cloud Risk IQ — Scoring Guide

Both tools (Live Dashboard and CSA Report) share the same **Fortinet Cloud Risk IQ** model on a **0–100 risk scale** — **lower is better**.

</div>

---

## Risk Score Model

| Score (0–100) | Security Posture | Color |
|:-------------:|------------------|:-----:|
| 0 – 19 | Proactive Security | 🟢 Green |
| 20 – 49 | Progressing Cloud Security Posture | 🔵 Blue |
| 50 – 79 | Some Attention Needed | 🟠 Orange |
| 80 – 100 | Immediate Attention Needed | 🔴 Red |

### Guidance

- **Green** — Very low risk exposure. Strong controls and mature security practices are in place.
- **Blue** — Moderate risk. Improvements are underway; continue reducing exposure.
- **Orange** — Meaningful gaps exist. Prioritize remediation across affected categories.
- **Red** — High risk exposure. Immediate focus is required to address critical findings.

> 📐 **Lower score = less risk = better posture.** A score of 0 means no penalty-triggering findings. A score of 100 means all inputs are fully saturated.

---

## Formula

```
penalty = min(vulns   / 15, 1) × 2.5
        + min(cvss10  / 10, 1) × 1.5
        + min(admins  / 30, 1) × 2.5
        + min(alerts  / 10, 1) × 1.5
        + min(comp    / 10, 1) × 1.0

score = round( (penalty / 9) × 100 )
```

Each category contributes independently. The total max penalty is **9.0**, mapping to a score of **100** (worst case).

| Input | Description | Saturates at | Max deduction |
|-------|-------------|:------------:|:-------------:|
| Critical vulns | CVEs with risk score ≥ 9.0 | 15 | 2.5 |
| Critical CVSS 10 | Subset with risk score = 10.0 | 10 | 1.5 |
| Admins without MFA | Admin identities — no MFA enabled | 30 | 2.5 |
| Critical alerts | Open, unresolved critical alerts | 10 | 1.5 |
| Non-compliance | Critical compliance control violations | 10 | 1.0 |

---

## Worked Example

A tenant with 10 critical CVEs (2 at CVSS 10), 5 admins without MFA, 3 alerts, 4 compliance violations:

```
p_vulns   = min(10/15, 1) × 2.5  = 0.667 × 2.5 = 1.67
p_cvss10  = min( 2/10, 1) × 1.5  = 0.200 × 1.5 = 0.30
p_admins  = min( 5/30, 1) × 2.5  = 0.167 × 2.5 = 0.42
p_alerts  = min( 3/10, 1) × 1.5  = 0.300 × 1.5 = 0.45
p_comp    = min( 4/10, 1) × 1.0  = 0.400 × 1.0 = 0.40
                                               ──────
                              total penalty  = 3.24

score = round((3.24 / 9) × 100) = round(36.0) = 36
        → 🔵 Progressing Cloud Security Posture (20–49)
```

---

## Dashboard Gauge

The **Fortinet Cloud Risk IQ** gauge is a 270° gradient arc displayed on the overview panel:

- Arc goes from **green** (left, score = 0) through yellow and orange to **red** (right, score = 100)
- A dark needle points to the current score position on the arc
- Boundary labels appear at **0 / 20 / 50 / 80 / 100**
- The band label below the gauge updates with the score color

---

<div align="center">

[← Back to README](README.md) · [📝 Changelog](CHANGELOG.md) · [📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
