<div align="center">

# Cloud Security Posture Score — Scoring Guide

Both tools (Live Dashboard and CSA Report) share the same **Cloud Security Posture Score** model on a **0–100 scale** — **higher is better**.

</div>

---

## Score Bands

| Score (0–100) | Security Posture | Color |
|:-------------:|------------------|:-----:|
| 90 – 100 | Proactive Security | 🟢 Green |
| 60 – 89 | Some Attention Needed | 🟠 Orange |
| 0 – 59 | URGENT – Attention Needed | 🔴 Red |

### Guidance

- **Green (90–100)** — Very low risk exposure. Strong controls and mature security practices are in place.
- **Orange (60–89)** — Meaningful gaps exist. Prioritize remediation across affected categories.
- **Red (0–59)** — High risk exposure. Immediate, focused action is required to address critical findings.

> **Higher score = lower risk = better posture.** A score of 100 means no penalty-triggering findings. A score of 0 means all categories are fully saturated with critical findings.

---

## Formula

```
postureScore = max(0, round(100 − mean(findingRiskScores) − secretCount × 0.5))
```

Each active finding contributes a **risk weight** to the mean pool. Secrets are treated separately — they apply a **−0.5 pt penalty per detected secret** on top of the mean, so they always reduce the score regardless of the existing finding pool size.

| Category | Risk Weight / Penalty | Notes |
|----------|:---------------------:|-------|
| Critical Alerts | 95 (in mean) | Open, unresolved critical alerts |
| Critical CVEs | `riskScore × 10` (max 100, in mean) | CVEs with risk score ≥ 9.0 |
| Compliance Violations | 80 (in mean) | Critical control violations |
| Identity Risk | `risk_score × 100` (max 100, in mean) | Admin identities with MFA gaps |
| Secrets | **−0.5 pts each** (outside mean) | Each secret detected via `LW_HE_SECRETS_ALL` |

---

## Worked Example

A tenant with 3 alerts, 5 CVEs (avg risk score 9.5), 4 compliance violations, 2 risky identities (risk_score 0.8), and 6 discovered secrets:

```
findings = [
  95, 95, 95,           // 3 alerts → weight 95 each
  95, 95, 95, 95, 95,   // 5 CVEs at riskScore 9.5 → 9.5×10 = 95
  80, 80, 80, 80,       // 4 compliance violations → weight 80 each
  80, 80                // 2 identities at risk_score 0.8 → 0.8×100 = 80
]

mean = (8×95 + 6×80) / 14
     = (760 + 480) / 14
     = 1240 / 14 ≈ 88.6

secretPenalty = 6 × 0.5 = 3.0

postureScore = round(100 − 88.6 − 3.0) = round(8.4) = 8   → 🔴 URGENT – Attention Needed
```

---

## Dashboard Gauge

The **Cloud Security Posture Score** gauge is a 180° gradient arc on the overview panel:

- Arc fills left to right as score increases — **red → orange → green**
- Gradient band boundaries: score 60 (65.4% of arc width) and score 90 (97.5%)
- White tick marks at **60** and **90** separate the colour bands
- Scale labels **0** and **100** appear at the arc endpoints
- The large score number in the centre updates colour with the band

---

<div align="center">

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
