<div align="center">

# Cloud Security Posture Score — Scoring Guide

</div>

---

## Plain English: What, How, and Why

### What is the score?

Every cloud environment assessed by this tool receives a single number between **0 and 100**.

**Higher is better.** A score of 100 means no security issues were detected. A score of 0 means the environment is saturated with critical problems across every category. Most real-world environments sit somewhere in the middle.

Think of it like a health check-up result — it gives you one clear number to share with leadership, and then the dashboard lets you drill into exactly where the problems are.

---

### How is it calculated?

The score is built in two steps.

**Step 1 — One score per cloud provider (AWS, Azure, GCP)**

For each cloud, we look at three types of security findings:

- **High-Fidelity Alerts** — real-time threats detected by FortiCNAPP's AI engine (anomaly detection and correlated attack patterns)
- **Compliance Violations** — cloud configuration rules that are failing against industry benchmarks (CIS, NIST, SOC 2, etc.)
- **Identity Risks** — cloud accounts and roles that have excessive permissions or signs of misuse

Each finding is sorted into one of four severity buckets: **Critical**, **High**, **Medium**, or **Low**.

The score penalty works like this — each bucket has a maximum amount it can deduct from 100:

| Severity | Max deduction | Real-world meaning |
|----------|:------------:|-------------------|
| Critical | 40 points | Immediate threat — active attack path, authentication bypass, root-level exposure |
| High | 30 points | Serious gap — exploitable misconfiguration, privileged identity at risk |
| Medium | 20 points | Needs attention — policy drift, over-permissioned role, unreviewed access |
| Low | 10 points | Informational — best-practice deviation, minor hygiene issue |

The key insight is that the penalty grows **logarithmically**, not linearly. This means:

- The **1st** critical finding hurts your score more than the **10th** one does.
- A large volume of low-priority findings does not make your score collapse if your critical issues are clean.
- This reflects how risk actually works in operations: once you know about a class of problem, each additional instance adds less new risk than the first one did.

**Step 2 — One global score**

The global score displayed on the main gauge is the straight average of the three cloud scores:

```
Global Score = (AWS Score + Azure Score + GCP Score) / 3
```

If a cloud has no findings at all, it contributes a perfect 100 to the average.

---

### Why does it work this way?

**The old approach had a real problem.**

Traditional scoring takes every finding, assigns it a weight (e.g. 95 for critical, 80 for compliance), and averages them all together. The result: one critical alert in a 5,000-asset environment scores exactly the same as one critical alert in a 10-asset environment. That is not realistic, and it leads to two bad outcomes:

1. **Score shock** — a single finding drops a large, mostly clean environment from 100 to 5. Security teams lose confidence in the number.
2. **Alert fatigue** — a flood of low-priority items tanks the score even when nothing truly dangerous is happening, making it hard to see what matters.

**The new model fixes both problems.**

- **Severity buckets** ensure a critical issue always weighs more than a medium one — they are never mixed together in a way that lets one cancel out the other.
- **Logarithmic scaling** means volume does not punish you unfairly. Ten medium findings are worse than one, but not ten times worse.
- **Per-cloud scoring first** means your AWS score reflects your AWS risk, not a diluted blend of all three clouds. If Azure is clean but AWS has issues, that shows clearly.
- **The score stays meaningful** — a score of 88 with one unresolved critical alert is a useful, actionable number. A score of 5 for the same situation is demoralizing and stops being useful as a communication tool.

---

## Score Bands

| Score | Security Posture | Colour | Meaning |
|:-----:|-----------------|:------:|---------|
| 90 – 100 | Proactive Security | Green | Strong controls. Low risk. Findings are informational or in active remediation. |
| 50 – 89 | Some Attention Needed | Amber | Real gaps exist. Prioritise remediation — especially any Critical or High findings. |
| 0 – 49 | URGENT | Red | High risk exposure. Immediate, focused action required. |

---

## Technical Reference

### Per-CSP Score Formula

```
penalty = 40 × log₁₁(1 + C)
        + 30 × log₁₁(1 + H)
        + 20 × log₁₁(1 + M)
        + 10 × log₁₁(1 + L)

CSP score = max(0, round(100 − min(100, penalty)))
```

Where `log₁₁(x) = ln(x) / ln(11)` and C / H / M / L are finding counts per severity bucket.

**Bucket assignment:**

| Finding | Bucket rule |
|---------|------------|
| Alert — Critical | → C |
| Alert — High | → H |
| Compliance violation — Critical severity | → C |
| Compliance violation — High severity | → H |
| Identity — `risk_score ≥ 0.80` | → C |
| Identity — `risk_score ≥ 0.50` | → H |
| Identity — `risk_score ≥ 0.20` | → M |
| Identity — `risk_score < 0.20` | → L |

> CVEs (vulnerabilities) and Secrets are not included in the per-CSP score because the FortiCNAPP API does not tag them to a specific cloud provider. They appear in the global findings panels but do not contribute to the CSP gauge scores.

### Alert Query (High-Fidelity Filter)

Only alerts that meet **all** of the following criteria are counted:

| Filter | Value |
|--------|-------|
| Severity | Critical or High |
| Category | Anomaly or Composite |
| Status | Open or In Progress |
| Look-back window | 21 days (split into 7-day API chunks) |

Anomaly and Composite are FortiCNAPP's AI-generated alert categories — they represent machine-learning detections and correlated attack patterns, not simple policy checks. This filter removes noise and surfaces only the findings that indicate real, active threats.

### Global Score Formula

```
Global Score = round((AWS Score + Azure Score + GCP Score) / 3)
```

Each cloud with zero findings contributes 100 to the average.

### Worked Example

**Environment:** AWS with 2 Critical alerts, 5 High compliance violations, 20 Medium identity risks.

```
C = 2   H = 5   M = 20   L = 0

penalty = 40 × log₁₁(3)  +  30 × log₁₁(6)  +  20 × log₁₁(21)  +  0
        = 40 × 0.458      +  30 × 0.748      +  20 × 1.326
        = 18.3            +  22.4            +  26.5
        = 67.2

AWS Score = round(100 − 67.2) = 33
```

If Azure scores 85 and GCP scores 92:

```
Global Score = round((33 + 85 + 92) / 3) = round(70) = 70  →  Amber
```

---

<div align="center">

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
