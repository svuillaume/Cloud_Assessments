<div align="center">

# Cloud Security Posture Score — Scoring Guide

</div>

---

## Plain English: What, How, and Why

### There are two scores in this tool — don't confuse them

- **Cloud Security Posture Score** — the main gauge on the dashboard and the number shown in
  generated reports. It's a straight **average of every individual finding's risk weight**
  across Alerts, CVEs, Compliance, Identities, and Secrets — one flat pool, no per-cloud
  grouping.
- **CSP Lab per-cloud scores** — a separate comparison view (AWS / Azure / GCP tabs) used to
  see *where* risk concentrates. Each cloud gets its own score from its own findings, and the
  Lab's "Global" number is the plain average of those three — it is **not** the same number as
  the main Posture Score gauge, and the two will often disagree (that's expected — they measure
  different things).

This guide covers both, in the order you'd actually look at them.

---

### 1. Cloud Security Posture Score (the main gauge)

**What it is:** one number, 0–100, higher is better. It's the average "badness" of every open
finding, inverted — no findings at all means a perfect 100.

**The logic:** every finding gets a fixed risk weight based on *what kind of finding it is and
how severe it is*, not a raw count. Averaging (rather than summing) means the score reflects the
overall mix of your findings, not just how many there are — a tenant with 3 findings and a tenant
with 300 findings of the same severity mix land at the same score.

```
postureScore = max(0, round(100 − mean(findingRiskScores)))
```

| Finding type | Risk weight | Why |
|---|---|---|
| High-Fidelity Alert — Critical | 80 | Alerts are FortiCNAPP's AI-correlated, active-threat detections — already the highest-confidence signal in the tool, so severity still matters within that set |
| High-Fidelity Alert — High | 60 | |
| High-Fidelity Alert — Medium | 40 | |
| CVE (Internet Threat Exposure) | `riskScore × 10` (max 100), **only CVEs with `riskScore ≥ 8`** | Below-8 CVEs are common and rarely represent a real, exploitable threat on their own — including them would dilute the score with noise. `riskScore` already blends CVSS severity with exploitability and network exposure, so scaling it ×10 turns FortiCNAPP's own composite judgment directly into the weight, per CVE |
| Critical Misconfiguration | 80 | Policy violations against CIS/NIST/SOC2-style benchmarks — a real control gap, but typically not an active attack in progress the way an Alert is |
| Identity — Admin **and** No-MFA **and** (unused entitlements ≥ 80% **or** an access key ≥ 180 days old) | 80 | This is the identity most likely to actually get abused: a human admin account with no second factor, *and* either evidence it's stale (barely used, most of its permissions dormant) or evidence of poor credential hygiene (a long-lived, never-rotated key). Any one of unused-permissions-heavy or old-key is enough — both point at the same underlying problem, an account nobody is actively maintaining |
| Identity — everything else | `risk_score × 100` (max 100) | Falls back to FortiCNAPP's own CIEM risk score for service accounts, roles, MFA-protected users, and admins that don't meet the staleness/hygiene bar above |
| Secret (discovered credential) | 10 | A discovered secret is a real finding, but on its own — unpaired with proof it's live, privileged, or reachable — it's the lowest-signal item in the pool. It still pulls the average down, just not as hard as an active alert or an admin account with no MFA |

Non-obvious effect worth knowing: because the score is a **mean**, changing any one weight
(as above) doesn't just change how that finding type looks — it reshapes the whole average.
Lowering Secrets from their old value and gating CVEs at `riskScore ≥ 8` both push the typical
tenant's score *up*, since fewer/lighter findings are dragging the mean down. That's an intended
consequence of this weighting, not a bug — but it does mean scores shown in reports generated
before vs. after this change aren't directly comparable.

#### Score bands

| Score | Security Posture | Colour | Meaning |
|:-----:|-----------------|:------:|---------|
| 90 – 100 | Proactive Security | Green | Strong controls. Low risk. Findings are informational or in active remediation. |
| 50 – 89 | Some Attention Needed | Amber | Real gaps exist. Prioritise remediation — especially any Critical or High findings. |
| 0 – 49 | URGENT | Red | High risk exposure. Immediate, focused action required. |

> On-screen, this is the gauge labeled **"Cloud Security Risk Score"** at the top of the
> Overview page — same number, same formula, just the display name shown to a reader.

---

### 1a. CVE and host-risk thresholds — don't confuse them either

Findings get filtered at several different, independently-tuned cutoffs across the tool. Each one
exists for a different purpose, and they intentionally disagree with each other — some are
per-*CVE* thresholds, one is a per-*host* threshold:

| Where | Threshold | Field | Why this cutoff |
|---|---|---|---|
| **Posture score** (§1 above) | `riskScore ≥ 8` | `riskScore` (host-composite metric, can vary per host for the same CVE) | The score's own weighting formula — below-8 CVEs are common and rarely represent a real, standalone exploitable threat, so they're excluded to avoid diluting the mean |
| **Private Host Most Exposed** panel | `cveRiskScore ≥ 9` | `cveRiskScore` (the CVE's own intrinsic severity — consistent across every host it appears on) | A tighter, panel-specific view of only the highest-severity CVEs on a given host, filtered client-side on top of the posture score's already-fetched ≥8 pool (9 is a strict subset, so no extra API call is needed) |
| **Internet Exposed Host** panel | `hostRiskScore ≥ 7` — a **host**-level threshold, not a CVE one | `hostRiskScore` (Lacework's composite per-machine score) | Deliberately reproduces the FortiCNAPP console's own "Hosts" query (`Risk score ≥ 7` · `Internet exposed = True` · `Machine status Online/Launched` · has a Vulnerable-status observation) rather than this app's usual CVE-level cutoffs — it's a side-by-side comparison view, not a variant of the other two rows. Also uses Lacework's *raw* `lw_InternetExposureRaw` exposure tag, not the app's stricter verified signal every other panel uses |
| **Risk Findings Inventory → Host Exposure** | `cveRiskScore ≥ 9.95` | `cveRiskScore` | The tightest cut — only CVEs whose *displayed* risk score (`Math.round(cveRiskScore × 10)`) reads a full **100**. In live data, `cveRiskScore` never actually reaches the raw scale's true max of 10 (observed max ≈ 9.98), so an exact `=== 10` filter would silently return zero rows; 9.95 is the correct cutoff where the rounded display hits 100. Sourced from a separate, fully-paginated fetch (`fetchHighRiskVulns()`, any severity) rather than the posture score's 500-row-capped pool, then further restricted to hosts also confirmed internet-exposed (via the app's verified signal, not the raw one) |

The practical effect: a CVE can appear in the posture score's pool without showing up in Private
Host Most Exposed, and can appear there without qualifying for the Risk Findings Inventory's Host
Exposure count. That's by design — each view answers a narrower question than the last. Because
Private Host Most Exposed and Internet Exposed Host use different exposure definitions (verified
vs. raw), the app explicitly excludes any host qualifying for Internet Exposed Host from the
Private list too, so the same host never appears as both "Private" and "Internet Exposed" at once.

---

### 2. CSP Lab per-cloud scores

**What it is:** three separate 0–100 scores, one per cloud provider, plus a "Global" number that
averages them. Used in the Lab view to answer "which of my clouds is riskiest," not to drive the
main gauge.

**The logic — rate-based, not count-based.** Each cloud's findings (Alerts, Compliance,
Identities — CVEs and Secrets aren't tagged to a specific cloud by the API, so they're excluded
here) are sorted into four severity buckets: Critical, High, Medium, Low. The penalty is a
weighted average of each bucket's **share of that cloud's total findings**, not the raw count:

```
penalty = 40 × (Critical / total)
        + 30 × (High / total)
        + 20 × (Medium / total)
        + 10 × (Low / total)

CSP score = max(0, round(100 − penalty))
```

**Why rate-based:** a cloud with far more inventory (say AWS with 233 identities vs. Azure's 30)
shouldn't be penalized just for having more assets to find things in — only a genuinely worse
*ratio* of critical/high findings should lower the score. Counting raw findings would make a big,
well-instrumented AWS account look artificially riskier than a small, under-scanned Azure account
purely because more of its surface area gets looked at.

**Bucket assignment:**

| Finding | Bucket rule |
|---|---|
| Alert — Critical | → Critical |
| Alert — High | → High |
| Alert — Medium | → Medium |
| Compliance violation — Critical severity | → Critical |
| Compliance violation — High (or any non-Critical) severity | → High |
| Identity — Admin + No-MFA + (unused ≥ 80% or key ≥ 180d old), or `identityRiskScore ≥ 80` | → Critical |
| Identity — `identityRiskScore ≥ 50` | → High |
| Identity — `identityRiskScore ≥ 20` | → Medium |
| Identity — `identityRiskScore < 20` | → Low |

> CVEs and Secrets are not included in the per-CSP score because the FortiCNAPP API does not tag
> them to a specific cloud provider. They appear in the global findings panels and drive the main
> Posture Score, but not the CSP Lab gauges.

**Global (Lab) score:**

```
Global Score = round((AWS Score + Azure Score + GCP Score) / 3)
```

Each cloud with zero findings contributes a perfect 100 to the average.

### Alert Query (High-Fidelity Filter)

Only alerts that meet **all** of the following criteria are counted, anywhere in the tool:

| Filter | Value |
|--------|-------|
| Severity | Critical, High, or Medium |
| Category | Anomaly or Composite |
| Status | Open or In Progress |
| Look-back window | 21 days (split into 7-day API chunks) |

Anomaly and Composite are FortiCNAPP's AI-generated alert categories — they represent
machine-learning detections and correlated attack patterns, not simple policy checks. This filter
removes noise and surfaces only the findings that indicate real, active threats.

### Worked Example — CSP Lab per-cloud score

**Environment:** AWS with 2 Critical alerts, 5 High compliance violations, 20 Medium identity
risks (27 findings total, none Low).

```
C = 2   H = 5   M = 20   L = 0   total = 27

penalty = 40 × (2/27)  +  30 × (5/27)  +  20 × (20/27)  +  10 × (0/27)
        = 40 × 0.0741   +  30 × 0.1852   +  20 × 0.7407
        = 2.96           +  5.56           +  14.81
        = 23.33

AWS Score = max(0, round(100 − 23.33)) = 77
```

If Azure scores 85 and GCP scores 92:

```
Lab Global Score = round((77 + 85 + 92) / 3) = round(84.7) = 85  →  Amber-to-Green border
```

Note this 85 is the **Lab's** global number — it is unrelated to the main dashboard's Cloud
Security Posture Score gauge, which is computed separately (see §1 above) from the full,
un-bucketed finding pool including CVEs and Secrets.

---

<div align="center">

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
