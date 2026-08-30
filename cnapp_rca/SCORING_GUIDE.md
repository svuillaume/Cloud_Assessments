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

All finding weights are drawn from one shared constants table, `SEVERITY_WEIGHTS = { critical:
100, high: 70, medium: 40, low: 10 }`, defined once in `server.js` and reused by the posture
score, the asset risk map, and the per-CSP score below — a "Critical" finding is worth the same
100 points everywhere in the tool, not a different number per formula.

| Finding type | Risk weight | Why |
|---|---|---|
| High-Fidelity Alert — Critical | `SEVERITY_WEIGHTS.critical` = 100 | Alerts are FortiCNAPP's AI-correlated, active-threat detections — already the highest-confidence signal in the tool, so severity still matters within that set |
| High-Fidelity Alert — High | `SEVERITY_WEIGHTS.high` = 70 | |
| High-Fidelity Alert — Medium | `SEVERITY_WEIGHTS.medium` = 40 | |
| CVE (Internet Threat Exposure) | `(cveRiskScore ?? riskScore) × 10` (max 100), **only if that value ≥ `HIGH_RISK_CVE_THRESHOLD` (9.85)** | Below-threshold CVEs are common and rarely represent a real, exploitable threat on their own — including them would dilute the score with noise. `cveRiskScore` is FortiCNAPP's own documented "Risk Score" (prevalence + CVSS + exploitability + exposure, not plain CVSS — see §1a below), preferred over the separate, less-trusted `riskScore` field wherever both exist. Scaling it ×10 turns FortiCNAPP's own composite judgment directly into the weight, per CVE |
| Critical Misconfiguration | `SEVERITY_WEIGHTS.critical` = 100 | Policy violations against CIS/NIST/SOC2-style benchmarks — a real control gap, but typically not an active attack in progress the way an Alert is |
| Identity — Admin **and** No-MFA **and** (unused entitlements ≥ 80% **or** an access key ≥ 180 days old) | 80 (a fixed value, not drawn from `SEVERITY_WEIGHTS`) | This is the identity most likely to actually get abused: a human admin account with no second factor, *and* either evidence it's stale (barely used, most of its permissions dormant) or evidence of poor credential hygiene (a long-lived, never-rotated key). Any one of unused-permissions-heavy or old-key is enough — both point at the same underlying problem, an account nobody is actively maintaining |
| Identity — everything else | `risk_score × 100` (max 100) | Falls back to FortiCNAPP's own CIEM risk score for service accounts, roles, MFA-protected users, and admins that don't meet the staleness/hygiene bar above |
| Secret (discovered credential) | `SEVERITY_WEIGHTS.low` = 10 | A discovered secret is a real finding, but on its own — unpaired with proof it's live, privileged, or reachable — it's the lowest-signal item in the pool. It still pulls the average down, just not as hard as an active alert or an admin account with no MFA |

Non-obvious effect worth knowing: because the score is a **mean**, changing any one weight
reshapes the whole average, not just how that finding type looks on its own. Raising Alert/
Compliance weights from their older values (80→100, 60→70) while keeping the CVE-inclusion floor
high (9.85, previously 8) pulls in opposite directions — heavier top-end weights push a typical
tenant's score *down*, a stricter CVE floor (fewer, lighter findings dragging the mean down)
pushes it *up*. The net effect depends on a given tenant's actual finding mix, so don't assume
either direction without recomputing. Scores shown in reports generated before vs. after a weight
change aren't directly comparable.

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

There used to be a scattered, independently-tuned mix of CVE cutoffs here (`riskScore ≥ 8` in one
place, `cveRiskScore ≥ 9` in another, `≥ 9.5` documented but `≥ 9.95` actually running in a third)
— they've since been unified onto one shared constant, `HIGH_RISK_CVE_THRESHOLD = 9.85`, defined
once in `server.js` and reused everywhere a "high-risk CVE" gate is needed. All of them now read
`cveRiskScore ?? riskScore ?? ...` — preferring `cveRiskScore`, FortiCNAPP's own documented,
console-matching **"Risk Score"** (an environment-specific *impact* score blending CVSS/CVE
severity with prevalence — number of hosts/images/packages affected — internet exposure, and
known/active exploit signals; see [Fortinet's own Risk Score
docs](https://docs.fortinet.com/document/forticnapp/latest/administration-guide/903844/risk-score)).
The plain `riskScore` field is a separate, less-trusted number on the same CVE record — empirically
not the same value (one live CVE sat at `cveRiskScore` 9.95 while its `riskScore` was only 6.3) —
used only as a fallback.

| Where | Threshold | Notes |
|---|---|---|
| **Posture score** (§1 above) | `cveRiskScore ?? riskScore ≥ 9.85` | Same shared constant as every row below now — previously its own separate, looser `riskScore ≥ 8` |
| **Private Host Most Exposed** panel | `cveRiskScore ?? riskScore ?? hostRiskScore ≥ 9.85` | Filtered client-side on top of the underlying fetch's own wider `cveRiskScore ≥ 8` API floor (a strict subset, so no extra API call needed) |
| **Risk Findings Inventory → Host Exposure** | `cveRiskScore ?? riskScore ≥ 9.85` | Sourced from a separate, fully-paginated fetch (`fetchHighRiskVulns()`, any severity) rather than the posture score's 500-row-capped pool, then further restricted to hosts also confirmed internet-exposed. Previously its own separate, tighter `≥ 9.95` |
| **Internet Exposed Resource** panel (formerly "Internet Exposed Host") | `path_score ≥ 40` | Not a CVE-risk-score threshold at all — this panel was reworked to list every resource FortiCNAPP's Attack Path engine (`LW_APA_ATTACK_PATHS`) has traced an Internet route to, with no severity/host-risk-score cutoff, and isn't restricted to compute hosts (S3 buckets and other resource types appear too). The old `hostRiskScore ≥ 7` "reproduce the console's Hosts query" mechanism this row used to describe no longer exists in the code |
| `buildReportHtml`'s report-only `critCnt`/"full system compromise" copy | `cveRiskScore ?? riskScore ≥ 9.95` (`MAX_SEVERITY_CVE_THRESHOLD`) | A second, deliberately *tighter* tier that stayed separate from 9.85 on purpose — collapsing it onto the shared threshold would make it equal every row already passing the report's own CVE-listing floor, erasing the "even more severe" distinction it exists for. `cveRiskScore` practically never reaches exactly 10 (observed max ≈ 9.98), so 9.95 stays a meaningful, reachable near-max cutoff |

The practical effect: because the posture score, Private Host Most Exposed, and Risk Findings
Inventory's Host Exposure category now all share the exact same `HIGH_RISK_CVE_THRESHOLD` on the
same preferred field, a CVE either clears all three at once or none of them — that "graduated
staircase" of slightly different cutoffs no longer exists between those three views. What still
differs between them is *scope*, not *threshold*: which pool of vulns each one starts from (the
500-row-capped fetch vs. the separate fully-paginated one), and which hosts/severities that pool
was filtered to before this CVE-level cutoff is applied. The Internet Exposed Resource panel is a
different kind of signal altogether — Attack Path traced-exploitability, not CVE severity — so it
was never part of this "staircase" to begin with, but the app still excludes any host qualifying
for it from the Private Host Most Exposed list, so the same host never appears as both "Private"
and "Internet Exposed" at once.

---

### 2. CSP Lab per-cloud scores

**What it is:** three separate 0–100 scores, one per cloud provider, plus a "Global" number that
averages them. Used in the Lab view to answer "which of my clouds is riskiest," not to drive the
main gauge.

**The logic — rate-based, not count-based.** Each cloud's findings (Alerts, Compliance,
Identities — CVEs and Secrets aren't tagged to a specific cloud by the API, so they're excluded
here) are sorted into four severity buckets: Critical, High, Medium, Low. The penalty is a
weighted average of each bucket's **share of that cloud's total findings**, not the raw count —
using the same shared `SEVERITY_WEIGHTS` table as the posture score above, not a separate scale:

```
penalty = SEVERITY_WEIGHTS.critical × (Critical / total)   // 100 × (Critical / total)
        + SEVERITY_WEIGHTS.high     × (High / total)       //  70 × (High / total)
        + SEVERITY_WEIGHTS.medium   × (Medium / total)     //  40 × (Medium / total)
        + SEVERITY_WEIGHTS.low      × (Low / total)        //  10 × (Low / total)

CSP score = max(0, round(100 − penalty))
```

This changed from an earlier, CSP-score-only 40/30/20/10 penalty scale that capped the maximum
possible penalty at 40 (so a cloud whose findings were 100% Critical still floored at score 60).
On the current shared 100/70/40/10 scale, penalty can reach 100, so **a cloud whose findings are
entirely Critical can now score as low as 0** — a real, larger swing than before, not just a
relabeling of the same numbers.

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

penalty = 100 × (2/27)  +  70 × (5/27)  +  40 × (20/27)  +  10 × (0/27)
        = 100 × 0.0741    +  70 × 0.1852   +  40 × 0.7407
        = 7.41              +  12.96          +  29.63
        = 50.00

AWS Score = max(0, round(100 − 50.00)) = 50
```

If Azure scores 85 and GCP scores 92:

```
Lab Global Score = round((50 + 85 + 92) / 3) = round(75.7) = 76  →  Amber border
```

Note this 85 is the **Lab's** global number — it is unrelated to the main dashboard's Cloud
Security Posture Score gauge, which is computed separately (see §1 above) from the full,
un-bucketed finding pool including CVEs and Secrets.

---

<div align="center">

[📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
