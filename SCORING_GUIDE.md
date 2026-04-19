# Scoring & Gauge Calculation Guide

This document explains every variable, formula, and threshold used to produce the
security posture scores displayed in the CSA Detailed Report.

---

## 1. Global Cloud Security Posture Score

**Range:** 0 – 10  
**Displayed on:** Risk Summary section

The score starts at **10.0** (perfect posture) and subtracts a **penalty** for each
risk domain. Each domain penalty is capped at its maximum weight so that a single
catastrophic domain cannot push the score below zero.

```
posture_score = max(10.0 − (p_comp + p_vuln + p_admin + p_alerts + p_secrets), 0)
```

### Penalty components

| Variable | Formula | Max penalty | Saturation point |
|---|---|---|---|
| `p_comp` | `min(critical_compliance / 10, 1) × 1.5` | 1.5 pts | 10 critical findings |
| `p_vuln` | `min(critical_vulns / 15, 1) × 2.5` | 2.5 pts | 15 critical CVEs |
| `p_admin` | `min(admin_no_mfa / 30, 1) × 2.5` | 2.5 pts | 30 admin identities without MFA |
| `p_alerts` | `min(critical_alerts / 10, 1) × 1.5` | 1.5 pts | 10 critical behavioral alerts |
| `p_secrets` | `min(_sc / 3, 1) × 2.0` | 2.0 pts | 3 risky secrets |
| **Total max penalty** | | **10.0 pts** | |

### Data sources

| Signal | Source |
|---|---|
| `critical_compliance` | Sum of critical findings across all CSPs from FortiCNAPP CSPM |
| `critical_vulns` | Combined host + container CVEs with Risk Score ≥ 9 |
| `admin_no_mfa` | `total_admin.val` — identities with admin privileges and no MFA |
| `critical_alerts` | `alerts_data.high_critical_finding_count` |
| `_sc` | `secrets_data.risky_secrets_count` — see Section 3 |

---

## 2. Per-CSP Gauge Scores (AWS / Azure / GCP)

**Range:** 0 – 10  
**Displayed on:** Assessment section, three side-by-side gauges

Each cloud provider gets its own score using only signals available
**per provider**: compliance findings and CIEM admin-without-MFA count.
Vulnerabilities and alerts are not split by provider in the current data model.

```
score_csp = max(10.0 − (min(cc / 10, 1) × 6.0) − (min(ac / 30, 1) × 4.0), 0)
```

| Variable | Meaning | Max penalty | Saturates at |
|---|---|---|---|
| `cc` | Critical compliance findings for that CSP | 6.0 pts | 10 findings |
| `ac` | Admin identities without MFA for that CSP (`ciem_data[CSP].root_count`) | 4.0 pts | 30 accounts |

### Cover page circle score

The cover page circle shows **`avg_csp_score`** — the straight average of the
three per-CSP gauge scores:

```
avg_csp_score = (score_aws + score_azure + score_gcp) / 3.0
```

This keeps the headline number visually consistent with the three gauges shown
directly below it on the cover.

---

## 3. `_sc` — Risky Secrets Count

`_sc` is **not** the total number of secrets detected. It is the count of secrets
found in file paths where `chmod 600` (owner read-only) is **not** the strong
default — i.e., locations where the file may be world-readable or group-readable.

### Classification logic (`secrets.py → _is_secure_default`)

| Path pattern | Secure default? | Included in `_sc`? |
|---|---|---|
| `/home/…` | Yes — owner:owner 600 | **No** |
| `/root/…` | Yes — root:root 600 | **No** |
| `/etc/…` | Yes — root:root 600 | **No** |
| `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.crt` | Yes — 600 (key/cert standard) | **No** |
| Any other Linux/Unix path | Yes — 600 is the recommended default | **No** |
| `/var/…` | No — 640 minimum (group-readable) | **Yes** |
| `/tmp/…` | No — world-readable (777) | **Yes** |
| Windows paths (`C:\…`, `\\…`) | No — no chmod concept; ACL must be audited | **Yes** |

> **Key rule:** `_sc = 0` whenever all detected secrets reside in chmod ≤ 600
> locations. In that case `p_secrets = 0` and secrets contribute **zero penalty**
> to the gauge.

### Effect on the report

| `_sc` value | Effect |
|---|---|
| `_sc == 0` | Secrets excluded from gauge penalty. TOC card hidden. Risk chart bar hidden. Section summary shows **"✓ No risk exposure — files are owner read-only"**. No badge in product recommendations. |
| `_sc > 0` | Gauge penalised (up to −2.0 pts). TOC card shown. Bar visible in Risk Summary chart. Urgent rotation message displayed. Badge shown in product recommendations. |

---

## 4. Gauge Colour Thresholds

### Per-CSP gauge labels

| Score | Label | Colour |
|---|---|---|
| ≤ 3.0 | CRITICAL | Red `#DA291C` |
| 3.1 – 5.0 | POOR | Red `#DA291C` |
| 5.1 – 6.0 | AT RISK | Red `#DA291C` |
| 6.1 – 7.9 | MODERATE | Blue `#2563EB` |
| 8.0 – 8.9 | GOOD | Green `#1E7A3E` |
| ≥ 9.0 | EXCELLENT | Green `#1E7A3E` |

### Global posture score labels

| Score | Label |
|---|---|
| < 3.0 | VERY POOR |
| 3.0 – 4.9 | POOR |
| 5.0 – 6.9 | MODERATE |
| 7.0 – 8.9 | GOOD |
| ≥ 9.0 | EXCELLENT |

---

## 5. Alert Risk Classification

When a **bad host** (IP address or domain name) is detected in an alert, a **Risk**
badge is shown in the Top Critical Alerts table. The badge is derived from the
`alertType` field using the following mapping:

### Bad host detection

1. `alertInfo.subject` — used first (Lacework sets this to the primary entity for network alerts)
2. Pattern `bad host <X> at` parsed from `alertInfo.description`
3. Any IPv4 address found in the description text (fallback)

If no host is found, the Risk column shows `—`.

### Risk categories

| Badge | Colour | Alert types included | Meaning |
|---|---|---|---|
| **Malicious** | Red | Bad IP/DNS connections, suspicious logins from bad sources, malicious files, privilege escalation, unauthorized API calls | Active attacker or known-bad infrastructure |
| **Negligent** | Orange | MFA-less logins, root account usage, CloudTrail disabled, open S3 ACLs, IAM policy changes, KMS key destroyed | Misconfig or weak security controls |
| **Unauthorized** | Purple | New services, new regions, new cloud accounts, new users, new external connections, new storage buckets | Shadow IT or unsanctioned cloud activity |

Full `alertType → Risk` mapping is in `modules/alerts.py → _RISK_MAP`.

---

## 6. SSH Key Type — Risk Classification

The secrets table colour-codes rows by SSH key algorithm:

| Key type | Row colour | Meaning |
|---|---|---|
| `ssh-rsa` | Red | Legacy RSA — susceptible to timing attacks; upgrade required |
| `rsa-sha2-256` | Green | RSA with SHA-256 — acceptable but RSA key rotation still recommended |
| All others (`ssh-ed25519`, `ecdsa-sha2-*`, etc.) | No highlight | Modern algorithm — no immediate action required |

When a row is `ssh-rsa`, the **Recommendation** column reads:
> *Upgrade to ssh-ed25519 — stronger, faster, and immune to RSA timing attacks*

---

## 7. CSP Inference for Secrets

Because the `LW_HE_SECRETS_SSH_PRIVATE_KEYS` data source only returns
`HOSTNAME`, `FILE_PATH`, and `SSH_KEY_TYPE`, the cloud provider is **inferred**
from the hostname using pattern matching (`secrets.py → _infer_csp`):

| Pattern | Inferred CSP |
|---|---|
| Starts with `ip-` · matches `i-[0-9a-f]{8,17}` · contains `ec2`, `aws`, `amazon` | AWS |
| Contains `azure`, ends with `-vm`, contains `azurevm` or `msft` | Azure |
| Contains `gcp`, `google` · matches `instance-[0-9]…` | GCP |
| No match | Unknown |

This is best-effort. Where hostname naming conventions differ from cloud defaults,
the CSP column may show *Unknown*.

---

## 8. Worked Example

**Environment:**
- 12 critical compliance findings (AWS: 8, Azure: 3, GCP: 1)
- 20 critical CVEs (Risk Score ≥ 9)
- 6 admin identities without MFA (AWS: 4, Azure: 2, GCP: 0)
- 5 critical behavioral alerts
- 8 secrets found, all in `/home/` and `/etc/` (chmod 600 standard) → `_sc = 0`

**Global posture score:**
```
p_comp    = min(12/10, 1) × 1.5 = 1.0 × 1.5 = 1.50
p_vuln    = min(20/15, 1) × 2.5 = 1.0 × 2.5 = 2.50
p_admin   = min(6/30,  1) × 2.5 = 0.2 × 2.5 = 0.50
p_alerts  = min(5/10,  1) × 1.5 = 0.5 × 1.5 = 0.75
p_secrets = min(0/3,   1) × 2.0 = 0.0 × 2.0 = 0.00  ← secrets excluded

posture_score = 10.0 − (1.50 + 2.50 + 0.50 + 0.75 + 0.00) = 4.75  → POOR (red)
```

**Per-CSP scores:**
```
score_aws   = 10.0 − min(8/10,  1)×6.0 − min(4/30, 1)×4.0
            = 10.0 − 4.80 − 0.53 = 4.67  → POOR (red)

score_azure = 10.0 − min(3/10,  1)×6.0 − min(2/30, 1)×4.0
            = 10.0 − 1.80 − 0.27 = 7.93  → MODERATE (blue)

score_gcp   = 10.0 − min(1/10,  1)×6.0 − min(0/30, 1)×4.0
            = 10.0 − 0.60 − 0.00 = 9.40  → EXCELLENT (green)
```

**MultiCloud cover score:**
```
avg_csp_score = (4.67 + 7.93 + 9.40) / 3.0 = 7.33  → GOOD (green)
```
