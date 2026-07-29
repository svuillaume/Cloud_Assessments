# Risk Findings Weighting Revision — Design

**Date:** 2026-07-28
**Component:** `cnapp_rca/rca_ui/server.js`
**Status:** Approved by user, ready for implementation plan

## Background

The dashboard's "Risk Findings Inventory" panel (`renderRiskFindings()`, server.js:4448) and the
Cloud Security Posture Score (`calcPostureScore()`, server.js:4435) both assign a 0–100 risk
weight to every finding, grouped into five types: Alerts, CVEs (Host Exposure), Identities,
Compliance, Secrets. Today these weights are mostly flat, type-level constants:

| Group | Current weight |
|---|---|
| High Fidelity Alerts | flat 95 |
| Host Exposure (CVEs) | `riskScore × 10`, uncapped filter (all CVEs counted) |
| Identities | `METRICS.risk_score × 100` (raw FortiCNAPP CIEM score) |
| Critical Misconfigurations | flat 80 |
| Secrets Detected | flat 90 in the table / flat 75 in the posture score (pre-existing inconsistency, noted separately) |

This spec revises four of the five groups (Compliance is untouched) to weight findings more
specifically by real risk signals, replacing several flat constants with severity-tiered or
condition-based values.

## New Weight Rules

| Group | New weight |
|---|---|
| Secrets Detected | flat **10** (both the table and the posture score use this same value — removes the existing 90-vs-75 inconsistency) |
| High Fidelity Alerts | **CRITICAL = 80, HIGH = 60, MEDIUM = 40**, read from `r.severity` (case-insensitive) |
| Host Exposure (CVEs) | `riskScore × 10`, but **only for CVEs with `riskScore ≥ 8`** — CVEs below 8 are excluded from this finding group entirely (not shown, not counted, not scored) |
| Identities | If the identity is an **Admin** (`isHighPermissive(r)`, and not a service account or IAM role) **and has No-MFA**, **and** either **unused entitlements ≥ 80%** (`unusedPctOf(r) >= 80`) **or** **has an access key ≥ 180 days old** (see below) → flat **80**. Otherwise, falls back to the existing `min(100, METRICS.risk_score × 100)` formula. |
| Critical Misconfigurations | unchanged, flat 80 |

### Identity classification helpers

Reuses/extracts the classification pattern that already exists (duplicated) inside
`buildReportHtml2()` at server.js:7881-7902 and server.js:8262-8283:

```js
function isServiceAccount(r) { /* existing pattern, see server.js:7881 */ }
function isRoleType(r)       { /* existing pattern, see server.js:7885 */ }
function isHighPermissive(r) { /* existing pattern, see server.js:7895 */ }
function isNoMfa(r)          { /* existing pattern, see server.js:7900 */ }
function unusedPctOf(r)      { /* existing pattern, see server.js:7889 */ }

function isOldAccessKey(r, thresholdDays = 180) {
  // Field name TBD — see "Open verification item" below.
  return (r.ACCESS_KEYS || []).some(k => {
    const created = k && k.<TBD_FIELD_NAME>;
    if (!created) return false;
    const ageDays = (Date.now() - new Date(created).getTime()) / 86400000;
    return ageDays >= thresholdDays;
  });
}

function isAdminNoMfaIdentity(r) {
  return !isServiceAccount(r) && !isRoleType(r) && isHighPermissive(r) && isNoMfa(r);
}

function identityRiskScore(r) {
  const qualifies = isAdminNoMfaIdentity(r) && (unusedPctOf(r) >= 80 || isOldAccessKey(r));
  return qualifies ? 80 : Math.min(100, (r.METRICS?.risk_score || 0) * 100);
}
```

### Open verification item — access key age field

No field name for an access key's creation/rotation date is documented anywhere in this
codebase, and there is no mock data file (`MOCK_FILE`) in this checkout to inspect real
`ACCESS_KEYS[]` payloads. **Before wiring `isOldAccessKey()`, the implementation must verify the
real field name** — either against a live FortiCNAPP account (open an identity's detail drawer in
the running dashboard, which prints every raw key on an access key generically, server.js:5855-5864)
or a fresh `MOCK_FILE` snapshot.

Fallback if no usable date field exists: treat "has ≥ 1 access key at all" as the signal instead
of a genuine age check, and note this explicitly in a code comment so it isn't mistaken for a real
180-day check later.

### New API fetch: Medium-severity alerts

`fetchAlerts()` (server.js:300-305) currently only ever fetches `severity='Critical'` and
`severity='High'` in two parallel calls. For the new `MEDIUM=40` alert weight to ever apply
(today no alert record can have `severity='Medium'`), add a third parallel call:

```js
post('Alerts/search', { timeFilter: tf, filters: [{ field: 'severity', expression: 'eq', value: 'Medium' }], returns: RETURNS, paging: { rows: 500 } })
```

This third call must go through the same 7-day time-window chunking (`alertTimeWindows()`) as the
existing two when `dynamicDaysBack > 7`, and its results merge into the same `alerts` array/`cache.alerts`.
This means Medium alerts will now appear throughout the dashboard wherever `d.alerts` is read
(alert counts, High Fidelity Alerts panel, reports), not just in the new weight calculation — that
is an intentional, accepted side effect.

## Call Sites To Update

The file has no shared runtime between the client dashboard script, the mobile view, and the two
server-side report builders — each maintains its own duplicated copy of scoring logic (an existing,
accepted pattern in this codebase, e.g. `calcCspScore`/`computeCspScores`). All of the following
need the new weight rules applied identically:

1. `renderRiskFindings()` — server.js:4448 (client). The Risk Findings Inventory table itself.
   The CVE (Host Exposure) group's `items` list must filter to `riskScore >= 8` before mapping,
   so sub-8 CVEs disappear from both the row list and the group's finding count.
2. `calcPostureScore()` — server.js:4435 (client). Main dashboard posture score.
3. Mobile `calcScore()` — inside `MOBILE_HTML`, ~server.js:6055. Mobile posture score. Same CVE
   filter and weight rules.
4. Server-side `calcRiskScore()` — server.js:1333. Diagnostic/log-only score computed during
   `refreshData()`. Lower priority (not user-facing) but kept consistent.
5. `computeCspScores()` (server, server.js:7041) and its client mirror `calcCspScore()`
   (~server.js:4508) — feed the per-cloud score gauges on the dashboard and both reports. These
   currently bucket only Alerts + Compliance + Identities into Critical/High/Medium/Low (no CVEs
   at all — that is pre-existing and out of scope to change here). Needs updating so:
   - A Medium-severity alert buckets as "Medium", not folded into "High" as it effectively is today
     (today only Critical/High alerts exist, so the medium bucket for alerts is presently unreachable).
   - An identity matching the new Admin+No-MFA+(...) rule buckets as "Critical" (matching its new
     weight-80 severity), instead of being bucketed purely by raw `risk_score` thresholds as today.

Because items 4 and 5 both run server-side (unlike the client/mobile duplicates, which execute in
the browser), the identity/alert classification helpers can be defined once at module scope and
shared between `calcRiskScore()` and `computeCspScores()` rather than duplicated a third time.

## Explicitly Out of Scope

- **`computeAssetRiskMap()`** (server.js:6961) — the "Correlated Risk Findings per Asset" panel
  and its host risk-tier system. This has its own established, documented formula (CIEM secret /
  generic secret / CVE / misconfiguration point totals) and is not mentioned in this change.
- **Report-specific logic** in `buildReportHtml()` / `buildReportHtml2()` beyond the posture-score
  ripple effect — the customer report's displayed posture score number will shift because it reads
  from the same weight functions, but no report-only code (identity/admin badges, CVE tables, etc.)
  is being changed here.
- The pre-existing **Secrets weight inconsistency** (90 in the table vs. 75 in the posture score)
  is resolved as a side effect of this change (both become 10) rather than needing separate
  investigation.

## Risks / Notes

- Changing Secrets from 75/90 down to 10, Alerts from a flat 95 down to a 40–80 tiered range, and
  gating CVEs at `riskScore ≥ 8` will noticeably raise most tenants' displayed posture score
  (fewer/lighter-weighted findings pulling the average down). This is an intended consequence of
  the new weighting, not a bug, but is worth calling out since it changes a number customers see in
  generated reports.
- Adding a third alert-severity fetch increases API call volume per refresh cycle (alerts already
  chunk into 7-day windows when `dynamicDaysBack > 7`); no rate-limit issue is expected given
  `withRetry()`'s existing backoff, but worth watching on first live test.
