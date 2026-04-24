<div align="center">

# 📝 Release Notes & Changelog

**All notable changes to FortiCNAPP Rapid Cloud Assessment.**

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning follows [SemVer](https://semver.org/).

</div>

---

## 📖 How to read this file

Each release is grouped by **version** and **date**, then organized into these categories:

| Section | What goes here |
|---------|----------------|
| ✨ **Added** | New features, new files, new API endpoints |
| 🔧 **Changed** | Improvements to existing behavior |
| 🗑️ **Removed** | Deleted features or files |
| 🐛 **Fixed** | Bug fixes |
| 🔒 **Security** | Security-related fixes or hardening |
| 📚 **Docs** | Documentation-only updates |

> 💡 **Releasing a new version?** See the [📦 Release template](#-release-template) at the bottom of this file.

---

## [Unreleased]

Changes on `main` that haven't shipped in a tagged release yet.

### ✨ Added
-

### 🔧 Changed
-

### 🐛 Fixed
-

---

## [1.3.0] — 2026-04-24

### ✨ Added
- **RiskIQ Score** — new branded name for the posture gauge, displayed on the overview panel and the Risk Findings view.
- **NPS-style multi-band arc gauge** replacing the tick-mark gauge — colored arcs (Red / Orange / Blue / Green) with a triangular needle pointer and boundary labels at 0 / 20 / 50 / 80 / 100.
- **Findings summary grid** below the gauge on the overview panel — Alerts, CVEs, Identities, Compliance counts are now clickable shortcuts to their respective views.
- **New RiskIQ scoring formula** (5 inputs, 0–100 output, max combined penalty = 9.0):

  | Metric | Input | Formula | Saturates at |
  |--------|-------|---------|-------------|
  | Vulnerabilities | Critical vulns | min(count/15, 1) × 2.5 | 15 CVEs |
  | CVSS 10 | Critical CVSS 10.0 | min(count/10, 1) × 1.5 | 10 CVEs |
  | Identities | Admin no MFA | min(count/30, 1) × 2.5 | 30 admins |
  | Alerts | Critical alerts | min(count/10, 1) × 1.5 | 10 alerts |
  | Non-Compliance | Critical findings | min(count/10, 1) × 1.0 | 10 findings |

  `score = round((1 − penalty / 9) × 100)`

### 🔧 Changed
- **White + Fortinet brand theme** — dashboard redesigned from dark to light: white main area, dark navy sidebar, Fortinet red (`#DA291C`) as the primary accent and active-nav color.
- **Risk score bands** updated to a 0–100 scale with new labels:
  - 🔴 0–19 — Immediate Attention Needed
  - 🟠 20–49 — Some Attention Needed
  - 🔵 50–79 — Progressing Security
  - 🟢 80–100 — Proactive Security
- **Login screen** restyled to white card on dark gradient background using Fortinet red call-to-action button.
- **Sidebar nav** active item now uses Fortinet red highlight instead of navy blue.
- **Generate Report button** and modal updated to Fortinet red palette.
- Score display throughout (Risk Findings view, Recommended Next Steps) updated to 0–100 integer.

---

## [1.2.0] — 2026-04-24

### 📚 Docs
- Complete rewrite of the top-level [README.md](README.md) as a beginner-friendly step-by-step guide — prerequisites, numbered steps, flag explanations, troubleshooting, and FAQ.
- New beginner-friendly [rca_ui/README.md](rca_ui/README.md) using the same template — dedicated walkthrough for the dashboard component.
- Restored full README content after a previous paste-truncation incident (prior file cut at line 102).

### 🗑️ Removed
- Lambda deployment scaffolding, CI/CD configs, and PyInstaller packaging removed — repo now focuses on local Docker + Python workflows.
- Duplicate files eliminated from the root tree.

### 🐛 Fixed
- **Login flow:** fixed email validation so invalid addresses are rejected before being written to `contacts.csv`. Each new visitor now appends a clean row `Timestamp, FirstName, LastName, Company, Role, Email`.

---

## [1.1.0] — 2026-04-21

### ✨ Added
- **Semi-circle posture gauge** on the cover page (main) plus a secondary **findings donut** for at-a-glance posture summary.

### 🔧 Changed
- **Dashboard gauges swapped** and relabeled with positive posture terminology (*Building → Maturing → Optimizing*) for clearer executive messaging.
- **Report button** on the dashboard now links directly to the GitHub Pages sample report.

### 🐛 Fixed
- **Docker build:** pinned Python to **3.12** and dropped the abandoned `datapane` dependency to unblock image builds.

### 🔒 Security
- Added `FORTINET_*.json` cached API token files to `.gitignore` to prevent accidental credential commits.

---

## [1.0.0] — 2026-04-20

First public-ready release of the Rapid Cloud Assessment toolkit.

### ✨ Added
- **Live Dashboard** (`rca_ui/server.js`) — single-file Node.js server with no npm dependencies, proxies the FortiCNAPP v2 API.
  - Dark-theme UI showing alerts, CVEs, identity exposure, and compliance in one view.
  - Auto-refresh every 60 minutes.
  - **Mock mode** (`MOCK_FILE=/app/mock_data.json`) for credential-free demos.
- **CSA Report Generator** (`lw_report_gen.py`) — produces HTML and PDF Cloud Security Assessment reports.
  - Supports frameworks: CIS, PCI, NIST_CSF, SOC2, HIPAA, ISO_27001, CSA_CCM.
  - `--cache-data` flag for offline / repeat runs.
- **Cover cards** with clickable links to detail sections plus a back-to-overview navigation.
- Consistent *"Top Critical X Findings"* heading across all 5 report sections.
- **Visitor contact capture** — dashboard logins recorded to `contacts.csv` inside the container, retrievable via `docker cp`.
- **Host-side Report Runner** (`rca_ui/report_runner.js`) on port `8081` for on-demand live report generation.
- **Scoring guide** (`SCORING_GUIDE.md`) documenting the risk and maturity score formulas.

### 🔧 Changed
- Visual design aligned with the `rca.html` reference template.

---

## 📦 Release template

Copy this block when cutting a new release. Replace the version, date, and fill in the sections that apply — delete the ones that don't.

```markdown
## [X.Y.Z] — YYYY-MM-DD

### ✨ Added
- Brief description of the new feature (link to PR/issue if useful).

### 🔧 Changed
- What behavior changed and why.

### 🗑️ Removed
- What was removed and what replaces it (if anything).

### 🐛 Fixed
- The bug, symptom, and root cause in one line.

### 🔒 Security
- CVE or advisory reference if applicable.

### 📚 Docs
- Documentation-only updates.
```

---

## 🔢 Versioning rules

We follow **Semantic Versioning** — `MAJOR.MINOR.PATCH`:

| Part | Bump when… | Example |
|:----:|-----------|---------|
| **MAJOR** | Breaking changes — existing users must adjust config or commands | `1.x.x → 2.0.0` |
| **MINOR** | New backward-compatible feature | `1.1.0 → 1.2.0` |
| **PATCH** | Backward-compatible bug fix or docs-only update | `1.2.0 → 1.2.1` |

---

## 🏷️ Cutting a GitHub Release

After updating this file:

```bash
# 1. Tag the commit
git tag -a v1.2.0 -m "Release 1.2.0"
git push origin v1.2.0

# 2. Create the GitHub Release from the tag (uses this file's section as notes)
gh release create v1.2.0 \
  --title "v1.2.0 — Beginner-friendly docs overhaul" \
  --notes-from-tag
```

Or create it from the web UI: **Releases → Draft a new release → pick the tag → paste the section from this file**.

---

<div align="center">

[← Back to README](README.md) · [🐛 Report an issue](../../issues) · [📄 Sample Report](https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html)

</div>
