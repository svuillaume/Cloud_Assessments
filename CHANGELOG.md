# Changelog

All notable changes to this project are documented here.

---

## [Unreleased] — 2026-04-19

### Added
- **Compliance framework selection** (`--compliance-framework`): choose from CIS (default), PCI, NIST_CSF, NIST_800_53, SOC2, HIPAA, ISO_27001, or CSA_CCM at the command line. Framework is applied across all three cloud providers (AWS, Azure, GCP).
- **Alert IP/Domain Reputation column**: network threat alerts now surface the bad host (IP or domain) parsed from `alertInfo.subject` with a regex fallback on the description. Reputation badge is color-coded: Malicious (red), Negligent (orange), Unauthorized (purple).
- **Alert Risk Classification** (`_RISK_MAP`): alert types are mapped to Malicious / Negligent / Unauthorized risk categories.
- **Spinner terminal-width awareness**: spinner line is truncated to terminal width using `shutil.get_terminal_size()` to prevent mid-word wraps on narrow terminals.
- **Page breaks**: `page-break-before: always` applied between major report sections and within long sections for clean PDF rendering.

### Changed
- **Report spacing**: significantly increased body padding, table cell padding, and heading margins for a more readable, modern layout.
- **Cover page**: removed book cover image; score circle is centered alone. Fortinet logo repositioned beside QR code in the footer.
- **Intro section**: replaced three methodology cards with a single prose paragraph placed before the Risk Findings TOC.
- **Key Algorithm Advisory**: now recommends only `ssh-ed25519` (`ssh-keygen -t ed25519`); legacy `rsa-sha2-256` recommendation removed.
- **Footer text**: updated to "Powered by FortiCNAPP".
- **Alerts table**: removed Location and Bad Host columns; "Risk" column renamed to "IP or Domain Reputation".

### Fixed
- Entity-map enrichment removed from `reportgen.py` (was slow and error-prone); alert data now gathered directly.

---

## [2.0.0] — 2025 (branch: nfr)

### Added
- **CIEM (Identity & Entitlements)** module: surfaces over-privileged identities with configurable threshold (`--ciem-threshold`, default 70%).
- **Secrets scanning** module: reports exposed secrets found by FortiCNAPP.
- **Dynamic report discovery**: `utils.get_available_reports()` walks `modules/reports/` via AST — new report classes appear automatically in `--list-reports` and the GUI without loader changes.
- **`--logo`** flag: specify a custom PNG to replace the default Fortinet logo.
- **`--cache-data`** flag: serialize API responses to `.cache` pickle files for faster iterative development.
- **Jinja2 templating**: all report HTML is generated via Jinja2 templates in `templates/`.
- **Spinner** with rotating FortiCNAPP / industry security facts while the report generates.
- **SCORING_GUIDE.md**: documents the Risk Score formula, per-CSP compliance scoring, and alert risk classification.
- **Lambda adapter** (`lambda_function.py`): run the report generator via AWS Lambda; event payload maps to CLI args.
- **GUI mode** (`--gui`): Tkinter-based interface for report configuration without CLI flags.
- **PDF output** (`--report-format PDF`): via WeasyPrint with A2/A3 page size options.
- **`CSA_Detailed` report**: executive-ready Rapid Cloud Assessment covering compliance, vulnerabilities (Risk Score ≥ 9), CIEM, secrets, and critical alerts with a 30–60–90 day action plan.

### Changed
- Refactored from a single-file script into a modular architecture (`modules/`).
- Credential resolution priority: `--api-key-file` → `~/.lacework.toml` → env vars (`LW_ACCOUNT`, `LW_API_KEY`, `LW_API_SECRET`).

---

## [1.0.0] — Initial release

- Basic compliance report (CIS only) for AWS.
- Host and container vulnerability listings.
- Alert summary.
- Single Jinja2 HTML template output.
