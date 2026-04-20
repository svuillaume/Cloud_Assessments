# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run in GUI mode
python3 lw_report_gen.py --gui --api-key-file credentials.json

# Run in CLI mode (generates both full and compact HTML variants)
python3 lw_report_gen.py --author "Name" --customer "Acme" --report CSA_Detailed --report-format HTML

# Run in PDF mode (generates both full and compact PDF variants)
python3 lw_report_gen.py --author "Name" --customer "Acme" --report-format PDF

# List available report types
python3 lw_report_gen.py --list-reports

# Run tests
pytest

# Build standalone binary
poetry run pyinstaller lw_report_gen.spec
poetry run poe clean  # remove build/dist artifacts
```

Use `--cache-data` during development to avoid live API calls (responses cached as `.cache` pickle files alongside the script).

## Output Files

Every run produces two variants automatically:

| File | Contents |
|------|----------|
| `<customer>_RCA_<date>.html` / `.pdf` | Full report including Annex |
| `<customer>_RCA_C<date>.html` / `.pdf` | Compact — no Annex section |

The compact variant is rendered by calling `report_generator.render(..., include_annex=False)` after the main report is generated, reusing the already-gathered data.

## Architecture

This tool queries the FortiCNAPP (Lacework) API and generates HTML/PDF security reports. The pipeline is:

**CLI args → Credentials → API queries → Data processing → Jinja2 template → HTML/PDF output**

### Layers

**Entry point** — `lw_report_gen.py` parses args, dynamically loads report classes from `modules/reports/`, then routes to GUI (`modules/gui_main.py`) or CLI execution. After generation it writes both full and compact variants, then converts to PDF via Chrome headless (primary) or WeasyPrint (fallback).

**PDF backend** — `_find_chrome()` searches OS-specific paths. `_html_to_pdf_chrome()` renders at A3 landscape (`--paper-width=16.54 --paper-height=11.69`). WeasyPrint is used when Chrome is not found.

**Credential resolution** — `modules/process_args.py` tries in order: `--api-key-file` JSON, `~/.lacework.toml`, then env vars (`LW_ACCOUNT`, `LW_API_KEY`, `LW_API_SECRET`).

**API client** — `modules/lacework_interface.py` wraps `laceworksdk.LaceworkClient`. Each method (`get_host_vulns`, `get_alerts`, `get_compliance_reports`, etc.) returns a typed data object. The `@cache_results` decorator serializes responses to disk for dev/testing. Compliance framework is selected via `compliance_report_lookup` dict mapping `(provider, framework)` → API report string.

**Data modules** — Each security domain has its own module (`host_vulnerabilities.py`, `container_vulnerabilities.py`, `alerts.py`, `compliance.py`, `secrets.py`, `identity_entitlements.py`) that normalizes raw API responses into pandas DataFrames and Plotly SVG charts (via `chart_utils.py`), ready for template injection.

**Report base class** — `modules/reportgen.py` defines `gather_*` methods for each data type, Jinja2 template loading, and base64 image embedding (`file_to_image_tag`). All images (charts, logos) are embedded inline so reports are self-contained single files.

**Concrete reports** — Classes in `modules/reports/` inherit `ReportGen` and implement:
- `gather_data()` — calls the relevant `gather_*` methods; accepts `progress_cb` for live spinner updates
- `render()` — populates the Jinja2 template dict; accepts `include_annex=True` to toggle the product details annex
- `generate()` — orchestrates gather → render → return HTML string

**Progress bar** — `modules/spinner.py` renders a terminal progress bar. `generate()` accepts `progress_cb=spinner.update`; `gather_data()` calls `_step(pct, label)` at each API fetch stage.

**Dynamic report discovery** — `utils.get_available_reports()` walks `modules/reports/*.py` and discovers report classes via AST parsing. New reports appear automatically in `--list-reports` and the GUI without any loader changes.

## Template Structure (`templates/csa_detailed_report.jinja2`)

Section order: Cover → TOC + CSP gauges → Executive Summary → Secrets → Compliance → Vulnerabilities → Identity → Alerts → Recommendations → **Annex — Fortinet Product Details**

Key template variables:
- `include_annex` — boolean controlling whether the Annex section renders
- `pdf` — boolean; guards `{% if not pdf %}` blocks for HTML-only animations
- `total_compliance_critical`, `total_vuln_critical`, `total_admin.val`, `total_identity_high.val`, `critical_alert_count`, `_sc` — finding counts used to conditionally render product cards
- `_total_findings` — sum of all finding counts, shown in the recommendations banner

**Product recommendations logic** — Each of the 20 Fortinet products maps to exactly one finding category. Products only render when their specific finding type is present (no OR conditions across categories):
- Compliance → FortiGate · FortiManager · FortiAnalyzer
- Vulns → FortiGate (if no compliance block) · FortiWeb · FortiEDR · FortiSandbox
- Identity/MFA → FortiAuthenticator · FortiToken · FortiPAM · FortiCASB
- Alerts → FortiSIEM · FortiSOAR · FortiXDR · FortiNDR
- Secrets → FortiDLP · FortiPAM

## Adding a New Report Type

1. Create `modules/reports/reportgen_<name>.py`
2. Define a class inheriting from `ReportGen` (import from `modules.reportgen`)
3. Set class attributes `report_short_name`, `report_name`, `report_description`
4. Implement `gather_data()`, `render()`, and `generate()`
5. Create a matching Jinja2 template in `templates/`
6. The report appears automatically — no loader changes needed

## Key CLI Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--compliance-framework` | `CIS` | Choices: `CIS` `PCI` `NIST_CSF` `NIST_800_53` `SOC2` `HIPAA` `ISO_27001` `CSA_CCM` |
| `--vulns-start-time` | `7:0` | Format: `days:hours` |
| `--alerts-start-time` | `7:0` | Format: `days:hours` |
| `--ciem-threshold` | `70` | Unused entitlement % threshold |
| `--logo` | Fortinet logo | Path to custom PNG |
| `--cache-data` | off | Reuse cached API responses |

## GitHub Pages

`rca.html` on the `gh-pages` branch is served at `https://svuillaume.github.io/FortiCNAPP_RapidCloudAssessment/rca.html`. It should be kept in sync with the latest compact (`_C`) report variant. Update via a separate clone of the `gh-pages` branch — do not mix with the main working tree.

## AWS Lambda

`lambda_function.py` adapts the CLI for Lambda invocation. Event payload maps to CLI args.
