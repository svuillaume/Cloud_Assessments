# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install dependencies
pip3 install -r requirements.txt

# Run in GUI mode
python3 lw_report_gen.py --gui --api-key-file credentials.json

# Run in CLI mode
python3 lw_report_gen.py --author "Name" --customer "Acme" --report CSA_Detailed --report-format HTML

# List available report types
python3 lw_report_gen.py --list-reports

# Run tests
pytest

# Build standalone binary
poetry run pyinstaller lw_report_gen.spec
poetry run poe clean  # remove build/dist artifacts
```

Use `--cache-data` during development to avoid live API calls (responses cached as `.cache` pickle files alongside the script).

## Architecture

This tool queries the FortiCNAPP (Lacework) API and generates HTML/PDF security reports. The pipeline is:

**CLI args → Credentials → API queries → Data processing → Jinja2 template → HTML/PDF output**

### Layers

**Entry point** — `lw_report_gen.py` parses args, dynamically loads report classes from `modules/reports/`, then routes to GUI (`modules/gui_main.py`) or CLI execution.

**Credential resolution** — `modules/process_args.py` tries in order: `--api-key-file` JSON, `~/.lacework.toml`, then env vars (`LW_ACCOUNT`, `LW_API_KEY`, `LW_API_SECRET`).

**API client** — `modules/lacework_interface.py` wraps `laceworksdk.LaceworkClient`. Each method (`get_host_vulns`, `get_alerts`, `get_compliance_reports`, etc.) returns a typed data object. The `@cache_results` decorator serializes responses to disk for dev/testing.

**Data modules** — Each security domain has its own module (`host_vulnerabilities.py`, `container_vulnerabilities.py`, `alerts.py`, `compliance.py`, `secrets.py`, `identity_entitlements.py`) that normalizes raw API responses into pandas DataFrames and Plotly SVG charts (via `chart_utils.py`), ready for template injection.

**Report base class** — `modules/reportgen.py` defines `gather_*` methods for each data type, Jinja2 template loading, and base64 image embedding (`file_to_image_tag`). All images (charts, logos) are embedded inline so reports are self-contained single files.

**Concrete reports** — Classes in `modules/reports/` inherit `ReportGen` and implement:
- `gather_data()` — calls the relevant `gather_*` methods from the base class
- `render()` — populates the Jinja2 template dict
- `generate()` — orchestrates gather → render → return HTML string

**Dynamic report discovery** — `utils.get_available_reports()` walks `modules/reports/*.py` and discovers report classes via AST parsing. New reports appear automatically in `--list-reports` and the GUI without any loader changes.

**Output** — HTML written directly; PDF via `weasyprint`.

## Adding a New Report Type

1. Create `modules/reports/reportgen_<name>.py`
2. Define a class inheriting from `ReportGen` (import from `modules.reportgen`)
3. Set class attributes `REPORT_SHORT_NAME`, `REPORT_FULL_NAME`, `REPORT_DESCRIPTION`
4. Implement `gather_data()`, `render()`, and `generate()`
5. Create a matching Jinja2 template in `templates/`
6. The report appears automatically — no loader changes needed

## Key CLI Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--vulns-start-time` | `7:0` | Format: `days:hours` |
| `--alerts-start-time` | `7:0` | Format: `days:hours` |
| `--ciem-threshold` | `70` | Unused entitlement % threshold |
| `--logo` | Fortinet logo | Path to custom PNG |
| `--cache-data` | off | Reuse cached API responses |

## AWS Lambda

`lambda_function.py` adapts the CLI for Lambda invocation. Event payload maps to CLI args.
