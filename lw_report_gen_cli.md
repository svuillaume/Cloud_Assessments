# lw_report_gen

A command-line tool to generate Lacework (FortiCNAPP) security reports. By default it produces a **Cloud Security Assessment (CSA)** report in HTML format.

---

## Requirements

- Python 3.x
- A Lacework API key file (JSON), **or** credentials configured in `~/.lacework.toml`, **or** environment variables (see [GitHub page](https://github.com/lacework/extensible-reporting))

---

## Usage

```bash
python3 lw_report_gen.py [OPTIONS]
```

### Quick Start

```bash
# Minimal — uses credentials from .lacework.toml
python3 lw_report_gen.py --author 'John D' --customer 'Acme Co.'

# With API key file
python3 lw_report_gen.py --author 'John D' --customer 'Acme Co.' --api-key-file mykey.json

# Custom vulnerability query window (start 7 days and 2 hours ago)
python3 lw_report_gen.py --author 'John D' --customer 'Acme Co.' --vulns-start-time 7:2

# List available report types
python3 lw_report_gen.py --list-reports

# Generate a specific report as PDF
python3 lw_report_gen.py --report CSA_Detailed --report-format PDF --author 'John D' --customer 'Acme Co.'
```

---

## Options

| Option | Description |
|---|---|
| `--author AUTHOR` | Author name inserted into the report |
| `--customer CUSTOMER` | Customer / company name inserted into the report |
| `--api-key-file FILE` | Path to a Lacework API key JSON file downloaded from the UI |
| `--report REPORT` | Report type to generate (default: `CSA_Detailed`) |
| `--report-format FORMAT` | Output format: `HTML` or `PDF` (default: `HTML`) |
| `--report-path PATH` | Filename/path to save the generated report |
| `--logo FILE` | Custom logo PNG file to include in the report |
| `--list-reports` | List all available report types and exit |
| `--gui` | Launch in GUI mode for additional customization options |
| `--cache-data` | Use locally cached Lacework data (useful for development/testing) |

### Time Range Options

Time values use the format `D:H` — days and hours in the past relative to **now**.

| Option | Default | Description |
|---|---|---|
| `--vulns-start-time D:H` | `1:1` (25 hours ago) | Start of vulnerability query window |
| `--vulns-end-time D:H` | `0:0` (now) | End of vulnerability query window |
| `--alerts-start-time D:H` | `7:0` (7 days ago) | Start of alert query window |
| `--alerts-end-time D:H` | `0:0` (now) | End of alert query window |

### Other Options

| Option | Description |
|---|---|
| `--ciem-threshold N` | Unused entitlement count threshold for CIEM analysis (default: `70`) |
| `--v` | Verbose logging |
| `--vv` | Extremely verbose logging |

---

## Credentials

The tool resolves credentials in this order:

1. `--api-key-file` flag (JSON key file downloaded from the Lacework UI)
2. Default profile in `~/.lacework.toml`
3. Environment variables (see [GitHub page](https://github.com/lacework/extensible-reporting) for variable names)

---

## Examples

```bash
# HTML report with custom time windows
python3 lw_report_gen.py \
  --author 'Jane Smith' \
  --customer 'Acme Corp' \
  --api-key-file acme.json \
  --vulns-start-time 7:0 \
  --alerts-start-time 30:0 \
  --report-path acme_report.html

# PDF report with custom logo
python3 lw_report_gen.py \
  --author 'Jane Smith' \
  --customer 'Acme Corp' \
  --api-key-file acme.json \
  --report-format PDF \
  --logo acme_logo.png \
  --report-path acme_report.pdf

# GUI mode
python3 lw_report_gen.py --gui
```

---

## More Information

- GitHub: [https://github.com/lacework/extensible-reporting](https://github.com/lacework/extensible-reporting)
