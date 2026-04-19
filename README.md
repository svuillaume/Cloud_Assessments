# FortiCNAPP Rapid Cloud Assessment Tool

> **Automated cloud security assessment reports powered by the FortiCNAPP API**
>
> Copyright 2025, Fortinet Inc. — Licensed under the [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0)

---

## ⚠️ Important Notice — Binary Release

**Do not use the compiled binary (Release v2.0.2).**

The binary package available at the [Releases page](https://github.com/lacework/extensible-reporting/releases/tag/v2.0.2) is incomplete — not all report scripts are compiled and included.

**Until a new release is published, always run from source using the Python script.**

---

## Overview

This tool is a FortiCNAPP-enhanced fork of the [Lacework Extensible Reporting](https://github.com/lacework/extensible-reporting) project. It uses the FortiCNAPP API to automatically generate **Cloud Security Assessment (CSA)** reports in HTML and PDF formats — ideal for PreSales engagements, internal audits, and compliance reviews.

**What it produces:**
- Critical and high vulnerability findings across cloud workloads
- CSPM misconfiguration findings ranked by severity
- CIEM insights — over-privileged identities and unused permissions
- Alert trend analysis using FortiCNAPP composite alert data

---

## Prerequisites

- Python 3.9 or later
- A valid [FortiCNAPP API key](#authentication)
- At least one cloud account onboarded in your FortiCNAPP instance

---

## Installation

### Option 1: Virtual Environment (Recommended)

Running inside a virtual environment keeps dependencies isolated from your system Python.

```bash
# Clone the repository
git clone https://github.com/lacework/extensible-reporting
cd extensible-reporting

# Create and activate the virtual environment (one-time setup)
python3 -m venv venv

# Activate — macOS / Linux
source venv/bin/activate

# Activate — Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# If activation is blocked, run first:
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

You should see `(venv)` in your shell prompt once active.

To deactivate the environment when you are done:

```bash
deactivate
```

---

## Authentication

You need a valid FortiCNAPP API key before running the tool. To create and download one, go to **Settings → Configuration → API Keys** in your FortiCNAPP instance.

Full API documentation: https://docs.fortinet.com/document/lacework-forticnapp/latest/api-reference/863111/about-the-lacework-forticnapp-api

Three authentication methods are supported:

### Method 1: JSON API Key File (Recommended)

Download the API key JSON file from your FortiCNAPP instance and pass it directly:

```bash
python lw_report_gen.py --api-key-file <instancename>.json
```

### Method 2: FortiCNAPP CLI Profile

If you have the FortiCNAPP CLI installed and configured (`~/.lacework.toml`), the tool reads credentials from it automatically — no additional flags required.

CLI setup guide: https://docs.fortinet.com/document/lacework-forticnapp/latest/cli-reference/68020/get-started-with-the-lacework-forticnapp-cli

### Method 3: Environment Variables

The tool honours the same environment variables as the FortiCNAPP CLI:

| Variable | Description | Required |
|---|---|:---:|
| `LW_ACCOUNT` | Account domain, e.g. `mycompany.lacework.net` — domain only, no `https://` | ✅ |
| `LW_API_KEY` | API access key | ✅ |
| `LW_API_SECRET` | API access secret | ✅ |
| `LW_SUBACCOUNT` | Sub-account name (multi-tenant deployments) | — |
| `LW_PROFILE` | CLI profile name from `~/.lacework.toml` | — |

```bash
export LW_ACCOUNT="mycompany"
export LW_API_KEY="<your-key>"
export LW_API_SECRET="<your-secret>"
```

> **Note:** `LW_ACCOUNT` should be the subdomain only — `mycompany`, not `https://mycompany.lacework.net`.

---

## Running the Tool

### GUI Mode (Recommended for First Use)

Launches an interactive interface that guides you through report options:

```bash
python lw_report_gen.py --gui --api-key-file <instancename>.json
```

### CLI / Headless Mode

Suitable for automation, scripting, and scheduled report generation:

```bash
python lw_report_gen.py \
  --author "Your Name" \
  --customer "Acme Corp" \
  --report CSA_Detailed \
  --report-format PDF \
  --api-key-file <instancename>.json
```

Common `--report-format` values: `HTML` (default), `PDF`

To see all available options:

```bash
python lw_report_gen.py -h
```

---

## Query Time Ranges

### Defaults

| Data Type | Default Query Window |
|---|---|
| Vulnerability data | 25 hours prior to execution → now |
| Alert data | 7 days prior to execution → now |

### Custom Time Ranges

Time range flags accept values in `"days:hours"` format, representing time prior to execution.

```bash
# Extend alert window to 14 days
python lw_report_gen.py \
  --author "Your Name" --customer "Acme Corp" \
  --alerts-start-time 14:0

# Query a historical 7-day window that ended 2 weeks ago
python lw_report_gen.py \
  --author "Your Name" --customer "Acme Corp" \
  --alerts-start-time 14:0 --alerts-end-time 7:0
```

Available flags:

| Flag | Description |
|---|---|
| `--alerts-start-time` | Start of the alert query window (`days:hours` prior to now) |
| `--alerts-end-time` | End of the alert query window (`days:hours` prior to now) |
| `--vulns-start-time` | Start of the vulnerability query window |
| `--vulns-end-time` | End of the vulnerability query window |

---

## Development — Caching API Responses

The `--cache-data` flag saves API responses to disk on first run and reuses them on subsequent runs. This avoids repeated live API calls during report development and customization.

```bash
# First run — fetches from API and writes cache files
python lw_report_gen.py --cache-data --api-key-file dev.json --report CSA_Detailed

# Subsequent runs — reads from cache, no API calls
python lw_report_gen.py --cache-data --api-key-file dev.json --report CSA_Detailed

# Clear cache to force a fresh fetch (macOS / Linux)
rm *.cache
```

> Cache files do not expire automatically. Delete them manually to refresh data.

---

## Logging

The tool writes a log file to `lw_report_gen.log` in the working directory. If you encounter a bug or unexpected behaviour, include the relevant entries from this file when opening an issue on GitHub.

---

## Creating Custom Reports

The tool uses a plugin architecture — each report type is a Python module that inherits from `modules.reportgen` and renders output via [Jinja2](https://jinja.palletsprojects.com/) templates.

> Custom reports require running from source. The compiled binary does not support them.

### Directory Structure

```
extensible-reporting/
├── lw_report_gen.py              # Entry point
├── modules/
│   └── reports/
│       ├── reportgen_csa.py      # Default CSA report — use as reference
│       └── my_custom_report.py   # Your custom report module goes here
└── templates/
    └── my_custom_template.html.j2  # Optional custom Jinja2 template
```

### Minimum Required Class Structure

```python
from modules.reportgen import reportgen

class MyCustomReport(reportgen):
    report_short_name = "MY_REPORT"           # Used in --report flag
    report_name = "My Custom Security Report"
    report_description = "Description shown in GUI report picker"

    def generate(self):
        # Query FortiCNAPP API via self.client
        # Render output via Jinja2 template
        pass
```

Place the module in `modules/reports/`. The tool's dynamic module loader discovers it automatically based on the three required class variables.

For a complete working example, review `modules/reports/reportgen_csa.py`.

---

## Troubleshooting

### API Authentication Fails

- Confirm the API key JSON file is for the correct FortiCNAPP instance.
- If using `LW_ACCOUNT`, set the subdomain only — `mycompany`, not `https://mycompany.lacework.net`.
- Test with the FortiCNAPP CLI: `lacework api get /api/v2/UserProfile`

### Report Contains No Data

- Verify at least one cloud account is onboarded: **Settings → Cloud Accounts**
- For newly onboarded accounts, allow 30–60 minutes for initial data ingestion.
- Extend the query time range with `--alerts-start-time` and `--vulns-start-time`.
- Run with `--cache-data` — if the cache files populate but the report is empty, the issue is in report logic rather than API connectivity.

### PDF Generation Fails

PDF rendering requires system libraries. Install the appropriate package for your OS:

```bash
# macOS
brew install pango cairo

# Debian / Ubuntu
sudo apt-get install libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0

# Fallback: generate HTML and print to PDF from your browser
```

### Virtual Environment Won't Activate (Windows PowerShell)

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

---

## Contributing

Pull requests are welcome. Please include relevant log output and a clear description of the change when opening a PR or issue.

---

## License

```
Copyright 2025, Fortinet Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
