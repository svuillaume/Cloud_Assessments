# FortiCNAPP Rapid Cloud Assessment 

## Important Notice 

### Do Not Use the Compiled Binary (Release v2.0.2)

Please **do not use the compiled binary** available on the Releases page:

https://github.com/lacework/extensible-reporting/releases/tag/v2.0.2

At this time, **not all scripts have been compiled and included** in the binary package.

### Recommended Usage

Until the next **Extensible-Reporting** release is published:

- Use the **Python script version only**
- Run directly from source
- Avoid relying on the current compiled executable

## Description

A updated FortiCNAPP project forked from Lacework Extensible Report to generate automated Rapid Cloud Assessment Reports 

## Quickstart

1. Ensure you have some method of authenticating against your FortiCNAPP API. The easiest
    way is to download an API key file from your FortiCNAPP UI under Settings ->  API Keys. 

2. Run the python script using the following flags: 

`--gui --api-key-file <keyfile>`

--gui is optional

Where \<keyfile> is the name of the api key file you downloaded. 

For example on an ARM based Mac download the ARM binary file from the "Releases" section of this page (lw_report_gen_mac_arm
) and execute it:

`lw_report_gen.py --gui --api-key-file example.json`


## Usage for CSA Reports

This tool leverages the FortiCNAPP API to create HTML and PDF reports. 

## Downloading and Setting up the Tool


### Option 1: Run from source using a virtual environment (recommended)

This option runs `lw_report_gen.py` directly from the cloned repo inside an isolated Python virtual environment so dependencies don't pollute your system Python.

**Prerequisites:** `python3` (3.9+) available on your PATH.

#### 1 — Create and activate the virtual environment

```bash
# Create the venv (only needed once)
python3 -m venv venv

# Activate — macOS / Linux
source venv/bin/activate

# Activate — Windows (PowerShell)
.\venv\Scripts\Activate.ps1
```

You should see `(venv)` in your shell prompt once active.

#### 2 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 3 — Run the tool

GUI mode (recommended for first use):
```bash
python lw_report_gen.py --gui --api-key-file <instancename>.json
```

CLI mode (headless / automation):
```bash
python lw_report_gen.py \
  --author "Your Name" \
  --customer "Acme Corp" \
  --report CSA_Detailed \
  --report-format HTML \
  --api-key-file <instancename>.json
```

#### 4 — Deactivate when done

```bash
deactivate
```

> **Tip:** use `--cache-data` on subsequent runs to skip live API calls and reuse cached responses during development.

## Command Line Mode

If you do not want to run this tool in gui mode omit the `--gui' command line flag. You will likely need to specify additional flags
such as specifying the report format (pdf or html) `--report-format PDF`.

Run the tool with the `-h` flag to see a full list of options. 

## Specifying a Lacework FortiCNAPP instance and credentials:

You must have a valid Lacework FortiCNAPP API key for your Lacework FortiCNAPP instance to run this tool. You can read about creating and downloading 
an API key here: 

https://docs.fortinet.com/document/lacework-forticnapp/latest/api-reference/863111/about-the-lacework-forticnapp-api

Once you have created an API key There are three ways to specify the Lacework FortiCNAPP API instance/credentials used when generating a report:

1. Install and configure the Lacework FortiCNAPP CLI to setup a credentials file which this tool will read.
2. Specify a JSON file containing your API instance/credentials. 
3. Specify your credentials via variables.

### Method 1: Lacework FortiCNAPP CLI
Though it is not required, you may wish to install and configure the Lacework FortiCNAPP CLI to create a .lacework.toml file containing your API credentials. Instructions to do so can be found here: https://docs.fortinet.com/document/lacework-forticnapp/latest/cli-reference/68020/get-started-with-the-lacework-forticnapp-cli

### Method 2: JSON File

You may download an API key JSON file from your Lacework FortiCNAPP instance (Settings > Configuration > API keys) and specify it using the ````"--api-key-file"```` command line
parameter. 

### Method 3: Environment Variables

If you wish to configure the Lacework FortiCNAPP Client instance using environment variables, this tool honors the same
variables used by the Lacework FortiCNAPP CLI. The `account`, `subaccount`, `api_key`, `api_secret`, and `profile` parameters
can all be configured as specified below.

| Environment Variable | Description                                                          | Required |
| -------------------- | -------------------------------------------------------------------- | :------: |
| `LW_PROFILE`         | Lacework CLI profile to use (configured at ~/.lacework.toml)         |    N     |
| `LW_ACCOUNT`         | Lacework account/organization domain (i.e. `<account>`.lacework.net) |    Y     |
| `LW_SUBACCOUNT`      | Lacework sub-account                                                 |    N     |
| `LW_API_KEY`         | Lacework API Access Key                                              |    Y     |
| `LW_API_SECRET`      | Lacework API Access Secret                                           |    Y     |
## Query Time Ranges

By default the tool will query Lacework FortiCNAPP for data in the following time ranges:
```
Vulnerability Data Start: 25 hours prior to execution time -> End : Current time at execution
Alert Data Start Time: 7 days prior to execution time -> End: Current time at execution
```
If you with to change the time range of these queries you can specify new start and stop times using the following flags:

```
--vulns-start-time
--vulns-end-time
--alerts-start-time
--alerts-end-time
```

To use these flags you must specify a number of days and hours prior to execution time in the format `````"days:hours"`````

For example to specify a 14 day window for alerts you would specify:
```
lw_report_gen.py --author your_name --customer your_customer --alerts-start-time 14:0
```

Whereas to specify a 7 day window for alerts that starts 2 weeks in the past you would specify:
```
lw_report_gen.py --author your_name --customer your_customer --alerts-start-time 14:0 --alerts-end-time 7:0
```
## Cached Data

To simplify development and limit the API calls made to a provider's backend, the main CLI interface supports the `--cache-data` flag. 
If you are customizing this script you may wish to use this flag to speed up script execution during testing and eliminate most of the API calls to Lacework FortiCNAPP. 
Note that the cache files created the first time you use this flag will be used in all subsequent runs in which you use this flag. They will not expire. 
If you want to create new cache files you need to manually delete the cache files. For instance on Mac and Linux:
```
rm *.cache
```

## Logging

The script will generate a log file called ```lw_report_gen.log```If you encounter an issue or bug please include the relevant log entries when filing an issue on our github page. 

## Contributing

Open a pull request!


Have a look at the default CSA report in `modules/reports/reportgen_csa.py`  for an example.

This tool uses the "jinja2" templating engine to generate the report HTML. Depending on how customized
you want your report to be you may also need to create a custom jinja2 template and 
put it in the `templates` folder. You can then reference this template in your custom report class.  

## License and Copyright

Copyright 2025, Fortinet Inc.

```
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
