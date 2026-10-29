# Phase 7 — Investigation Reporting & CSV/JSON Export Guide

## Overview

The toolkit reads supported Linux OpenSSH and Windows Security XML authentication
logs, detects suspicious authentication activity, correlates findings, and builds
an evidence-linked incident report. Phase 7 adds **reusable read-only reporting**
on top of existing Phase 4/5/6 report JSON. It does not change the detection
engine or construct extra alerts.

## CLI examples (Windows PowerShell, VS Code terminal)

```powershell
# Start in your existing project folder:
Set-Location "$HOME\CyberSecurity-Projects\python-security-log-toolkit"

# Create a report using the Phase 6 workflow (only if not already generated):
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --output reports/phase7_analysis.json

# Print a concise investigation summary:
.\.venv\Scripts\python.exe -m security_log_toolkit report --input reports/phase7_analysis.json

# Build a folder containing all export formats:
.\.venv\Scripts\python.exe -m security_log_toolkit export --input reports/phase7_analysis.json --format both --output-dir reports/phase7_export
```

Available formats: `csv`, `json`, `both` (default). Output filenames:

| File | Contents | Expected sample rows |
|---|---|---:|
| `summary.csv` | One row of investigation metrics and evidence scope | 1 |
| `incidents.csv` | Incidents, accounts, rule IDs, analyst summaries | 4 |
| `findings.csv` | Detection findings and their incident associations | 6 |
| `evidence.csv` | Incident-linked source evidence and provenance | 22 |
| `timelines.csv` | Incident-linked chronological activity | 22 |
| `investigation.json` | Original nested report data in JSON | — |
| `export_manifest.json` | Format, export version, file hashes and row counts | — |

CSV output uses UTF-8 with BOM for Excel and CRLF rows; rows are escaped using
Python's `csv` library. Text cells that look like formulas after leading
spaces/control characters are prefixed with an apostrophe for safer spreadsheet
opening. This reduces common CSV injection patterns but does not replace normal
caution with untrusted spreadsheet data.

The output's SHA-256 digests detect accidental changes; they are not digital
signatures and do not prove authenticity. Preserve the original logs and their
chain of custody for actual investigations.

### Output safety

The input report must be a valid **incident investigation** report (not merely
normalized events or a detection-only report). The CLI limits input reports
to 50 MiB. A destination directory must not already exist unless `--force` is
supplied. Even with `--force`, a directory that has no toolkit export manifest
or includes unexpected files will not be overwritten. The CLI will not write
into a directory containing its input report. The original report is never
modified. Generated folders under `reports/` are intentionally Git-ignored.

### Older report compatibility

Phase 4 incident JSON is accepted. Without timelines, `timelines.csv` contains
only headers and the summary correctly records zero timelines. Phase 5 reports
and full Phase 6/7 reports contain timeline data. Reports can contain personal
or sensitive authentication data — use synthetic or authorized data and do not
publish real incident exports.

## Reusable Python API (for Phase 10)

```python
import json
from pathlib import Path
from security_log_toolkit.reporting import (
    build_report_tables,
    build_export_artifacts,
    summarize_report,
)

report = json.loads(Path("reports/phase7_analysis.json").read_text(encoding="utf-8"))

print(summarize_report(report))
tables = build_report_tables(report)   # Dict of row dictionaries for filtering/charts
files = build_export_artifacts(report, "both")  # filename -> bytes, zero disk writes

# Streamlit can pass bytes directly to st.download_button, e.g.:
# st.download_button("Download findings CSV", files["findings.csv"],
#                    file_name="findings.csv", mime="text/csv")
```

The web dashboard must **reuse** these services, not duplicate CSV mapping,
YAML validation, or detection logic. Do not publicly host sensitive logs.

## Verify the complete project

```powershell
.\.venv\Scripts\python.exe -m pytest -v
.\.venv\Scripts\python.exe -m security_log_toolkit status
```

The synthetic input fixture `samples/reports/synthetic_investigation.json` is
tracked for reproducible unit tests and offline demonstrations.
