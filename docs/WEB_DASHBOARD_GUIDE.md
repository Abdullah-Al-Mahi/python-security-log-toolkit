
# Sentinel Prism — Local Dashboard Guide

**Application:** Sentinel Prism SOC Dashboard  
**Version:** 1.0.0  
**Status:** Implemented and accepted for local use

## Overview

I built Sentinel Prism as an interactive interface over the existing Python security-analysis toolkit.

The dashboard provides investigation summaries, log intake, incident filtering, evidence timelines, session-based detection configuration, synthetic validation, and report exports.

The CLI and dashboard share the same backend services.

## Requirements

- Python 3.13 or newer
- Windows 11 or another supported Python environment
- Streamlit and optional web dependencies
- A modern browser

## Installation

Open a terminal at the repository root.

For my Windows development environment, the project directory is:

```text
E:\CS PROJECTS\python-security-log-toolkit
```

Create a virtual environment if one does not already exist:

```powershell
py -3.13 -m venv .venv
```

Install the dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev,web]"
```

Start the local application:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

Open http://127.0.0.1:8501.

Stop the server with Ctrl+C in the terminal.

## Dashboard Workspaces

### 1. Command Center

The Command Center provides summary metrics, severity analysis, detection rule counts, source-IP insights, and linked evidence activity.

The bundled synthetic demo contains:

| Metric | Value |
|---|---:|
| Events | 29 |
| Findings | 6 |
| Incidents | 4 |
| Linked evidence events | 22 |

These values come from synthetic fixtures, not live network telemetry.

### 2. Log Intake

The upload interface supports:

- Linux OpenSSH `.log` and `.txt` files.
- Windows Security Event XML `.xml` exports.
- Existing toolkit investigation JSON files for review.

Linux input requires an explicit calendar year and timezone offset.

Binary `.evtx` input is not supported.

Upload limits are 4 files, 16 MiB per raw file, and 32 MiB combined.

### 3. Incident Explorer

Investigations can be filtered using severity, platform, detection rule, source IP, hostname, account, or incident identifier.

Case details display incident relationships and linked evidence.

### 4. Evidence Timeline

This workspace presents chronological linked authentication evidence with source references.

The timeline is limited to detection-linked records and is not a complete forensic log history.

### 5. Detection Lab

I implemented session-only configuration controls for enabling rules and adjusting thresholds, time windows, severity, and correlation limits.

Configuration changes affect new analyses. Existing investigation results are not automatically recomputed.

The original YAML files remain unchanged unless deliberately modified outside the dashboard.

### 6. Validation & Performance

This workspace calls the backend's labeled synthetic scenario evaluator and bounded in-memory benchmark.

Synthetic accuracy metrics are not estimates of real-world detection rates.

Benchmark results do not include complete log ingestion, disk I/O, or UI rendering.

### 7. Report Center

The reporting workspace downloads:

- `summary.csv`
- `incidents.csv`
- `findings.csv`
- `evidence.csv`
- `timelines.csv`
- `investigation.json`
- `export_manifest.json`

The SHA-256 manifest supports integrity checking relative to its recorded hashes; it is not a digital signature.

## Appearance

Sentinel Prism includes light and dark appearance modes.

The sidebar switch changes the interface appearance for the current browser session.

Visual customization is implemented in:

- `dashboard/app.py`
- `dashboard/sentinel.css`
- `.streamlit/config.toml`

The theme does not change the analysis results.

## Privacy and Security

I designed the dashboard primarily for local, single-user operation.

- The default server binds to `127.0.0.1`.
- No application login system is implemented.
- Raw uploads are processed through temporary files.
- Temporary files are removed after analysis.
- Streamlit may retain uploaded data in server memory during a session.
- Reports are generated for local download rather than automatically published.
- Input validation and size limits apply.

The application should not be exposed directly to the public internet or used as an authenticated multi-user SOC platform.

Only authorized logs should be analyzed.

## Testing

Run the regression suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Check environment diagnostics:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
```

At Phase 10 acceptance, 460 automated tests passed and all seven workspaces were manually verified on Windows 11.

Further UI updates require fresh tests.

## Limitations

Sentinel does not provide real-time network telemetry, native binary EVTX parsing, continuous enterprise log ingestion, production SIEM integrations, or automated response actions.

The interface is a local investigation prototype that demonstrates the underlying Python security-analysis workflow.

## Related Documentation

- [Architecture](ARCHITECTURE.md)
- [CLI Guide](CLI_GUIDE.md)
- [Security Validation](SECURITY_VALIDATION_GUIDE.md)
- [Reporting](REPORTING_GUIDE.md)
