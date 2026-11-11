
# Sentinel — Command-Line Interface Guide

## Overview

I designed Sentinel with a standalone Python command-line interface so authentication analysis, incident investigation, validation, and reporting can be performed without opening the Streamlit dashboard.

The CLI and dashboard use the same underlying Python services.

All examples below run from the repository root.

## Requirements

- Python 3.13 or newer.
- The project's Python virtual environment.
- Installed project dependencies.

Install the development dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

The optional Streamlit interface can be installed separately using `.[dev,web]`.

## 1. Verify the Environment

Check the version:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit --version
```

Display feature availability:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit status
```

Run environment diagnostics:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
```

`doctor` validates the Python environment and supported configuration files. It does not automatically repair software or contact remote systems.

## 2. Inspect Configuration

Validate the committed rules:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit config validate
```

Inspect the current configuration:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit config show
```

Configuration is stored in:

```text
config/detection_rules.yaml
config/correlation_rules.yaml
```

The CLI uses validated YAML rather than evaluating arbitrary Python expressions.

## 3. Analyze Authentication Logs

The unified `analyze` command processes raw supported input formats and returns an investigation report.

Example using bundled synthetic files:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --output reports/investigation.json
```

The bundled demonstration produces:

| Metric | Expected |
|---|---:|
| Normalized events | 29 |
| Detection findings | 6 |
| Incidents | 4 |
| Investigation timelines | 4 |
| Linked evidence entries | 22 |

The explicit year and timezone offset apply to the bundled Linux demonstration. For other logs, use their actual year and original timezone offset.

### Show a Summary Without Writing a Report

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --summary
```

Without a requested output or summary, the CLI can emit the full JSON investigation to standard output.

## 4. Read an Investigation Report

After generating `reports/investigation.json`:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit report --input reports/investigation.json
```

The summary includes event counts, findings, incident counts, severity, and linked timeline evidence.

## 5. Export Investigation Data

Generate CSV and JSON reports:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit export --input reports/investigation.json --format both --output-dir reports/investigation_exports
```

Supported formats:

- `csv`
- `json`
- `both`

The combined format creates five CSV files, a JSON investigation report, and a SHA-256 manifest.

See [REPORTING_GUIDE.md](REPORTING_GUIDE.md) for file details.

## 6. Earlier CLI Commands

The toolkit also retains the earlier commands:

| Command | Purpose |
|---|---|
| `parse` | Convert supported raw authentication logs into normalized events |
| `detect` | Run configured detection rules |
| `correlate` | Group findings into incidents |
| `timeline` | Generate linked investigation timelines |
| `analyze` | Execute the integrated raw-log workflow |
| `report` | Display an analyst-readable summary |
| `export` | Produce structured investigation artifacts |
| `config` | Inspect and validate YAML settings |
| `doctor` | Check environment readiness |
| `validate` | Evaluate labeled synthetic detection scenarios |
| `benchmark` | Measure bounded in-memory processing |
| `status` | Display project capabilities |

Use `--help` with a command to inspect its supported options.

## 7. Synthetic Validation

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit validate
```

This evaluates rule/source-IP presence against labeled synthetic scenarios.

The results do not establish real-world detection accuracy.

## 8. Performance Benchmark

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit benchmark --events 1000 --runs 3
```

The benchmark measures an in-memory workflow, not end-to-end SIEM ingestion.

## 9. Portfolio Demonstration

Generate repeatable synthetic demonstration artifacts:

```powershell
.\.venv\Scripts\python.exe scripts/demo_portfolio.py --output-dir reports/portfolio_demo
```

The destination should not already exist. For another run, use a different output directory.

The demo uses bundled synthetic fixtures.

## 10. Publication Safety Audit

Inspect currently Git-tracked files for selected publication risks:

```powershell
.\.venv\Scripts\python.exe scripts/audit_portfolio.py
```

This is a limited local audit, not a comprehensive secret scanner or historical Git review.

## 11. Output Protection

Generated reports are generally protected against accidental overwriting.

Selected commands allow `--force` when replacing a generated output is intentional.

The CLI protects source and configuration paths according to each command's validation rules.

Use a new output path if an existing report should be preserved.

## 12. Troubleshooting

**Missing Python environment:** Create `.venv` and install dependencies.

**Missing source file:** Confirm the working directory and relative path.

**Linux year/timezone required:** Provide the correct `--year` and `--utc-offset`.

**Output already exists:** Choose a new filename or review the command's supported `--force` option.

**Invalid YAML:** Review the rule settings and supported schema.

**Unsupported EVTX:** Export Windows authentication records to supported XML before analysis.

**Streamlit not installed:** Install the optional `web` dependencies. The CLI does not require Streamlit.

## 13. CLI and Dashboard Relationship

I retained the CLI as a first-class interface when developing Sentinel Prism.

The Streamlit dashboard uses the existing backend instead of reimplementing detection, correlation, or reporting logic.

This separation makes it possible to maintain both interfaces without duplicating security-analysis functionality.

## Security Scope

The toolkit is a local authentication investigation prototype.

Its findings are indicators for analyst review, not confirmed intrusions. Linked timelines do not represent complete system activity.

Only authorized log data should be processed.
