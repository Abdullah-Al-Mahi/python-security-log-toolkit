# Phase 6 CLI Guide — Offline Workflow & Configuration

All examples use Windows PowerShell from the **project root**.

## Verify the project

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit --version
.\.venv\Scripts\python.exe -m security_log_toolkit status
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
.\.venv\Scripts\python.exe -m security_log_toolkit doctor --json
```

`doctor` checks the Python version and validates both YAML files. It does not
install or repair software, contact the network, or access Windows Security logs.

## Validate or inspect configuration

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit config validate
.\.venv\Scripts\python.exe -m security_log_toolkit config show
```

Optionally specify custom YAML files:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit config validate --rules config/detection_rules.yaml --correlation-config config/correlation_rules.yaml
```

The JSON output of `config show` can be used directly in the Phase 10 dashboard.
Both commands are read-only. Invalid or unsafe YAML is rejected.

## One-command analysis from raw logs

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --output reports/phase6_analysis.json
```

Expected:

```text
Processed 2 source files; normalized 29 events (2 unsupported records skipped).
Detected 6 findings; created 4 incidents and 4 timelines (22 linked evidence events).
Saved investigation JSON: reports\phase6_analysis.json
```

The output includes full incident and finding records, incident timelines,
linked evidence, a per-source ingestion summary and counts. Linked evidence is
only a subset of normalized events. The CLI does not store extra intermediate
normalized files during this workflow.

To see a concise summary **without writing a file**:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --summary
```

With no `--output` and no `--summary`, the CLI emits the complete JSON report on
stdout. The `--linux` and `--windows` options may be repeated for more files.
Use explicit timezone details for Linux; Windows-only analysis does not require them.

### Output protection

Existing report files are **not overwritten** by the `analyze` command unless
`--force` is specified. You can rerun the same demonstration using:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --output reports/phase6_analysis.json --force
```

Source logs or the chosen YAML configuration cannot be overwritten, even with
`--force`. This guarantee applies to the new `analyze` command; legacy commands
retain their earlier file output semantics for compatibility.

## Existing commands remain supported

- `parse linux PATH --year YYYY --utc-offset +HH:MM [--output PATH]`
- `parse windows PATH [--output PATH]` (Windows Security XML, not `.evtx`)
- `detect NORMALIZED.json [NORMALIZED.json ...] [--rules PATH] [--output PATH]`
- `correlate NORMALIZED.json ... [--rules PATH] [--correlation-config PATH] [--output PATH]`
- `timeline NORMALIZED.json ... [--rules PATH] [--correlation-config PATH] [--output PATH]`
- `timeline --incident-report INCIDENTS.json [--output PATH]`

All commands also have `--help`. Use `security-log.exe` in the virtual environment
as an alternative to `python.exe -m security_log_toolkit`.

## Troubleshooting

- **`security-log: error: Linux sources require both --year and --utc-offset`**:
  add the log's calendar year and actual local timezone offset. Never assume
  `+08:00` for a log generated outside Malaysia.
- **`Output already exists; use --force`**: choose a new output filename or add
  `--force` only when replacing the generated report is intended.
- **`Input file does not exist`**: run from the correct project root and verify
  the filename with `Test-Path`.
- **Invalid YAML**: check the supplied rules/settings against the sample configs.
- **`.evtx is not supported`**: export Windows Security events to supported XML first.
- **`python was not found`**: use `\.venv\Scripts\python.exe` exactly as shown.

## Interpreting security findings

Rules detect patterns **for investigation**, not confirmed intrusions. A timeline
records only evidence linked to detection findings, rather than all system activity.
Do not upload real authentication logs, personal data, or security incidents to
public repositories or third-party services.
