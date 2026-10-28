# Python Security Automation & Log Correlation Toolkit

An offline-first Python project for normalizing authentication logs, then adding security detections, correlation and incident-investigation workflows.

## Status

**Version:** 0.2.0  
**Current milestone:** Phase 2 — Linux / Windows ingestion and normalization

**Implemented:** Python package, CLI, Linux OpenSSH syslog parser, Windows Security XML parser (4624/4625), normalized UTC events, synthetic example data, pytest tests.

**Not implemented yet:** Detection rules, correlation, incident timelines, finding reports, CSV export, live Windows collection, direct binary `.evtx` parsing.

## Prerequisites

- Windows 11 / PowerShell / VS Code
- Python 3.13+ (verified in Phase 0)
- Git (optional for running; used for version control)

## Setup (Windows PowerShell)

From the project root, create and use a project-only virtual environment:

```powershell
& "C:\Program Files\Python314\python.exe" -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

Your Python executable location may differ. Avoid recreating an already working `.venv`.

## Run the CLI

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit --help
.\.venv\Scripts\python.exe -m security_log_toolkit status
```

Parse Linux SSH authentication messages in traditional `/var/log/auth.log` syslog format:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse linux samples/linux/auth.log --year 2026 --utc-offset +08:00 --output reports/linux_normalized.json
```

Parse a Windows Security event XML export containing Event ID 4624 and 4625:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse windows samples/windows/security.xml --output reports/windows_normalized.json
```

Omit `--output` to print normalized JSON directly to the terminal.

**Important:** Traditional Linux syslog timestamps omit both year and timezone. Always supply the source log's actual year and UTC offset. Windows `SystemTime` timestamps include a timezone and are converted to UTC. Data is sorted chronologically within each input file.

## Normalized event schema

- `timestamp` — UTC ISO 8601 timestamp, ending with `Z`
- `platform` — `linux` or `windows`
- `event_type` — `login_success` or `login_failure`
- `hostname`, `username` — target host and account
- `source_ip`, `source_port` — IP and port; null when unavailable
- `authentication_method` — e.g. `password`, `publickey`, or `NTLM`
- `event_id` — `sshd`, `4624`, or `4625`
- `record_id` — Windows EventRecordID, if available
- `source_file`, `source_line` — original file reference, and line number for Linux
- `details` — extra context such as Windows logon type/status or Linux invalid-user flag

JSON contains `summary.records_examined`, `summary.normalized`, `summary.skipped`, `summary.login_success`, and `summary.login_failure`.

## Supported input and limitations

- Linux: **syslog-style OpenSSH `sshd` Accepted/Failed password, publickey and keyboard-interactive/pam** events, UTF-8. Other lines are counted as skipped.
- Windows: **UTF-8/UTF-16 XML** with a single `<Event>` or an `<Events>` root containing `<Event>` children in the Microsoft event XML namespace (or without namespace). Only IDs 4624/4625 are normalized; other IDs are counted as skipped.
- Binary Windows `.evtx` files are **not supported yet**. Export records to XML before parsing.
- XML must be a valid single document, not multiple standalone XML documents concatenated together.
- `skipped` means out-of-scope or unrecognized records, **not** proof that each source log entry was fully understood. Recognized malformed records cause an explicit error.
- Windows source IPs may be missing or `-` for local/service logons; null in the normalized event is correct.
- Windows fractional timestamps are stored at Python's microsecond precision (more precise original fractions are truncated).
- No detection alert is generated in this phase: parsing is not evidence of a threat.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Folder layout

- `src/security_log_toolkit/` — Python code
- `src/security_log_toolkit/parsers/` — source-specific parsers
- `tests/` — test suite
- `samples/linux/` and `samples/windows/` — entirely synthetic logs
- `config/` — future detection rules
- `reports/` — generated output (ignored by Git)

## Privacy and security

Only analyze logs that you own or are authorized to inspect. Real security logs can include usernames, IP addresses and other sensitive data. Do not commit genuine records to a public GitHub repository. The sample IPs use documentation-only ranges.

## License

MIT — see `LICENSE`.
