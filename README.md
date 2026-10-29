# Python Security Automation & Log Correlation Toolkit

An **offline-first, free Python cybersecurity portfolio project** for analyzing Linux
OpenSSH and Windows Security XML authentication logs, finding suspicious login
patterns, correlating related events into incidents, and generating
**evidence-linked investigation timelines**.

**Version:** 0.6.0 | **Current milestone:** Phase 6 — Advanced CLI & Configuration

> Phase 10 — a modern, local browser dashboard — is a required deliverable.
> The CLI and future web UI will share the same Python services and data models.

## Implemented features

- Normalization of Linux `sshd` syslog records (explicit year and UTC offset)
- Windows Security XML Event IDs `4624` (success) and `4625` (failure)
- JSON-safe UTC `SecurityEvent` records retaining original source references
- YAML-configurable brute force, password spraying, and success-after-failures rules
- Host/IP/platform-bounded incident correlation and stable incident identifiers
- Evidence-linked investigation timelines, conservative summaries and suggested checks
- `parse`, `detect`, `correlate`, `timeline` CLI commands (backward compatible)
- **Phase 6:** `analyze` single-step raw-log workflow (no temporary normalized files)
- **Phase 6:** `config show`, `config validate`, and `doctor` commands
- **Phase 6:** output safeguards (`--force` required to replace existing reports)
- Framework-independent services for a future local Streamlit dashboard
- Synthetic authentication datasets and a regression test suite

## Requirements

- Windows 11 + VS Code, Python 3.13+, Git
- Free libraries: PyYAML and pytest (installed through `.[dev]`)
- No paid API, network service, cloud account, or WSL required

## Windows setup or upgrade

Open the existing project folder in VS Code. From its PowerShell terminal:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m security_log_toolkit --version
.\.venv\Scripts\python.exe -m pytest -v
```

Do not recreate `.venv` or overwrite `.git` when applying a phase ZIP.

## Recommended Phase 6 demo — one command on raw logs

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit analyze --linux samples/linux/attack_auth.log --windows samples/windows/attack_security.xml --year 2026 --utc-offset +08:00 --rules config/detection_rules.yaml --correlation-config config/correlation_rules.yaml --output reports/phase6_analysis.json
```

Expected: **2 source files, 29 normalized events, 2 unsupported records, 6 findings,
4 incidents, 4 timelines, and 22 evidence events linked to detections**.

The command loads raw logs, normalizes, detects, correlates, constructs timelines,
and returns one complete structured report. It works **without creating temporary
normalized JSON files**. `--linux` and `--windows` may be repeated for multiple files.

The Linux parser requires `--year` and `--utc-offset` in this new workflow to avoid
assuming time metadata absent from traditional syslog. For Windows-only input,
these options are not needed.

Running the command again with the same `--output` is blocked unless you add
`--force`. Source logs and YAML configuration are protected **even with** `--force`.
Use `--summary` without `--output` to see a brief textual summary; by default,
without `--output`, the full report is printed as JSON.

## Configuration inspection and environment check

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit config show
.\.venv\Scripts\python.exe -m security_log_toolkit config validate
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
.\.venv\Scripts\python.exe -m security_log_toolkit doctor --json
```

Run from the project root, where the default YAML configurations reside.
Use `--rules` and `--correlation-config` to point to custom YAML files.
Configuration reading uses safe YAML parsing with strict field validation.

## Original multi-step pipeline remains supported

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse linux samples/linux/attack_auth.log --year 2026 --utc-offset +08:00 --output reports/linux_attacks.json
.\.venv\Scripts\python.exe -m security_log_toolkit parse windows samples/windows/attack_security.xml --output reports/windows_attacks.json
.\.venv\Scripts\python.exe -m security_log_toolkit detect reports/linux_attacks.json reports/windows_attacks.json --output reports/phase3_findings.json
.\.venv\Scripts\python.exe -m security_log_toolkit correlate reports/linux_attacks.json reports/windows_attacks.json --output reports/phase4_incidents.json
.\.venv\Scripts\python.exe -m security_log_toolkit timeline --incident-report reports/phase4_incidents.json --output reports/phase5_timelines.json
```

You can also invoke `timeline` directly on normalized JSON files as before.

## Reusable Python services for Phase 10

```python
from pathlib import Path
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs
from security_log_toolkit.configuration import inspect_configuration

settings = inspect_configuration(
    Path("config/detection_rules.yaml"), Path("config/correlation_rules.yaml")
)
report = analyze_raw_logs(
    [
        RawLogSource("linux", Path("samples/linux/attack_auth.log")),
        RawLogSource("windows", Path("samples/windows/attack_security.xml")),
    ],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
    year=2026,
    utc_offset="+08:00",
)
```

Both services return JSON-safe dicts and **never print or save reports**. This
keeps the future Streamlit UI independent of CLI argument parsing. The older
`investigate()` and `investigate_with_timelines()` functions remain supported.

## Documents

- [CLI Guide](docs/CLI_GUIDE.md) — examples, options, troubleshooting
- [Investigation Guide](docs/INVESTIGATION_GUIDE.md) — cautious evidence interpretation
- [Official Roadmap](docs/ROADMAP.md) — Phases 0–10, including required dashboard

## Scope, limitations and safety

- Use **synthetic or explicitly authorized** logs. Never commit real authentication
  credentials, sensitive user activity or confidential incident records.
- Reports in `reports/` are excluded from Git by the existing `.gitignore`.
- Linux: classic OpenSSH syslog-format events. Windows: Security **XML exports only**,
  not binary `.evtx`. Live monitoring, remote collection, and remediation are not present.
- Incident timelines contain **only evidence linked to findings**, not full host history.
- A successful login after multiple failures is not proof of compromise.
- Phase 7 adds robust CSV/JSON export options; Phase 10 adds the local browser UI.

## License

MIT. See your existing `LICENSE` file, which is not replaced by phase updates.
