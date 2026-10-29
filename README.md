# Python Security Automation & Log Correlation Toolkit

A **free, offline-first** Python security automation project for analyzing Linux and
Windows authentication logs, detecting suspicious patterns, correlating related
findings and constructing evidence-linked investigation timelines. Built on Windows 11
with Python 3.13, and suitable for a cybersecurity internship portfolio.

## Current milestone: Phase 5 — Version 0.5.0

**Implemented:**

- Linux OpenSSH `sshd` authentication log parsing with explicit timezone/year inputs
- Windows Security **XML** Event 4624/4625 parsing (not binary `.evtx`)
- Consistent, timezone-aware `SecurityEvent` model and normalized JSON files
- Three YAML-configurable detections: brute force, password spraying and login after failures
- Incident correlation by platform, host, source IP and configurable time windows
- Deterministic incident IDs with unique evidence references and linked finding IDs
- **Evidence-linked, chronological incident timelines** with relative timing and source provenance
- Conservative incident summaries, observed patterns and suggested investigation checks
- Reusable `investigate_with_timelines()` and `attach_timelines()` services for Phase 10 web UI
- Free local CLI, automated tests, and synthetic Linux/Windows attack datasets

**Still planned:** Enhanced CLI (Phase 6), CSV and expanded JSON exports (Phase 7),
security/robustness testing (Phase 8), portfolio documentation (Phase 9), and the
**required modern, local Streamlit web dashboard (Phase 10)**.

Official roadmap: [docs/ROADMAP.md](docs/ROADMAP.md).
Investigation interpretation: [docs/INVESTIGATION_GUIDE.md](docs/INVESTIGATION_GUIDE.md).

## Windows setup

Use the existing project `.venv` — do **not** recreate it or delete Git history.
From the project root in VS Code PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m security_log_toolkit --version
.\.venv\Scripts\python.exe -m pytest -v
```

No additional third-party dependency is required beyond Phase 4's PyYAML and pytest.

## End-to-end sample workflow

### 1. Parse synthetic authentication logs

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse linux samples/linux/attack_auth.log --year 2026 --utc-offset +08:00 --output reports/linux_attacks.json
.\.venv\Scripts\python.exe -m security_log_toolkit parse windows samples/windows/attack_security.xml --output reports/windows_attacks.json
```

Expected: **15 Linux** events and **14 Windows** events; each sample skips one unsupported
record. Linux syslog has no embedded year or timezone, so these are specified.

### 2. Detect suspicious activity (Phase 3)

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit detect reports/linux_attacks.json reports/windows_attacks.json --rules config/detection_rules.yaml --output reports/phase3_findings.json
```

Expected: **six findings** (two each for brute force, password spraying, and successful
login after failures).

### 3. Correlate findings (Phase 4)

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit correlate reports/linux_attacks.json reports/windows_attacks.json --rules config/detection_rules.yaml --correlation-config config/correlation_rules.yaml --output reports/phase4_incidents.json
```

Expected: **four incidents** from six findings (two correlated and two single-finding).

### 4. Build evidence-linked timelines (new Phase 5)

**Option A — Create timelines directly from normalized files:**

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit timeline reports/linux_attacks.json reports/windows_attacks.json --rules config/detection_rules.yaml --correlation-config config/correlation_rules.yaml --output reports/phase5_timelines.json
```

**Option B — Enrich the existing Phase 4 incident JSON without rerunning detection:**

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit timeline --incident-report reports/phase4_incidents.json --output reports/phase5_timelines_from_report.json
```

Both options should produce **four incident timelines containing 22 linked evidence
entries**. These are the **22 deduplicated evidence events associated with findings**,
not all 29 normalized input events. Two incidents include an observed successful login.

Each incident gains a `timeline` object containing:

- `scope`: `linked_detection_evidence_only` (an explicit coverage warning)
- `first_seen`, `last_seen`, `duration_seconds`, and `event_count`
- `failed_logins`, `successful_logins`, `affected_accounts`, `observed_pattern`
- Conservative `analyst_summary` and `recommended_checks` (not automated actions)
- `events` sorted by UTC timestamp, each containing `sequence`, `evidence_id`,
  `seconds_from_start`, source filename/line/record ID, and `linked_finding_ids`

The top-level report adds `timeline_summary` and `timeline_generator_version`, while
keeping all Phase 4 fields intact. When enhancing a Phase 4 file, the original
`tool_version` stays `0.4.0` for provenance and the new `timeline_generator_version`
identifies the `0.5.0` enrichment.

### Show a timeline in PowerShell

```powershell
$report = Get-Content 'reports\phase5_timelines.json' -Raw | ConvertFrom-Json
$report.timeline_summary | Format-List
$first = $report.incidents | Select-Object -First 1
$first.timeline | Select-Object incident_id, observed_pattern, analyst_summary | Format-List
$first.timeline.events | Select-Object sequence, timestamp, stage, account, evidence_id | Format-Table -AutoSize
```

## Development tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The full suite includes regression coverage for Phases 1–4 and additional Phase 5
validation for ordering, UTC offsets, evidence traceability, Windows domains,
non-mutating services, output protection and sample workflows.

## Reusable Python API for the future web dashboard

```python
from pathlib import Path
from security_log_toolkit.investigation import investigate_with_timelines, attach_timelines

report = investigate_with_timelines(
    [Path("reports/linux_attacks.json"), Path("reports/windows_attacks.json")],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
)

# Or enrich a Phase 4 report already held in memory:
# timeline_report = attach_timelines(phase4_report_dict)
```

The analysis services have **no dependency on terminal output, Streamlit, a database,
cloud hosting or paid APIs**. Phase 10 will reuse them in a browser dashboard running
on localhost.

## Important evidence limitations

- These timelines include **only events linked to detection findings**, not every log
  entry. The raw input may contain events absent from the incident timeline.
- A successful authentication after failures is an **observation**, not proof of
  compromise or attribution. Investigators must corroborate with other records.
- Read and analyze **only synthetic or explicitly authorized security logs**. Do not
  publish private user, IP or authentication data in a public portfolio.
- The current tool supports Windows Security **XML** exports, not binary `.evtx`.
- The tool does not yet perform live collection, remote monitoring, or remediation.
- Outputs under `reports/` are excluded from Git to avoid accidental disclosure.

## License

MIT — see your existing `LICENSE` file. Phase updates do not replace that file.
