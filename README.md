# Python Security Automation & Log Correlation Toolkit

An **offline-first, free** Python cybersecurity portfolio project for analyzing Linux and
Windows authentication logs, detecting suspicious login activity, and grouping related
findings into investigator-friendly incidents. Designed for Windows 11 and Python 3.13.

## Project status

**Version 0.4.0 — Phase 4: Event Correlation Engine**

Already implemented:

- Linux OpenSSH authentication syslog parsing (`sshd` accepted/failed messages)
- Windows Security XML parsing (Event IDs 4624 and 4625; binary `.evtx` not yet supported)
- UTC-normalized `SecurityEvent` representation with source evidence metadata
- YAML-configurable brute-force, password spraying, and success-after-failures rules
- Deterministic security finding IDs and JSON output
- Incident grouping by platform, hostname, source IP and bounded time proximity
- Stable incident IDs, severity, finding references and **deduplicated** event evidence
- An importable, CLI-independent `investigate()` function for the future local web dashboard
- Offline synthetic Linux/Windows attack datasets and automated tests
- A professional CLI with `status`, `parse`, `detect`, and **`correlate`** commands

Still planned: full investigation timelines (Phase 5); enhanced CLI (6);
CSV/JSON export improvements (7); validation and resilience (8); portfolio preparation (9);
and the **required modern Streamlit web dashboard (Phase 10)**.
The existing JSON evidence list is not yet the full analyst timeline feature.

For the official eleven-phase roadmap, see [docs/ROADMAP.md](docs/ROADMAP.md).

## Phase 4 upgrade — Windows PowerShell

Keep your existing `.venv`, `.git` and `reports/` directory. Apply the Phase 4 ZIP from
inside your project folder. Then reinstall this project in editable mode:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m security_log_toolkit --version
.\.venv\Scripts\python.exe -m pytest -v
```

No new runtime library is needed beyond Phase 3 (PyYAML); YAML is read with `safe_load()`.
No API keys, cloud accounts or paid subscriptions are required.

## 1. Parse the sample attack logs

Traditional Linux syslog does not include a year or timezone; specify both:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse linux samples/linux/attack_auth.log --year 2026 --utc-offset +08:00 --output reports/linux_attacks.json
.\.venv\Scripts\python.exe -m security_log_toolkit parse windows samples/windows/attack_security.xml --output reports/windows_attacks.json
```

Expected counts: Linux **15 normalized** and **1 skipped**; Windows **14 normalized** and **1 skipped**.

## 2. Detect suspicious logins (Phase 3 command still works)

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit detect reports/linux_attacks.json reports/windows_attacks.json --rules config/detection_rules.yaml --output reports/phase3_findings.json
```

Expected: **6 findings** — 2 brute force, 2 password spray, and 2 success-after-failures.

## 3. Correlate findings into incidents (new Phase 4 command)

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit correlate reports/linux_attacks.json reports/windows_attacks.json --rules config/detection_rules.yaml --correlation-config config/correlation_rules.yaml --output reports/phase4_incidents.json
```

Expected summary:

- `events_analyzed`: **29**
- `findings_analyzed`: **6**
- `total_incidents`: **4**
- `correlated_incidents`: **2** (brute force + success-after-failures, one Linux and one Windows)
- `single_finding_incidents`: **2** (one Linux and one Windows password-spray finding)
- `by_severity`: **2 critical**, **2 high**

If `--output` is omitted, the entire JSON report prints to stdout. The output path
cannot be the same as any input file or YAML configuration file.

## Correlation configuration

Edit `config/correlation_rules.yaml`:

```yaml
version: 1
correlation:
  max_gap_minutes: 15
  max_incident_minutes: 60
```

- `max_gap_minutes`: largest allowed delay between the next finding's first evidence
  and the current incident's most recent evidence.
- `max_incident_minutes`: maximum allowed span of an incident **when joining findings**.
- Both settings must be positive integers. Unknown YAML fields and unsafe YAML are rejected.
- Groups never cross **platform, host or source IP** boundaries. Host names are compared
  case-insensitively. Nearby activities across unrelated hosts are deliberately separate.
- Finding IDs and incident IDs are stable for the same evidence and configuration;
  repeated evidence inside several findings is stored once per incident with links
  to each contributing finding.
- **All** findings remain visible, including those without any correlation partner.
- Correlation is a context-building heuristic, **not** proof of a compromised system.

## Incident report JSON structure

Top-level keys:

- `tool_version`, `input_files`, `detection_rules_file`, `correlation_rules_file`
- `summary` — event/finding/incident counts and incident severity breakdown
- `incidents` — grouped incidents with linked finding IDs, affected accounts,
  normalized time boundaries, and chronological deduplicated evidence
- `findings` — complete original detection findings, preserved for traceability

## Reusable API (planned Phase 10 UI integration)

```python
from pathlib import Path
from security_log_toolkit.correlation import investigate

report = investigate(
    [Path("reports/linux_attacks.json"), Path("reports/windows_attacks.json")],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
)
```

`investigate()` returns a JSON-serializable dictionary. It has **no terminal,
web-server, network or Streamlit dependency**, and can be used by both the CLI and
future browser dashboard. The dashboard will run locally, without paid hosting.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Tests include earlier phase regression checks plus incident grouping, time and
host boundaries, deterministic IDs, shared-evidence deduplication, malicious
configuration rejection, CLI protection and a full synthetic dataset workflow.

## Privacy and limitations

Use synthetic or authorized logs only. No live collection or `.evtx` binary reading is
implemented. Do not commit real login information, credentials, tokens or private
incident reports to GitHub. Generated `reports/` output is ignored by Git.
Everything runs offline and is suitable for small/moderate datasets in memory.

## License

MIT — see `LICENSE`.
