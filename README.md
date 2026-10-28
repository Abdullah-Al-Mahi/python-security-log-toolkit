# Python Security Automation & Log Correlation Toolkit

An **offline-first, free** Python project for normalizing authentication logs and detecting suspicious login patterns. Developed primarily on Windows 11 with VS Code and Python 3.13.

## Project status

**Version 0.3.0 — Phase 3: Detection Rules Engine**

Implemented:

- Linux OpenSSH syslog ingestion (`sshd` Accepted/Failed messages)
- Windows Security XML ingestion (Event IDs **4624** and **4625**)
- Unified, UTC-normalized authentication-event schema
- YAML-configurable brute-force, password-spray, and successful-login-after-failures rules
- Deterministic finding IDs, source event evidence, severity, and JSON output
- Synthetic Linux and Windows attack datasets and automated tests
- Git-friendly package and CLI (`status`, `parse`, `detect`)

**Not implemented:** Cross-event investigation timelines, incident correlation, CSV export, direct `.evtx` ingestion, live log monitoring, and production SIEM integrations. These are later phases.

## Setup / upgrade (Windows PowerShell)

From `C:\Users\abmah\CyberSecurity-Projects\python-security-log-toolkit` with your existing `.venv`:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m security_log_toolkit --version
.\.venv\Scripts\python.exe -m pytest -v
```

The only new runtime dependency is **PyYAML**, used with `yaml.safe_load()` for safer configuration parsing. The project requires no API key or subscription.

## CLI: parse synthetic attack logs

Traditional Linux syslog lacks a year/timezone, so supply both accurately:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse linux samples/linux/attack_auth.log --year 2026 --utc-offset +08:00 --output reports/linux_attacks.json
```

Windows Security XML already carries timezone-aware timestamps:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse windows samples/windows/attack_security.xml --output reports/windows_attacks.json
```

The original Phase 2 examples and `parse` commands still work:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit parse linux samples/linux/auth.log --year 2026 --utc-offset +08:00 --output reports/linux_normalized.json
.\.venv\Scripts\python.exe -m security_log_toolkit parse windows samples/windows/security.xml --output reports/windows_normalized.json
```

## CLI: detect suspicious logins

Run all three rules across both normalized datasets:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit detect reports/linux_attacks.json reports/windows_attacks.json --rules config/detection_rules.yaml --output reports/phase3_findings.json
```

If you omit `--output`, the entire findings report prints as JSON. For CLI usage help:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit detect --help
```

### Expected findings from the synthetic attacks

Six findings total: **2 brute-force**, **2 password-spray**, **2 successful logins after repeated failures**. The finding's evidence includes source event timestamps, account names, IP addresses, event IDs, source paths, and line/record identifiers when available. Reports are written under `reports/` and ignored by Git.

## Rule configuration

Edit `config/detection_rules.yaml` when adjusting thresholds. YAML fields are strictly validated:

- `enabled`: true or false
- `severity`: low, medium, high, critical
- `window_minutes`: positive integer for the rolling time window
- `min_failures`: positive integer
- `min_distinct_accounts`: password-spray rule only, positive integer

The three implemented rules are **fixed rule types**, not a general-purpose custom rule language. To switch off a detection, set its `enabled` field to `false` (leave its other fields present). Running detection never changes the YAML file.

### Detection grouping and limitations

- Brute force: a configurable number of failed logins against **one account**, from **one source IP**, on **one host/platform**, within a rolling time window.
- Password spray: a configurable number of failures across distinct accounts from **one source IP**, on **one host/platform**, within a rolling window.
- Success after failures: a successful login after enough recent failed attempts for the **same source IP, host and account**. A successful login resets the prior-failure sequence to reduce repeat alerts.
- Overlapping qualifying windows for brute-force and spraying are merged into one finding, reducing alert spam. Distinct bursts separated by an inactive period can produce separate findings.
- Windows account matching is case-insensitive and domain-aware; Linux account matching is case-sensitive.
- Local logons with missing IPs are retained in normalized input but excluded from IP-based rules. They are counted under `summary.missing_source_ip_events`.
- Duplicate identical normalized events across input files are deduplicated before detection. Everything is processed **in memory**, suitable for modest offline samples rather than huge enterprise datasets.
- Rules use simple thresholds and **surface leads for human investigation**, not proof of compromise. Legitimate mistyping, penetration tests, proxies, NAT, shared sources and service activity can cause false positives or reduce attribution accuracy.
- Multiple platform/host groups can be analyzed together, but **cross-host incident correlation is not implemented yet** (planned Phase 4).

## Data formats

`parse` consumes Linux OpenSSH-style syslog or Windows Security event XML (not binary `.evtx` files). Its JSON output has an `events` array containing UTC timestamps, host, platform, source IP, username, and other fields.

`detect` consumes **one or more of these normalized JSON files** and outputs JSON with `summary` and `findings`. Each finding includes a stable `finding_id`, `rule_id`, severity, affected usernames, time range, evidence count, and the contributing evidence records.

The synthetic IP addresses use RFC 5737 documentation-only IPv4 ranges. Never commit real credentials, tokens, or sensitive authentication logs to a public repository.

## Validation

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The test suite covers Phase 2 compatibility, configuration safety, expected attack findings, threshold boundaries, account/IP/host isolation, deduplication, invalid inputs and CLI output protection.

## Folder layout

- `src/security_log_toolkit/` — application package
- `src/security_log_toolkit/parsers/` — Linux/Windows parsers
- `src/security_log_toolkit/detection/` — YAML rules and detection engine
- `config/detection_rules.yaml` — detection thresholds and severities
- `samples/linux/`, `samples/windows/` — synthetic source logs
- `tests/` — automated tests
- `reports/` — generated JSON results, excluded from Git

## License

MIT — see `LICENSE`.
