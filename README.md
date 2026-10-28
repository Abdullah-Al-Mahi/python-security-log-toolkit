
# Python Security Automation & Log Correlation Toolkit

A modular, offline-first Python application for security log analysis,
threat detection, event correlation, and incident investigation.

## Project Status

**Version:** 0.1.0  
**Current milestone:** Phase 1 - Project foundation

The initial CLI and automated smoke tests are implemented.
Log parsing, detection, correlation, and reporting are planned
for future development phases.

## Planned Features

- Linux SSH and authentication log parsing
- Windows authentication/security event parsing
- Unified, normalized security event schema
- Configurable detection rules
- Brute-force and password-spraying detection
- Suspicious authentication sequence analysis
- Event correlation by account, source IP, and time
- Investigation timelines
- CSV and JSON exports
- Professional command-line interface
- Automated unit and integration testing

## Technology

- Python 3.13+
- Python standard library
- pytest
- Git
- Visual Studio Code

## Platform

Developed and tested primarily on Windows 11.

The core analysis workflow is designed for offline log files.
No external APIs, subscriptions, or cloud services are required.

## Setup (Windows PowerShell)

From the project root, create a virtual environment:

```powershell
& "C:\Program Files\Python314\python.exe" -m venv .venv
```

Install the project and development dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## CLI Usage

Display help:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit --help
```

Display version:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit --version
```

Check installation status:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit status
```

After installation, you can also use the console entry point:

```powershell
.\.venv\Scripts\security-log.exe status
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Project Organization

- `src/security_log_toolkit/` - Main Python package
- `tests/` - Automated tests
- `samples/linux/` - Synthetic Linux log datasets
- `samples/windows/` - Synthetic Windows event datasets
- `config/` - Detection and application configuration
- `reports/` - Generated outputs
- `.vscode/` - Development environment settings

## Privacy and Safety

Use synthetic or properly authorized log data.

Do not commit real usernames, credentials, personal information,
authentication tokens, or sensitive incident records.

## License

MIT License. See `LICENSE`.
