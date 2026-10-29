# Phase 10 — Modern Web Dashboard implementation handoff (REQUIRED)

This is a design contract, **not an implemented interface**. The CLI must remain
functional in Phase 10. The UI should run locally with free Streamlit and bind
to `127.0.0.1` by default. No public hosting, analytics trackers, or private
log uploads should be required.

## Existing reusable services

```python
from pathlib import Path
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs
from security_log_toolkit.reporting import build_report_tables, build_export_artifacts

report = analyze_raw_logs(
    [RawLogSource("windows", Path("samples/windows/attack_security.xml"))],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
)
tables = build_report_tables(report)
files = build_export_artifacts(report, "both")
```

The dashboard must not reproduce or bypass the rule engine. Keep upload parsing,
config validation, report schema validation, CSV formula guarding and source
limits in shared Python services.

## Required UI pages / capabilities

1. **Overview:** event/findings/incidents counters and severity charts, explicitly
   labeled synthetic vs user-provided inputs.
2. **Upload and analyze:** Linux `.log` and Windows XML files, explicit year
   and UTC offset for Linux; input size checks; reject unsupported `.evtx`.
3. **Incident explorer:** search and filter by source IP, platform, host,
   severity and rule; stable identifiers; open an incident detail panel.
4. **Timeline:** chronological evidence-linked events, analyst observations,
   source line/record references, cautious failure-to-success summaries.
5. **Configuration:** inspect rule and correlation YAML; editable validated
   thresholds without overwriting tracked configs unless explicitly requested.
6. **Reports:** CSV/JSON download buttons consuming `build_export_artifacts()`
   bytes, including `export_manifest.json` and SHA-256 descriptions.
7. **Validation:** show synthetic P/R/F1 labels and benchmark results with
   prominent non-production scope caveats.

## Important UI safety tests

- Accepted format and size boundaries; no unexpected file upload persistence.
- Path traversal checks; no arbitrary file reads from user-supplied names.
- No unsafe rendering of raw log text as HTML or scripts.
- Graceful errors for malformed XML, invalid YAML and missing inputs.
- Protected local configuration files and explicit deliberate overwrite flow.
- No public network binding by default; no analytics or cloud API dependency.
- CLI regression suite still passes when Streamlit is installed.

## Phase 10 acceptance criteria

The dashboard must run **locally for free**, handle the bundled synthetic
Linux/Windows demo, expose usable investigation and reporting views, preserve
all previous CLI commands, and pass functional plus security regression tests.
Do not claim the dashboard is complete until user verifies it on Windows 11.
