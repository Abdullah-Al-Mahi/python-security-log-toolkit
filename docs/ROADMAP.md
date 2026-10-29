# Official project roadmap — Phases 0–10

**Phase 10 (Modern Web Dashboard) is REQUIRED.** One offline Python analysis backend
powers both a CLI and a local browser-based user interface. No paid APIs, hosting,
subscriptions, or public deployment are needed.

| Phase | Milestone | Status | Reusable backend/dashboard relevance |
|---|---|---|---|
| 0 | Windows 11 development environment | Complete | Python 3.13, VS Code, Git verified |
| 1 | Python package and Git foundation | Complete | Installable package and tests |
| 2 | Linux/Windows ingestion & UTC normalization | Complete | `SecurityEvent`, `ingest_file()` |
| 3 | YAML-based authentication detections | Complete | `detect_events()` and validated rules |
| 4 | Event correlation | Complete | `investigate()` and incident records |
| 5 | Evidence-linked investigation timelines | Complete | `attach_timelines()`, `investigate_with_timelines()` |
| 6 | Advanced CLI & configuration | Complete | `analyze_raw_logs()`, `inspect_configuration()`, config/doctor CLI |
| 7 | CSV/JSON reporting and exports | Complete | Shared export adapters for CLI and browser downloads |
| 8 | Comprehensive security/scale/edge-case validation | **Current** | Input-hardening and stable service contracts |
| 9 | GitHub portfolio, docs and demo scenarios | Planned | Reproducible offline demonstrations |
| 10 | Modern local web dashboard | **Required** | Streamlit UI calls backend services; uploads/charts/filters/timelines/downloads |

## Phase 6 interfaces

The new `analyze` CLI uses `analyze_raw_logs()` to accept raw files directly and
return complete investigation timelines without intermediate files. Settings
are validated by `inspect_configuration()` and the existing safe YAML loaders.

```python
from pathlib import Path
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs

report = analyze_raw_logs(
    [RawLogSource("windows", Path("samples/windows/attack_security.xml"))],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
)
```

`analyze_raw_logs()` uses `investigate_events()` in correlation/service.py,
which also powers the existing file-based `investigate()` function.
The services are framework-neutral and return data rather than printing output.

### Phase 10 UI direction (design contract)

The local dashboard will display:

- Upload of Linux `.log`/Windows `.xml` files with year/UTC inputs when needed
- Analysis summary cards, charts for outcomes and rule severity
- Searchable incident and finding tables with host/IP/account filters
- Evidence-linked incident detail timelines and analyst summaries
- Configuration inspector and adjustable rules with validation
- CSV and JSON report downloads from shared Phase 7 exporters

Do not build a second detection engine inside the dashboard. Use the shared
Python services. The interface is intended for **localhost** by default;
private local use requires no external hosting.

## Evidence and input limitations

- Timelines represent linked detection evidence only, **not full log history**.
- Detections are indicators for investigation, not proven compromise or attribution.
- Correlation separates platforms/hosts/source IPs and respects time boundaries.
- Linux OpenSSH syslog requires user-supplied year and UTC offset; Windows events
  are XML 4624/4625 exports, not binary `.evtx`.
- Raw logs can contain personal data; do not upload private logs to public services.

## Phase 7 reporting contract

`security_log_toolkit.reporting.build_report_tables(report)` returns Python
row lists suitable for charts, tables and filters. `build_export_artifacts(report,
fmt)` returns deterministic in-memory bytes for CSV/JSON downloads, and
`write_export_bundle()` writes them safely for the CLI. A Streamlit dashboard
will call these services directly — no backend HTTP service is necessary.

CSV sheets share `incident_id`, `finding_id`, and `evidence_id` references;
timeline rows show linked evidence, **not complete security event history**.
`export_manifest.json` includes SHA-256 digests for file integrity checking.

## Phase 8 security and quality gates

- Offline raw input bounds (16 MiB), normalized JSON cap (32 MiB), timeline
  import cap (50 MiB), and Linux single-line cap (65,536 characters).
- Reject XML DTD and entity declarations. Continue to accept supported UTF-16 exports.
- Manually labeled scenario-level validation (6 positive rule+IP pairs across four
  synthetic logs), with clear caveats: **not production accuracy**.
- Bounded in-memory throughput benchmark (100–5000 events, 2–10 repetitions).
- Extensive negative tests and regression suite; keep CLI and exporters stable.
- Framework-neutral validation functions feed the future **required** Phase 10 UI.

See `docs/SECURITY_VALIDATION_GUIDE.md`.
