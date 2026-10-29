# Official project roadmap — Phases 0–10

**Phase 10 (Modern Web Dashboard) is a REQUIRED deliverable.** The project will have
one Python analysis backend powering **both** an advanced CLI and a local browser UI.
No paid APIs, subscriptions or public deployment are needed.

| Phase | Scope | State | Dashboard-facing architecture |
|---|---|---|---|
| 0 | Windows 11 and developer tools | Complete | Verified Python 3.13, Git, VS Code |
| 1 | Git/package foundation and CLI | Complete | Importable source package |
| 2 | Linux/Windows parsing and normalization | Complete | `SecurityEvent` model |
| 3 | Authentication security detection | Complete | Data-only `Finding` records and safe YAML rules |
| 4 | Incident correlation | Complete | `investigate()` creates JSON-safe incidents |
| 5 | Analyst timelines and evidence context | Current | `investigate_with_timelines()` / `attach_timelines()`; no UI dependencies |
| 6 | CLI ergonomics and configuration | Planned | Consistent service and configuration interfaces |
| 7 | Robust CSV / JSON reporting and exports | Planned | Shared formatters for CLI and browser downloads |
| 8 | Validation, security, scale and edge cases | Planned | Test backend and UI-facing service contracts |
| 9 | GitHub portfolio, documentation and demos | Planned | Reproducible offline demo materials |
| 10 | Modern web dashboard | **Required** | Streamlit local UI reuses existing backend and export services |

## Phase 5 service contract

```python
from pathlib import Path
from security_log_toolkit.investigation import investigate_with_timelines, attach_timelines

report = investigate_with_timelines(
    [Path("reports/linux_attacks.json"), Path("reports/windows_attacks.json")],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
)

# Or enrich a precomputed Phase 4 report without re-parsing files:
# enhanced = attach_timelines(phase4_report)
```

A Phase 5 report includes all Phase 4 report fields, plus a per-incident `timeline`
and top-level `timeline_summary` plus `timeline_generator_version`. This is designed for eventual dashboard filtering,
incident detail views and interactive timelines.

## Safe interpretations and scope boundaries

- **Evidence scope:** incident timelines include only authentication events supporting
  one or more detections. They are not comprehensive activity timelines.
- **Identity boundaries:** Linux usernames are case-sensitive. Windows accounts use
  case-insensitive usernames with domains when present. Correlation is bounded by
  source IP, host and platform and does not identify real adversaries.
- **Analyst context:** suggested checks are **recommendations**, not actions the tool
  performs; labels are observations, not verified compromises.
- **Input limitations:** offline Linux OpenSSH syslog and Windows Security XML only.
- **Data safety:** use synthetic or approved datasets. Do not expose real log records
  via public GitHub or third-party hosting.
