# Project roadmap — Phase 0 through Phase 10 (official)

**Phase 10 is part of the required project scope, not an optional extra.**

The core principle: one local Python security analysis engine with **two front ends**:
(1) a production-style CLI; (2) a modern, browser-based investigation dashboard.
The browser will call the same Python functions, not a second copy of the rules.
No paid API, subscription, cloud hosting, or external authentication service is required.

| Phase | Name | State | Architecture decision for dashboard compatibility |
|---|---|---|---|
| 0 | Windows development environment verification | Complete | Python 3.13, VS Code and Git |
| 1 | Independent project setup and packaging | Complete | Importable `src/security_log_toolkit` package |
| 2 | Linux/Windows log parsing and normalization | Complete | Standardized `SecurityEvent` objects |
| 3 | Configurable security detection rules | Complete | Data-only findings and YAML configuration |
| 4 | Incident correlation engine | Current | Reusable `investigate()` service and JSON-safe incident model |
| 5 | Investigation timelines and evidence context | Planned | Framework-independent timeline builder, provenance and event ordering |
| 6 | Enhanced CLI and configuration experience | Planned | CLI calls reusable services; no business logic inside UI |
| 7 | Reporting and CSV/JSON exports | Planned | Shared export services for both CLI and browser downloads |
| 8 | Security, robustness, evaluation and automated tests | Planned | Exercise backend and UI-facing service boundaries using synthetic logs |
| 9 | Portfolio packaging, documentation and demo scenario | Planned | Screenshots, architecture, README and offline reproducibility |
| 10 | Modern local web dashboard | Required | Streamlit-based UI reusing the backend, local upload/filters/charts/incidents |

## Backend service contract introduced in Phase 4

```python
from pathlib import Path
from security_log_toolkit.correlation import investigate

report = investigate(
    [Path("reports/linux_attacks.json"), Path("reports/windows_attacks.json")],
    detection_rules=Path("config/detection_rules.yaml"),
    correlation_rules=Path("config/correlation_rules.yaml"),
)
# `report` contains JSON-serializable metadata, findings, and incidents.
```

The service has no dependency on a CLI, web framework, cloud, or environment variables.
This allows a local Streamlit dashboard to call it directly in Phase 10.

## Privacy, scope and limitations

- Use synthetic or explicitly authorized logs. Authentication logs can contain personal data.
- The core tool is **offline**. The web dashboard is intended to run on `localhost`.
- Correlation deliberately uses **same platform, same hostname, same source IP** plus
  a configurable inactivity gap and maximum incident span. It does **not** attempt
  uncertain cross-host/identity attribution or infer attacker identity.
- A single finding still becomes a single-finding incident, so no alert is dropped.
- The initial Phase 4 incident output has chronological **evidence**. Advanced analyst
  timelines, notes and richer investigation context belong to Phase 5.
- Both UI surfaces share the same analysis and report schema. No duplication of
  another SOC dashboard project is necessary.
