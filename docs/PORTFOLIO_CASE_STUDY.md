# Portfolio case study — Security Log Automation and Correlation

**Project:** Python Security Automation & Log Correlation Toolkit
**Role:** Independent Python/cybersecurity portfolio implementation
**Scope:** Offline Linux/Windows login analysis; free tools, no external services
**Stack:** Python 3.13, PyYAML, pytest, Git, Windows 11 / VS Code

## Problem

Authentication evidence in Linux OpenSSH and Windows Security logs is represented
differently. Manually reviewing login attempts across files makes it difficult
to spot repeated failures, account spraying, and failed attempts followed by
successful logins. A raw alert list also lacks incident context and evidence
traceability.

## Approach

I built an offline Python pipeline that normalizes Linux/Windows authentication
records to a common UTC model. YAML-configurable rules detect three patterns:
brute force, password spraying, and authentication success after failures.
Related findings are correlated by platform, host, source IP and time window.
The pipeline generates evidence-linked timelines with cautious analyst summaries,
then produces readable reports and five linked CSV tables with full JSON and
SHA-256 export metadata.

From Phase 6 onward, the same services can analyze raw files in a single run
without writing intermediate normalized JSON. Phase 8 adds bounded inputs,
malformed/hostile XML checks, adverse fixtures and independent test coverage.

## Reproducible results (synthetic samples only)

| Measurement | Bundled demonstration |
|---|---:|
| Raw log files | 2 |
| Normalized events | 29 |
| Rule findings | 6 |
| Incidents | 4 |
| Linked evidence entries | 22 |
| Manually labeled scenarios | 4 |
| Rule/IP labels TP / FP / FN | 6 / 0 / 0 |
| Report export files | 7 |

The scenario-level P/R/F1 result of 1.0 is not a field estimate of detection
accuracy. Metrics do not prove attribution, account compromise, or resilience to
all adversarial log inputs. Performance measured in Phase 8 is in-memory and
hardware-specific, excluding parsing, I/O and dashboard costs.

## Engineering decisions and tradeoffs

- **Offline-first:** no account, subscription, API key or external database is
  required; useful for reproducible demonstration and privacy.
- **Shared backend:** both the CLI and required Phase 10 dashboard will call
  the same functions instead of maintaining duplicate rule logic.
- **Evidence over claims:** preserve source line/record references and link
  detection findings to incidents and timeline entries.
- **Defensive processing:** conservative input limits, explicit syslog timezone,
  bounded XML, safe configuration loaders, output replacement protections and
  CSV spreadsheet-injection mitigations.
- **Current limitations:** only Linux `sshd` patterns and Windows exported
  Security XML 4624/4625 are supported; no native binary `.evtx`, live ingestion,
  SIEM connector, storage server, or production incident response automation.

## Demo and code review

See [`DEMO_WALKTHROUGH.md`](DEMO_WALKTHROUGH.md),
[`ARCHITECTURE.md`](ARCHITECTURE.md), and
[`SECURITY_VALIDATION_GUIDE.md`](SECURITY_VALIDATION_GUIDE.md).
The project maintains a fully functional CLI. Phase 10 is a **planned required**
local visual dashboard and is not part of the present release.

## CV-ready bullets (use only after verifying on your machine)

- Developed an offline Python security log toolkit integrating Linux/Windows
  authentication normalization, YAML-based detection, incident correlation, and
  evidence-linked investigation timelines.
- Implemented deterministic CSV/JSON reporting, SHA-256 export manifests,
  cross-platform input validation, and a regression suite of 360+ automated
  tests including adversarial scenarios.
- Evaluated four labeled synthetic authentication scenarios and implemented
  bounded in-memory benchmarking, documenting the limitations of each metric.

## Short interview explanation

"The hardest part was preserving traceability while merging different log
formats. I used a shared event representation with stable evidence links and
made detection rules configurable. Instead of claiming that a login success
means compromise, the tool shows the observed sequence and suggests follow-up
checks. I also wrote adversarial regression tests and used Git checkpoints to
keep earlier functionality intact."
