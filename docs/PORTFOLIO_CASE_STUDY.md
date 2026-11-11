
# Sentinel — Cybersecurity Engineering Case Study

## Project Profile

**Project:** Python Security Automation & Log Correlation Toolkit  
**Interface:** Sentinel Prism SOC Dashboard  
**Version:** 1.0.0  
**Project type:** Independent cybersecurity portfolio project  
**Technologies:** Python, Streamlit, PyYAML, Pytest, Altair, Git, Linux SSH, Windows Security XML

## 1. Background

I developed Sentinel to gain practical experience with security automation, authentication log analysis, incident correlation, and evidence-based investigation.

My goal was to build something that could demonstrate how raw authentication records become structured, actionable investigation data.

I focused on creating a functional Python toolkit rather than a dashboard with hard-coded security statistics.

## 2. Problem

Linux OpenSSH and Windows Security XML authentication records have different formats, field structures, and timestamp representations.

Reviewing them manually makes it difficult to identify repeated authentication failures, password spraying, and sequences involving successful logins.

Individual alerts also lack sufficient context unless their underlying evidence can be linked and inspected.

## 3. My Approach

I divided the project into reusable components:

1. Log ingestion and normalization.
2. YAML-based authentication threat detection.
3. Correlation of related detection findings.
4. Evidence-linked investigation timelines.
5. Structured CSV and JSON reporting.
6. Security validation and automated testing.
7. A Streamlit dashboard over the shared Python backend.

I completed the work incrementally, using Git commits and regression tests to protect functionality developed in earlier phases.

## 4. Main Engineering Work

### Cross-Platform Event Normalization

I implemented parsers for supported Linux OpenSSH logs and Windows Security XML events.

The parsers normalize timestamp, account, host, platform, source IP, and event-reference fields for downstream processing.

### Detection Rules

I developed configurable rules to identify:

- Repeated failed authentication attempts.
- Password spraying patterns.
- Successful authentication following suspicious failures.

The YAML configuration allows thresholds and time windows to be adjusted without rewriting the detection engine.

### Incident Correlation

I implemented correlation boundaries based on platform, hostname, source IP, and time.

I tested scenarios involving separate hosts and interleaved source addresses to reduce incorrect grouping of unrelated activity.

### Evidence and Reporting

I preserved relationships between findings, incidents, and source events.

Investigation outputs include chronological linked-evidence timelines, analyst summaries, five CSV tables, a full JSON report, and SHA-256 manifests.

### Sentinel Prism Dashboard

I built a seven-workspace Streamlit interface for visually exploring investigations.

The interface provides dark and light appearance modes, analytics charts, incident filters, evidence views, session-based detection controls, validation, and report downloads.

Both the dashboard and CLI use the same analysis services.

## 5. Defensive Design Decisions

| Decision | Why I Chose It |
|---|---|
| Shared backend | Keep CLI and dashboard results consistent |
| File-size limits | Bound resource consumption |
| XML DTD/entity rejection | Reduce exposure to unsafe XML declarations |
| Schema-validated YAML | Reject malformed configuration |
| Temporary raw file processing | Avoid persistent upload files during analysis |
| Stable evidence references | Improve traceability |
| CSV formula safeguards | Reduce spreadsheet injection risks |
| Synthetic demonstration data | Provide reproducible testing without real private logs |

These safeguards reduce certain risks but do not make Sentinel production-hardened.

## 6. Validation

### Windows 11 Acceptance Milestone

At the completed Phase 10 acceptance milestone:

- 460 automated tests passed.
- All seven dashboard workspaces were manually verified.
- The CLI remained operational.
- Environment diagnostics reported READY.
- The repository changes were committed.

Subsequent interface revisions should be retested before claiming an updated total.

### Synthetic Investigation

| Metric | Observed Result |
|---|---:|
| Normalized authentication events | 29 |
| Detection findings | 6 |
| Incidents | 4 |
| Linked evidence entries | 22 |
| Labeled scenarios | 4 |
| Scenario-level TP / FP / FN | 6 / 0 / 0 |

The validation dataset is small and synthetic. These numbers do not establish production detection accuracy or real-world false-positive rates.

## 7. Technical Challenges

**Preserving evidence relationships:** I needed findings, incidents, and timelines to reference the correct source records rather than presenting untraceable alert counts.

**Keeping correlation boundaries reliable:** Different hosts, platforms, and IP addresses had to remain distinguishable.

**Maintaining CLI compatibility:** Adding a browser interface could not require changing the behavior of earlier command-line workflows.

**Presenting security information accurately:** I avoided representing authentication anomalies as confirmed attacks or inventing unsupported network metrics.

## 8. Limitations

Sentinel currently supports selected authentication events rather than complete endpoint or network telemetry.

It does not include native binary EVTX parsing, live SIEM ingestion, public multi-user deployment, application authentication, or production incident-response automation.

Linked timelines represent detection evidence, not a complete forensic reconstruction.

## 9. Demonstration

The application runs locally using bundled synthetic data.

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

I can demonstrate the project through the [five-minute walkthrough](DEMO_WALKTHROUGH.md) and its [architecture documentation](ARCHITECTURE.md).

## 10. Outcome

Through Sentinel, I applied Python development, cybersecurity analysis, configurable detection logic, defensive input handling, automated testing, and interactive application design to an end-to-end investigation workflow.

The completed project serves as practical evidence of my technical skills for cybersecurity, SOC analysis, security engineering, and IT infrastructure internship opportunities.
