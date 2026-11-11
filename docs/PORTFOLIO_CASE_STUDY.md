
# Sentinel — Cybersecurity Engineering Case Study

## Project Summary

**Project:** Python Security Automation & Log Correlation Toolkit  
**Interface:** Sentinel Prism SOC Dashboard  
**Release:** Version 1.0.0  
**Project Type:** Independent cybersecurity portfolio project  
**Technologies:** Python, Streamlit, PyYAML, Pytest, Altair, Git, Windows Security XML, Linux SSH logs  

## 1. Problem

Security analysts frequently investigate authentication events from multiple operating systems.

Linux OpenSSH and Windows Security logs use different formats, fields and time representations. This makes manual review and correlation of suspicious login activity more difficult.

The goal was to develop a repeatable investigation workflow that could identify authentication attack patterns and preserve the underlying evidence.

## 2. Solution

Sentinel is an offline-first Python security analysis application with two interfaces:

- A command-line toolkit for scripted analysis and report generation.
- A seven-workspace Streamlit dashboard for interactive investigation.

Both interfaces share the same parsing, detection, correlation, validation and reporting services.

## 3. Core Implementation

### Log Processing

Implemented supported Linux SSH and Windows Security XML parsing, with normalized timestamps, hosts, accounts, source IPs and source references.

### Threat Detection

Implemented configurable YAML-based rules for:

- Repeated authentication failures consistent with brute-force activity.
- Password spraying across multiple accounts.
- Successful authentication following suspicious failures.

### Incident Correlation

Grouped related detection findings using platform, host, source IP and bounded time windows.

### Investigation and Reporting

Generated evidence-linked timelines, analyst summaries, five structured CSV tables, JSON investigation reports and SHA-256 export manifests.

### Interactive Interface

Developed Sentinel Prism using Streamlit, including investigation dashboards, filtering, charts, dark/light appearance modes, session-based rule configuration, validation and exports.

## 4. Security Engineering Decisions

| Decision | Reason |
|---|---|
| Shared backend services | Avoid inconsistent behavior between the CLI and dashboard |
| Explicit log time information | Prevent ambiguous Linux timestamp assumptions |
| File-size limits | Reduce accidental and malicious resource consumption |
| XML DTD/entity rejection | Reduce exposure to unsafe XML declarations |
| Validated YAML configuration | Reject malformed or unsupported rule settings |
| Temporary raw-upload processing | Avoid persistent raw log files during dashboard analysis |
| Evidence identifiers | Preserve traceability between findings, incidents and source events |
| CSV formula safeguards | Reduce spreadsheet formula interpretation risk |

These defenses improve robustness but do not make the application suitable for exposure as an unauthenticated public service.

## 5. Testing and Results

### Verified Development Milestone

At the Phase 10 Windows acceptance milestone:

- 460 automated tests passed.
- All seven dashboard workspaces were manually accepted.
- Existing CLI functionality remained operational.
- The application returned READY during environment diagnostics.

Later UI-only changes require fresh regression testing before a newer validation claim is made.

### Bundled Synthetic Investigation

| Metric | Result |
|---|---:|
| Normalized events | 29 |
| Findings | 6 |
| Incidents | 4 |
| Linked evidence entries | 22 |
| Ground-truth scenarios | 4 |
| Scenario-level TP / FP / FN | 6 / 0 / 0 |

Synthetic scenario scores are not estimates of production detection accuracy.

## 6. Technical Challenges

### Cross-Platform Normalization

A shared event schema was necessary to analyze Windows and Linux authentication evidence consistently.

### Correlation Accuracy

Correlation boundaries needed to prevent unrelated hosts and source IPs from being incorrectly merged into one incident.

### Evidence Integrity

Reports and timelines needed to preserve event relationships and source references instead of showing only alert counts.

### Interface and Backend Separation

The dashboard was designed as a presentation layer over the existing analysis engine rather than a duplicate implementation.

## 7. Scope and Limitations

Sentinel is a local single-user investigation prototype.

It does not support native binary EVTX parsing, continuous SIEM ingestion, network traffic analysis, user authentication, public multi-user deployment or production response automation.

A successful authentication after failures is an investigative signal, not proof of account compromise.

The application should only process logs obtained with appropriate authorization.

## 8. Demonstration

Start the dashboard:

```powershell
.\.venv\Scripts\python.exe -m streamlit run dashboard\app.py --server.address 127.0.0.1 --server.port 8501
```

The bundled synthetic dataset allows an employer to explore the dashboard without sharing sensitive real-world security events.

See the [Demonstration Walkthrough](DEMO_WALKTHROUGH.md) and [System Architecture](ARCHITECTURE.md).

## 9. Project Outcome

The completed project demonstrates practical application of:

- Python security automation and log processing.
- Authentication threat detection and incident correlation.
- Evidence-focused security investigation.
- Secure input handling and defensive validation.
- Automated regression testing.
- Interactive cybersecurity interface development.

It is intended to demonstrate relevant skills for cybersecurity, SOC analyst, security engineering and IT infrastructure internship positions.
