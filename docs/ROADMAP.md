
# Sentinel — Development Roadmap

**Project:** Python Security Automation & Log Correlation Toolkit  
**Release:** 1.0.0  
**Development status:** All 11 planned phases completed

## Project Goal

I developed Sentinel as an independent cybersecurity portfolio project to demonstrate how Python can support authentication log analysis, security detection, incident correlation, investigation, and reporting.

I organized the development into 11 phases, progressing from foundational log processing to a functional local web dashboard.

## Completed Development Phases

| Phase | Development Milestone | Status |
|---|---|---|
| 0 | Windows 11 environment, Python, VS Code and Git | Complete |
| 1 | Python package structure and project foundation | Complete |
| 2 | Linux/Windows log parsing and UTC normalization | Complete |
| 3 | Configurable authentication detection engine | Complete |
| 4 | Incident correlation | Complete |
| 5 | Evidence-linked investigation timelines | Complete |
| 6 | Unified CLI workflow and configuration diagnostics | Complete |
| 7 | CSV/JSON reporting and investigation exports | Complete |
| 8 | Security validation, edge-case tests and benchmarks | Complete |
| 9 | GitHub documentation and reproducible portfolio demo | Complete |
| 10 | Streamlit SOC dashboard | Complete |

## Phase 0–2: Foundation and Data Processing

I established the development environment and built a reusable Python package.

I implemented parsers for supported Linux OpenSSH authentication logs and Windows Security XML events, mapping them into a common event structure.

Normalization preserves timestamps, hostnames, accounts, source IPs, and original source references.

## Phase 3–5: Detection and Investigation

I implemented YAML-configured authentication detection rules for:

- Brute-force patterns.
- Password spraying.
- Successful authentication after suspicious failures.

I then added incident correlation and chronological evidence-linked timelines.

Correlation respects platform, hostname, source IP, and configured time boundaries.

## Phase 6–7: CLI and Reporting

I created an integrated command-line workflow for analyzing raw logs without manually generating intermediate files.

I added configuration inspection, environment diagnostics, readable investigation summaries, five CSV tables, JSON reports, and SHA-256 export manifests.

## Phase 8: Validation and Hardening

I expanded automated coverage for malformed inputs, XML declarations, file-size limits, invalid configuration, and correlation edge cases.

I implemented synthetic scenario validation and bounded in-memory performance benchmarking.

These results are reproducible but are not production security certification or real-world detection accuracy measurements.

## Phase 9: Portfolio Documentation

I prepared a reproducible synthetic demonstration, architecture diagrams, security documentation, testing instructions, and a publication-safety audit.

These materials document both the system's capabilities and its limitations.

## Phase 10: Sentinel Prism Dashboard

I implemented the local Streamlit interface with seven workspaces:

1. Command Center
2. Log Intake
3. Incident Explorer
4. Evidence Timeline
5. Detection Lab
6. Validation & Performance
7. Report Center

I subsequently refined the presentation with light/dark appearance modes and a more structured security dashboard layout.

The CLI remains independently functional and shares the same backend services.

## Verification

At the Phase 10 Windows acceptance milestone:

- 460 automated tests passed.
- All seven dashboard workspaces were manually verified.
- The CLI remained functional.
- Environment diagnostics returned READY.

Newer UI revisions should be tested separately before reporting an updated passing-test count.

## Current Scope

Sentinel is a completed local cybersecurity portfolio prototype.

It supports selected authentication log formats, not complete endpoint monitoring, network telemetry, or live SIEM ingestion.

It does not provide an authenticated public multi-user service, native binary EVTX parsing, or automated incident response.

## Future Enhancements

These are ideas for possible future development, not unfinished requirements of the original 11-phase roadmap:

- Additional authentication event sources.
- Optional native EVTX support.
- Larger-scale ingestion and streaming processing.
- Broader automated integration tests.
- Expanded investigation workflows.
- Authenticated multi-user deployment architecture, subject to a separate security review.

The original planned development roadmap is complete.
