
# Sentinel — Security Validation and Performance Evaluation

**Version:** 1.0.0  
**Scope:** Authentication log analysis and local investigation workflows

## Overview

I developed automated validation and defensive input tests to assess the reliability of Sentinel's supported authentication analysis workflows.

The tests cover malformed inputs, configuration errors, correlation boundaries, source-size limits, and selected adversarial cases.

The validation exercises are reproducible, but they do not establish immunity to all security threats or production detection accuracy.

## Supported Inputs

Sentinel processes:

- Supported Linux OpenSSH authentication logs.
- Windows Security XML authentication events, primarily Event IDs 4624 and 4625.
- Validated normalized JSON and existing investigation reports for supported workflows.

Native binary `.evtx` files are not supported.

## Input and Resource Limits

| Input Type | Limit |
|---|---|
| Raw Linux or Windows log file | 16 MiB each |
| Dashboard raw uploads | 4 files, 32 MiB combined |
| Normalized JSON file | 32 MiB |
| Existing investigation JSON | 50 MiB |
| Individual Linux syslog line | 65,536 characters |

The limits reduce accidental and malicious resource consumption. They do not guarantee resistance against every denial-of-service or parser attack.

## Defensive Input Handling

### XML Validation

I added rejection checks for XML DTD and entity declarations, including supported UTF-16 inputs.

Malformed XML is rejected instead of being interpreted as valid security evidence.

### Configuration Validation

Detection and correlation settings use schema-checked YAML.

Unsupported settings, invalid values, and unsafe YAML structures are rejected.

### Event Validation

The event-processing pipeline checks important fields such as timestamps and source IP addresses.

It does not invent missing source addresses or silently merge unrelated host activity.

### Correlation Boundaries

I tested the separation of events by platform, hostname, source IP, and time window.

This helps avoid incorrect grouping of unrelated authentication activity.

## Labeled Synthetic Detection Evaluation

The evaluation manifest is stored at:

```text
samples/validation/ground_truth.json
```

The ground truth contains four manually labeled synthetic scenarios.

Each expected label represents a rule ID and source-IP combination within a scenario.

Run the evaluator:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit validate
```

Expected default synthetic results:

| Measurement | Value |
|---|---:|
| Scenarios | 4 |
| Normalized events | 41 |
| True positives | 6 |
| False positives | 0 |
| False negatives | 0 |
| Precision | 1.0 |
| Recall | 1.0 |
| F1 | 1.0 |

### Interpretation

These measurements evaluate whether expected rule/IP combinations are present in the labeled synthetic scenarios.

They do not measure:

- Overall production detection accuracy.
- Real-world false-positive rate.
- Exact alert onset timing.
- Confirmed compromise.
- Resistance to every evasion technique.

The evaluation does not define a complete true-negative population, so overall accuracy and real-world false-positive rates are not reported.

## Performance Benchmark

Sentinel includes a bounded in-memory benchmark for detection, correlation, and incident serialization.

Run:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit benchmark --events 1000 --runs 3
```

Accepted ranges:

| Parameter | Range |
|---|---|
| Generated events | 100–5000 |
| Repetitions | 2–10 |

The benchmark reports median latency, nearest-rank p95 latency, and an estimated event-processing rate for the measured in-memory workflow.

It excludes raw-log parsing, disk I/O, CSV generation, dashboard rendering, and live operational ingestion.

Performance depends on the hardware and software environment.

## Adversarial Test Fixtures

The repository includes synthetic fixtures for cases such as:

- Rejected XML entity declarations.
- Malformed XML.
- Invalid source IP values.
- Interleaved Linux source IPs.
- Windows events from distinct hosts.
- Unsupported event formats.

Additional automated tests generate oversized or malformed inputs, UTF-16 XML declaration cases, and invalid scenario paths.

These datasets are not real incident evidence.

## Automated Regression Testing

Run the complete suite from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

At the completed Phase 10 Windows milestone, I verified 460 passing tests, including a Streamlit smoke test.

Subsequent UI changes should be retested before claiming a newer total.

Environment diagnostics:

```powershell
.\.venv\Scripts\python.exe -m security_log_toolkit doctor
```

## Report Protection

The CLI generally refuses to overwrite an existing generated output unless an appropriate command explicitly supports `--force`.

Input files and protected configuration paths are not intended to be overwritten during analysis.

Generated reports should remain outside Git tracking and should not contain real sensitive information intended for public distribution.

## Deployment Limitations

Sentinel is a local single-user prototype.

The security checks do not make it suitable for unauthenticated internet deployment, forensic chain-of-custody certification, or production SOC operations.

Only authorized log data should be processed.

## Related Documentation

- [Architecture](ARCHITECTURE.md)
- [Dashboard Guide](WEB_DASHBOARD_GUIDE.md)
- [CLI Guide](CLI_GUIDE.md)
- [Reporting Guide](REPORTING_GUIDE.md)
