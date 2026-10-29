"""UI-neutral incident investigation services for CLI and future web dashboard.

No printing, command-line parsing or framework-specific state is used here.
"""

from pathlib import Path
from typing import Iterable

from security_log_toolkit import __version__
from security_log_toolkit.events import SecurityEvent
from security_log_toolkit.correlation.config import CorrelationConfig, load_correlation_config
from security_log_toolkit.correlation.engine import correlate_findings
from security_log_toolkit.detection import (
    detect_events, load_detection_config, load_normalized_events,
)
from security_log_toolkit.detection.config import DetectionConfig


def investigate_events(
    events: Iterable[SecurityEvent], *, input_files: Iterable[Path],
    detection_rules: Path, correlation_rules: Path, duplicate_count: int = 0,
    detection_config: DetectionConfig | None = None,
    correlation_config: CorrelationConfig | None = None,
) -> dict:
    """Correlate normalized events in memory; return a JSON-safe incident report.

    Both file-based investigations and one-step raw-log analysis use this same
    backend. No logs or reports are written by this function.
    """
    ordered_events = list(events)
    rules = detection_config or load_detection_config(Path(detection_rules))
    correlation = correlation_config or load_correlation_config(Path(correlation_rules))
    findings = detect_events(ordered_events, rules)
    incidents = correlate_findings(findings, correlation)
    serialized_incidents = [incident.to_dict() for incident in incidents]
    serialized_findings = [finding.to_dict() for finding in findings]
    return {
        "tool_version": __version__,
        "input_files": [str(path) for path in input_files],
        "detection_rules_file": str(detection_rules),
        "correlation_rules_file": str(correlation_rules),
        "summary": {
            "events_analyzed": len(ordered_events),
            "duplicate_events_skipped": duplicate_count,
            "findings_analyzed": len(findings),
            "total_incidents": len(incidents),
            "correlated_incidents": sum(len(incident.findings) > 1 for incident in incidents),
            "single_finding_incidents": sum(len(incident.findings) == 1 for incident in incidents),
            "unique_evidence_events": sum(
                incident["unique_evidence_events"] for incident in serialized_incidents
            ),
            "by_severity": {
                severity: sum(item["severity"] == severity for item in serialized_incidents)
                for severity in ("critical", "high", "medium", "low")
            },
        },
        "incidents": serialized_incidents,
        "findings": serialized_findings,
    }


def investigate(
    inputs: Iterable[Path], *, detection_rules: Path, correlation_rules: Path,
) -> dict:
    """Analyze existing Phase 2 JSON files using the same shared backend."""
    paths = list(inputs)
    if not paths:
        raise ValueError("At least one normalized input file is required")
    # Keep legacy config validation/error order intact.
    rules = load_detection_config(Path(detection_rules))
    correlation = load_correlation_config(Path(correlation_rules))
    events, duplicate_count = load_normalized_events(paths)
    return investigate_events(
        events, input_files=paths, detection_rules=detection_rules,
        correlation_rules=correlation_rules, duplicate_count=duplicate_count,
        detection_config=rules, correlation_config=correlation,
    )
