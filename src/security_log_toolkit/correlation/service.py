"""UI-neutral investigation service, shared by CLI and future web dashboard.

No printing, command-line parsing or framework-specific state is used here.
"""

from pathlib import Path
from typing import Iterable

from security_log_toolkit import __version__
from security_log_toolkit.correlation.config import load_correlation_config
from security_log_toolkit.correlation.engine import correlate_findings
from security_log_toolkit.detection import (
    detect_events, load_detection_config, load_normalized_events,
)


def investigate(
    inputs: Iterable[Path], *, detection_rules: Path, correlation_rules: Path,
) -> dict:
    """Analyze Phase 2 normalized files end-to-end and return a JSON-safe report.

    The same function will be usable by the Phase 10 local dashboard.
    """
    paths = list(inputs)
    if not paths:
        raise ValueError("At least one normalized input file is required")
    rules = load_detection_config(detection_rules)
    correlation = load_correlation_config(correlation_rules)
    events, duplicate_count = load_normalized_events(paths)
    findings = detect_events(events, rules)
    incidents = correlate_findings(findings, correlation)
    serialized_incidents = [incident.to_dict() for incident in incidents]
    serialized_findings = [finding.to_dict() for finding in findings]
    return {
        "tool_version": __version__,
        "input_files": [str(path) for path in paths],
        "detection_rules_file": str(detection_rules),
        "correlation_rules_file": str(correlation_rules),
        "summary": {
            "events_analyzed": len(events),
            "duplicate_events_skipped": duplicate_count,
            "findings_analyzed": len(findings),
            "total_incidents": len(incidents),
            "correlated_incidents": sum(len(incident.findings) > 1 for incident in incidents),
            "single_finding_incidents": sum(len(incident.findings) == 1 for incident in incidents),
            "unique_evidence_events": sum(item["unique_evidence_events"] for item in serialized_incidents),
            "by_severity": {
                severity: sum(item["severity"] == severity for item in serialized_incidents)
                for severity in ("critical", "high", "medium", "low")
            },
        },
        "incidents": serialized_incidents,
        "findings": serialized_findings,
    }
