"""Framework-independent timeline report services for CLI and future dashboard."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

from security_log_toolkit import __version__
from security_log_toolkit.correlation.service import investigate
from security_log_toolkit.investigation.timeline import build_incident_timeline


def attach_timelines(report: Mapping[str, Any]) -> dict:
    """Enrich an existing Phase 4 report; preserve its original fields.

    Accepts an in-memory report or a previously loaded Phase 4 JSON report.
    Never edits the supplied report, and never fabricates missing evidence.
    """
    if not isinstance(report, Mapping):
        raise ValueError("Investigation report must be an object")
    incidents = report.get("incidents")
    if not isinstance(incidents, list):
        raise ValueError("Investigation report must contain an incidents list")
    if "summary" not in report or not isinstance(report["summary"], dict):
        raise ValueError("Investigation report must contain a summary object")
    result = deepcopy(dict(report))
    # Preserve the originating report version, while marking which release
    # enriched it (especially useful for older Phase 4 JSON inputs).
    result["timeline_generator_version"] = __version__
    for incident in result["incidents"]:
        if not isinstance(incident, dict):
            raise ValueError("Incidents must be objects")
        incident["timeline"] = build_incident_timeline(incident)
    result["timeline_summary"] = {
        "total_timelines": len(result["incidents"]),
        "total_timeline_entries": sum(
            incident["timeline"]["event_count"] for incident in result["incidents"]
        ),
        "incidents_with_observed_successes": sum(
            incident["timeline"]["successful_logins"] > 0
            for incident in result["incidents"]
        ),
        "evidence_scope": "Linked evidence only; not complete security log history.",
    }
    return result


def investigate_with_timelines(
    inputs: Iterable[Path], *, detection_rules: Path, correlation_rules: Path,
) -> dict:
    """Run Phase 2–5 analysis using the existing shared backend services."""
    return attach_timelines(investigate(
        inputs, detection_rules=detection_rules, correlation_rules=correlation_rules,
    ))
