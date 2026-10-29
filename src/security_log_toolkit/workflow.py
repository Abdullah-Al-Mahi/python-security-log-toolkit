"""Single-step raw-log analysis, shared by the CLI and future local dashboard.

Uses the existing parsers, detection rules, correlation engine and timeline
service. This module performs no console I/O or disk report writes.
"""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Iterable

from security_log_toolkit.correlation.service import investigate_events
from security_log_toolkit.events import SecurityEvent
from security_log_toolkit.ingest import ingest_file
from security_log_toolkit.investigation.service import attach_timelines


@dataclass(frozen=True, slots=True)
class RawLogSource:
    """A supported local source and its input format (linux or windows)."""

    source_format: str
    path: Path


def _event_identity(event: SecurityEvent) -> str:
    return json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True)


def analyze_raw_logs(
    sources: Iterable[RawLogSource],
    *,
    detection_rules: Path,
    correlation_rules: Path,
    year: int | None = None,
    utc_offset: str | None = None,
) -> dict:
    """Parse raw logs and return complete JSON-safe incident timelines.

    Repeated references to the same file and identical normalized events are
    deduplicated. Source provenance is preserved in each evidence item.
    Linux syslog requires an explicit year and timezone offset.
    """
    supplied = list(sources)
    if not supplied:
        raise ValueError("Specify at least one --linux or --windows source file")
    if any(not isinstance(source, RawLogSource) for source in supplied):
        raise ValueError("Each raw log source must be a RawLogSource")
    if any(source.source_format not in {"linux", "windows"} for source in supplied):
        raise ValueError("Raw source format must be linux or windows")
    if any(source.source_format == "linux" for source in supplied):
        if year is None or utc_offset is None:
            raise ValueError("Linux sources require both --year and --utc-offset")

    # Validate both YAML configurations before reading potentially large logs.
    from security_log_toolkit.detection.config import load_detection_config
    from security_log_toolkit.correlation.config import load_correlation_config

    detection = load_detection_config(Path(detection_rules))
    correlation = load_correlation_config(Path(correlation_rules))

    seen_paths: set[tuple[str, Path]] = set()
    unique_events: set[str] = set()
    all_events: list[SecurityEvent] = []
    source_records: list[dict] = []
    duplicate_events = 0
    duplicate_files = 0
    original_count = 0

    for source in supplied:
        source_path = Path(source.path)
        key = (source.source_format, source_path.resolve())
        if key in seen_paths:
            duplicate_files += 1
            continue
        seen_paths.add(key)
        result = ingest_file(
            source.source_format,
            source_path,
            year=year if source.source_format == "linux" else None,
            utc_offset=utc_offset or "+00:00",
        )
        parsed = result.to_dict()
        # Keep only source provenance and counts, not a second copy of the events.
        source_records.append({key: value for key, value in parsed.items() if key != "events"})
        original_count += len(result.events)
        for event in result.events:
            identity = _event_identity(event)
            if identity in unique_events:
                duplicate_events += 1
                continue
            unique_events.add(identity)
            all_events.append(event)

    all_events.sort(key=lambda e: (e.timestamp, _event_identity(e)))
    report = investigate_events(
        all_events,
        input_files=[Path(entry["input_file"]) for entry in source_records],
        detection_rules=Path(detection_rules),
        correlation_rules=Path(correlation_rules),
        duplicate_count=duplicate_events,
        detection_config=detection,
        correlation_config=correlation,
    )
    report = attach_timelines(report)
    report["workflow"] = "raw_log_analysis"
    report["raw_log_summary"] = {
        "source_files_processed": len(source_records),
        "duplicate_source_files_skipped": duplicate_files,
        "records_examined": sum(s["summary"]["records_examined"] for s in source_records),
        "normalized_before_deduplication": original_count,
        "normalized_events": len(all_events),
        "duplicate_events_skipped": duplicate_events,
        "unsupported_records_skipped": sum(s["summary"]["skipped"] for s in source_records),
    }
    report["raw_log_sources"] = source_records
    return report
