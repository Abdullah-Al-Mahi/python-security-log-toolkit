"""Offline ingestion entry point for supported authentication log formats."""

from dataclasses import dataclass
from pathlib import Path

from security_log_toolkit.events import SecurityEvent
from security_log_toolkit.parsers.linux import parse_linux_file
from security_log_toolkit.parsers.windows import parse_windows_file
from security_log_toolkit.security_limits import MAX_RAW_LOG_BYTES, require_bounded_file


@dataclass(slots=True)
class ParseResult:
    source_format: str
    input_file: str
    records_examined: int
    events: list[SecurityEvent]

    def to_dict(self) -> dict:
        normalized = [event.to_dict() for event in self.events]
        return {
            "source_format": self.source_format,
            "input_file": self.input_file,
            "summary": {
                "records_examined": self.records_examined,
                "normalized": len(normalized),
                "skipped": self.records_examined - len(normalized),
                "login_success": sum(e.event_type == "login_success" for e in self.events),
                "login_failure": sum(e.event_type == "login_failure" for e in self.events),
            },
            "events": normalized,
        }


def ingest_file(
    source_format: str,
    path: Path,
    *,
    year: int | None = None,
    utc_offset: str = "+00:00",
) -> ParseResult:
    """Read an offline file and normalize recognized authentication records."""
    require_bounded_file(path, MAX_RAW_LOG_BYTES, "Raw log")
    if source_format == "linux":
        if year is None:
            raise ValueError("Linux syslog requires --year because its timestamps omit the year")
        events, records = parse_linux_file(path, year=year, utc_offset=utc_offset)
    elif source_format == "windows":
        events, records = parse_windows_file(path)
    else:
        raise ValueError(f"Unsupported source format: {source_format}")

    events.sort(key=lambda item: item.timestamp)
    return ParseResult(source_format, str(path), records, events)
