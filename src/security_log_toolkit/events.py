"""Shared, timezone-aware representation of authentication events."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address


def normalize_ip(value: str | None) -> str | None:
    """Return a canonical IPv4/IPv6 address, or None for missing/invalid data."""
    if not value or value.strip() in {"-", ""}:
        return None
    try:
        return str(ip_address(value.strip()))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Normalized event used by future detection and correlation modules."""

    timestamp: datetime
    platform: str
    event_type: str
    hostname: str
    username: str
    source_ip: str | None
    source_port: int | None
    authentication_method: str | None
    event_id: str
    record_id: str | None
    source_file: str
    source_line: int | None = None
    details: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation with UTC timestamps."""
        if self.timestamp.tzinfo is None:
            raise ValueError("SecurityEvent timestamps must include a timezone")
        utc_time = self.timestamp.astimezone(timezone.utc)
        precision = "microseconds" if utc_time.microsecond else "seconds"
        timestamp_text = utc_time.isoformat(timespec=precision).replace("+00:00", "Z")
        return {
            "timestamp": timestamp_text,
            "platform": self.platform,
            "event_type": self.event_type,
            "hostname": self.hostname,
            "username": self.username,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "authentication_method": self.authentication_method,
            "event_id": self.event_id,
            "record_id": self.record_id,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "details": self.details,
        }
