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

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityEvent":
        """Validate and rehydrate one normalized Phase 2 JSON event."""
        if not isinstance(data, dict):
            raise ValueError("normalized event must be a JSON object")
        required = (
            "timestamp", "platform", "event_type", "hostname", "username",
            "source_ip", "event_id", "source_file",
        )
        for key in required:
            if key not in data:
                raise ValueError(f"missing required field '{key}'")
        stamp = data["timestamp"]
        if not isinstance(stamp, str):
            raise ValueError("timestamp must be an ISO 8601 string")
        try:
            timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp is not valid ISO 8601") from exc
        if timestamp.tzinfo is None:
            raise ValueError("timestamp must include a timezone")
        for key in ("hostname", "username", "event_id", "source_file"):
            if not isinstance(data[key], str) or not data[key].strip():
                raise ValueError(f"{key} must be a nonempty string")
        if data["platform"] not in ("linux", "windows"):
            raise ValueError("platform must be linux or windows")
        if data["event_type"] not in ("login_failure", "login_success"):
            raise ValueError("event_type must be login_failure or login_success")
        raw_ip = data["source_ip"]
        if raw_ip is not None:
            if not isinstance(raw_ip, str) or normalize_ip(raw_ip) is None:
                raise ValueError("source_ip must be a valid IP address or null")
        port = data.get("source_port")
        if port is not None and (type(port) is not int or not 0 <= port <= 65535):
            raise ValueError("source_port must be an integer between 0 and 65535 or null")
        line = data.get("source_line")
        if line is not None and (type(line) is not int or line < 1):
            raise ValueError("source_line must be a positive integer or null")
        details = data.get("details", {})
        if (not isinstance(details, dict)
                or not all(isinstance(k, str) and isinstance(v, str) for k, v in details.items())):
            raise ValueError("details must be an object of string keys and values")
        for optional in ("record_id", "authentication_method"):
            value = data.get(optional)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"{optional} must be a string or null")
        return cls(
            timestamp=timestamp.astimezone(timezone.utc),
            platform=data["platform"],
            event_type=data["event_type"],
            hostname=data["hostname"],
            username=data["username"],
            source_ip=normalize_ip(raw_ip),
            source_port=port,
            authentication_method=data.get("authentication_method"),
            event_id=data["event_id"],
            record_id=data.get("record_id"),
            source_file=data["source_file"],
            source_line=line,
            details=details,
        )
