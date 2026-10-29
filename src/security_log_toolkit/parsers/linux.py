"""Parser for traditional Linux syslog-format OpenSSH authentication logs."""

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from security_log_toolkit.events import SecurityEvent, normalize_ip
from security_log_toolkit.security_limits import MAX_LINUX_LINE_CHARS

_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)
_AUTH = re.compile(
    r"^(?P<outcome>Accepted|Failed)\s+"
    r"(?P<method>password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)\b"
)
_OFFSET = re.compile(r"^(?P<sign>[+-])(?P<hours>\d{2}):(?P<minutes>\d{2})$")


def parse_utc_offset(value: str) -> timezone:
    """Parse an explicit fixed UTC offset such as +08:00 or -05:00."""
    match = _OFFSET.fullmatch(value)
    if not match:
        raise ValueError("UTC offset must use +HH:MM or -HH:MM (for example +08:00)")
    hours = int(match["hours"])
    minutes = int(match["minutes"])
    if hours > 23 or minutes > 59:
        raise ValueError("UTC offset hours/minutes are out of range")
    duration = timedelta(hours=hours, minutes=minutes)
    if match["sign"] == "-":
        duration = -duration
    return timezone(duration)


def parse_linux_file(
    path: Path, *, year: int, utc_offset: str = "+00:00"
) -> tuple[list[SecurityEvent], int]:
    """Return (recognized events, nonempty records examined).

    Non-SSH and unsupported SSH messages are counted but not normalized.
    Traditional syslog omits year/timezone, so the caller must supply both.
    """
    tz = parse_utc_offset(utc_offset)
    if not 1970 <= year <= 9999:
        raise ValueError("--year must be between 1970 and 9999")

    events: list[SecurityEvent] = []
    records = 0
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if len(line) > MAX_LINUX_LINE_CHARS:
                raise ValueError(f"{path}:{line_number}: syslog line exceeds {MAX_LINUX_LINE_CHARS} characters")
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            records += 1
            header = _SYSLOG.match(line)
            if not header:
                continue
            auth = _AUTH.match(header["message"])
            if not auth:
                continue
            try:
                local_time = datetime.strptime(
                    f"{year} {header['month']} {header['day']} {header['clock']}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=tz)
                port = int(auth["port"])
                normalized_ip = normalize_ip(auth["ip"])
                if normalized_ip is None or not 0 <= port <= 65535:
                    raise ValueError("invalid SSH source IP address or port")
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc

            events.append(
                SecurityEvent(
                    timestamp=local_time,
                    platform="linux",
                    event_type=(
                        "login_success" if auth["outcome"] == "Accepted" else "login_failure"
                    ),
                    hostname=header["host"],
                    username=auth["user"],
                    source_ip=normalized_ip,
                    source_port=port,
                    authentication_method=auth["method"],
                    event_id="sshd",
                    record_id=None,
                    source_file=str(path),
                    source_line=line_number,
                    details={"invalid_user": "true" if auth["invalid"] else "false"},
                )
            )

    return events, records
