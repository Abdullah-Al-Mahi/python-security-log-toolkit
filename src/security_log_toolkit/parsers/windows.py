"""Parser for XML exports of Windows Security events 4624 and 4625."""

from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from security_log_toolkit.events import SecurityEvent, normalize_ip


def _name(element: ET.Element) -> str:
    """Remove an optional XML namespace from a tag name."""
    return element.tag.rsplit("}", 1)[-1]


def _child(element: ET.Element | None, name: str) -> ET.Element | None:
    if element is None:
        return None
    return next((part for part in element if _name(part) == name), None)


def _text(element: ET.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""


def _time_from_windows(value: str) -> datetime:
    if not value:
        raise ValueError("missing System/TimeCreated/@SystemTime")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Windows SystemTime must include a timezone")
    return parsed.astimezone(timezone.utc)


def parse_windows_file(path: Path) -> tuple[list[SecurityEvent], int]:
    """Read an <Event> or <Events> XML document (not binary .evtx)."""
    if path.suffix.lower() == ".evtx":
        raise ValueError("Binary .evtx is not supported; export Security events as XML first")

    tree = ET.parse(path)
    root = tree.getroot()
    if _name(root) == "Event":
        records = [root]
    elif _name(root) == "Events":
        records = [element for element in root if _name(element) == "Event"]
    else:
        raise ValueError("Windows XML root must be <Event> or <Events>")

    events: list[SecurityEvent] = []
    for index, element in enumerate(records, start=1):
        system = _child(element, "System")
        event_id = _text(_child(system, "EventID"))
        if event_id not in {"4624", "4625"}:
            continue
        try:
            clock = _child(system, "TimeCreated")
            timestamp = _time_from_windows(
                clock.attrib.get("SystemTime", "") if clock is not None else ""
            )
            hostname = _text(_child(system, "Computer"))
            if not hostname:
                raise ValueError("missing System/Computer")
            data_node = _child(element, "EventData")
            values = {
                item.attrib["Name"]: _text(item)
                for item in data_node
                if "Name" in item.attrib
            } if data_node is not None else {}
            username = values.get("TargetUserName", "")
            if not username:
                raise ValueError("missing EventData/TargetUserName")
            port_text = values.get("IpPort", "")
            source_port = int(port_text) if port_text.isdecimal() else None
            if source_port == 0:
                source_port = None
            if source_port is not None and source_port > 65535:
                raise ValueError("invalid EventData/IpPort")
        except ValueError as exc:
            raise ValueError(f"{path}: XML event #{index}: {exc}") from exc

        raw_ip = values.get("IpAddress", "")
        details = {
            "domain": values.get("TargetDomainName", ""),
            "logon_type": values.get("LogonType", ""),
            "status": values.get("Status", ""),
            "sub_status": values.get("SubStatus", ""),
            "workstation": values.get("WorkstationName", ""),
        }
        if raw_ip and normalize_ip(raw_ip) is None:
            details["source_ip_raw"] = raw_ip

        events.append(
            SecurityEvent(
                timestamp=timestamp,
                platform="windows",
                event_type="login_success" if event_id == "4624" else "login_failure",
                hostname=hostname,
                username=username,
                source_ip=normalize_ip(raw_ip),
                source_port=source_port,
                authentication_method=values.get("AuthenticationPackageName") or None,
                event_id=event_id,
                record_id=_text(_child(system, "EventRecordID")) or None,
                source_file=str(path),
                details=details,
            )
        )

    return events, len(records)
