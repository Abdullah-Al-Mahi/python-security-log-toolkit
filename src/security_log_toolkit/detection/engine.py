"""Offline, deterministic rule evaluation on normalized authentication events."""

import hashlib
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from security_log_toolkit import __version__
from security_log_toolkit.detection.config import DetectionConfig, RuleSettings
from security_log_toolkit.events import SecurityEvent


RULE_TITLES = {
    "brute_force": "Possible brute-force authentication",
    "password_spray": "Possible password spraying",
    "success_after_failures": "Successful login following repeated failures",
}


def _account(event: SecurityEvent) -> str:
    """Windows account names are case-insensitive; keep Linux case-sensitive."""
    username = event.username.casefold() if event.platform == "windows" else event.username
    domain = event.details.get("domain", "").casefold() if event.platform == "windows" else ""
    return f"{domain}\\{username}" if domain else username


def _iso(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds" if normalized.microsecond else "seconds").replace("+00:00", "Z")


def _event_key(event: SecurityEvent) -> str:
    return json.dumps(event.to_dict(), sort_keys=True, ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: str
    platform: str
    hostname: str
    source_ip: str
    evidence: tuple[SecurityEvent, ...]

    def to_dict(self) -> dict:
        ordered = tuple(sorted(self.evidence, key=lambda e: (e.timestamp, _event_key(e))))
        digest_input = json.dumps(
            [self.rule_id, *[_event_key(e) for e in ordered]],
            sort_keys=True, ensure_ascii=False,
        )
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        event_refs = []
        for event in ordered:
            event_refs.append({
                "timestamp": _iso(event.timestamp),
                "event_type": event.event_type,
                "platform": event.platform,
                "hostname": event.hostname,
                "username": event.username,
                "source_ip": event.source_ip,
                "event_id": event.event_id,
                "record_id": event.record_id,
                "source_file": event.source_file,
                "source_line": event.source_line,
            })
        return {
            "finding_id": f"F-{digest}",
            "rule_id": self.rule_id,
            "title": RULE_TITLES[self.rule_id],
            "severity": self.severity,
            "platform": self.platform,
            "hostname": self.hostname,
            "source_ip": self.source_ip,
            "usernames": sorted({_account(event) for event in ordered}, key=str.casefold),
            "first_seen": _iso(ordered[0].timestamp),
            "last_seen": _iso(ordered[-1].timestamp),
            "event_count": len(ordered),
            "evidence": event_refs,
        }


def load_normalized_events(paths: Iterable[Path]) -> tuple[list[SecurityEvent], int]:
    """Load one or more Phase 2 parse outputs and skip byte-identical events."""
    events: list[SecurityEvent] = []
    unique: set[str] = set()
    duplicates = 0
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("events"), list):
            raise ValueError(f"{path}: expected a Phase 2 JSON object with an 'events' list")
        for index, item in enumerate(data["events"], start=1):
            try:
                event = SecurityEvent.from_dict(item)
                key = _event_key(event)
            except (ValueError, TypeError, KeyError, AttributeError) as exc:
                raise ValueError(f"{path}: event #{index}: {exc}") from exc
            if key in unique:
                duplicates += 1
                continue
            unique.add(key)
            events.append(event)
    events.sort(key=lambda event: (event.timestamp, _event_key(event)))
    return events, duplicates


def _windows(events: list[SecurityEvent], settings: RuleSettings, rule_id: str) -> list[tuple[SecurityEvent, ...]]:
    """Build merged, overlapping qualifying rolling windows for one scope."""
    minutes = timedelta(minutes=settings.window_minutes)
    first = 0
    usernames: Counter[str] = Counter()
    ranges: list[tuple[int, int]] = []
    for last, event in enumerate(events):
        usernames[_account(event)] += 1
        while event.timestamp - events[first].timestamp > minutes:
            old = _account(events[first])
            usernames[old] -= 1
            if usernames[old] == 0:
                del usernames[old]
            first += 1
        sufficient = last - first + 1 >= settings.min_failures
        if rule_id == "password_spray":
            sufficient = sufficient and len(usernames) >= settings.min_distinct_accounts
        if sufficient:
            if ranges and first <= ranges[-1][1]:
                ranges[-1] = (ranges[-1][0], last)
            else:
                ranges.append((first, last))
    return [tuple(events[start:end + 1]) for start, end in ranges]


def detect_events(events: Iterable[SecurityEvent], rules: DetectionConfig) -> list[Finding]:
    """Find IP-scoped authentication patterns within each host and platform."""
    failures_by_account: dict[tuple, list[SecurityEvent]] = defaultdict(list)
    failures_by_host: dict[tuple, list[SecurityEvent]] = defaultdict(list)
    history_by_account: dict[tuple, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if event.event_type not in {"login_success", "login_failure"}:
            continue
        if event.source_ip is None:
            continue  # A local/service logon cannot safely be assigned a remote IP.
        host = (event.platform, event.hostname.casefold(), event.source_ip)
        account = (*host, _account(event))
        history_by_account[account].append(event)
        if event.event_type == "login_failure":
            failures_by_account[account].append(event)
            failures_by_host[host].append(event)

    findings: list[Finding] = []

    def add(rule_id: str, severity: str, evidence: tuple[SecurityEvent, ...]):
        first = evidence[0]
        findings.append(Finding(
            rule_id, severity, first.platform, first.hostname, first.source_ip or "", evidence
        ))

    if rules.brute_force.enabled:
        for group in failures_by_account.values():
            group.sort(key=lambda event: (event.timestamp, _event_key(event)))
            for evidence in _windows(group, rules.brute_force, "brute_force"):
                add("brute_force", rules.brute_force.severity, evidence)

    if rules.password_spray.enabled:
        for group in failures_by_host.values():
            group.sort(key=lambda event: (event.timestamp, _event_key(event)))
            for evidence in _windows(group, rules.password_spray, "password_spray"):
                add("password_spray", rules.password_spray.severity, evidence)

    if rules.success_after_failures.enabled:
        window = timedelta(minutes=rules.success_after_failures.window_minutes)
        for group in history_by_account.values():
            group.sort(key=lambda event: (event.timestamp, _event_key(event)))
            recent: deque[SecurityEvent] = deque()
            for event in group:
                while recent and event.timestamp - recent[0].timestamp > window:
                    recent.popleft()
                if event.event_type == "login_failure":
                    recent.append(event)
                else:
                    if len(recent) >= rules.success_after_failures.min_failures:
                        add(
                            "success_after_failures", rules.success_after_failures.severity,
                            (*recent, event),
                        )
                    recent.clear()  # Don't reuse failures for subsequent successes.

    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda finding: (
        finding.evidence[0].timestamp, priority[finding.severity], finding.rule_id,
        finding.hostname.casefold(), finding.source_ip,
    ))
    return findings


def detection_report(
    events: list[SecurityEvent], findings: list[Finding],
    input_files: list[Path], duplicate_count: int, config_file: Path,
) -> dict:
    """Serialize findings together with useful analysis metadata."""
    serialized = [finding.to_dict() for finding in findings]
    return {
        "tool_version": __version__,
        "input_files": [str(path) for path in input_files],
        "rules_file": str(config_file),
        "summary": {
            "events_analyzed": len(events),
            "duplicate_events_skipped": duplicate_count,
            "missing_source_ip_events": sum(event.source_ip is None for event in events),
            "total_findings": len(serialized),
            "by_rule": {
                rule: sum(f["rule_id"] == rule for f in serialized)
                for rule in RULE_TITLES
            },
            "by_severity": {
                severity: sum(f["severity"] == severity for f in serialized)
                for severity in ("critical", "high", "medium", "low")
            },
        },
        "findings": serialized,
    }
