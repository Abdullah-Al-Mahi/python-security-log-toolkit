"""Deterministic offline correlation of Phase 3 security findings into incidents.

The grouping key is (platform, case-insensitive hostname, source IP).
An incident may contain one finding; no alert is silently discarded.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Iterable

from security_log_toolkit.correlation.config import CorrelationConfig
from security_log_toolkit.detection.engine import Finding
from security_log_toolkit.events import SecurityEvent

_SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _iso(dt: datetime) -> str:
    utc = dt.astimezone(timezone.utc)
    precision = "microseconds" if utc.microsecond else "seconds"
    return utc.isoformat(timespec=precision).replace("+00:00", "Z")


def _event_signature(event: SecurityEvent) -> str:
    """Stable signature used to remove overlapping evidence across findings."""
    return json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _finding_id(finding: Finding) -> str:
    return finding.to_dict()["finding_id"]


def _bounds(finding: Finding) -> tuple[datetime, datetime]:
    if not finding.evidence:
        raise ValueError("Cannot correlate a finding with no evidence")
    timestamps = [event.timestamp for event in finding.evidence]
    if any(value.tzinfo is None for value in timestamps):
        raise ValueError("Finding evidence timestamps must be timezone-aware")
    return min(timestamps), max(timestamps)


@dataclass(frozen=True, slots=True)
class Incident:
    """One incident containing either a single or multiple related findings."""

    platform: str
    hostname: str
    source_ip: str
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict:
        """Return JSON-safe, evidence-preserving incident representation."""
        if not self.findings:
            raise ValueError("An incident must contain at least one finding")

        summaries = [finding.to_dict() for finding in self.findings]
        summaries.sort(key=lambda f: f["finding_id"])
        finding_ids = [item["finding_id"] for item in summaries]
        digest = hashlib.sha256(json.dumps(
            [self.platform, self.hostname.casefold(), self.source_ip, finding_ids],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()[:16]

        # Findings frequently share the same failed-login events. Count each once.
        evidence_by_key: dict[str, dict] = {}
        for finding in self.findings:
            fid = _finding_id(finding)
            for event in finding.evidence:
                signature = _event_signature(event)
                if signature not in evidence_by_key:
                    data = event.to_dict()
                    evidence_by_key[signature] = {
                        "evidence_id": "E-" + hashlib.sha256(signature.encode("utf-8")).hexdigest()[:16],
                        **data,
                        "linked_finding_ids": [],
                    }
                evidence_by_key[signature]["linked_finding_ids"].append(fid)
        evidence = list(evidence_by_key.values())
        for event in evidence:
            event["linked_finding_ids"] = sorted(set(event["linked_finding_ids"]))
        evidence.sort(key=lambda event: (event["timestamp"], event["evidence_id"]))

        all_times = [event.timestamp for finding in self.findings for event in finding.evidence]
        highest = min((item["severity"] for item in summaries), key=_SEVERITY_PRIORITY.__getitem__)
        rule_ids = sorted({item["rule_id"] for item in summaries})
        users = sorted({user for item in summaries for user in item["usernames"]}, key=str.casefold)
        return {
            "incident_id": f"I-{digest}",
            "classification": "correlated" if len(summaries) > 1 else "single_finding",
            "severity": highest,
            "platform": self.platform,
            "hostname": self.hostname,
            "source_ip": self.source_ip,
            "first_seen": _iso(min(all_times)),
            "last_seen": _iso(max(all_times)),
            "finding_count": len(summaries),
            "finding_ids": finding_ids,
            "rule_ids": rule_ids,
            "affected_accounts": users,
            "unique_evidence_events": len(evidence),
            "evidence": evidence,
        }


def correlate_findings(
    findings: Iterable[Finding], config: CorrelationConfig,
) -> list[Incident]:
    """Group related findings by source/host and bounded time proximity.

    A new finding can join an incident when it begins no later than the
    last finding's end plus max_gap_minutes AND the resulting full incident
    span fits max_incident_minutes. No cross-host or cross-platform linking.
    """
    if (type(config.max_gap_minutes) is not int or config.max_gap_minutes < 1
            or type(config.max_incident_minutes) is not int or config.max_incident_minutes < 1):
        raise ValueError("Correlation windows must be positive integers")
    groups: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        if not finding.source_ip:
            raise ValueError("Cannot correlate finding without a source IP")
        _bounds(finding)
        if finding.severity not in _SEVERITY_PRIORITY:
            raise ValueError("Unsupported finding severity")
        groups[(finding.platform, finding.hostname.casefold(), finding.source_ip)].append(finding)

    incidents: list[Incident] = []
    gap = timedelta(minutes=config.max_gap_minutes)
    span_limit = timedelta(minutes=config.max_incident_minutes)
    for group_key, items in sorted(groups.items()):
        items.sort(key=lambda item: (*_bounds(item), _finding_id(item)))
        batch: list[Finding] = []
        batch_start: datetime | None = None
        batch_end: datetime | None = None

        def emit() -> None:
            if batch:
                # Pick the hostname deterministically when letter casing varies.
                hostname = sorted((item.hostname for item in batch), key=lambda x: (x.casefold(), x))[0]
                incidents.append(Incident(group_key[0], hostname, group_key[2], tuple(batch)))

        for finding in items:
            start, end = _bounds(finding)
            if batch and batch_start is not None and batch_end is not None:
                if start - batch_end > gap or max(end, batch_end) - batch_start > span_limit:
                    emit()
                    batch = []
                    batch_start = None
                    batch_end = None
            if not batch:
                batch_start, batch_end = start, end
            else:
                batch_end = max(batch_end, end)  # type: ignore[arg-type]
            batch.append(finding)
        emit()

    incidents.sort(key=lambda i: (
        min(event.timestamp for finding in i.findings for event in finding.evidence),
        i.platform, i.hostname.casefold(), i.source_ip,
        tuple(sorted(_finding_id(finding) for finding in i.findings)),
    ))
    return incidents
