"""Evidence-linked, UTC-ordered incident timelines and conservative analyst context.

This module accepts Phase 4's *serialized* incident dictionaries, making it usable
from a command-line program, local web UI or offline JSON report reader without
re-running parsers or depending on a web framework.

A timeline contains only evidence that contributed to an alert. It is NOT a
complete host activity history and does not establish compromise or intent.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be valid ISO 8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _account(event: Mapping[str, Any]) -> str:
    """Compute evidence-level identities while respecting Windows domains."""
    name = event.get("username")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("Timeline evidence must contain a nonempty username")
    if event.get("platform") != "windows":
        return name
    details = event.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("Evidence details must be an object")
    domain = details.get("domain", "")
    if not isinstance(domain, str):
        raise ValueError("Evidence domain must be a string")
    return f"{domain.casefold()}\\{name.casefold()}" if domain else name.casefold()


def _entry(event: Mapping[str, Any], *, index: int, first: datetime) -> dict:
    kind = event.get("event_type")
    if kind not in {"login_failure", "login_success"}:
        raise ValueError(f"Unsupported timeline event type: {kind!r}")
    evidence_id = event.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise ValueError("Timeline evidence must include an evidence_id")
    links = event.get("linked_finding_ids")
    if not isinstance(links, list) or not links or not all(
        isinstance(value, str) and value for value in links
    ):
        raise ValueError("Timeline evidence must include linked_finding_ids")
    observed_at = _time(event.get("timestamp"), "evidence timestamp")
    source_line = event.get("source_line")
    record_id = event.get("record_id")
    source = event.get("source_file")
    if not isinstance(source, str) or not source.strip():
        raise ValueError("Timeline evidence must include source_file")
    account = _account(event)
    successful = kind == "login_success"
    return {
        "sequence": index,
        "evidence_id": evidence_id,
        "timestamp": observed_at.isoformat(timespec=("microseconds" if observed_at.microsecond else "seconds")).replace("+00:00", "Z"),
        "seconds_from_start": round((observed_at - first).total_seconds(), 6),
        "event_type": kind,
        "stage": "authentication_success" if successful else "authentication_failure",
        "label": "Successful authentication observed" if successful else "Failed authentication observed",
        "account": account,
        "username": event["username"],
        "source_ip": event.get("source_ip"),
        "hostname": event.get("hostname"),
        "platform": event.get("platform"),
        "authentication_method": event.get("authentication_method"),
        "event_id": event.get("event_id"),
        "source": {"file": source, "line": source_line, "record_id": record_id},
        "linked_finding_ids": sorted(set(links)),
    }


def build_incident_timeline(incident: Mapping[str, Any]) -> dict:
    """Return a JSON-safe timeline and conservative assessment for one incident.

    No mutation of incident inputs; no new evidence synthesized.
    """
    if not isinstance(incident, Mapping):
        raise ValueError("Incident must be a mapping")
    incident_id = incident.get("incident_id")
    if not isinstance(incident_id, str) or not incident_id.strip():
        raise ValueError("Incident must have an incident_id")
    evidence = incident.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("Incident evidence must be a nonempty list")
    for event in evidence:
        if not isinstance(event, dict):
            raise ValueError("Each timeline evidence event must be an object")
    # Sort by real UTC instants, not text (which may contain timezone offsets).
    ordered = sorted(evidence, key=lambda e: (_time(e.get("timestamp"), "evidence timestamp"), str(e.get("evidence_id", ""))))
    first = _time(ordered[0]["timestamp"], "first evidence timestamp")
    last = _time(ordered[-1]["timestamp"], "last evidence timestamp")
    evidence_ids = [event.get("evidence_id") for event in ordered]
    if not all(isinstance(eid, str) and eid.strip() for eid in evidence_ids):
        raise ValueError("Timeline evidence must include an evidence_id")
    if len(set(evidence_ids)) != len(evidence_ids):
        raise ValueError("Incident timeline contains duplicate evidence IDs")

    entries = [_entry(event, index=n, first=first) for n, event in enumerate(ordered, start=1)]
    failures = [item for item in entries if item["event_type"] == "login_failure"]
    successes = [item for item in entries if item["event_type"] == "login_success"]
    accounts = sorted({e["account"] for e in entries}, key=lambda s: (s.casefold(), s))
    related_successes = [
        success for success in successes
        if any(fail["account"] == success["account"] and fail["timestamp"] < success["timestamp"]
               for fail in failures)
    ]
    if related_successes:
        pattern = "failure_then_success_same_account"
        observation = (
            "Failed authentications followed by a successful authentication "
            "for the same account were observed in linked evidence."
        )
    elif failures and successes:
        pattern = "mixed_failures_and_successes"
        observation = "Both failed and successful authentications were observed; affected accounts may differ."
    elif failures and len(accounts) > 1:
        pattern = "failures_across_multiple_accounts"
        observation = "Failed authentications affecting multiple accounts were observed."
    elif failures:
        pattern = "repeated_authentication_failures"
        observation = "Failed authentications were observed for one account."
    else:
        pattern = "successful_authentication_only"
        observation = "Successful authentications were observed in the linked evidence."

    # These are investigation suggestions, not actions the tool has carried out.
    checks = [
        "Confirm whether the authentication activity was expected and authorized.",
        "Compare source IP, affected accounts, and timestamps against other authorized records.",
    ]
    if successes:
        checks.append("Verify successful sessions and review subsequent host activity using other logs.")
    else:
        checks.append("Check whether other telemetry shows later successful authentication attempts.")

    counts = Counter(item["stage"] for item in entries)
    return {
        "incident_id": incident_id,
        "scope": "linked_detection_evidence_only",
        "first_seen": entries[0]["timestamp"],
        "last_seen": entries[-1]["timestamp"],
        "duration_seconds": round((last - first).total_seconds(), 6),
        "event_count": len(entries),
        "failed_logins": counts["authentication_failure"],
        "successful_logins": counts["authentication_success"],
        "affected_accounts": accounts,
        "observed_pattern": pattern,
        "analyst_summary": observation + " This is not proof of compromise.",
        "recommended_checks": checks,
        "events": entries,
    }
