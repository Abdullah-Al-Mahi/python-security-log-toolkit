"""Read-only, reusable CSV/JSON investigation report exports.

Pure build_export_artifacts() is intended for both the CLI and a future UI.
write_export_bundle() safely installs a complete set of artifacts on disk.
"""

from __future__ import annotations

import csv
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Literal
from uuid import uuid4

from security_log_toolkit import __version__

ExportFormat = Literal["csv", "json", "both"]
REPORT_FILENAMES = ("summary.csv", "incidents.csv", "findings.csv", "evidence.csv", "timelines.csv")
MANIFEST_NAME = "export_manifest.json"

CSV_COLUMNS: dict[str, tuple[str, ...]] = {
    "summary.csv": (
        "tool_version", "workflow", "events_analyzed", "findings_analyzed",
        "total_incidents", "correlated_incidents", "single_finding_incidents",
        "unique_evidence_events", "total_timelines", "timeline_entries", "evidence_scope",
        "critical_incidents", "high_incidents", "medium_incidents", "low_incidents",
    ),
    "incidents.csv": (
        "incident_id", "classification", "severity", "platform", "hostname",
        "source_ip", "first_seen", "last_seen", "finding_count",
        "affected_accounts", "rule_ids", "finding_ids", "unique_evidence_events",
        "observed_pattern", "analyst_summary",
    ),
    "findings.csv": (
        "finding_id", "rule_id", "title", "severity", "platform", "hostname",
        "source_ip", "usernames", "first_seen", "last_seen", "event_count",
        "incident_ids",
    ),
    "evidence.csv": (
        "incident_id", "evidence_id", "timestamp", "event_type", "platform",
        "hostname", "username", "source_ip", "source_port", "authentication_method",
        "event_id", "record_id", "source_file", "source_line", "linked_finding_ids",
        "details_json",
    ),
    "timelines.csv": (
        "incident_id", "sequence", "timestamp", "seconds_from_start", "stage",
        "event_type", "label", "account", "source_ip", "hostname", "platform",
        "evidence_id", "linked_finding_ids", "source_file", "source_line", "record_id",
    ),
}


def validate_investigation_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return JSON-safe independent data, or reject a malformed report."""
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
        raise ValueError("Expected an investigation JSON report with a summary object")
    if not isinstance(report.get("incidents"), list):
        raise ValueError("Investigation report must contain an incidents list")
    if not isinstance(report.get("findings", []), list):
        raise ValueError("Investigation findings must be a list")
    try:
        safe = json.loads(json.dumps(report, ensure_ascii=False, allow_nan=False))
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise ValueError("Investigation report contains non-JSON data") from exc
    incidents = safe["incidents"]
    findings = safe.get("findings", [])
    if safe["summary"].get("total_incidents") != len(incidents):
        raise ValueError("Report incident count does not match incidents list")
    if "findings_analyzed" in safe["summary"] and safe["summary"]["findings_analyzed"] != len(findings):
        raise ValueError("Report findings count does not match findings list")
    incident_ids = set()
    for incident in incidents:
        if not isinstance(incident, dict):
            raise ValueError("Each incident must be an object")
        iid = incident.get("incident_id")
        if not isinstance(iid, str) or not iid or iid in incident_ids:
            raise ValueError("Incident IDs must be nonempty and unique")
        incident_ids.add(iid)
        if not isinstance(incident.get("evidence"), list):
            raise ValueError(f"Incident {iid} must contain an evidence list")
        if not isinstance(incident.get("finding_ids"), list):
            raise ValueError(f"Incident {iid} must contain finding IDs")
        evidence_ids = set()
        for evidence in incident["evidence"]:
            if not isinstance(evidence, dict) or not isinstance(evidence.get("evidence_id"), str):
                raise ValueError(f"Incident {iid} contains invalid evidence")
            if evidence["evidence_id"] in evidence_ids:
                raise ValueError(f"Incident {iid} contains duplicate evidence IDs")
            evidence_ids.add(evidence["evidence_id"])
        if "timeline" in incident:
            timeline = incident["timeline"]
            if not isinstance(timeline, dict) or not isinstance(timeline.get("events"), list):
                raise ValueError(f"Incident {iid} timeline must contain events")
            for event in timeline["events"]:
                if not isinstance(event, dict) or event.get("evidence_id") not in evidence_ids:
                    raise ValueError(f"Incident {iid} timeline references unknown evidence")
    finding_ids = set()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("finding_id"), str):
            raise ValueError("Each finding must have a finding ID")
        if finding["finding_id"] in finding_ids:
            raise ValueError("Finding IDs must be unique")
        finding_ids.add(finding["finding_id"])
    return safe


def _joined(value: Any) -> str:
    if isinstance(value, list):
        return " | ".join(str(item) for item in value)
    return "" if value is None else str(value)


def build_report_tables(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Transform validated investigation JSON into presentation-neutral tables."""
    data = validate_investigation_report(report)
    incidents = sorted(data["incidents"], key=lambda i: (str(i.get("first_seen", "")), i["incident_id"]))
    findings = sorted(data.get("findings", []), key=lambda f: (str(f.get("first_seen", "")), f["finding_id"]))
    summary = data["summary"]
    timelines = data.get("timeline_summary") or {}
    severity = summary.get("by_severity") or {}
    counts = dict(
        tool_version=data.get("tool_version", ""), workflow=data.get("workflow", ""),
        events_analyzed=summary.get("events_analyzed", 0),
        findings_analyzed=summary.get("findings_analyzed", 0),
        total_incidents=summary.get("total_incidents", 0),
        correlated_incidents=summary.get("correlated_incidents", 0),
        single_finding_incidents=summary.get("single_finding_incidents", 0),
        unique_evidence_events=summary.get("unique_evidence_events", 0),
        total_timelines=timelines.get("total_timelines", 0),
        timeline_entries=timelines.get("total_timeline_entries", 0),
        evidence_scope=timelines.get("evidence_scope", "Linked detection evidence only; not full log history"),
        critical_incidents=severity.get("critical", 0), high_incidents=severity.get("high", 0),
        medium_incidents=severity.get("medium", 0), low_incidents=severity.get("low", 0),
    )
    tables: dict[str, list[dict[str, Any]]] = {name: [] for name in CSV_COLUMNS}
    tables["summary.csv"].append(counts)
    finding_to_incidents: dict[str, list[str]] = {}
    for incident in incidents:
        iid = incident["incident_id"]
        for fid in incident["finding_ids"]:
            finding_to_incidents.setdefault(fid, []).append(iid)
        timeline = incident.get("timeline") or {}
        tables["incidents.csv"].append({
            **{k: incident.get(k) for k in (
                "incident_id", "classification", "severity", "platform", "hostname",
                "source_ip", "first_seen", "last_seen", "finding_count", "unique_evidence_events"
            )},
            "affected_accounts": _joined(incident.get("affected_accounts")),
            "rule_ids": _joined(incident.get("rule_ids")),
            "finding_ids": _joined(incident["finding_ids"]),
            "observed_pattern": timeline.get("observed_pattern", ""),
            "analyst_summary": timeline.get("analyst_summary", ""),
        })
        for evidence in sorted(incident["evidence"], key=lambda e: (str(e.get("timestamp", "")), e["evidence_id"])):
            tables["evidence.csv"].append({
                "incident_id": iid,
                **{key: evidence.get(key) for key in (
                    "evidence_id", "timestamp", "event_type", "platform", "hostname",
                    "username", "source_ip", "source_port", "authentication_method",
                    "event_id", "record_id", "source_file", "source_line",
                )},
                "linked_finding_ids": _joined(evidence.get("linked_finding_ids")),
                "details_json": json.dumps(evidence.get("details", {}), ensure_ascii=False, sort_keys=True),
            })
        for event in sorted(timeline.get("events", []), key=lambda e: (e.get("sequence", 0), str(e.get("evidence_id", "")))):
            source = event.get("source") or {}
            tables["timelines.csv"].append({
                "incident_id": iid,
                **{key: event.get(key) for key in (
                    "sequence", "timestamp", "seconds_from_start", "stage", "event_type",
                    "label", "account", "source_ip", "hostname", "platform", "evidence_id",
                )},
                "linked_finding_ids": _joined(event.get("linked_finding_ids")),
                "source_file": source.get("file"),
                "source_line": source.get("line"),
                "record_id": source.get("record_id"),
            })
    for finding in findings:
        tables["findings.csv"].append({
            **{key: finding.get(key) for key in (
                "finding_id", "rule_id", "title", "severity", "platform", "hostname",
                "source_ip", "first_seen", "last_seen", "event_count",
            )},
            "usernames": _joined(finding.get("usernames")),
            "incident_ids": _joined(sorted(finding_to_incidents.get(finding["finding_id"], []))),
        })
    return tables


def _safe_csv_value(value: Any) -> Any:
    """Prevent common spreadsheet formula injection on opening CSV in Excel."""
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    # Excel may interpret leading whitespace/control characters as formula prefixes.
    if text.lstrip(" \t\r\n\ufeff").startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def _encode_csv(name: str, rows: list[dict[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS[name], lineterminator="\r\n", extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _safe_csv_value(row.get(key)) for key in CSV_COLUMNS[name]})
    return stream.getvalue().encode("utf-8-sig")


def build_export_artifacts(report: dict[str, Any], fmt: ExportFormat = "both") -> dict[str, bytes]:
    """Build deterministic downloadable files in memory; never writes to disk.

    Streamlit can directly pass a returned bytes value to a download control.
    """
    if fmt not in ("csv", "json", "both"):
        raise ValueError("Format must be csv, json, or both")
    safe = validate_investigation_report(report)
    result: dict[str, bytes] = {}
    if fmt in ("json", "both"):
        result["investigation.json"] = (json.dumps(safe, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    row_counts: dict[str, int] = {}
    if fmt in ("csv", "both"):
        tables = build_report_tables(safe)
        for name, rows in tables.items():
            result[name] = _encode_csv(name, rows)
            row_counts[name] = len(rows)
    manifest = {
        "application": "python-security-log-toolkit",
        "export_schema_version": 1,
        "exporter_version": __version__,
        "format": fmt,
        "files": {name: {"sha256": sha256(content).hexdigest(), "bytes": len(content), **({"rows": row_counts[name]} if name in row_counts else {})} for name, content in sorted(result.items())},
        "notes": "Timelines contain linked detection evidence only, not full security log history.",
    }
    result[MANIFEST_NAME] = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return result


def summarize_report(report: dict[str, Any]) -> str:
    """Concise human-readable investigation summary."""
    data = validate_investigation_report(report)
    summary = data["summary"]
    timeline = data.get("timeline_summary") or {}
    sev = summary.get("by_severity") or {}
    lines = [
        "Security Log Toolkit — Investigation Summary",
        "--------------------------------------------",
        f"Report version: {data.get('tool_version', 'unknown')}",
        f"Events analyzed: {summary.get('events_analyzed', 0)}",
        f"Detection findings: {summary.get('findings_analyzed', len(data.get('findings', [])))}",
        f"Incidents: {summary['total_incidents']} ({summary.get('correlated_incidents', 0)} correlated)",
        "Incident severity: " + ", ".join(f"{k}={sev.get(k, 0)}" for k in ("critical", "high", "medium", "low")),
        f"Incident timelines: {timeline.get('total_timelines', 0)}",
        f"Linked timeline entries: {timeline.get('total_timeline_entries', 0)}",
        "Evidence scope: linked detection evidence, not complete log history.",
    ]
    return "\n".join(lines)


def write_export_bundle(
    artifacts: dict[str, bytes], output_dir: Path, *,
    protected_paths: list[Path] | None = None, force: bool = False,
) -> list[Path]:
    """Stage export files, then install as one directory with rollback on failure.

    --force can only replace an export previously created by this toolkit, and
    will not remove unexpected files from the existing target directory.
    """
    target = Path(output_dir).absolute()
    if target.is_symlink():
        raise ValueError("Export destination must not be a symbolic link")
    for source in protected_paths or []:
        resolved = Path(source).resolve()
        if resolved == target.resolve() or target.resolve() in resolved.parents:
            raise ValueError("Export destination must not contain the input report")
    if not artifacts or MANIFEST_NAME not in artifacts:
        raise ValueError("Export artifacts must include a manifest")
    if any(name not in (*REPORT_FILENAMES, "investigation.json", MANIFEST_NAME) for name in artifacts):
        raise ValueError("Unexpected export filename")
    if target.exists():
        if not target.is_dir():
            raise ValueError("Export destination exists and is not a directory")
        if not force:
            raise ValueError("Export destination exists; use --force to replace an existing export")
        marker = target / MANIFEST_NAME
        if not marker.is_file() or marker.is_symlink():
            raise ValueError("--force only replaces directories created by the toolkit exporter")
        try:
            prior = json.loads(marker.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            raise ValueError("Existing export manifest is invalid") from exc
        if prior.get("application") != "python-security-log-toolkit" or prior.get("export_schema_version") != 1:
            raise ValueError("Existing directory is not a toolkit export")
        if any(entry.is_symlink() or not entry.is_file() or entry.name not in (*REPORT_FILENAMES, "investigation.json", MANIFEST_NAME) for entry in target.iterdir()):
            raise ValueError("Existing export directory contains unexpected files")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".security-log-export-", dir=target.parent))
    backup: Path | None = None
    try:
        for name, content in artifacts.items():
            if not isinstance(content, bytes):
                raise ValueError("Export artifacts must contain bytes")
            (stage / name).write_bytes(content)
        if target.exists():
            backup = target.parent / f".security-log-backup-{uuid4().hex}"
            os.replace(target, backup)
        try:
            os.replace(stage, target)
        except OSError:
            if backup is not None:
                os.replace(backup, target)
                backup = None
            raise
        if backup is not None:
            shutil.rmtree(backup)
        return [target / filename for filename in sorted(artifacts)]
    finally:
        if stage.exists():
            shutil.rmtree(stage)
