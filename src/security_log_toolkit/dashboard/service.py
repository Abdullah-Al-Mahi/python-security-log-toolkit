"""Bounded, privacy-conscious dashboard adapters for existing analysis services.

No Streamlit import here: CLI and dashboard both use the same validators,
detection, correlation, timeline and export functions. Raw uploads are written
only to a TemporaryDirectory, deleted before this function returns. Never use
client-supplied filenames to build filesystem paths.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from io import BytesIO
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import tempfile
from xml.etree.ElementTree import ParseError
from typing import Mapping, Sequence
from zipfile import ZipFile, ZIP_DEFLATED

import yaml

from security_log_toolkit.correlation.config import load_correlation_config
from security_log_toolkit.detection.config import RULE_FIELDS, SEVERITIES, load_detection_config
from security_log_toolkit.reporting import (
    build_export_artifacts, build_report_tables, validate_investigation_report,
)
from security_log_toolkit.security_limits import MAX_RAW_LOG_BYTES, MAX_INVESTIGATION_JSON_BYTES
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs

MAX_UPLOAD_FILES = 4
MAX_UPLOAD_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILENAME_CHARS = 120


@dataclass(frozen=True, slots=True)
class UploadedSource:
    """Uploaded raw file, never interpreted as a trusted local path."""

    name: str
    source_format: str
    payload: bytes


def _safe_display_name(name: str) -> str:
    if not isinstance(name, str) or not name.strip() or len(name) > MAX_FILENAME_CHARS:
        raise ValueError("Upload filenames must contain 1-120 characters")
    # Browser filenames are only labels; disallow paths even though they are
    # never used to name a real file. This also makes upload provenance clear.
    if ("/" in name or "\\" in name or "\x00" in name
            or PurePosixPath(name).name != name
            or PureWindowsPath(name).name != name):
        raise ValueError("Upload filename must not contain a path")
    return name


def validate_uploads(sources: Sequence[UploadedSource]) -> list[UploadedSource]:
    if not isinstance(sources, (list, tuple)) or not 1 <= len(sources) <= MAX_UPLOAD_FILES:
        raise ValueError("Upload 1 to 4 supported raw log files")
    results: list[UploadedSource] = []
    total = 0
    for source in sources:
        if not isinstance(source, UploadedSource):
            raise ValueError("Each upload must be an UploadedSource")
        name = _safe_display_name(source.name)
        if source.source_format not in ("linux", "windows"):
            raise ValueError("Upload format must be linux or windows")
        extension = Path(name).suffix.lower()
        permitted = {"linux": {".log", ".txt"}, "windows": {".xml"}}
        if extension not in permitted[source.source_format]:
            raise ValueError("Linux accepts .log/.txt; Windows accepts .xml only (not binary .evtx)")
        if not isinstance(source.payload, bytes) or not source.payload:
            raise ValueError("Upload must contain nonempty bytes")
        if len(source.payload) > MAX_RAW_LOG_BYTES:
            raise ValueError("Each raw log must be at most 16 MiB")
        total += len(source.payload)
        if total > MAX_UPLOAD_TOTAL_BYTES:
            raise ValueError("Combined raw uploads exceed the 32 MiB limit")
        results.append(source)
    return results


def _strict_positive(value: object, title: str) -> int:
    if type(value) is not int or not 1 <= value <= 1440:
        raise ValueError(f"{title} must be an integer between 1 and 1440")
    return value


def build_rule_yaml(base_rules: Path, overrides: Mapping[str, Mapping] | None = None) -> bytes:
    """Return safe YAML using the existing strict settings schema.

    Settings remain ephemeral. This function NEVER writes to base_rules.
    """
    config = load_detection_config(Path(base_rules))
    from dataclasses import asdict
    originals = asdict(config)
    overrides = {} if overrides is None else overrides
    if not isinstance(overrides, Mapping) or set(overrides) - set(RULE_FIELDS):
        raise ValueError("Unknown detection rule overrides")
    for name, changes in overrides.items():
        if not isinstance(changes, Mapping) or set(changes) - RULE_FIELDS[name]:
            raise ValueError(f"Invalid settings for {name}")
        originals[name].update(changes)
    clean: dict[str, dict] = {}
    for name in ("brute_force", "password_spray", "success_after_failures"):
        item = originals[name]
        if type(item["enabled"]) is not bool:
            raise ValueError(f"{name}.enabled must be true or false")
        if not isinstance(item["severity"], str) or item["severity"] not in SEVERITIES:
            raise ValueError(f"{name}.severity is invalid")
        for key in ("window_minutes", "min_failures"):
            _strict_positive(item[key], f"{name}.{key}")
        if name == "password_spray":
            _strict_positive(item["min_distinct_accounts"], "password_spray.min_distinct_accounts")
        clean[name] = {key: item[key] for key in sorted(RULE_FIELDS[name])}
    return yaml.safe_dump({"version": 1, "rules": clean}, sort_keys=False).encode("utf-8")


def build_correlation_yaml(base_rules: Path, overrides: Mapping | None = None) -> bytes:
    from dataclasses import asdict
    config = asdict(load_correlation_config(Path(base_rules)))
    overrides = {} if overrides is None else overrides
    if not isinstance(overrides, Mapping) or set(overrides) - set(config):
        raise ValueError("Unknown correlation settings")
    config.update(overrides)
    for name, value in config.items():
        _strict_positive(value, name)
    return yaml.safe_dump({"version": 1, "correlation": config}, sort_keys=False).encode("utf-8")


def analyze_uploaded_sources(
    sources: Sequence[UploadedSource], *,
    detection_rules: Path, correlation_rules: Path,
    year: int | None = None, utc_offset: str | None = None,
    detection_overrides: Mapping[str, Mapping] | None = None,
    correlation_overrides: Mapping | None = None,
) -> dict:
    """Process uploads privately and return a detached, validated report.

    Files and temporary YAML exist only within this call. The returned report
    uses stable uploaded labels instead of disclosing deleted temp file paths.
    """
    checked = validate_uploads(sources)
    if any(item.source_format == "linux" for item in checked):
        if type(year) is not int or not 1970 <= year <= 9999 or not utc_offset:
            raise ValueError("Linux uploads require a valid year and explicit UTC offset")
    d_yaml = build_rule_yaml(detection_rules, detection_overrides)
    c_yaml = build_correlation_yaml(correlation_rules, correlation_overrides)
    with tempfile.TemporaryDirectory(prefix="security-log-dashboard-") as folder:
        root = Path(folder)
        rule_path = root / "detection_rules.yaml"
        corr_path = root / "correlation_rules.yaml"
        rule_path.write_bytes(d_yaml)
        corr_path.write_bytes(c_yaml)
        # Confirm generated YAML agrees with original strict validators.
        load_detection_config(rule_path)
        load_correlation_config(corr_path)
        source_paths = []
        aliases: dict[str, str] = {str(rule_path): "session:detection_rules.yaml", str(corr_path): "session:correlation_rules.yaml"}
        used_names: set[str] = set()
        for i, item in enumerate(checked, 1):
            ext = Path(item.name).suffix.lower()
            raw_path = root / f"raw_{i:02d}{ext}"
            raw_path.write_bytes(item.payload)
            source_paths.append(RawLogSource(item.source_format, raw_path))
            label = item.name
            if label in used_names:
                label = f"{i} - {label}"
            used_names.add(label)
            aliases[str(raw_path)] = f"uploaded:{label}"
        try:
            report = analyze_raw_logs(
                source_paths, detection_rules=rule_path, correlation_rules=corr_path,
                year=year, utc_offset=utc_offset,
            )
        except ParseError as exc:
            raise ValueError(f"Malformed Windows Security XML: {exc}") from exc
        # Serialized report may contain source paths in timeline references and
        # evidence. Replace every matching *string value* before temp deletion.
        def replace_paths(value: object) -> object:
            if isinstance(value, str):
                return aliases.get(value, value)
            if isinstance(value, list):
                return [replace_paths(v) for v in value]
            if isinstance(value, dict):
                return {k: replace_paths(v) for k, v in value.items()}
            return value
        safe = replace_paths(report)
    assert isinstance(safe, dict)
    safe["dashboard_input_type"] = "user_upload"
    safe["dashboard_note"] = "Uploaded bytes processed in temporary storage; no raw log files retained by the toolkit."
    return validate_investigation_report(safe)


def load_synthetic_demo(project_root: Path) -> dict:
    root = Path(project_root)
    report = analyze_raw_logs(
        [
            RawLogSource("linux", root / "samples/linux/attack_auth.log"),
            RawLogSource("windows", root / "samples/windows/attack_security.xml"),
        ],
        detection_rules=root / "config/detection_rules.yaml",
        correlation_rules=root / "config/correlation_rules.yaml",
        year=2026, utc_offset="+08:00",
    )
    report["dashboard_input_type"] = "bundled_synthetic_demo"
    return validate_investigation_report(report)


def load_investigation_json(payload: bytes) -> dict:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_INVESTIGATION_JSON_BYTES:
        raise ValueError("Investigation JSON must be nonempty and at most 50 MiB")
    try:
        data = json.loads(payload.decode("utf-8-sig"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Non-finite JSON value")))
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Investigation JSON is malformed or contains unsupported values") from exc
    report = validate_investigation_report(data)
    report["dashboard_input_type"] = "imported_report"
    return report


def filter_incidents(
    report: dict, *, severity: Sequence[str] = (), platform: Sequence[str] = (),
    rule: Sequence[str] = (), query: str = "",
) -> list[dict]:
    incidents = validate_investigation_report(report)["incidents"]
    severities = set(severity)
    platforms = set(platform)
    rules = set(rule)
    term = str(query).strip().casefold()
    matched = []
    for entry in incidents:
        if severities and entry.get("severity") not in severities:
            continue
        if platforms and entry.get("platform") not in platforms:
            continue
        if rules and not (rules & set(entry.get("rule_ids") or [])):
            continue
        searchable = " ".join(str(v) for v in (
            entry.get("incident_id", ""), entry.get("source_ip", ""),
            entry.get("hostname", ""), entry.get("platform", ""),
            entry.get("severity", ""), " ".join(entry.get("affected_accounts") or []),
            " ".join(entry.get("rule_ids") or []),
        )).casefold()
        if term and term not in searchable:
            continue
        matched.append(entry)
    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(matched, key=lambda i: (priority.get(i.get("severity"), 4), str(i.get("first_seen", "")), i["incident_id"]))


def incident_detail(report: dict, incident_id: str) -> dict:
    for incident in validate_investigation_report(report)["incidents"]:
        if incident["incident_id"] == incident_id:
            return incident
    raise ValueError("Unknown incident ID")


def severity_summary(report: dict) -> list[dict]:
    counts = Counter(x.get("severity", "unknown") for x in validate_investigation_report(report)["incidents"])
    return [{"severity": key, "incidents": counts.get(key, 0)} for key in ("critical", "high", "medium", "low")]


def rule_summary(report: dict) -> list[dict]:
    counts = Counter(x.get("rule_id", "unknown") for x in validate_investigation_report(report).get("findings", []))
    return [{"rule": key, "findings": counts[key]} for key in sorted(counts)]


def top_sources(report: dict, limit: int = 8) -> list[dict]:
    counts = Counter(x.get("source_ip", "unknown") for x in validate_investigation_report(report)["incidents"])
    return [{"source_ip": k or "unknown", "incidents": v} for k, v in counts.most_common(limit)]


def timeline_activity(report: dict) -> list[dict]:
    counts: Counter[tuple[str, str]] = Counter()
    for incident in validate_investigation_report(report)["incidents"]:
        for event in (incident.get("timeline") or {}).get("events", []):
            counts[(str(event.get("timestamp", ""))[:16], str(event.get("stage", "unknown")))] += 1
    return [{"minute": k[0], "stage": k[1], "events": v} for k, v in sorted(counts.items())]


def build_dashboard_downloads(report: dict) -> dict[str, bytes]:
    return build_export_artifacts(report, "both")


def build_dashboard_zip(report: dict) -> bytes:
    files = build_dashboard_downloads(report)
    stream = BytesIO()
    with ZipFile(stream, "w", ZIP_DEFLATED, compresslevel=6) as archive:
        for name, payload in sorted(files.items()):
            archive.writestr(name, payload)
    return stream.getvalue()
