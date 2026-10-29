"""Reproducible, offline synthetic portfolio demonstration for Phase 9.

This does not perform network I/O, publish reports, or generate screenshots.
It builds artifacts in memory using the same backend the CLI and upcoming
Phase 10 local browser interface will use.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

from security_log_toolkit import __version__
from security_log_toolkit.quality import evaluate_scenarios
from security_log_toolkit.reporting import build_export_artifacts, summarize_report
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs

EXPECTED = {
    "events_analyzed": 29,
    "findings_analyzed": 6,
    "total_incidents": 4,
    "unique_evidence_events": 22,
}
EXPECTED_VALIDATION = {
    "scenarios": 4,
    "events": 41,
    "true_positives": 6,
    "false_positives": 0,
    "false_negatives": 0,
}


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def build_portfolio_artifacts(project_root: Path) -> dict[str, bytes]:
    """Build demonstration artifacts, without modifying a user's project.

    Uses bundled *synthetic* fixtures. The count checks prevent publishing a
    misleading sample if rules or fixtures change in a future phase.
    """
    root = Path(project_root).resolve()
    rules = root / "config/detection_rules.yaml"
    correlation = root / "config/correlation_rules.yaml"
    report = analyze_raw_logs(
        [
            RawLogSource("linux", root / "samples/linux/attack_auth.log"),
            RawLogSource("windows", root / "samples/windows/attack_security.xml"),
        ],
        detection_rules=rules,
        correlation_rules=correlation,
        year=2026,
        utc_offset="+08:00",
    )
    counts = report["summary"]
    for name, expected in EXPECTED.items():
        if counts[name] != expected:
            raise ValueError(f"Synthetic demo changed: {name}={counts[name]}, expected {expected}")

    validation = evaluate_scenarios(
        root / "samples/validation/ground_truth.json",
        samples_dir=root / "samples",
        detection_rules=rules,
    )
    validation_counts = validation["summary"]
    for name, expected in EXPECTED_VALIDATION.items():
        if validation_counts[name] != expected:
            raise ValueError(f"Synthetic validation changed: {name}={validation_counts[name]}, expected {expected}")

    # Validate and build all seven linked CSV/JSON export artifacts in memory.
    exports = build_export_artifacts(report, "both")
    artifacts = {f"export/{name}": content for name, content in exports.items()}
    artifacts["investigation.json"] = _json_bytes(report)
    artifacts["analyst_summary.txt"] = (summarize_report(report) + "\n").encode("utf-8")
    artifacts["validation_summary.json"] = _json_bytes({
        "assessment": "synthetic_rule_label_validation",
        "summary": validation_counts,
        "limitations": validation["limitations"],
    })
    manifest = {
        "schema_version": 1,
        "application": "python-security-log-toolkit",
        "tool_version": __version__,
        "dataset": "bundled synthetic fixtures only",
        "report_counts": {name: counts[name] for name in EXPECTED},
        "validation_counts": {name: validation_counts[name] for name in EXPECTED_VALIDATION},
        "files": {name: {"sha256": sha256(data).hexdigest(), "bytes": len(data)}
                  for name, data in sorted(artifacts.items())},
        "notes": "This demo proves only expected behavior on bundled synthetic fixtures; it is not production detection accuracy.",
    }
    artifacts["portfolio_manifest.json"] = _json_bytes(manifest)
    return artifacts


def write_portfolio_artifacts(artifacts: dict[str, bytes], output_dir: Path) -> list[Path]:
    """Write a new demo directory; refuse overwrites and unsafe filenames.

    No force flag by design: never delete or replace earlier investigation work.
    """
    target = Path(output_dir)
    if target.is_symlink() or target.exists():
        raise ValueError("Output directory already exists; choose a fresh --output-dir")
    if target.resolve().is_relative_to(Path.cwd().resolve() / "src"):
        raise ValueError("Do not write portfolio outputs inside source code")
    allowed = {"investigation.json", "analyst_summary.txt", "validation_summary.json", "portfolio_manifest.json"}
    export_allowed = {"summary.csv", "incidents.csv", "findings.csv", "evidence.csv", "timelines.csv", "investigation.json", "export_manifest.json"}
    if not artifacts or "portfolio_manifest.json" not in artifacts:
        raise ValueError("Portfolio artifacts must include a manifest")
    for name, content in artifacts.items():
        if name not in allowed and not (name.startswith("export/") and name.removeprefix("export/") in export_allowed):
            raise ValueError(f"Unexpected portfolio filename: {name}")
        if not isinstance(content, bytes):
            raise ValueError("Portfolio artifacts must be bytes")
    target.mkdir(parents=True, exist_ok=False)
    created = []
    try:
        for name, content in sorted(artifacts.items()):
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            created.append(path)
    except BaseException:
        # Only remove files this function itself successfully created.
        for path in reversed(created):
            path.unlink(missing_ok=True)
        for child in sorted(target.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        target.rmdir()
        raise
    return created
