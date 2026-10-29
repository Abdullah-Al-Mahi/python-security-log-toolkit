"""Rule-level accuracy checks against explicitly hand-labeled synthetic cases.

These metrics are *not* estimates of production sensitivity or false-positive rate.
The manifest enumerates expected (rule, source_ip) labels per test scenario.
"""
import json
from ipaddress import ip_address
from pathlib import Path, PurePosixPath, PureWindowsPath

from security_log_toolkit.detection import detect_events, load_detection_config
from security_log_toolkit.ingest import ingest_file
from security_log_toolkit.security_limits import require_bounded_file

KNOWN_RULES = frozenset(("brute_force", "password_spray", "success_after_failures"))


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _scenario_labels(expected: object) -> set[tuple[str, str]]:
    if not isinstance(expected, list):
        raise ValueError("scenario expected labels must be a list")
    labels: set[tuple[str, str]] = set()
    for entry in expected:
        if not isinstance(entry, dict) or set(entry) != {"rule_id", "source_ip"}:
            raise ValueError("expected label must contain only rule_id and source_ip")
        rule = _string(entry["rule_id"], "rule_id")
        if rule not in KNOWN_RULES:
            raise ValueError(f"unknown ground-truth rule_id: {rule}")
        ip = _string(entry["source_ip"], "source_ip")
        try:
            ip = str(ip_address(ip))
        except ValueError as exc:
            raise ValueError("expected label source_ip must be a valid IP address") from exc
        label = (rule, ip)
        if label in labels:
            raise ValueError(f"duplicate expected label: {label}")
        labels.add(label)
    return labels


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate_scenarios(
    truth_path: Path, *, samples_dir: Path, detection_rules: Path,
) -> dict:
    """Evaluate labeled offline files; return a pure JSON-safe report.

    The manifest is local, small, and explicitly scoped to samples_dir.
    Results reflect per-scenario rule+IP presence, not alert timing or incident
    severity correctness. No generated output is written here.
    """
    truth_path = Path(truth_path)
    require_bounded_file(truth_path, 1024 * 1024, "Ground truth")
    try:
        truth = json.loads(truth_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Ground truth JSON is invalid: {exc}") from exc
    if not isinstance(truth, dict) or truth.get("schema_version") != 1:
        raise ValueError("Ground truth must use schema_version 1")
    if not isinstance(truth.get("scenarios"), list) or not truth["scenarios"]:
        raise ValueError("Ground truth requires a nonempty scenarios list")
    rules = load_detection_config(Path(detection_rules))
    sample_root = Path(samples_dir).resolve()
    results: list[dict] = []
    seen_names: set[str] = set()
    tp_total = fp_total = fn_total = event_total = 0

    for scenario in truth["scenarios"]:
        if not isinstance(scenario, dict):
            raise ValueError("Each scenario must be an object")
        name = _string(scenario.get("name"), "scenario name")
        if name in seen_names:
            raise ValueError(f"Duplicate scenario name: {name}")
        seen_names.add(name)
        kind = scenario.get("format")
        if kind not in ("linux", "windows"):
            raise ValueError(f"{name}: format must be linux or windows")
        # Validate both pathname conventions, regardless of the host OS.
        # WindowsPath("/etc/passwd") is root-relative but not is_absolute(),
        # while PosixPath("C:\\Windows") treats a drive as plain text.
        # Using both PurePath variants makes the manifest portable and keeps
        # rooted, drive-qualified, UNC, and traversal paths out of samples_dir.
        file_value = _string(scenario.get("file"), "scenario file")
        posix_path = PurePosixPath(file_value)
        windows_path = PureWindowsPath(file_value)
        if (
            posix_path.is_absolute()
            or bool(windows_path.anchor)
            or ".." in posix_path.parts
            or ".." in windows_path.parts
        ):
            raise ValueError(f"{name}: file must be relative to samples directory")
        relative = Path(file_value)
        path = (sample_root / relative).resolve()
        if not path.is_relative_to(sample_root):
            raise ValueError(f"{name}: file must stay inside samples directory")
        if kind == "linux":
            year = scenario.get("year")
            offset = scenario.get("utc_offset")
            if type(year) is not int or not isinstance(offset, str):
                raise ValueError(f"{name}: Linux scenario requires year and utc_offset")
        else:
            year = None
            offset = "+00:00"
        expected = _scenario_labels(scenario.get("expected"))
        parsed = ingest_file(kind, path, year=year, utc_offset=offset)
        observed = {(f.rule_id, f.source_ip) for f in detect_events(parsed.events, rules)}
        tp = expected & observed
        fp = observed - expected
        fn = expected - observed
        event_total += len(parsed.events)
        tp_total += len(tp)
        fp_total += len(fp)
        fn_total += len(fn)
        results.append({
            "name": name,
            "source_format": kind,
            "source_file": str(path),
            "events": len(parsed.events),
            "true_positives": len(tp),
            "false_positives": len(fp),
            "false_negatives": len(fn),
            "expected": [{"rule_id": x[0], "source_ip": x[1]} for x in sorted(expected)],
            "observed": [{"rule_id": x[0], "source_ip": x[1]} for x in sorted(observed)],
            "unexpected": [{"rule_id": x[0], "source_ip": x[1]} for x in sorted(fp)],
            "missed": [{"rule_id": x[0], "source_ip": x[1]} for x in sorted(fn)],
        })

    precision = _rate(tp_total, tp_total + fp_total)
    recall = _rate(tp_total, tp_total + fn_total)
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision is not None and recall is not None and precision + recall else None)
    return {
        "assessment": "synthetic_rule_label_validation",
        "truth_file": str(truth_path),
        "rules_file": str(detection_rules),
        "limitations": (
            "Scenario-level (rule_id, source_ip) presence on hand-labeled synthetic logs only. "
            "Does not measure real-world detection accuracy, true negatives, "
            "alert timing, or account compromise."
        ),
        "summary": {
            "scenarios": len(results),
            "events": event_total,
            "true_positives": tp_total,
            "false_positives": fp_total,
            "false_negatives": fn_total,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
        },
        "scenarios": results,
    }
