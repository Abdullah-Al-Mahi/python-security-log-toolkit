"""Labeled-scenario metrics and bounded reproducible benchmark contracts."""
import json
from pathlib import Path

import pytest

from security_log_toolkit.quality import evaluate_scenarios, run_benchmark
from security_log_toolkit.quality.benchmark import generate_benchmark_events

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "samples/validation/ground_truth.json"
SAMPLES = ROOT / "samples"
RULES = ROOT / "config/detection_rules.yaml"
CORRELATION = ROOT / "config/correlation_rules.yaml"


def evaluate(truth=TRUTH, samples=SAMPLES, rules=RULES):
    return evaluate_scenarios(truth, samples_dir=samples, detection_rules=rules)


def test_expected_synthetic_accuracy():
    report = evaluate()
    assert report["summary"] == {
        "scenarios": 4, "events": 41, "true_positives": 6,
        "false_positives": 0, "false_negatives": 0,
        "precision": 1.0, "recall": 1.0, "f1_score": 1.0,
    }
    assert "not measure real-world" in report["limitations"]


def test_cases_include_benign_and_attacks():
    rows = evaluate()["scenarios"]
    assert [r["name"] for r in rows] == [
        "linux_attack", "windows_attack", "linux_below_threshold", "windows_below_threshold"
    ]
    assert [r["true_positives"] for r in rows] == [3, 3, 0, 0]


def test_accuracy_is_reproducible():
    assert evaluate() == evaluate()


def test_accuracy_output_json_serializable():
    assert json.loads(json.dumps(evaluate()))["summary"]["true_positives"] == 6


def test_accuracy_rule_disabled_gives_false_negatives(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(RULES.read_text().replace(
        "brute_force:\n    enabled: true", "brute_force:\n    enabled: false"
    ), encoding="utf-8")
    report = evaluate(rules=rules)
    assert report["summary"]["false_negatives"] == 2
    assert report["summary"]["true_positives"] == 4
    assert report["summary"]["recall"] == 0.6667


def _write_truth(tmp_path, mutate):
    data = json.loads(TRUTH.read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / "labels.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("update,match", [
    (lambda d: d.update(schema_version=2), "schema_version"),
    (lambda d: d.update(scenarios=[]), "nonempty scenarios"),
    (lambda d: d["scenarios"].append(d["scenarios"][0]), "Duplicate scenario"),
    (lambda d: d["scenarios"][0].update(format="other"), "format must"),
    (lambda d: d["scenarios"][0].update(file="../unsafe.log"), "relative"),
    (lambda d: d["scenarios"][0].update(file="/etc/passwd"), "relative"),
    (lambda d: d["scenarios"][0].update(name=""), "scenario name"),
    (lambda d: d["scenarios"][0].update(year=True), "requires year"),
    (lambda d: d["scenarios"][0].update(expected="brute_force"), "must be a list"),
    (lambda d: d["scenarios"][0]["expected"][0].update(rule_id="unknown"), "unknown ground-truth"),
    (lambda d: d["scenarios"][0]["expected"][0].update(source_ip="bad_ip"), "valid IP"),
    (lambda d: d["scenarios"][0]["expected"].append(d["scenarios"][0]["expected"][0]), "duplicate expected"),
    (lambda d: d["scenarios"][0]["expected"][0].update(note="bad"), "only rule_id"),
])
def test_invalid_labeling_fails_closed(tmp_path, update, match):
    path = _write_truth(tmp_path, update)
    with pytest.raises(ValueError, match=match):
        evaluate(truth=path)


@pytest.mark.parametrize("unsafe", [
    "/etc/passwd",                    # POSIX root, even on Windows
    "//server/share/some.log",        # POSIX and UNC-like root
    r"C:\Windows\win.ini",           # Windows drive root
    "C:/Windows/win.ini",             # Windows drive with forward slashes
    r"C:Windows\win.ini",           # Windows drive-relative path
    r"\\server\share\some.log",   # Windows UNC
    r"\Windows\win.ini",             # Windows root-relative path
    "../outside.log",                # POSIX parent traversal
    r"subdir\..\outside.log",       # Windows parent traversal
    "subdir/../../outside.log",     # Nested parent traversal
])
def test_reject_paths_rooted_or_traversing_on_either_platform(tmp_path, unsafe):
    """Reject hostile paths using either OS's syntax, even across platforms."""
    path = _write_truth(tmp_path, lambda data: data["scenarios"][0].update(file=unsafe))
    with pytest.raises(ValueError, match="relative to samples directory"):
        evaluate(truth=path)


def test_missing_truth(tmp_path):
    with pytest.raises(FileNotFoundError):
        evaluate(truth=tmp_path / "not-exist.json")


def test_broken_truth_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        evaluate(truth=path)


def test_benchmark_events_deterministic():
    first = generate_benchmark_events(200)
    assert first == generate_benchmark_events(200)
    assert len(first) == 200
    assert first[0].event_type == "login_failure"
    assert first[19].event_type == "login_success"
    assert first[0].source_file == "synthetic-benchmark-no-real-logs"


@pytest.mark.parametrize("bad", [0, 20, 99, 5001, -1, True, 10.5, None])
def test_invalid_benchmark_event_counts(bad):
    with pytest.raises(ValueError, match="between 100 and 5000"):
        generate_benchmark_events(bad)


@pytest.mark.parametrize("bad", [0, 1, 11, True, None, 2.5])
def test_invalid_benchmark_runs(bad):
    with pytest.raises(ValueError, match="between 2 and 10"):
        run_benchmark(event_count=100, runs=bad, detection_rules=RULES, correlation_rules=CORRELATION)


def test_benchmark_reports_measured_values():
    data = run_benchmark(event_count=100, runs=2, detection_rules=RULES, correlation_rules=CORRELATION)
    assert data["event_count"] == 100
    assert data["runs"] == 2
    assert data["median_ms"] >= 0
    assert data["p95_ms"] >= data["median_ms"]
    assert data["sample_incidents"] > 0
    assert data["sample_findings"] > 0
    assert "excluding raw parsing" in data["limitations"]


def test_benchmark_json_safe():
    data = run_benchmark(event_count=100, runs=2, detection_rules=RULES, correlation_rules=CORRELATION)
    assert json.loads(json.dumps(data))["assessment"] == "synthetic_in_memory_benchmark"
