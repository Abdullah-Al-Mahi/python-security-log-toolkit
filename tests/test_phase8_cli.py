"""Phase 8 CLI commands keep output safe and machine-readable."""
import json
from pathlib import Path

import pytest

from security_log_toolkit.cli import main, build_parser

ROOT = Path(__file__).resolve().parents[1]
TRUTH = ROOT / "samples/validation/ground_truth.json"
RULES = ROOT / "config/detection_rules.yaml"
CORR = ROOT / "config/correlation_rules.yaml"
SAMPLES = ROOT / "samples"


def test_new_commands_in_help():
    parser = build_parser()
    text = parser.format_help()
    assert "validate" in text and "benchmark" in text


def test_validation_success(capsys):
    assert main(["validate", "--truth", str(TRUTH), "--samples-dir", str(SAMPLES), "--rules", str(RULES)]) == 0
    assert "6 TP, 0 FP, 0 FN" in capsys.readouterr().out


def test_validate_file_written(tmp_path):
    target = tmp_path / "result.json"
    assert main(["validate", "--truth", str(TRUTH), "--samples-dir", str(SAMPLES), "--rules", str(RULES), "--output", str(target)]) == 0
    assert json.loads(target.read_text())["summary"]["true_positives"] == 6


def test_validate_existing_output_not_overwritten(tmp_path, capsys):
    target = tmp_path / "result.json"
    target.write_text("KEEP", encoding="utf-8")
    result = main(["validate", "--truth", str(TRUTH), "--samples-dir", str(SAMPLES), "--rules", str(RULES), "--output", str(target)])
    assert result == 2
    assert target.read_text() == "KEEP"
    assert "--force" in capsys.readouterr().err


def test_validate_force_replaces_output(tmp_path):
    target = tmp_path / "result.json"
    target.write_text("old", encoding="utf-8")
    assert main(["validate", "--truth", str(TRUTH), "--samples-dir", str(SAMPLES), "--rules", str(RULES), "--output", str(target), "--force"]) == 0
    assert json.loads(target.read_text())["summary"]["true_positives"] == 6


def test_validate_prevents_overwriting_manifest(capsys):
    assert main(["validate", "--truth", str(TRUTH), "--samples-dir", str(SAMPLES), "--output", str(TRUTH), "--force"]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_validate_prevents_overwriting_input_log(capsys):
    raw = SAMPLES / "linux/auth.log"
    assert main(["validate", "--truth", str(TRUTH), "--samples-dir", str(SAMPLES), "--output", str(raw), "--force"]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_validate_missing_truth(capsys, tmp_path):
    assert main(["validate", "--truth", str(tmp_path / "missing.json")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_benchmark_command(capsys):
    assert main(["benchmark", "--events", "100", "--runs", "2", "--rules", str(RULES), "--correlation-config", str(CORR)]) == 0
    assert "Excludes raw parsing" in capsys.readouterr().out


def test_benchmark_json_output(tmp_path):
    target = tmp_path / "bench.json"
    assert main(["benchmark", "--events", "100", "--runs", "2", "--rules", str(RULES), "--correlation-config", str(CORR), "--output", str(target)]) == 0
    assert json.loads(target.read_text())["event_count"] == 100


def test_benchmark_invalid_count(capsys):
    assert main(["benchmark", "--events", "999999", "--runs", "2", "--rules", str(RULES), "--correlation-config", str(CORR)]) == 2
    assert "between 100 and 5000" in capsys.readouterr().err


def test_benchmark_existing_output_rejected(tmp_path):
    target = tmp_path / "bench.json"
    target.write_text("KEEP", encoding="utf-8")
    assert main(["benchmark", "--events", "100", "--runs", "2", "--output", str(target)]) == 2
    assert target.read_text() == "KEEP"


def test_benchmark_force_replaces(tmp_path):
    target = tmp_path / "bench.json"
    target.write_text("old", encoding="utf-8")
    assert main(["benchmark", "--events", "100", "--runs", "2", "--rules", str(RULES), "--correlation-config", str(CORR), "--output", str(target), "--force"]) == 0
    assert json.loads(target.read_text())["event_count"] == 100


@pytest.mark.parametrize("mode", ["validate", "benchmark"])
def test_cannot_overwrite_detection_rules(mode, capsys):
    inputs = ["--truth", str(TRUTH), "--samples-dir", str(SAMPLES)] if mode == "validate" else ["--events", "100", "--runs", "2"]
    result = main([mode, *inputs, "--rules", str(RULES), "--output", str(RULES), "--force"])
    assert result == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_benchmark_cannot_overwrite_correlation_config(capsys):
    assert main(["benchmark", "--events", "100", "--runs", "2", "--correlation-config", str(CORR), "--output", str(CORR), "--force"]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_phase8_status_message(capsys):
    assert main(["status"]) == 0
    text = capsys.readouterr().out
    assert "Phase 9" in text
    assert "Security validation" in text
