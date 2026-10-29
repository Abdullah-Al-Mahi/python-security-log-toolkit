"""End-to-end regression tests for CLI phases 1 through 5."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security_log_toolkit import __version__
from security_log_toolkit.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
RULES = ROOT / "config" / "detection_rules.yaml"
CORRELATION = ROOT / "config" / "correlation_rules.yaml"


def test_version_is_defined():
    assert __version__ == "0.8.0"


def test_parser_program_name():
    assert build_parser().prog == "security-log"


def test_help_command(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    output = capsys.readouterr().out
    for command in ("security-log", "status", "parse", "detect", "correlate", "timeline"):
        assert command in output


def test_status_command(capsys):
    assert main(["status"]) == 0
    output = capsys.readouterr().out
    assert "Installation: OK" in output
    assert "Current milestone: Phase 8" in output
    assert "Log parsing: Linux SSH and Windows XML available" in output
    assert "Detection engine: 3 configurable rules available" in output
    assert "Event correlation: Incident grouping available" in output


def test_default_command_displays_help(capsys):
    assert main([]) == 0
    assert "usage:" in capsys.readouterr().out


def test_invalid_command():
    process = subprocess.run(
        [sys.executable, "-m", "security_log_toolkit", "unknown-command"],
        capture_output=True, text=True, check=False,
    )
    assert process.returncode == 2
    assert "invalid choice" in process.stderr


def test_module_entry_point():
    process = subprocess.run(
        [sys.executable, "-m", "security_log_toolkit", "status"],
        capture_output=True, text=True, check=False,
    )
    assert process.returncode == 0
    assert "Installation: OK" in process.stdout


def test_parse_linux_to_stdout(capsys):
    assert main([
        "parse", "linux", str(SAMPLES / "linux" / "auth.log"),
        "--year", "2026", "--utc-offset", "+08:00",
    ]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["normalized"] == 7
    assert data["events"][0]["timestamp"] == "2026-10-28T18:10:00Z"


def test_parse_windows_to_json_file(tmp_path, capsys):
    output = tmp_path / "normalized.json"
    assert main([
        "parse", "windows", str(SAMPLES / "windows" / "security.xml"),
        "--output", str(output),
    ]) == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["normalized"] == 5
    assert "Saved normalized JSON" in capsys.readouterr().out


def test_parse_missing_input_returns_error(capsys):
    assert main(["parse", "linux", "missing.log", "--year", "2026"]) == 2
    assert "Input file does not exist" in capsys.readouterr().err


def test_parse_prevents_overwriting_input(capsys):
    target = SAMPLES / "windows" / "security.xml"
    assert main(["parse", "windows", str(target), "--output", str(target)]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_detect_sample_datasets(tmp_path, capsys):
    linux = tmp_path / "linux.json"
    windows = tmp_path / "windows.json"
    findings = tmp_path / "findings.json"
    assert main([
        "parse", "linux", str(SAMPLES / "linux" / "attack_auth.log"),
        "--year", "2026", "--utc-offset", "+08:00", "--output", str(linux),
    ]) == 0
    assert main([
        "parse", "windows", str(SAMPLES / "windows" / "attack_security.xml"),
        "--output", str(windows),
    ]) == 0
    assert main([
        "detect", str(linux), str(windows),
        "--rules", str(RULES), "--output", str(findings),
    ]) == 0
    report = json.loads(findings.read_text(encoding="utf-8"))
    assert report["summary"]["total_findings"] == 6
    assert report["summary"]["by_rule"] == {
        "brute_force": 2, "password_spray": 2, "success_after_failures": 2,
    }
    assert "Saved findings JSON" in capsys.readouterr().out


def test_detect_stdout_json(tmp_path, capsys):
    linux = tmp_path / "normalized.json"
    assert main([
        "parse", "linux", str(SAMPLES / "linux" / "auth.log"),
        "--year", "2026", "--output", str(linux),
    ]) == 0
    capsys.readouterr()
    assert main(["detect", str(linux), "--rules", str(RULES)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert "findings" in report


def test_detect_missing_input_error(tmp_path, capsys):
    assert main(["detect", str(tmp_path / "missing.json"), "--rules", str(RULES)]) == 2
    assert "error:" in capsys.readouterr().err


def test_detect_does_not_overwrite_rule_config(tmp_path, capsys):
    input_file = tmp_path / "normalized.json"
    input_file.write_text('{"events": []}', encoding="utf-8")
    assert main([
        "detect", str(input_file), "--rules", str(RULES), "--output", str(RULES)
    ]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_detect_does_not_overwrite_input(tmp_path, capsys):
    input_file = tmp_path / "normalized.json"
    input_file.write_text('{"events": []}', encoding="utf-8")
    assert main([
        "detect", str(input_file), "--rules", str(RULES), "--output", str(input_file)
    ]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_correlate_sample_datasets(tmp_path, capsys):
    linux = tmp_path / "linux.json"
    windows = tmp_path / "windows.json"
    incidents = tmp_path / "incidents.json"
    assert main([
        "parse", "linux", str(SAMPLES / "linux" / "attack_auth.log"),
        "--year", "2026", "--utc-offset", "+08:00", "--output", str(linux),
    ]) == 0
    assert main([
        "parse", "windows", str(SAMPLES / "windows" / "attack_security.xml"),
        "--output", str(windows),
    ]) == 0
    assert main([
        "correlate", str(linux), str(windows),
        "--rules", str(RULES), "--correlation-config", str(CORRELATION),
        "--output", str(incidents),
    ]) == 0
    report = json.loads(incidents.read_text(encoding="utf-8"))
    assert report["summary"]["events_analyzed"] == 29
    assert report["summary"]["findings_analyzed"] == 6
    assert report["summary"]["total_incidents"] == 4
    assert report["summary"]["correlated_incidents"] == 2
    assert report["summary"]["single_finding_incidents"] == 2
    assert "Saved incident JSON" in capsys.readouterr().out


def test_correlate_stdout_json(tmp_path, capsys):
    source = tmp_path / "empty.json"
    source.write_text('{"events": []}', encoding="utf-8")
    assert main(["correlate", str(source), "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["summary"]["total_incidents"] == 0


def test_correlate_missing_input(capsys):
    assert main(["correlate", "does-not-exist.json", "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("protected", ["input", "rules", "correlation"])
def test_correlate_prevents_overwriting(tmp_path, capsys, protected):
    input_file = tmp_path / "events.json"
    input_file.write_text('{"events": []}', encoding="utf-8")
    targets = {"input": input_file, "rules": RULES, "correlation": CORRELATION}
    assert main([
        "correlate", str(input_file), "--rules", str(RULES),
        "--correlation-config", str(CORRELATION),
        "--output", str(targets[protected]),
    ]) == 2
    assert "must not overwrite" in capsys.readouterr().err


def test_timeline_from_normalized_attack_datasets(tmp_path, capsys):
    linux = tmp_path / "linux.json"
    windows = tmp_path / "windows.json"
    out = tmp_path / "timelines.json"
    assert main([
        "parse", "linux", str(SAMPLES / "linux" / "attack_auth.log"),
        "--year", "2026", "--utc-offset", "+08:00", "--output", str(linux),
    ]) == 0
    assert main([
        "parse", "windows", str(SAMPLES / "windows" / "attack_security.xml"),
        "--output", str(windows),
    ]) == 0
    assert main([
        "timeline", str(linux), str(windows), "--rules", str(RULES),
        "--correlation-config", str(CORRELATION), "--output", str(out),
    ]) == 0
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["total_incidents"] == 4
    assert report["timeline_summary"]["total_timelines"] == 4
    assert report["timeline_summary"]["total_timeline_entries"] == 22
    assert "Saved timeline JSON" in capsys.readouterr().out


def test_timeline_from_existing_phase4_incident_report(tmp_path, capsys):
    source = tmp_path / "phase4.json"
    target = tmp_path / "phase5.json"
    source.write_text(json.dumps({"summary": {}, "incidents": []}), encoding="utf-8")
    assert main(["timeline", "--incident-report", str(source), "--output", str(target)]) == 0
    assert json.loads(target.read_text(encoding="utf-8"))["timeline_summary"]["total_timelines"] == 0
    assert json.loads(source.read_text(encoding="utf-8")) == {"summary": {}, "incidents": []}
    assert "Saved timeline JSON" in capsys.readouterr().out


def test_timeline_stdout_json(tmp_path, capsys):
    source = tmp_path / "normalized.json"
    source.write_text('{"events": []}', encoding="utf-8")
    assert main(["timeline", str(source), "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["timeline_summary"]["total_timelines"] == 0


def test_timeline_no_sources_returns_error(capsys):
    assert main(["timeline"]) == 2
    assert "either normalized input files" in capsys.readouterr().err


def test_timeline_rejects_both_sources(tmp_path, capsys):
    f = tmp_path / "source.json"
    f.write_text('{"summary":{}, "incidents":[]}', encoding="utf-8")
    assert main(["timeline", str(f), "--incident-report", str(f)]) == 2
    assert "not both" in capsys.readouterr().err


def test_timeline_missing_incident_report(tmp_path, capsys):
    assert main(["timeline", "--incident-report", str(tmp_path / "missing.json")]) == 2
    assert "error:" in capsys.readouterr().err


def test_timeline_malformed_json_error(tmp_path, capsys):
    f = tmp_path / "broken.json"
    f.write_text('{ bad', encoding="utf-8")
    assert main(["timeline", "--incident-report", str(f)]) == 2
    assert "error:" in capsys.readouterr().err


def test_timeline_rejects_overwrite_incident_report(tmp_path, capsys):
    f = tmp_path / "phase4.json"
    f.write_text('{"summary":{},"incidents":[]}', encoding="utf-8")
    original = f.read_bytes()
    assert main(["timeline", "--incident-report", str(f), "--output", str(f)]) == 2
    assert f.read_bytes() == original
    assert "must not overwrite" in capsys.readouterr().err


@pytest.mark.parametrize("protected", ["input", "rules", "correlation"])
def test_timeline_rejects_overwrite_sources(tmp_path, capsys, protected):
    f = tmp_path / "events.json"
    f.write_text('{"events":[]}', encoding="utf-8")
    target = {"input": f, "rules": RULES, "correlation": CORRELATION}[protected]
    assert main(["timeline", str(f), "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION), "--output", str(target)]) == 2
    assert "must not overwrite" in capsys.readouterr().err
