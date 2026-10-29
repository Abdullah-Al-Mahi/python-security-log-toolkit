"""Phase 6 CLI ergonomics, configuration and safe output tests."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security_log_toolkit.cli import main

ROOT = Path(__file__).resolve().parents[1]
LINUX = ROOT / "samples/linux/attack_auth.log"
WINDOWS = ROOT / "samples/windows/attack_security.xml"
RULES = ROOT / "config/detection_rules.yaml"
CORRELATION = ROOT / "config/correlation_rules.yaml"


def analyze_args():
    return ["analyze", "--linux", str(LINUX), "--windows", str(WINDOWS),
            "--year", "2026", "--utc-offset", "+08:00",
            "--rules", str(RULES), "--correlation-config", str(CORRELATION)]


def test_new_commands_visible_in_help(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    for command in ("parse", "detect", "correlate", "timeline", "analyze", "config", "doctor"):
        assert command in out


def test_phase6_status(capsys):
    assert main(["status"]) == 0
    assert "Current milestone: Phase 8" in capsys.readouterr().out


def test_config_show_json(capsys):
    assert main(["config", "show", "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["enabled_detection_rules"] == 3
    assert data["detection_rules"]["brute_force"]["min_failures"] == 5


def test_config_validate(capsys):
    assert main(["config", "validate", "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 0
    out = capsys.readouterr().out
    assert "Configuration: VALID" in out
    assert "Correlation settings: VALID" in out


def test_config_subcommand_required():
    with pytest.raises(SystemExit) as e:
        main(["config"])
    assert e.value.code == 2


def test_config_broken_yaml_error(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("nonsense: [", encoding="utf-8")
    assert main(["config", "validate", "--rules", str(bad),
                 "--correlation-config", str(CORRELATION)]) == 2
    assert "error:" in capsys.readouterr().err


def test_config_missing_file_error(tmp_path, capsys):
    assert main(["config", "show", "--rules", str(tmp_path / "missing.yaml"),
                 "--correlation-config", str(CORRELATION)]) == 2
    assert "error:" in capsys.readouterr().err


def test_doctor_human(capsys):
    assert main(["doctor", "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 0
    out = capsys.readouterr().out
    assert "Result: READY" in out
    assert "Network access: Not required" in out


def test_doctor_json(capsys):
    assert main(["doctor", "--json", "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["python_compatible"] is True
    assert data["tool_version"] == "0.8.0"
    assert data["mode"] == "offline-local"


def test_doctor_bad_config(tmp_path, capsys):
    assert main(["doctor", "--rules", str(tmp_path / "missing.yaml"),
                 "--correlation-config", str(CORRELATION)]) == 2
    assert "error:" in capsys.readouterr().err


def test_analyze_file_output(tmp_path, capsys):
    target = tmp_path / "investigation.json"
    assert main([*analyze_args(), "--output", str(target)]) == 0
    out = capsys.readouterr().out
    assert "Detected 6 findings; created 4 incidents" in out
    report = json.loads(target.read_text(encoding="utf-8"))
    assert report["summary"]["total_incidents"] == 4
    assert report["timeline_summary"]["total_timeline_entries"] == 22


def test_analyze_stdout_json(capsys):
    assert main(analyze_args()) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["workflow"] == "raw_log_analysis"
    assert report["summary"]["events_analyzed"] == 29


def test_analyze_summary_without_writing_file(capsys):
    assert main([*analyze_args(), "--summary"]) == 0
    out = capsys.readouterr().out
    assert "Processed 2 source files" in out
    assert "4 incidents" in out
    assert not out.startswith("{")


def test_analyze_requires_source(capsys):
    assert main(["analyze"]) == 2
    assert "at least one" in capsys.readouterr().err


def test_analyze_requires_year(capsys):
    args = ["analyze", "--linux", str(LINUX), "--utc-offset", "+08:00",
            "--rules", str(RULES), "--correlation-config", str(CORRELATION)]
    assert main(args) == 2
    assert "both --year and --utc-offset" in capsys.readouterr().err


def test_analyze_requires_offset(capsys):
    args = ["analyze", "--linux", str(LINUX), "--year", "2026",
            "--rules", str(RULES), "--correlation-config", str(CORRELATION)]
    assert main(args) == 2
    assert "both --year and --utc-offset" in capsys.readouterr().err


def test_analyze_windows_without_linux_flags(capsys):
    assert main(["analyze", "--windows", str(WINDOWS), "--summary",
                 "--rules", str(RULES), "--correlation-config", str(CORRELATION)]) == 0
    assert "14 events" in capsys.readouterr().out


def test_analyze_multiple_linux_files_deduplicates(capsys):
    assert main([*analyze_args(), "--linux", str(LINUX), "--summary"]) == 0
    assert "Processed 2 source files" in capsys.readouterr().out


def test_analyze_prevents_source_overwrite(capsys):
    before = LINUX.read_bytes()
    assert main([*analyze_args(), "--output", str(LINUX), "--force"]) == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert LINUX.read_bytes() == before


@pytest.mark.parametrize("path", [RULES, CORRELATION])
def test_analyze_prevents_config_overwrite(path, capsys):
    before = path.read_bytes()
    assert main([*analyze_args(), "--output", str(path), "--force"]) == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert path.read_bytes() == before


def test_analyze_requires_force_on_existing_output(tmp_path, capsys):
    dest = tmp_path / "report.json"
    dest.write_text("DO NOT DELETE", encoding="utf-8")
    assert main([*analyze_args(), "--output", str(dest)]) == 2
    assert "--force" in capsys.readouterr().err
    assert dest.read_text(encoding="utf-8") == "DO NOT DELETE"


def test_analyze_force_replaces_only_report(tmp_path):
    dest = tmp_path / "report.json"
    dest.write_text("OLD", encoding="utf-8")
    assert main([*analyze_args(), "--output", str(dest), "--force"]) == 0
    report = json.loads(dest.read_text(encoding="utf-8"))
    assert report["summary"]["total_incidents"] == 4


def test_analyze_missing_input_no_report(tmp_path, capsys):
    dest = tmp_path / "output.json"
    args = ["analyze", "--windows", str(tmp_path / "absent.xml"),
            "--rules", str(RULES), "--correlation-config", str(CORRELATION),
            "--output", str(dest)]
    assert main(args) == 2
    assert not dest.exists()
    assert "error:" in capsys.readouterr().err


def test_analyze_invalid_config_no_report(tmp_path, capsys):
    dest = tmp_path / "report.json"
    bad = tmp_path / "broken.yaml"
    bad.write_text("not: valid: yaml", encoding="utf-8")
    args = [*analyze_args(), "--rules", str(bad), "--output", str(dest)]
    assert main(args) == 2
    assert not dest.exists()
    assert "error:" in capsys.readouterr().err


def test_analyze_rejects_evtx(tmp_path, capsys):
    file = tmp_path / "example.evtx"
    file.write_bytes(b"Evtx")
    assert main(["analyze", "--windows", str(file), "--rules", str(RULES),
                 "--correlation-config", str(CORRELATION)]) == 2
    assert "not supported" in capsys.readouterr().err


def test_cli_module_entry_for_new_commands():
    result = subprocess.run(
        [sys.executable, "-m", "security_log_toolkit", "config", "validate",
         "--rules", str(RULES), "--correlation-config", str(CORRELATION)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert "Configuration: VALID" in result.stdout
