"""Tests for the toolkit's command-line interface."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from security_log_toolkit import __version__
from security_log_toolkit.cli import build_parser, main

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_version_is_defined():
    assert __version__ == "0.2.0"


def test_parser_program_name():
    assert build_parser().prog == "security-log"


def test_help_command(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--help"])
    assert info.value.code == 0
    output = capsys.readouterr().out
    assert "security-log" in output
    assert "status" in output
    assert "parse" in output


def test_status_command(capsys):
    assert main(["status"]) == 0
    output = capsys.readouterr().out
    assert "Installation: OK" in output
    assert "Current milestone: Phase 2" in output
    assert "Log parsing: Linux SSH and Windows XML available" in output


def test_default_command_displays_help(capsys):
    assert main([]) == 0
    assert "usage:" in capsys.readouterr().out


def test_invalid_command():
    process = subprocess.run(
        [sys.executable, "-m", "security_log_toolkit", "unknown-command"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 2
    assert "invalid choice" in process.stderr


def test_module_entry_point():
    process = subprocess.run(
        [sys.executable, "-m", "security_log_toolkit", "status"],
        capture_output=True,
        text=True,
        check=False,
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
