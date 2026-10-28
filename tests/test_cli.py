
"""Tests for the security-log command-line interface."""

import subprocess
import sys

import pytest

from security_log_toolkit import __version__
from security_log_toolkit.cli import build_parser, main


def test_version_is_defined():
    """Verify the application version."""
    assert __version__ == "0.1.0"


def test_parser_program_name():
    """Verify the CLI program name."""
    parser = build_parser()
    assert parser.prog == "security-log"


def test_help_command(capsys):
    """Verify that --help displays help and exits successfully."""

    # argparse intentionally raises SystemExit(0)
    # when displaying the help message.
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])

    # Exit code 0 means successful execution.
    assert exc_info.value.code == 0

    output = capsys.readouterr().out

    assert "security-log" in output
    assert "status" in output


def test_status_command(capsys):
    """Verify the status command output."""
    result = main(["status"])

    output = capsys.readouterr().out

    assert result == 0
    assert "Installation: OK" in output
    assert "Current milestone: Phase 1" in output
    assert "Not implemented" in output


def test_default_command_displays_help(capsys):
    """Verify that no arguments display the help message."""
    result = main([])

    output = capsys.readouterr().out

    assert result == 0
    assert "usage:" in output


def test_invalid_command():
    """Verify that an invalid command returns an error."""
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_log_toolkit",
            "unknown-command",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode == 2
    assert "invalid choice" in process.stderr


def test_module_entry_point():
    """Verify execution through the Python module entry point."""
    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "security_log_toolkit",
            "status",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode == 0
    assert "Installation: OK" in process.stdout
