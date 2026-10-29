"""Phase 8 CLI integration checks for reporting and exports."""

import csv
import io
import json
from pathlib import Path

import pytest

from security_log_toolkit.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "samples/reports/synthetic_investigation.json"


def test_help_shows_new_commands():
    help_text = build_parser().format_help()
    assert "report" in help_text and "export" in help_text


def test_report_command(capsys):
    assert main(["report", "--input", str(REPORT)]) == 0
    out = capsys.readouterr().out
    assert "Events analyzed: 29" in out
    assert "Incidents: 4" in out


def test_export_both(tmp_path, capsys):
    target = tmp_path / "bundle"
    assert main(["export", "--input", str(REPORT), "--output-dir", str(target)]) == 0
    assert "Exported 7 files" in capsys.readouterr().out
    assert (target / "summary.csv").exists()
    assert json.loads((target / "investigation.json").read_text())["summary"]["total_incidents"] == 4


@pytest.mark.parametrize("fmt,count", [("csv", 6), ("json", 2), ("both", 7)])
def test_export_formats(tmp_path, fmt, count):
    target = tmp_path / fmt
    assert main(["export", "--input", str(REPORT), "--output-dir", str(target), "--format", fmt]) == 0
    assert len(list(target.iterdir())) == count


def test_export_does_not_overwrite(tmp_path, capsys):
    target = tmp_path / "bundle"
    assert main(["export", "--input", str(REPORT), "--output-dir", str(target)]) == 0
    assert main(["export", "--input", str(REPORT), "--output-dir", str(target)]) == 2
    assert "--force" in capsys.readouterr().err


def test_export_force_same_folder(tmp_path):
    target = tmp_path / "bundle"
    args = ["export", "--input", str(REPORT), "--output-dir", str(target)]
    assert main(args) == 0
    assert main(args + ["--force"]) == 0


def test_export_missing_report(tmp_path, capsys):
    result = main(["export", "--input", str(tmp_path / "missing.json"), "--output-dir", str(tmp_path / "export")])
    assert result == 2
    assert "security-log: error" in capsys.readouterr().err


def test_report_rejects_normalized_json(tmp_path, capsys):
    source = tmp_path / "normalized.json"
    source.write_text(json.dumps({"summary": {"normalized": 1}, "events": [{}]}), encoding="utf-8")
    assert main(["report", "--input", str(source)]) == 2
    assert "incidents" in capsys.readouterr().err


def test_report_rejects_broken_json(tmp_path, capsys):
    source = tmp_path / "broken.json"
    source.write_text("{broken", encoding="utf-8")
    assert main(["report", "--input", str(source)]) == 2
    assert "security-log: error" in capsys.readouterr().err


def test_export_does_not_touch_original_report(tmp_path):
    source = tmp_path / "original.json"
    original = REPORT.read_bytes()
    source.write_bytes(original)
    assert main(["export", "--input", str(source), "--output-dir", str(tmp_path / "out")]) == 0
    assert source.read_bytes() == original


def test_cli_rejects_input_report_inside_export_dir(tmp_path):
    target = tmp_path / "some-folder"
    target.mkdir()
    source = target / "data.json"
    source.write_bytes(REPORT.read_bytes())
    assert main(["export", "--input", str(source), "--output-dir", str(target), "--force"]) == 2
    assert source.exists()


def test_unrecognized_export_format_uses_argparse(capsys):
    with pytest.raises(SystemExit) as caught:
        main(["export", "--input", str(REPORT), "--output-dir", "somewhere", "--format", "xlsx"])
    assert caught.value.code == 2


def test_empty_report_generates_header_only_csv(tmp_path):
    source = tmp_path / "empty.json"
    source.write_text(json.dumps({"summary": {"total_incidents": 0}, "incidents": [], "findings": []}))
    folder = tmp_path / "export"
    assert main(["export", "--input", str(source), "--output-dir", str(folder), "--format", "csv"]) == 0
    stream = io.StringIO((folder / "incidents.csv").read_text(encoding="utf-8-sig"))
    assert list(csv.DictReader(stream)) == []
