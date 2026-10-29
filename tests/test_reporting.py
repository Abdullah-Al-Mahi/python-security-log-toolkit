"""Phase 8 reporting service: schema, deterministic outputs and CSV safety."""

import csv
from copy import deepcopy
from hashlib import sha256
import io
import json
from pathlib import Path

import pytest

from security_log_toolkit.reporting import (
    build_export_artifacts,
    build_report_tables,
    summarize_report,
    validate_investigation_report,
    write_export_bundle,
)

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_report():
    return json.loads((ROOT / "samples/reports/synthetic_investigation.json").read_text(encoding="utf-8"))


def csv_rows(content: bytes):
    return list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"), newline="")))


def test_baseline_counts(sample_report):
    tables = build_report_tables(sample_report)
    assert len(tables["summary.csv"]) == 1
    assert len(tables["incidents.csv"]) == 4
    assert len(tables["findings.csv"]) == 6
    assert len(tables["evidence.csv"]) == 22
    assert len(tables["timelines.csv"]) == 22


def test_baseline_row_details(sample_report):
    artifacts = build_export_artifacts(sample_report)
    assert len(csv_rows(artifacts["incidents.csv"])) == 4
    assert len(csv_rows(artifacts["findings.csv"])) == 6
    assert len(csv_rows(artifacts["evidence.csv"])) == 22
    assert len(csv_rows(artifacts["timelines.csv"])) == 22
    summary = csv_rows(artifacts["summary.csv"])[0]
    assert summary["critical_incidents"] == "2"
    assert summary["high_incidents"] == "2"
    assert summary["total_timelines"] == "4"


def test_evidence_has_source_references(sample_report):
    rows = csv_rows(build_export_artifacts(sample_report)["evidence.csv"])
    assert all(row["incident_id"] and row["evidence_id"] for row in rows)
    assert any(row["source_line"] for row in rows)
    assert any(row["record_id"] for row in rows)


def test_timeline_links_match_evidence(sample_report):
    artifacts = build_export_artifacts(sample_report)
    evidence = {(row["incident_id"], row["evidence_id"]) for row in csv_rows(artifacts["evidence.csv"])}
    for row in csv_rows(artifacts["timelines.csv"]):
        assert (row["incident_id"], row["evidence_id"]) in evidence


def test_finding_incident_mapping(sample_report):
    rows = csv_rows(build_export_artifacts(sample_report)["findings.csv"])
    assert all(row["incident_ids"] for row in rows)


@pytest.mark.parametrize("fmt,expected", [
    ("csv", 6), ("json", 2), ("both", 7),
])
def test_supported_formats(sample_report, fmt, expected):
    artifacts = build_export_artifacts(sample_report, fmt)
    assert len(artifacts) == expected
    assert "export_manifest.json" in artifacts
    assert ("investigation.json" in artifacts) == (fmt != "csv")
    assert ("evidence.csv" in artifacts) == (fmt != "json")


def test_invalid_format(sample_report):
    with pytest.raises(ValueError, match="Format"):
        build_export_artifacts(sample_report, "pdf")


def test_json_preserves_data(sample_report):
    data = json.loads(build_export_artifacts(sample_report)["investigation.json"])
    assert data == sample_report


def test_export_does_not_mutate_report(sample_report):
    prior = deepcopy(sample_report)
    build_export_artifacts(sample_report)
    assert sample_report == prior


def test_byte_for_byte_deterministic(sample_report):
    assert build_export_artifacts(sample_report) == build_export_artifacts(deepcopy(sample_report))


def test_manifest_hashes_and_rows(sample_report):
    files = build_export_artifacts(sample_report)
    meta = json.loads(files["export_manifest.json"])
    assert meta["export_schema_version"] == 1
    assert meta["application"] == "python-security-log-toolkit"
    for filename, record in meta["files"].items():
        assert record["sha256"] == sha256(files[filename]).hexdigest()
        assert record["bytes"] == len(files[filename])
        if filename.endswith(".csv"):
            assert record["rows"] == len(csv_rows(files[filename]))


def test_csv_utf8_bom_for_excel(sample_report):
    files = build_export_artifacts(sample_report, "csv")
    assert all(files[name].startswith(b"\xef\xbb\xbf") for name in files if name.endswith(".csv"))


def test_csv_has_windows_line_endings(sample_report):
    assert b"\r\n" in build_export_artifacts(sample_report)["summary.csv"]


@pytest.mark.parametrize("payload", [
    "=1+1", "+SUM(A1)", "-HYPERLINK(1)", "@SUM(A1)",
    "  =cmd", "\t=cmd", "\r=cmd", "\n=cmd", "\ufeff=cmd",
])
def test_excel_formula_guard(sample_report, payload):
    report = deepcopy(sample_report)
    report["incidents"][0]["hostname"] = payload
    output = build_export_artifacts(report, "csv")["incidents.csv"]
    rows = csv_rows(output)
    assert any(row["hostname"].startswith("'") and row["hostname"].endswith(payload) for row in rows)


def test_ordinary_text_is_unchanged(sample_report):
    rows = csv_rows(build_export_artifacts(sample_report)["incidents.csv"])
    assert rows[0]["hostname"] == "lab-linux"


def test_unicode_and_commas_escaped(sample_report):
    report = deepcopy(sample_report)
    report["incidents"][0]["hostname"] = 'café,"host"'
    rows = csv_rows(build_export_artifacts(report)["incidents.csv"])
    assert rows[0]["hostname"] == 'café,"host"'


def test_summary_scope_and_counts(sample_report):
    text = summarize_report(sample_report)
    assert "Events analyzed: 29" in text
    assert "Incidents: 4 (2 correlated)" in text
    assert "Linked timeline entries: 22" in text
    assert "not complete log history" in text


def test_accepts_phase4_without_timelines(sample_report):
    report = deepcopy(sample_report)
    report.pop("timeline_summary")
    for incident in report["incidents"]:
        incident.pop("timeline", None)
    artifacts = build_export_artifacts(report, "csv")
    assert csv_rows(artifacts["timelines.csv"]) == []
    assert len(csv_rows(artifacts["incidents.csv"])) == 4


def test_empty_incident_report():
    report = {"tool_version": "0.4.0", "summary": {"total_incidents": 0}, "incidents": [], "findings": []}
    data = build_export_artifacts(report)
    assert len(csv_rows(data["incidents.csv"])) == 0
    assert len(csv_rows(data["findings.csv"])) == 0
    assert len(csv_rows(data["summary.csv"])) == 1


@pytest.mark.parametrize("mutation,part", [
    (lambda x: x.pop("incidents"), "incidents"),
    (lambda x: x.update(summary=[]), "summary"),
    (lambda x: x.update(findings={}), "findings"),
    (lambda x: x["summary"].update(total_incidents=400), "incident count"),
    (lambda x: x["summary"].update(findings_analyzed=400), "findings count"),
    (lambda x: (x["incidents"].append(deepcopy(x["incidents"][0])), x["summary"].update(total_incidents=5)), "Incident IDs"),
    (lambda x: x["incidents"][0].update(evidence={}), "evidence list"),
    (lambda x: x["incidents"][0].update(finding_ids={}), "finding IDs"),
    (lambda x: x["incidents"][0]["evidence"].append(deepcopy(x["incidents"][0]["evidence"][0])), "duplicate evidence"),
    (lambda x: x["incidents"][0]["timeline"]["events"][0].update(evidence_id="not-linked"), "unknown evidence"),
    (lambda x: (x["findings"].append(deepcopy(x["findings"][0])), x["summary"].update(findings_analyzed=7)), "unique"),
])
def test_invalid_report_rejected(sample_report, mutation, part):
    mutation(sample_report)
    with pytest.raises(ValueError, match=part):
        validate_investigation_report(sample_report)


def test_json_nan_rejected(sample_report):
    sample_report["summary"]["events_analyzed"] = float("nan")
    with pytest.raises(ValueError, match="non-JSON"):
        validate_investigation_report(sample_report)


def test_write_bundle_roundtrip(tmp_path, sample_report):
    files = build_export_artifacts(sample_report)
    output = tmp_path / "exports"
    paths = write_export_bundle(files, output)
    assert len(paths) == 7
    assert {p.name for p in paths} == set(files)
    assert all(p.read_bytes() == files[p.name] for p in paths)


def test_existing_output_must_use_force(tmp_path, sample_report):
    files = build_export_artifacts(sample_report)
    target = tmp_path / "exports"
    write_export_bundle(files, target)
    with pytest.raises(ValueError, match="--force"):
        write_export_bundle(files, target)


def test_force_replaces_previous_bundle(tmp_path, sample_report):
    target = tmp_path / "exports"
    write_export_bundle(build_export_artifacts(sample_report), target)
    paths = write_export_bundle(build_export_artifacts(sample_report, "json"), target, force=True)
    assert len(paths) == 2
    assert not (target / "evidence.csv").exists()


def test_force_rejects_arbitrary_directory(tmp_path, sample_report):
    target = tmp_path / "user-files"
    target.mkdir()
    (target / "important.txt").write_text("valuable")
    with pytest.raises(ValueError, match="previous|toolkit"):
        write_export_bundle(build_export_artifacts(sample_report), target, force=True)
    assert (target / "important.txt").read_text() == "valuable"


def test_force_rejects_unexpected_extra_files(tmp_path, sample_report):
    target = tmp_path / "exports"
    files = build_export_artifacts(sample_report)
    write_export_bundle(files, target)
    (target / "human-notes.txt").write_text("preserve")
    with pytest.raises(ValueError, match="unexpected"):
        write_export_bundle(files, target, force=True)
    assert (target / "human-notes.txt").exists()


def test_output_must_not_contain_input_report(tmp_path, sample_report):
    target = tmp_path / "parent"
    target.mkdir()
    source = target / "input.json"
    source.write_text(json.dumps(sample_report))
    with pytest.raises(ValueError, match="input report"):
        write_export_bundle(build_export_artifacts(sample_report), target, protected_paths=[source], force=True)
    assert source.exists()


def test_existing_file_is_not_overwritten(tmp_path, sample_report):
    target = tmp_path / "existing"
    target.write_text("keep me")
    with pytest.raises(ValueError, match="not a directory"):
        write_export_bundle(build_export_artifacts(sample_report), target, force=True)
    assert target.read_text() == "keep me"


def test_unexpected_artifact_name_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unexpected"):
        write_export_bundle({"../../bad": b"hi", "export_manifest.json": b"{}"}, tmp_path / "export")
    assert not (tmp_path / "export").exists()


def test_missing_manifest_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="manifest"):
        write_export_bundle({"incidents.csv": b"hi"}, tmp_path / "export")


def test_bytes_only_required(tmp_path):
    with pytest.raises(ValueError, match="bytes"):
        write_export_bundle({"export_manifest.json": "not bytes"}, tmp_path / "export")
    assert not (tmp_path / "export").exists()
