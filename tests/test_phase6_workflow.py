"""Phase 6 unit/integration tests for the raw-log and dashboard-neutral APIs."""

import json
from pathlib import Path

import pytest

from security_log_toolkit.configuration import inspect_configuration
from security_log_toolkit.correlation.service import investigate, investigate_events
from security_log_toolkit.detection import load_normalized_events
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs
from security_log_toolkit.ingest import ingest_file

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "config/detection_rules.yaml"
CORRELATION = ROOT / "config/correlation_rules.yaml"
LINUX = ROOT / "samples/linux/attack_auth.log"
WINDOWS = ROOT / "samples/windows/attack_security.xml"


def analyze(*sources, year=2026, offset="+08:00"):
    return analyze_raw_logs(
        sources, year=year, utc_offset=offset,
        detection_rules=RULES, correlation_rules=CORRELATION,
    )


def test_configuration_snapshot():
    result = inspect_configuration(RULES, CORRELATION)
    assert result["config_version"] == 1
    assert result["summary"]["configuration_valid"] is True
    assert result["summary"]["total_detection_rules"] == 3
    assert result["summary"]["enabled_detection_rules"] == 3
    assert result["correlation"]["max_gap_minutes"] == 15
    json.dumps(result)


def test_configuration_disabled_rule(tmp_path):
    data = RULES.read_text(encoding="utf-8").replace("enabled: true", "enabled: false", 1)
    path = tmp_path / "rules.yaml"
    path.write_text(data, encoding="utf-8")
    snapshot = inspect_configuration(path, CORRELATION)
    assert snapshot["summary"]["enabled_detection_rules"] == 2
    assert snapshot["summary"]["disabled_detection_rules"] == 1


@pytest.mark.parametrize("config_type", ["detection", "correlation"])
def test_configuration_rejects_invalid_yaml(tmp_path, config_type):
    broken = tmp_path / "invalid.yaml"
    broken.write_text("value: !!python/object/apply:os.system ['echo no']", encoding="utf-8")
    with pytest.raises(ValueError):
        inspect_configuration(
            broken if config_type == "detection" else RULES,
            broken if config_type == "correlation" else CORRELATION,
        )


def test_raw_end_to_end_counts():
    result = analyze(RawLogSource("linux", LINUX), RawLogSource("windows", WINDOWS))
    assert result["workflow"] == "raw_log_analysis"
    assert result["tool_version"] == "0.9.0"
    assert result["raw_log_summary"]["records_examined"] == 31
    assert result["raw_log_summary"]["normalized_events"] == 29
    assert result["raw_log_summary"]["unsupported_records_skipped"] == 2
    assert result["summary"]["findings_analyzed"] == 6
    assert result["summary"]["total_incidents"] == 4
    assert result["timeline_summary"]["total_timelines"] == 4
    assert result["timeline_summary"]["total_timeline_entries"] == 22
    assert result["raw_log_summary"]["source_files_processed"] == 2
    json.dumps(result)


def test_raw_linux_only():
    result = analyze(RawLogSource("linux", LINUX))
    assert result["raw_log_summary"]["normalized_events"] == 15
    assert result["summary"]["findings_analyzed"] == 3
    assert result["summary"]["total_incidents"] == 2


def test_raw_windows_only_needs_no_linux_metadata():
    result = analyze_raw_logs(
        [RawLogSource("windows", WINDOWS)],
        detection_rules=RULES, correlation_rules=CORRELATION,
    )
    assert result["raw_log_summary"]["normalized_events"] == 14
    assert result["summary"]["total_incidents"] == 2


def test_source_order_does_not_change_incident_ids():
    forward = analyze(RawLogSource("linux", LINUX), RawLogSource("windows", WINDOWS))
    reverse = analyze(RawLogSource("windows", WINDOWS), RawLogSource("linux", LINUX))
    assert [i["incident_id"] for i in forward["incidents"]] == [
        i["incident_id"] for i in reverse["incidents"]
    ]


def test_duplicate_file_is_not_reprocessed():
    source = RawLogSource("linux", LINUX)
    result = analyze(source, source)
    assert result["raw_log_summary"]["source_files_processed"] == 1
    assert result["raw_log_summary"]["duplicate_source_files_skipped"] == 1
    assert result["raw_log_summary"]["normalized_events"] == 15
    assert result["summary"]["findings_analyzed"] == 3


def test_duplicate_file_alias_is_not_reprocessed():
    source = RawLogSource("linux", LINUX)
    alias = RawLogSource("linux", LINUX.parent / "." / LINUX.name)
    result = analyze(source, alias)
    assert result["raw_log_summary"]["source_files_processed"] == 1
    assert result["raw_log_summary"]["duplicate_source_files_skipped"] == 1


def test_empty_sources_rejected():
    with pytest.raises(ValueError, match="at least one"):
        analyze_raw_logs([], detection_rules=RULES, correlation_rules=CORRELATION)


@pytest.mark.parametrize("format", ["other", "", "LINUX"])
def test_invalid_source_format(format):
    with pytest.raises(ValueError, match="format"):
        analyze(RawLogSource(format, LINUX))


def test_invalid_source_object():
    with pytest.raises(ValueError, match="RawLogSource"):
        analyze("not a source")


@pytest.mark.parametrize("year,offset", [(None, "+08:00"), (2026, None)])
def test_linux_explicit_time_information_required(year, offset):
    with pytest.raises(ValueError, match="both --year and --utc-offset"):
        analyze_raw_logs(
            [RawLogSource("linux", LINUX)],
            detection_rules=RULES, correlation_rules=CORRELATION,
            year=year, utc_offset=offset,
        )


def test_bad_linux_offset_rejected():
    with pytest.raises(ValueError, match="UTC offset"):
        analyze(RawLogSource("linux", LINUX), offset="tomorrow")


def test_missing_file_rejected(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyze(RawLogSource("windows", tmp_path / "gone.xml"))


def test_binary_evtx_rejected(tmp_path):
    source = tmp_path / "sample.evtx"
    source.write_bytes(b"Evtx0000")
    with pytest.raises(ValueError, match="not supported"):
        analyze(RawLogSource("windows", source))


def test_report_keeps_source_provenance():
    result = analyze(RawLogSource("linux", LINUX))
    source = result["raw_log_sources"][0]
    assert source["summary"]["normalized"] == 15
    assert source["source_format"] == "linux"
    assert "events" not in source  # no redundant full event copies
    assert all("source_file" in e for i in result["incidents"] for e in i["evidence"])


def test_missing_ip_is_counted_not_guessed():
    result = analyze(RawLogSource("windows", WINDOWS))
    assert result["summary"]["events_analyzed"] == 14
    assert any(e["source_ip"] is not None for i in result["incidents"] for e in i["evidence"])


def test_in_memory_api_matches_existing_json_api(tmp_path):
    sources = [
        ("linux", LINUX, {"year": 2026, "utc_offset": "+08:00"}),
        ("windows", WINDOWS, {}),
    ]
    out_files = []
    for name, file, options in sources:
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(ingest_file(name, file, **options).to_dict()), encoding="utf-8")
        out_files.append(path)
    events, duplicates = load_normalized_events(out_files)
    from_memory = investigate_events(
        events, input_files=out_files,
        detection_rules=RULES, correlation_rules=CORRELATION,
        duplicate_count=duplicates,
    )
    from_files = investigate(out_files, detection_rules=RULES, correlation_rules=CORRELATION)
    assert from_memory == from_files


def test_single_step_consistent_with_previous_pipeline(tmp_path):
    raw = analyze(RawLogSource("linux", LINUX), RawLogSource("windows", WINDOWS))
    files = []
    for name, path, options in [
        ("linux", LINUX, {"year": 2026, "utc_offset": "+08:00"}),
        ("windows", WINDOWS, {}),
    ]:
        output = tmp_path / f"{name}.json"
        output.write_text(json.dumps(ingest_file(name, path, **options).to_dict()), encoding="utf-8")
        files.append(output)
    from security_log_toolkit.investigation import investigate_with_timelines
    previous = investigate_with_timelines(files, detection_rules=RULES, correlation_rules=CORRELATION)
    assert raw["summary"]["total_incidents"] == previous["summary"]["total_incidents"]
    assert raw["timeline_summary"] == previous["timeline_summary"]
    assert [x["incident_id"] for x in raw["incidents"]] == [x["incident_id"] for x in previous["incidents"]]
