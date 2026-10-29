"""Dashboard service tests: boundaries, shared engine and export parity."""
from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
from zipfile import ZipFile

import pytest
import yaml

from security_log_toolkit import __version__
from security_log_toolkit.dashboard import (
    UploadedSource, analyze_uploaded_sources, build_dashboard_downloads,
    build_dashboard_zip, build_rule_yaml, build_correlation_yaml,
    filter_incidents, incident_detail, load_investigation_json,
    load_synthetic_demo, severity_summary, rule_summary, timeline_activity, top_sources,
)
from security_log_toolkit.dashboard.service import validate_uploads
from security_log_toolkit.detection.config import load_detection_config
from security_log_toolkit.correlation.config import load_correlation_config
from security_log_toolkit.reporting import build_export_artifacts
from security_log_toolkit.security_limits import MAX_RAW_LOG_BYTES, MAX_INVESTIGATION_JSON_BYTES

ROOT = Path(__file__).resolve().parents[1]
DETECTION = ROOT / "config/detection_rules.yaml"
CORRELATION = ROOT / "config/correlation_rules.yaml"


@pytest.fixture(scope="module")
def baseline():
    return load_synthetic_demo(ROOT)


def _linux():
    return UploadedSource("attack.log", "linux", (ROOT / "samples/linux/attack_auth.log").read_bytes())


def _windows():
    return UploadedSource("security.xml", "windows", (ROOT / "samples/windows/attack_security.xml").read_bytes())


def _analyze(sources, **kwargs):
    return analyze_uploaded_sources(sources, detection_rules=DETECTION, correlation_rules=CORRELATION, **kwargs)


def test_version_and_importable_without_streamlit():
    assert __version__ == "1.0.0"


def test_demo_counts_and_scope(baseline):
    assert baseline["dashboard_input_type"] == "bundled_synthetic_demo"
    assert {key: baseline["summary"][key] for key in ("events_analyzed", "findings_analyzed", "total_incidents", "unique_evidence_events")} == {"events_analyzed": 29, "findings_analyzed": 6, "total_incidents": 4, "unique_evidence_events": 22}


def test_demo_findings_are_consistent(baseline):
    assert len(baseline["findings"]) == 6
    assert sum(x["incidents"] for x in severity_summary(baseline)) == 4
    assert sum(x["findings"] for x in rule_summary(baseline)) == 6
    assert sum(x["incidents"] for x in top_sources(baseline)) == 4
    assert sum(x["events"] for x in timeline_activity(baseline)) == 22


def test_filter_all(baseline):
    assert len(filter_incidents(baseline)) == 4


@pytest.mark.parametrize("kwargs,count", [
    ({"severity": ["critical"]}, 2), ({"severity": ["high"]}, 2),
    ({"platform": ["linux"]}, 2), ({"platform": ["windows"]}, 2),
    ({"rule": ["password_spray"]}, 2), ({"rule": ["success_after_failures"]}, 2),
    ({"query": "198.51.100.77"}, 1), ({"query": "LAB-WIN11"}, 2),
    ({"query": "ALICE"}, 1), ({"query": "no such machine"}, 0),
    ({"severity": ["critical"], "platform": ["linux"]}, 1),
])
def test_filters(baseline, kwargs, count):
    assert len(filter_incidents(baseline, **kwargs)) == count


def test_filter_order_by_severity(baseline):
    assert [x["severity"] for x in filter_incidents(baseline)] == ["critical", "critical", "high", "high"]


def test_incident_detail_and_unknown(baseline):
    iid = baseline["incidents"][0]["incident_id"]
    assert incident_detail(baseline, iid)["incident_id"] == iid
    with pytest.raises(ValueError, match="Unknown"):
        incident_detail(baseline, "nonexistent")


def test_export_matches_existing_backend(baseline):
    assert build_dashboard_downloads(baseline) == build_export_artifacts(baseline, "both")


def test_zip_has_seven_files_and_valid_hashes(baseline):
    blob = build_dashboard_zip(baseline)
    with ZipFile(BytesIO(blob)) as z:
        names = z.namelist()
        assert len(names) == 7
        manifest = json.loads(z.read("export_manifest.json"))
        for name, info in manifest["files"].items():
            assert sha256(z.read(name)).hexdigest() == info["sha256"]
        assert json.loads(z.read("investigation.json"))["summary"]["total_incidents"] == 4


def test_export_not_mutating_report(baseline):
    before = json.dumps(baseline, sort_keys=True)
    build_dashboard_zip(baseline)
    assert json.dumps(baseline, sort_keys=True) == before


def test_import_existing_report(baseline):
    data = build_dashboard_downloads(baseline)["investigation.json"]
    restored = load_investigation_json(data)
    assert restored["summary"] == baseline["summary"]
    assert restored["dashboard_input_type"] == "imported_report"


@pytest.mark.parametrize("blob", [b"", b"[]", b"null", b"not json", b'{"nan":NaN}', b"\xff\xff"])
def test_import_bad_json(blob):
    with pytest.raises(ValueError):
        load_investigation_json(blob)


def test_report_maximum_size_rejected():
    with pytest.raises(ValueError, match="50 MiB"):
        load_investigation_json(b"x" * (MAX_INVESTIGATION_JSON_BYTES + 1))


def test_upload_linux_and_windows_end_to_end():
    report = _analyze([_linux(), _windows()], year=2026, utc_offset="+08:00")
    assert report["summary"]["events_analyzed"] == 29
    assert report["summary"]["total_incidents"] == 4
    assert report["dashboard_input_type"] == "user_upload"
    text = json.dumps(report)
    assert "security-log-dashboard-" not in text
    assert "uploaded:attack.log" in text
    assert "uploaded:security.xml" in text
    assert "session:detection_rules.yaml" in text


def test_uploaded_windows_only_no_linux_year():
    report = _analyze([_windows()])
    assert report["summary"]["total_incidents"] == 2


def test_uploaded_linux_requires_metadata():
    with pytest.raises(ValueError, match="explicit"):
        _analyze([_linux()], year=2026)
    with pytest.raises(ValueError, match="valid year"):
        _analyze([_linux()], year=True, utc_offset="+08:00")


def test_uploaded_empty_rejected():
    with pytest.raises(ValueError, match="1 to 4"):
        validate_uploads([])


def test_five_files_rejected():
    with pytest.raises(ValueError, match="1 to 4"):
        validate_uploads([_windows()] * 5)


@pytest.mark.parametrize("source,pattern", [
    (UploadedSource("evil.evtX", "windows", b"a"), "Linux accepts"),
    (UploadedSource("security.xml", "linux", b"a"), "Linux accepts"),
    (UploadedSource("input.log", "unknown", b"a"), "format"),
    (UploadedSource("log.txt", "linux", b""), "nonempty"),
    (UploadedSource("A" * 121 + ".xml", "windows", b"a"), "120"),
    (UploadedSource("../escape.log", "linux", b"a"), "path"),
    (UploadedSource("C:\\temp\\secret.xml", "windows", b"a"), "path"),
    (UploadedSource("nested/secret.xml", "windows", b"a"), "path"),
    (UploadedSource("foo\x00.xml", "windows", b"a"), "path"),
])
def test_upload_bad_filenames_and_formats(source, pattern):
    with pytest.raises(ValueError, match=pattern):
        validate_uploads([source])


def test_file_size_guard():
    with pytest.raises(ValueError, match="16 MiB"):
        validate_uploads([UploadedSource("over.log", "linux", b"x" * (MAX_RAW_LOG_BYTES + 1))])


def test_combined_size_guard():
    blob = b"a" * (MAX_RAW_LOG_BYTES - 1024)
    with pytest.raises(ValueError, match="32 MiB"):
        validate_uploads([UploadedSource(f"a{i}.log", "linux", blob) for i in range(3)])


def test_bad_xml_still_fails():
    bad = (ROOT / "samples/validation/reject_external_entity.xml").read_bytes()
    with pytest.raises(ValueError):
        _analyze([UploadedSource("security.xml", "windows", bad)])


def test_temp_files_deleted_on_success_and_error(monkeypatch, tmp_path):
    import security_log_toolkit.dashboard.service as service
    real = service.tempfile.TemporaryDirectory
    created = []
    def make_tmp(*args, **kwargs):
        tmp = real(dir=tmp_path, *args, **kwargs)
        created.append(Path(tmp.name))
        return tmp
    monkeypatch.setattr(service.tempfile, "TemporaryDirectory", make_tmp)
    _analyze([_windows()])
    with pytest.raises(ValueError):
        _analyze([UploadedSource("security.xml", "windows", b"<bad xml")])
    assert len(created) == 2
    assert all(not p.exists() for p in created)


def test_rules_are_pure_and_unchanged(tmp_path):
    original = DETECTION.read_bytes()
    content = build_rule_yaml(DETECTION, {"brute_force": {"min_failures": 50, "enabled": False}})
    file = tmp_path / "rules.yaml"
    file.write_bytes(content)
    assert load_detection_config(file).brute_force.min_failures == 50
    assert not load_detection_config(file).brute_force.enabled
    assert DETECTION.read_bytes() == original


def test_correlation_is_pure_and_unchanged(tmp_path):
    original = CORRELATION.read_bytes()
    content = build_correlation_yaml(CORRELATION, {"max_gap_minutes": 5})
    file = tmp_path / "corr.yaml"
    file.write_bytes(content)
    assert load_correlation_config(file).max_gap_minutes == 5
    assert CORRELATION.read_bytes() == original


@pytest.mark.parametrize("override", [
    {"unknown": {"enabled": True}},
    {"brute_force": {"command": "evil"}},
    {"brute_force": {"enabled": 1}},
    {"brute_force": {"min_failures": 0}},
    {"brute_force": {"window_minutes": True}},
    {"brute_force": {"severity": "urgent"}},
    {"brute_force": {"severity": ["critical"]}},
    {"password_spray": {"min_distinct_accounts": 0}},
])
def test_invalid_rule_overrides_rejected(override):
    with pytest.raises(ValueError):
        build_rule_yaml(DETECTION, override)


@pytest.mark.parametrize("override", [
    {"unknown": 1}, {"max_gap_minutes": 0},
    {"max_gap_minutes": True}, {"max_incident_minutes": 2000},
])
def test_invalid_correlation_overrides_rejected(override):
    with pytest.raises(ValueError):
        build_correlation_yaml(CORRELATION, override)


def test_rule_changes_affect_engine_not_existing_config():
    source = [_linux()]
    baseline = _analyze(source, year=2026, utc_offset="+08:00")
    original = DETECTION.read_bytes()
    altered = _analyze(source, year=2026, utc_offset="+08:00", detection_overrides={
        "brute_force": {"enabled": False},
        "password_spray": {"enabled": False},
        "success_after_failures": {"enabled": False},
    })
    assert baseline["summary"]["findings_analyzed"] == 3
    assert altered["summary"]["findings_analyzed"] == 0
    assert altered["summary"]["total_incidents"] == 0
    assert DETECTION.read_bytes() == original


def test_empty_report_charts():
    empty = _analyze([UploadedSource("empty.log", "linux", b"noise\n")], year=2026, utc_offset="+08:00")
    assert filter_incidents(empty) == []
    assert timeline_activity(empty) == []
    assert severity_summary(empty)[0]["incidents"] == 0
    assert build_dashboard_zip(empty)


def test_architecture_contains_streamlit_web_extra():
    assert (ROOT / "dashboard/app.py").is_file()
    text = (ROOT / "pyproject.toml").read_text()
    assert 'web = ["streamlit>=1.45,<2"]' in text
    assert 'address = "127.0.0.1"' in (ROOT / ".streamlit/config.toml").read_text()


def test_all_ui_sources_compile():
    compile((ROOT / "dashboard/app.py").read_text(encoding="utf-8"), "dashboard/app.py", "exec")


def test_initial_dashboard_script_runs_with_simple_renderer_stub(monkeypatch):
    """Framework-free assembly test; the genuine Streamlit AppTest is separate."""
    import runpy
    import sys
    import types

    class State(dict):
        def __getattr__(self, key):
            return self[key]
        def __setattr__(self, key, value):
            self[key] = value

    calls = []

    class MockSurface:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return None
        def __getattr__(self, name):
            if name == "columns":
                return lambda columns, **kwargs: [MockSurface() for _ in range(columns if isinstance(columns, int) else len(columns))]
            if name == "radio":
                return lambda *args, **kwargs: "Command center"
            if name == "button":
                return lambda *args, **kwargs: False
            if name == "metric":
                return lambda title, value, **kwargs: calls.append((title, value))
            return lambda *args, **kwargs: None

    fake = types.ModuleType("streamlit")
    renderer = MockSurface()
    fake.sidebar = renderer
    fake.session_state = State()
    fake.columns = renderer.columns
    for method in ("markdown", "set_page_config", "caption", "divider", "subheader", "write", "bar_chart", "line_chart", "error", "info"):
        setattr(fake, method, getattr(renderer, method))
    fake.radio = renderer.radio
    fake.button = renderer.button
    monkeypatch.setitem(sys.modules, "streamlit", fake)
    runpy.run_path(str(ROOT / "dashboard/app.py"), run_name="__main__")
    assert calls == [
        ("Normalized events", "29"), ("Detection findings", "6"),
        ("Incidents opened", "4"), ("Linked evidence", "22"),
    ]
