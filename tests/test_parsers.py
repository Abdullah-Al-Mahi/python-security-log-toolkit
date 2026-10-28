"""Linux and Windows parser tests using synthetic security logs."""

from pathlib import Path

import pytest

from security_log_toolkit.events import SecurityEvent, normalize_ip
from security_log_toolkit.ingest import ingest_file
from security_log_toolkit.parsers.linux import parse_utc_offset

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_linux_event_counts():
    result = ingest_file(
        "linux", SAMPLES / "linux" / "auth.log", year=2026, utc_offset="+08:00"
    )
    summary = result.to_dict()["summary"]
    assert summary == {
        "records_examined": 9,
        "normalized": 7,
        "skipped": 2,
        "login_success": 3,
        "login_failure": 4,
    }


def test_linux_normalization_and_timezone():
    result = ingest_file(
        "linux", SAMPLES / "linux" / "auth.log", year=2026, utc_offset="+08:00"
    )
    first = result.events[0].to_dict()
    assert first["timestamp"] == "2026-10-28T18:10:00Z"
    assert first["username"] == "admin"
    assert first["source_ip"] == "198.51.100.23"
    assert first["source_port"] == 50101
    assert first["source_line"] == 1
    assert first["details"]["invalid_user"] == "true"
    assert first["event_type"] == "login_failure"


def test_linux_ipv6_and_auth_methods():
    result = ingest_file(
        "linux", SAMPLES / "linux" / "auth.log", year=2026, utc_offset="+08:00"
    )
    assert any(
        event.authentication_method == "publickey" and event.event_type == "login_success"
        for event in result.events
    )
    assert result.events[-1].source_ip == "2001:db8::42"


def test_linux_requires_explicit_year():
    with pytest.raises(ValueError, match="requires --year"):
        ingest_file("linux", SAMPLES / "linux" / "auth.log")


def test_linux_rejects_bad_offset():
    with pytest.raises(ValueError, match="UTC offset"):
        parse_utc_offset("Malaysia")


def test_linux_rejects_invalid_recognized_ip(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text(
        "Oct 29 02:10:00 lab-linux sshd[12]: Failed password for root from not-an-ip port 1000 ssh2\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid SSH source IP"):
        ingest_file("linux", path, year=2026)


def test_windows_event_counts():
    result = ingest_file("windows", SAMPLES / "windows" / "security.xml")
    assert result.to_dict()["summary"] == {
        "records_examined": 6,
        "normalized": 5,
        "skipped": 1,
        "login_success": 2,
        "login_failure": 3,
    }


def test_windows_field_mapping_and_subsecond_time():
    result = ingest_file("windows", SAMPLES / "windows" / "security.xml")
    first = result.events[0].to_dict()
    assert first["timestamp"] == "2026-10-28T18:10:03.123456Z"
    assert first["event_id"] == "4625"
    assert first["record_id"] == "3101"
    assert first["username"] == "analyst"
    assert first["source_ip"] == "198.51.100.23"
    assert first["details"]["logon_type"] == "3"
    assert first["details"]["status"] == "0xC000006D"
    assert first["authentication_method"] == "NTLM"


def test_windows_local_service_has_no_source_ip():
    result = ingest_file("windows", SAMPLES / "windows" / "security.xml")
    service = next(event for event in result.events if event.username == "svc_backup")
    assert service.source_ip is None
    assert service.source_port is None
    assert service.details["logon_type"] == "5"
    assert service.details["source_ip_raw"] == "-"


def test_windows_ipv6():
    result = ingest_file("windows", SAMPLES / "windows" / "security.xml")
    admin = next(event for event in result.events if event.username == "Administrator")
    assert admin.source_ip == "2001:db8::5"


def test_windows_single_event_without_namespace(tmp_path):
    path = tmp_path / "single.xml"
    path.write_text(
        '<Event><System><EventID>4624</EventID>'
        '<TimeCreated SystemTime="2026-10-28T18:00:00+00:00"/>'
        '<Computer>WIN-TEST</Computer></System><EventData>'
        '<Data Name="TargetUserName">operator</Data>'
        '</EventData></Event>',
        encoding="utf-8",
    )
    result = ingest_file("windows", path)
    assert len(result.events) == 1
    assert result.events[0].username == "operator"
    assert result.events[0].source_ip is None


def test_windows_rejects_binary_evtx(tmp_path):
    path = tmp_path / "security.evtx"
    path.write_bytes(b"not xml")
    with pytest.raises(ValueError, match="Binary .evtx"):
        ingest_file("windows", path)


def test_windows_rejects_missing_essential_field(tmp_path):
    path = tmp_path / "missing.xml"
    path.write_text(
        '<Event><System><EventID>4625</EventID>'
        '<TimeCreated SystemTime="2026-10-28T18:00:00Z"/>'
        '<Computer>WIN-TEST</Computer></System></Event>',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="TargetUserName"):
        ingest_file("windows", path)


def test_normalize_ip_missing_or_invalid():
    assert normalize_ip("-") is None
    assert normalize_ip("not an address") is None
    assert normalize_ip("2001:0db8::0005") == "2001:db8::5"


def test_utc_timestamps_required():
    from datetime import datetime

    event = SecurityEvent(
        timestamp=datetime(2026, 10, 29),
        platform="linux",
        event_type="login_failure",
        hostname="lab",
        username="user",
        source_ip=None,
        source_port=None,
        authentication_method=None,
        event_id="sshd",
        record_id=None,
        source_file="sample",
    )
    with pytest.raises(ValueError, match="timezone"):
        event.to_dict()
