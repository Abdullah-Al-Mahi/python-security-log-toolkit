"""Adversarial local inputs: bounded reads, malformed sources and safe rejection."""
import json
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from security_log_toolkit.ingest import ingest_file
from security_log_toolkit.detection.engine import load_normalized_events
from security_log_toolkit.security_limits import (
    MAX_RAW_LOG_BYTES, MAX_NORMALIZED_JSON_BYTES, MAX_LINUX_LINE_CHARS,
)

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_reject_external_entity_fixture():
    path = SAMPLES / "validation/reject_external_entity.xml"
    with pytest.raises(ValueError, match="DTD and entity"):
        ingest_file("windows", path)


def test_reject_entity_in_utf16(tmp_path):
    path = tmp_path / "bad_utf16.xml"
    path.write_bytes(
        '<!DOCTYPE Events [<!ENTITY harm "boom">]><Events/>'.encode("utf-16")
    )
    with pytest.raises(ValueError, match="DTD and entity"):
        ingest_file("windows", path)


@pytest.mark.parametrize("markup", [
    '<!DOCTYPE Events><Events/>',
    '<!ENTITY danger "ex"><Events/>',
    '<!doctype Events [<!entity X "y">]><Events/>',
    '<Events><!DOCTYPE foo></Events>',
])
def test_dtd_guards_reject_variants(tmp_path, markup):
    path = tmp_path / "bad.xml"
    path.write_text(markup, encoding="utf-8")
    with pytest.raises(ValueError, match="DTD and entity"):
        ingest_file("windows", path)


def test_reject_malformed_xml_fixture():
    with pytest.raises(ET.ParseError):
        ingest_file("windows", SAMPLES / "validation/reject_malformed.xml")


def test_reject_malformed_ip_fixture():
    with pytest.raises(ValueError, match="invalid SSH source IP"):
        ingest_file("linux", SAMPLES / "validation/reject_bad_ip.log", year=2026)


def test_large_linux_file_rejected_before_parse(tmp_path):
    path = tmp_path / "huge.log"
    with path.open("wb") as output:
        output.truncate(MAX_RAW_LOG_BYTES + 1)
    with pytest.raises(ValueError, match="16 MiB"):
        ingest_file("linux", path, year=2026)


def test_large_windows_file_rejected_before_parse(tmp_path):
    path = tmp_path / "huge.xml"
    with path.open("wb") as output:
        output.truncate(MAX_RAW_LOG_BYTES + 1)
    with pytest.raises(ValueError, match="16 MiB"):
        ingest_file("windows", path)


def test_large_linux_line_rejected_with_location(tmp_path):
    path = tmp_path / "oversize.log"
    path.write_text("x" * (MAX_LINUX_LINE_CHARS + 1), encoding="utf-8")
    with pytest.raises(ValueError, match=r"oversize.log:1: syslog line exceeds"):
        ingest_file("linux", path, year=2026)


def test_linux_exact_length_boundary_not_rejected(tmp_path):
    path = tmp_path / "exact.log"
    path.write_text("not-an-ssh-log" + "x" * (MAX_LINUX_LINE_CHARS - 14), encoding="utf-8")
    parsed = ingest_file("linux", path, year=2026)
    assert parsed.records_examined == 1
    assert not parsed.events


def test_large_normalized_json_rejected_before_decode(tmp_path):
    path = tmp_path / "too_big.json"
    with path.open("wb") as output:
        output.truncate(MAX_NORMALIZED_JSON_BYTES + 1)
    with pytest.raises(ValueError, match="32 MiB"):
        load_normalized_events([path])


def test_nonexistent_source_rejected(tmp_path):
    with pytest.raises(FileNotFoundError, match="Input file does not exist"):
        ingest_file("linux", tmp_path / "missing.log", year=2026)


def test_windows_preserves_supported_utf16(tmp_path):
    original = (SAMPLES / "windows/security.xml").read_text(encoding="utf-8")
    original = original.replace('encoding="utf-8"', 'encoding="utf-16"')
    path = tmp_path / "utf16.xml"
    path.write_bytes(original.encode("utf-16"))
    parsed = ingest_file("windows", path)
    assert len(parsed.events) == 5


def test_windows_normal_supported_source_unchanged():
    result = ingest_file("windows", SAMPLES / "windows/security.xml")
    assert result.records_examined == 6
    assert len(result.events) == 5


def test_linux_normal_supported_source_unchanged():
    result = ingest_file("linux", SAMPLES / "linux/auth.log", year=2026, utc_offset="+08:00")
    assert result.records_examined == 9
    assert len(result.events) == 7


def test_unsupported_evtx_still_rejected(tmp_path):
    path = tmp_path / "fake.evtx"
    path.write_bytes(b"ElfFile\x00" + b"A" * 200)
    with pytest.raises(ValueError, match="Binary .evtx"):
        ingest_file("windows", path)


def test_interleaved_linux_source_ips_not_falsely_merged():
    from security_log_toolkit.detection import detect_events, load_detection_config
    rules = Path(__file__).resolve().parents[1] / "config/detection_rules.yaml"
    result = ingest_file("linux", SAMPLES / "validation/edge_linux_auth.log", year=2026, utc_offset="+08:00")
    assert len(result.events) == 8
    assert detect_events(result.events, load_detection_config(rules)) == []


def test_same_ip_across_windows_hosts_not_falsely_merged():
    from security_log_toolkit.detection import detect_events, load_detection_config
    rules = Path(__file__).resolve().parents[1] / "config/detection_rules.yaml"
    result = ingest_file("windows", SAMPLES / "validation/edge_windows_security.xml")
    assert len(result.events) == 7
    assert result.records_examined == 8
    assert detect_events(result.events, load_detection_config(rules)) == []
