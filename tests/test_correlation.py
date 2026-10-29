"""Phase 4: incident grouping, evidence provenance, configuration and service."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from security_log_toolkit.correlation import (
    CorrelationConfig, correlate_findings, investigate, load_correlation_config,
)
from security_log_toolkit.detection import detect_events, load_detection_config
from security_log_toolkit.detection.engine import Finding
from security_log_toolkit.events import SecurityEvent
from security_log_toolkit.ingest import ingest_file

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "config" / "detection_rules.yaml"
CORRELATION = ROOT / "config" / "correlation_rules.yaml"


def example_event(minute=0, *, platform="linux", host="host-a", ip="198.51.100.23",
                  username="alice", outcome="login_failure", line=1):
    return SecurityEvent(
        timestamp=datetime(2026, 10, 29, 0, tzinfo=timezone.utc) + timedelta(minutes=minute),
        platform=platform, event_type=outcome, hostname=host, username=username,
        source_ip=ip, source_port=50123, authentication_method="password", event_id="sshd",
        record_id=None, source_file="synthetic-test.log", source_line=line,
    )


def finding(rule="brute_force", *, at=0, platform="linux", host="host-a",
            ip="198.51.100.23", username="alice", severity="high", line=1):
    event = example_event(at, platform=platform, host=host, ip=ip, username=username, line=line)
    return Finding(rule, severity, platform, host, ip, (event,))


def test_default_config():
    config = load_correlation_config(CORRELATION)
    assert config == CorrelationConfig(max_gap_minutes=15, max_incident_minutes=60)


def test_two_close_findings_merge():
    pair = [finding(at=0), finding("password_spray", at=4, line=2)]
    incidents = correlate_findings(pair, CorrelationConfig(15, 60))
    assert len(incidents) == 1
    item = incidents[0].to_dict()
    assert item["finding_count"] == 2
    assert item["classification"] == "correlated"
    assert item["severity"] == "high"
    assert len(item["finding_ids"]) == 2


def test_single_finding_is_not_discarded():
    item = correlate_findings([finding()], CorrelationConfig(15, 60))[0].to_dict()
    assert item["classification"] == "single_finding"
    assert item["finding_count"] == 1


def test_empty_findings():
    assert correlate_findings([], CorrelationConfig(15, 60)) == []


def test_separate_hosts():
    result = correlate_findings([
        finding(host="host-a"), finding("password_spray", host="host-b")
    ], CorrelationConfig(15, 60))
    assert len(result) == 2


def test_separate_ips():
    result = correlate_findings([
        finding(ip="198.51.100.23"), finding("password_spray", ip="198.51.100.24")
    ], CorrelationConfig(15, 60))
    assert len(result) == 2


def test_separate_platforms():
    result = correlate_findings([
        finding(platform="linux"), finding("password_spray", platform="windows")
    ], CorrelationConfig(15, 60))
    assert len(result) == 2


def test_host_case_insensitivity():
    result = correlate_findings([
        finding(host="LAB-HOST", line=1),
        finding("password_spray", host="lab-host", line=2),
    ], CorrelationConfig(15, 60))
    assert len(result) == 1
    assert result[0].hostname == "LAB-HOST"


def test_different_accounts_same_ip_host_can_link():
    result = correlate_findings([
        finding(username="alice"),
        finding("password_spray", username="bob", line=2),
    ], CorrelationConfig(15, 60))[0].to_dict()
    assert result["affected_accounts"] == ["alice", "bob"]


def test_exceed_gap_creates_new_incident():
    result = correlate_findings([
        finding(at=0), finding("password_spray", at=16)
    ], CorrelationConfig(15, 60))
    assert len(result) == 2


def test_boundary_gap_is_inclusive():
    result = correlate_findings([
        finding(at=0), finding("password_spray", at=15)
    ], CorrelationConfig(15, 60))
    assert len(result) == 1


def test_total_span_limit_blocks_transitive_chain():
    values = [finding(at=0, line=1),
              finding("password_spray", at=12, line=2),
              finding("success_after_failures", at=24, line=3)]
    result = correlate_findings(values, CorrelationConfig(15, 20))
    assert len(result) == 2
    assert [len(incident.findings) for incident in result] == [2, 1]


def test_max_span_boundary_inclusive():
    values = [finding(at=0), finding("password_spray", at=20, line=2)]
    assert len(correlate_findings(values, CorrelationConfig(20, 20))) == 1


def test_order_does_not_affect_incident_ids_or_details():
    a, b = finding(at=5), finding("password_spray", at=1, line=2)
    forward = [x.to_dict() for x in correlate_findings([a, b], CorrelationConfig(15, 60))]
    reverse = [x.to_dict() for x in correlate_findings([b, a], CorrelationConfig(15, 60))]
    assert forward == reverse


def test_shared_evidence_deduplicated_and_linked():
    common = example_event(line=1)
    first = Finding("brute_force", "high", "linux", "host-a", "198.51.100.23", (common,))
    second = Finding("success_after_failures", "critical", "linux", "host-a", "198.51.100.23", (common,))
    data = correlate_findings([first, second], CorrelationConfig(15, 60))[0].to_dict()
    assert data["unique_evidence_events"] == 1
    assert data["finding_count"] == 2
    assert len(data["evidence"][0]["linked_finding_ids"]) == 2
    assert data["severity"] == "critical"


def test_evidence_is_chronological():
    a = finding(at=10, line=2)
    b = finding("password_spray", at=5, line=1)
    data = correlate_findings([a, b], CorrelationConfig(15, 60))[0].to_dict()
    stamps = [event["timestamp"] for event in data["evidence"]]
    assert stamps == sorted(stamps)
    assert all(value.startswith("E-") for value in (e["evidence_id"] for e in data["evidence"]))


def test_invalid_empty_finding_rejected():
    bad = Finding("brute_force", "high", "linux", "host-a", "198.51.100.23", ())
    with pytest.raises(ValueError, match="no evidence"):
        correlate_findings([bad], CorrelationConfig(15, 60))


def test_finding_missing_ip_rejected():
    with pytest.raises(ValueError, match="source IP"):
        correlate_findings([finding(ip="")], CorrelationConfig(15, 60))


@pytest.mark.parametrize("bad_config", [CorrelationConfig(0, 60), CorrelationConfig(15, -1),
                                       CorrelationConfig(True, 30)])
def test_bad_direct_config_rejected(bad_config):
    with pytest.raises(ValueError, match="positive integers"):
        correlate_findings([], bad_config)


@pytest.mark.parametrize("yaml_text,expected", [
    ("[]", "exactly"),
    ("version: 2\ncorrelation: {}\n", "version 1"),
    ("version: 1\ncorrelation: {max_gap_minutes: 2}\n", "exactly"),
    ("version: 1\ncorrelation: {max_gap_minutes: true, max_incident_minutes: 60}\n", "positive integer"),
    ("version: 1\ncorrelation: {max_gap_minutes: 0, max_incident_minutes: 60}\n", "positive integer"),
    ("version: 1\ncorrelation: {max_gap_minutes: 15, max_incident_minutes: bad}\n", "positive integer"),
    ("version: 1\ncorrelation: {max_gap_minutes: 15, max_incident_minutes: 60, extra: 1}\n", "exactly"),
    ("version: 1\ncorrelation: [1, 2]\n", "exactly"),
    ("version: 1\ncorrelation: !!python/object/apply:os.system ['echo unsafe']\n", "Invalid YAML"),
])
def test_invalid_yaml_is_rejected(tmp_path, yaml_text, expected):
    path = tmp_path / "bad.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(ValueError, match=expected):
        load_correlation_config(path)


def test_investigate_returns_json_safe_report(tmp_path):
    linux_data = ingest_file(
        "linux", ROOT / "samples" / "linux" / "attack_auth.log", year=2026, utc_offset="+08:00"
    ).to_dict()
    win_data = ingest_file("windows", ROOT / "samples" / "windows" / "attack_security.xml").to_dict()
    files = [tmp_path / "linux.json", tmp_path / "windows.json"]
    for path, data in zip(files, (linux_data, win_data)):
        path.write_text(json.dumps(data), encoding="utf-8")
    report = investigate(files, detection_rules=RULES, correlation_rules=CORRELATION)
    assert report["tool_version"] == "0.5.0"
    assert report["summary"]["events_analyzed"] == 29
    assert report["summary"]["findings_analyzed"] == 6
    assert report["summary"]["total_incidents"] == 4
    assert report["summary"]["correlated_incidents"] == 2
    assert report["summary"]["single_finding_incidents"] == 2
    assert report["summary"]["by_severity"] == {
        "critical": 2, "high": 2, "medium": 0, "low": 0,
    }
    assert sum(inc["unique_evidence_events"] for inc in report["incidents"]) == 22
    assert len(report["findings"]) == 6
    assert isinstance(json.loads(json.dumps(report)), dict)


def test_investigate_rejects_missing_inputs():
    with pytest.raises(ValueError, match="At least one"):
        investigate([], detection_rules=RULES, correlation_rules=CORRELATION)


def test_duplicate_files_do_not_add_findings_or_incidents(tmp_path):
    source = tmp_path / "normalized.json"
    source.write_text(json.dumps(ingest_file(
        "linux", ROOT / "samples" / "linux" / "attack_auth.log", year=2026, utc_offset="+08:00"
    ).to_dict()), encoding="utf-8")
    one = investigate([source], detection_rules=RULES, correlation_rules=CORRELATION)
    two = investigate([source, source], detection_rules=RULES, correlation_rules=CORRELATION)
    assert two["summary"]["duplicate_events_skipped"] == 15
    assert two["summary"]["total_incidents"] == one["summary"]["total_incidents"]
    assert two["incidents"] == one["incidents"]


def test_existing_phase3_detection_still_produces_three_rules():
    events = ingest_file(
        "linux", ROOT / "samples" / "linux" / "attack_auth.log", year=2026, utc_offset="+08:00"
    ).events
    results = detect_events(events, load_detection_config(RULES))
    assert len(results) == 3
    assert {finding.rule_id for finding in results} == {
        "brute_force", "password_spray", "success_after_failures",
    }
