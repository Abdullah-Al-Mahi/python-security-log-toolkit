"""Security detection tests: thresholds, safety, and edge cases."""

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from security_log_toolkit.detection.config import load_detection_config
from security_log_toolkit.detection.engine import (
    detect_events,
    detection_report,
    load_normalized_events,
)
from security_log_toolkit.events import SecurityEvent

ROOT = Path(__file__).resolve().parents[1]
RULES_FILE = ROOT / "config" / "detection_rules.yaml"


def make_event(minute, username="alice", ip="198.51.100.77", outcome="login_failure",
               host="linux-test", platform="linux", domain=""):
    return SecurityEvent(
        timestamp=datetime(2026, 10, 29, tzinfo=timezone.utc) + timedelta(minutes=minute),
        platform=platform, event_type=outcome, hostname=host,
        username=username, source_ip=ip, source_port=45123,
        authentication_method="password", event_id="4625" if platform == "windows" else "sshd",
        record_id=None, source_file="synthetic.log", source_line=None,
        details={"domain": domain} if domain else {},
    )


@pytest.fixture
def rules():
    return load_detection_config(RULES_FILE)


def ids(events, rules):
    return [finding.rule_id for finding in detect_events(events, rules)]


def test_default_rules_load(rules):
    assert rules.brute_force.min_failures == 5
    assert rules.password_spray.min_distinct_accounts == 5
    assert rules.success_after_failures.min_failures == 4


def test_five_failures_trigger_brute_force(rules):
    events = [make_event(i / 10) for i in range(5)]
    assert ids(events, rules) == ["brute_force"]


def test_four_failures_do_not_trigger_brute_force(rules):
    assert ids([make_event(i / 10) for i in range(4)], rules) == []


def test_failures_outside_window_do_not_trigger(rules):
    assert ids([make_event(i * 6) for i in range(5)], rules) == []


def test_five_accounts_trigger_spray(rules):
    events = [make_event(i / 10, username=f"account{i}") for i in range(5)]
    assert ids(events, rules) == ["password_spray"]


def test_spray_requires_distinct_accounts(rules):
    events = [make_event(i / 10, username=("a" if i < 3 else "b")) for i in range(5)]
    assert ids(events, rules) == []


def test_success_after_failures(rules):
    events = [make_event(i / 10) for i in range(4)] + [make_event(0.5, outcome="login_success")]
    assert ids(events, rules) == ["success_after_failures"]


def test_success_outside_rule_window(rules):
    events = [make_event(i / 10) for i in range(4)] + [make_event(11, outcome="login_success")]
    assert ids(events, rules) == []


def test_no_double_alert_after_success(rules):
    events = [make_event(i / 10) for i in range(4)] + [
        make_event(0.5, outcome="login_success"), make_event(0.6, outcome="login_success")
    ]
    assert ids(events, rules) == ["success_after_failures"]


def test_missing_ip_does_not_trigger(rules):
    events = [make_event(i / 10, ip=None) for i in range(6)]
    assert ids(events, rules) == []


def test_host_boundaries_are_not_mixed(rules):
    events = [make_event(i / 10, host="server-a") for i in range(3)]
    events += [make_event(i / 10, host="server-b") for i in range(3)]
    assert ids(events, rules) == []


def test_source_ip_boundaries_are_not_mixed(rules):
    events = [make_event(i / 10, ip="198.51.100.77") for i in range(3)]
    events += [make_event(i / 10, ip="203.0.113.8") for i in range(3)]
    assert ids(events, rules) == []


def test_platform_boundaries_are_not_mixed(rules):
    events = [make_event(i / 10, platform="linux") for i in range(3)]
    events += [make_event(i / 10, platform="windows") for i in range(3)]
    assert ids(events, rules) == []


def test_windows_names_case_insensitive(rules):
    events = [make_event(i / 10, username=("Alice" if i % 2 else "ALICE"), platform="windows") for i in range(5)]
    assert ids(events, rules) == ["brute_force"]


def test_windows_domains_separate_accounts(rules):
    events = [make_event(i / 10, platform="windows", domain="A") for i in range(3)]
    events += [make_event(i / 10, platform="windows", domain="B") for i in range(3)]
    assert ids(events, rules) == []


def test_linux_names_case_sensitive(rules):
    events = [make_event(i / 10, username=("Alice" if i % 2 else "alice")) for i in range(5)]
    assert ids(events, rules) == []


def test_disabled_rules(rules):
    disabled = replace(
        rules,
        brute_force=replace(rules.brute_force, enabled=False),
        password_spray=replace(rules.password_spray, enabled=False),
        success_after_failures=replace(rules.success_after_failures, enabled=False),
    )
    assert ids([make_event(i / 10) for i in range(7)], disabled) == []


def test_custom_thresholds(rules):
    custom = replace(rules, brute_force=replace(rules.brute_force, min_failures=3))
    assert ids([make_event(i / 10) for i in range(3)], custom) == ["brute_force"]


def test_distinct_bursts_generate_distinct_findings(rules):
    events = [make_event(i / 10) for i in range(5)]
    events += [make_event(60 + i / 10) for i in range(5)]
    assert ids(events, rules) == ["brute_force", "brute_force"]


def test_extended_burst_single_finding(rules):
    events = [make_event(i / 10) for i in range(15)]
    assert ids(events, rules) == ["brute_force"]
    assert len(detect_events(events, rules)[0].evidence) == 15


def test_input_order_does_not_affect_finding_ids(rules):
    events = [make_event(i / 10) for i in range(5)]
    forward = detect_events(events, rules)[0].to_dict()["finding_id"]
    backward = detect_events(list(reversed(events)), rules)[0].to_dict()["finding_id"]
    assert forward == backward


def test_finding_evidence_and_times(rules):
    events = [make_event(i / 10) for i in range(5)]
    finding = detect_events(events, rules)[0].to_dict()
    assert finding["severity"] == "high"
    assert finding["event_count"] == 5
    assert finding["first_seen"].endswith("Z")
    assert finding["evidence"][0]["source_file"] == "synthetic.log"


def test_validation_rejects_malformed_yaml(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: [\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_detection_config(path)


def test_validation_rejects_unsafe_yaml(tmp_path):
    path = tmp_path / "unsafe.yaml"
    path.write_text("!!python/object/apply:os.system ['echo SHOULD_NOT_RUN']", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid YAML"):
        load_detection_config(path)


@pytest.mark.parametrize("replacement, substitute, expected", [
    ("min_failures: 5", "min_failures: true", "positive integer"),
    ("window_minutes: 5", "window_minutes: 0", "positive integer"),
    ("severity: high", "severity: urgent", "severity"),
    ("enabled: true", "enabled: yes-it-is", "true or false"),
])
def test_validation_rejects_bad_values(tmp_path, replacement, substitute, expected):
    path = tmp_path / "rules.yaml"
    path.write_text(RULES_FILE.read_text(encoding="utf-8").replace(replacement, substitute, 1), encoding="utf-8")
    with pytest.raises(ValueError, match=expected):
        load_detection_config(path)


def test_validation_rejects_unknown_rule_setting(tmp_path):
    path = tmp_path / "rules.yaml"
    source = RULES_FILE.read_text(encoding="utf-8")
    path.write_text(source.replace("    min_failures: 5", "    min_failures: 5\n    mystery: 1", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown settings"):
        load_detection_config(path)


def test_input_validation_rejects_missing_timestamp():
    data = make_event(0).to_dict()
    del data["timestamp"]
    with pytest.raises(ValueError, match="timestamp"):
        SecurityEvent.from_dict(data)


def test_input_validation_rejects_naive_timestamp():
    data = make_event(0).to_dict()
    data["timestamp"] = "2026-10-29T00:00:00"
    with pytest.raises(ValueError, match="timezone"):
        SecurityEvent.from_dict(data)


def test_input_validation_rejects_bad_ip():
    data = make_event(0).to_dict()
    data["source_ip"] = "not-an-ip"
    with pytest.raises(ValueError, match="source_ip"):
        SecurityEvent.from_dict(data)


def test_input_validation_roundtrip():
    data = make_event(0).to_dict()
    assert SecurityEvent.from_dict(data).to_dict() == data


def test_loader_rejects_not_phase2_json(tmp_path):
    target = tmp_path / "bad.json"
    target.write_text('{"findings": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="Phase 2 JSON"):
        load_normalized_events([target])


def test_loader_rejects_bad_event_with_context(tmp_path):
    target = tmp_path / "bad.json"
    target.write_text(json.dumps({"events": [{"timestamp": "bad"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="event #1"):
        load_normalized_events([target])


def test_duplicate_input_is_removed(tmp_path):
    target = tmp_path / "normalized.json"
    target.write_text(json.dumps({"events": [make_event(0).to_dict()]}), encoding="utf-8")
    events, duplicates = load_normalized_events([target, target])
    assert len(events) == 1
    assert duplicates == 1


def test_empty_events_generate_no_findings(rules):
    assert detect_events([], rules) == []


def test_report_counts_and_exclusions(rules):
    events = [make_event(i / 10) for i in range(5)] + [make_event(2, ip=None)]
    findings = detect_events(events, rules)
    result = detection_report(events, findings, [Path("x.json")], 0, RULES_FILE)
    assert result["summary"]["total_findings"] == 1
    assert result["summary"]["missing_source_ip_events"] == 1


def test_windows_finding_account_names_are_normalized(rules):
    events = [make_event(i / 10, username=("ALICE" if i % 2 else "Alice"),
                         platform="windows", domain="LAB") for i in range(5)]
    finding = detect_events(events, rules)[0].to_dict()
    assert finding["usernames"] == ["lab\\alice"]
