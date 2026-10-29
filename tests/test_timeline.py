"""Phase 5 timeline tests: traceability, ordering, cautious analysis, safety."""

from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path

import pytest

from security_log_toolkit.investigation import (
    attach_timelines, build_incident_timeline, investigate_with_timelines,
)

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "config" / "detection_rules.yaml"
CORRELATION = ROOT / "config" / "correlation_rules.yaml"


def evidence(n, *, kind="login_failure", timestamp=None, account="alice", platform="linux", domain=""):
    return {
        "evidence_id": f"E-{n}",
        "timestamp": timestamp or f"2026-10-28T18:00:{n:02}Z",
        "platform": platform,
        "event_type": kind,
        "hostname": "lab-host",
        "username": account,
        "source_ip": "198.51.100.77",
        "source_port": 50222,
        "authentication_method": "password",
        "event_id": "4625" if kind == "login_failure" else "4624",
        "record_id": str(n) if platform == "windows" else None,
        "source_file": "samples/fake.xml" if platform == "windows" else "samples/fake.log",
        "source_line": n if platform == "linux" else None,
        "details": {"domain": domain} if domain else {},
        "linked_finding_ids": ["F-aaa"],
    }


def incident(*events):
    return {"incident_id": "I-abc", "evidence": list(events)}


def test_timeline_chronological_even_when_evidence_reversed():
    obj = build_incident_timeline(incident(evidence(2), evidence(1)))
    assert [e["evidence_id"] for e in obj["events"]] == ["E-1", "E-2"]
    assert [e["sequence"] for e in obj["events"]] == [1, 2]
    assert [e["seconds_from_start"] for e in obj["events"]] == [0.0, 1.0]


def test_timezone_sort_by_instant_not_lexical():
    obj = build_incident_timeline(incident(
        evidence(1, timestamp="2026-10-28T20:00:00+02:00"),
        evidence(2, timestamp="2026-10-28T18:00:01Z"),
    ))
    assert [e["evidence_id"] for e in obj["events"]] == ["E-1", "E-2"]
    assert obj["first_seen"] == "2026-10-28T18:00:00Z"


def test_microseconds_and_elapsed_seconds():
    obj = build_incident_timeline(incident(
        evidence(1, timestamp="2026-10-28T18:00:00.123456Z"),
        evidence(2, timestamp="2026-10-28T18:00:03.123457Z"),
    ))
    assert obj["duration_seconds"] == 3.000001
    assert obj["events"][1]["seconds_from_start"] == 3.000001


def test_first_and_last_times():
    obj = build_incident_timeline(incident(evidence(4), evidence(9)))
    assert obj["first_seen"] == "2026-10-28T18:00:04Z"
    assert obj["last_seen"] == "2026-10-28T18:00:09Z"
    assert obj["duration_seconds"] == 5


def test_evidence_links_preserved_and_sorted():
    event = evidence(1)
    event["linked_finding_ids"] = ["F-z", "F-a", "F-z"]
    entry = build_incident_timeline(incident(event))["events"][0]
    assert entry["linked_finding_ids"] == ["F-a", "F-z"]
    assert entry["evidence_id"] == "E-1"


def test_source_ref_keeps_linux_line():
    entry = build_incident_timeline(incident(evidence(3)))["events"][0]
    assert entry["source"] == {"file": "samples/fake.log", "line": 3, "record_id": None}


def test_source_ref_keeps_windows_record_id():
    entry = build_incident_timeline(incident(evidence(3, platform="windows")))["events"][0]
    assert entry["source"] == {"file": "samples/fake.xml", "line": None, "record_id": "3"}


def test_failed_success_classification_is_cautious():
    obj = build_incident_timeline(incident(evidence(1), evidence(2, kind="login_success")))
    assert obj["observed_pattern"] == "failure_then_success_same_account"
    assert obj["failed_logins"] == 1
    assert obj["successful_logins"] == 1
    assert "not proof of compromise" in obj["analyst_summary"]


def test_mixed_account_does_not_claim_same_account_success():
    obj = build_incident_timeline(incident(
        evidence(1, account="alice"),
        evidence(2, account="bob", kind="login_success"),
    ))
    assert obj["observed_pattern"] == "mixed_failures_and_successes"
    assert "may differ" in obj["analyst_summary"]


def test_success_before_failure_not_misclassified():
    obj = build_incident_timeline(incident(
        evidence(1, kind="login_success"), evidence(2, kind="login_failure")
    ))
    assert obj["observed_pattern"] == "mixed_failures_and_successes"


def test_simultaneous_failure_and_success_not_claimed_as_following():
    same = "2026-10-28T18:00:01Z"
    obj = build_incident_timeline(incident(
        evidence(1, timestamp=same),
        evidence(2, timestamp=same, kind="login_success"),
    ))
    assert obj["observed_pattern"] == "mixed_failures_and_successes"


def test_multiple_accounts_failure_pattern():
    obj = build_incident_timeline(incident(evidence(1), evidence(2, account="bob")))
    assert obj["observed_pattern"] == "failures_across_multiple_accounts"
    assert obj["affected_accounts"] == ["alice", "bob"]


def test_single_account_failure_pattern():
    obj = build_incident_timeline(incident(evidence(1), evidence(2)))
    assert obj["observed_pattern"] == "repeated_authentication_failures"


def test_success_only_pattern():
    obj = build_incident_timeline(incident(evidence(1, kind="login_success")))
    assert obj["observed_pattern"] == "successful_authentication_only"


def test_windows_account_uses_domain_and_casefold():
    obj = build_incident_timeline(incident(
        evidence(1, account="ADMIN", platform="windows", domain="LAB"),
        evidence(2, account="admin", platform="windows", domain="lab", kind="login_success"),
    ))
    assert obj["affected_accounts"] == ["lab\\admin"]
    assert obj["observed_pattern"] == "failure_then_success_same_account"


def test_windows_domains_separate_accounts():
    obj = build_incident_timeline(incident(
        evidence(1, account="admin", platform="windows", domain="OPS"),
        evidence(2, account="admin", platform="windows", domain="LAB", kind="login_success"),
    ))
    assert obj["observed_pattern"] == "mixed_failures_and_successes"
    assert obj["affected_accounts"] == ["lab\\admin", "ops\\admin"]


def test_linux_accounts_remain_case_sensitive():
    obj = build_incident_timeline(incident(
        evidence(1, account="Admin"), evidence(2, account="admin", kind="login_success")
    ))
    assert obj["observed_pattern"] == "mixed_failures_and_successes"


def test_recommended_checks_depend_on_success():
    successes = build_incident_timeline(incident(evidence(1, kind="login_success")))
    failures = build_incident_timeline(incident(evidence(1)))
    assert any("subsequent host activity" in x for x in successes["recommended_checks"])
    assert any("later successful" in x for x in failures["recommended_checks"])


@pytest.mark.parametrize("bad", [None, "text", [], 3])
def test_invalid_incident_type(bad):
    with pytest.raises(ValueError, match="mapping"):
        build_incident_timeline(bad)


@pytest.mark.parametrize("bad", [[], "broken", None])
def test_invalid_evidence(bad):
    with pytest.raises(ValueError, match="evidence"):
        build_incident_timeline({"incident_id": "I-x", "evidence": bad})


def test_invalid_evidence_item():
    with pytest.raises(ValueError, match="object"):
        build_incident_timeline(incident("broken"))


def test_invalid_timestamp_rejected():
    with pytest.raises(ValueError, match="ISO 8601"):
        build_incident_timeline(incident(evidence(1, timestamp="not-a-time")))


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError, match="timezone"):
        build_incident_timeline(incident(evidence(1, timestamp="2026-10-28T18:00:01")))


def test_unknown_event_type_rejected():
    e = evidence(1)
    e["event_type"] = "process_creation"
    with pytest.raises(ValueError, match="Unsupported"):
        build_incident_timeline(incident(e))


def test_missing_finding_links_rejected():
    e = evidence(1)
    e["linked_finding_ids"] = []
    with pytest.raises(ValueError, match="linked_finding_ids"):
        build_incident_timeline(incident(e))


def test_duplicate_evidence_id_rejected():
    e = evidence(1)
    with pytest.raises(ValueError, match="duplicate"):
        build_incident_timeline(incident(e, deepcopy(e)))


def test_source_file_missing_rejected():
    e = evidence(1)
    e["source_file"] = ""
    with pytest.raises(ValueError, match="source_file"):
        build_incident_timeline(incident(e))


def test_input_not_mutated():
    original = incident(evidence(2), evidence(1))
    before = deepcopy(original)
    build_incident_timeline(original)
    assert original == before


def test_report_enrichment_preserves_existing_fields():
    original = {
        "summary": {"total_incidents": 1},
        "incidents": [incident(evidence(1))],
        "findings": [{"finding_id": "F-aaa"}],
        "tool_version": "0.4.0",
    }
    before = deepcopy(original)
    result = attach_timelines(original)
    assert original == before
    assert result["summary"] == original["summary"]
    assert result["timeline_generator_version"] == "0.5.0"
    assert result["tool_version"] == "0.4.0"
    assert result["findings"] == original["findings"]
    assert result["timeline_summary"]["total_timelines"] == 1
    assert result["incidents"][0]["timeline"]["scope"] == "linked_detection_evidence_only"
    assert "timeline" not in original["incidents"][0]


def test_empty_report_has_zero_timelines():
    out = attach_timelines({"summary": {"total_incidents": 0}, "incidents": [], "findings": []})
    assert out["timeline_summary"]["total_timelines"] == 0
    assert out["timeline_summary"]["total_timeline_entries"] == 0


def test_invalid_report_rejected():
    with pytest.raises(ValueError, match="incidents"):
        attach_timelines({"summary": {}, "incidents": "invalid"})


def test_serializable_after_enrichment():
    data = attach_timelines({"summary": {}, "incidents": [incident(evidence(1))]})
    assert json.loads(json.dumps(data))["timeline_summary"]["total_timelines"] == 1


def test_end_to_end_on_real_synthetic_datasets(tmp_path):
    from security_log_toolkit.ingest import ingest_file

    linux = tmp_path / "linux.json"
    windows = tmp_path / "windows.json"
    linux.write_text(json.dumps(ingest_file(
        "linux", ROOT / "samples" / "linux" / "attack_auth.log", year=2026, utc_offset="+08:00",
    ).to_dict()), encoding="utf-8")
    windows.write_text(json.dumps(ingest_file(
        "windows", ROOT / "samples" / "windows" / "attack_security.xml",
    ).to_dict()), encoding="utf-8")
    result = investigate_with_timelines(
        [linux, windows], detection_rules=RULES, correlation_rules=CORRELATION,
    )
    assert result["summary"]["total_incidents"] == 4
    assert result["timeline_summary"] == {
        "total_timelines": 4,
        "total_timeline_entries": 22,
        "incidents_with_observed_successes": 2,
        "evidence_scope": "Linked evidence only; not complete security log history.",
    }
    assert sum(i["timeline"]["failed_logins"] for i in result["incidents"]) == 20
    assert sum(i["timeline"]["successful_logins"] for i in result["incidents"]) == 2
    assert all(
        [entry["evidence_id"] for entry in i["timeline"]["events"]]
        == [entry["evidence_id"] for entry in i["evidence"]]
        for i in result["incidents"]
    )
