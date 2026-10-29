"""Phase 9 offline portfolio, demonstrator and publishing-safety tests."""
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from security_log_toolkit import __version__
from security_log_toolkit.portfolio import (
    EXPECTED,
    EXPECTED_VALIDATION,
    build_portfolio_artifacts,
    write_portfolio_artifacts,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_portfolio import audit_paths, tracked_paths  # noqa: E402


@pytest.fixture(scope="module")
def artifacts():
    return build_portfolio_artifacts(ROOT)


def test_version_phase9():
    assert __version__ == "1.0.0"


def test_demo_report_counts(artifacts):
    report = json.loads(artifacts["investigation.json"])
    for key, expected in EXPECTED.items():
        assert report["summary"][key] == expected
    assert report["tool_version"] == "1.0.0"


def test_validation_synthetic_count(artifacts):
    data = json.loads(artifacts["validation_summary.json"])
    for key, expected in EXPECTED_VALIDATION.items():
        assert data["summary"][key] == expected
    assert "real-world" in data["limitations"]


def test_demo_artifact_names(artifacts):
    assert set(artifacts) == {
        "investigation.json", "analyst_summary.txt", "validation_summary.json", "portfolio_manifest.json",
        "export/investigation.json", "export/export_manifest.json",
        "export/summary.csv", "export/incidents.csv", "export/findings.csv",
        "export/evidence.csv", "export/timelines.csv",
    }


def test_export_manifest_verified(artifacts):
    manifest = json.loads(artifacts["export/export_manifest.json"])
    for name, info in manifest["files"].items():
        content = artifacts["export/" + name]
        assert info["sha256"] == sha256(content).hexdigest()


def test_portfolio_manifest_verified(artifacts):
    manifest = json.loads(artifacts["portfolio_manifest.json"])
    for name, info in manifest["files"].items():
        content = artifacts[name]
        assert info == {"sha256": sha256(content).hexdigest(), "bytes": len(content)}
    assert "synthetic" in manifest["dataset"]


def test_csv_counts(artifacts):
    for filename, expected in (("incidents", 4), ("findings", 6), ("evidence", 22), ("timelines", 22), ("summary", 1)):
        info = json.loads(artifacts["export/export_manifest.json"])["files"][filename + ".csv"]
        assert info["rows"] == expected


def test_two_identical_runs_have_identical_bytes(artifacts):
    repeat = build_portfolio_artifacts(ROOT)
    assert repeat == artifacts


def test_no_extra_files_written_during_build(tmp_path):
    before = list(tmp_path.iterdir())
    build_portfolio_artifacts(ROOT)
    assert list(tmp_path.iterdir()) == before


def test_write_new_directory(tmp_path, artifacts):
    result = write_portfolio_artifacts(artifacts, tmp_path / "demo")
    assert len(result) == 11
    assert (tmp_path / "demo" / "portfolio_manifest.json").is_file()
    assert (tmp_path / "demo" / "export" / "incidents.csv").is_file()


def test_existing_directory_never_overwritten(tmp_path, artifacts):
    target = tmp_path / "demo"
    target.mkdir()
    (target / "keep.txt").write_text("important", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        write_portfolio_artifacts(artifacts, target)
    assert (target / "keep.txt").read_text() == "important"


def test_existing_file_never_overwritten(tmp_path, artifacts):
    target = tmp_path / "demo"
    target.write_text("important", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        write_portfolio_artifacts(artifacts, target)
    assert target.read_text() == "important"


@pytest.mark.parametrize("invalid", ["../escape", "export/../../evil.txt", "/tmp/external", "extra.txt"])
def test_reject_unexpected_output_names(tmp_path, artifacts, invalid):
    broken = {**artifacts, invalid: b"x"}
    with pytest.raises(ValueError, match="Unexpected portfolio filename"):
        write_portfolio_artifacts(broken, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_missing_manifest_refused(tmp_path, artifacts):
    broken = dict(artifacts)
    del broken["portfolio_manifest.json"]
    with pytest.raises(ValueError, match="manifest"):
        write_portfolio_artifacts(broken, tmp_path / "out")


def test_non_bytes_output_refused(tmp_path, artifacts):
    broken = {**artifacts, "analyst_summary.txt": "not bytes"}
    with pytest.raises(ValueError, match="bytes"):
        write_portfolio_artifacts(broken, tmp_path / "out")


def test_cli_demo_creates_bundle_in_own_repo(tmp_path):
    target = tmp_path / "proof"
    run = subprocess.run([sys.executable, str(ROOT / "scripts/demo_portfolio.py"), "--output-dir", str(target)], cwd=ROOT, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert "Synthetic demo created 11 files" in run.stdout
    assert (target / "portfolio_manifest.json").exists()
    rerun = subprocess.run([sys.executable, str(ROOT / "scripts/demo_portfolio.py"), "--output-dir", str(target)], cwd=ROOT, capture_output=True, text=True)
    assert rerun.returncode == 2
    assert "already exists" in rerun.stderr


def test_audit_flags_private_filenames(tmp_path):
    files = ["reports/secret.json", "private/id_rsa", ".venv/lib/mod.py", "test.db"]
    for name in files:
        file = tmp_path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("dummy", encoding="utf-8")
    findings = audit_paths(tmp_path, files)
    assert len(findings) >= len(files)


def test_audit_detects_sensitive_token_without_echo(tmp_path):
    private = tmp_path / "notes.md"
    token = "ghp_" + "X" * 30
    private.write_text("key=" + token, encoding="utf-8")
    issues = audit_paths(tmp_path, ["notes.md"])
    assert any("token-shaped" in issue for issue in issues)
    assert token not in str(issues)


def test_audit_allows_tracked_synthetic_report_fixture(tmp_path):
    file = tmp_path / "samples/reports/synthetic_investigation.json"
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text('{"synthetic": true}', encoding="utf-8")
    assert audit_paths(tmp_path, ["samples/reports/synthetic_investigation.json"]) == []


def test_audit_safe_synthetic_fixture(tmp_path):
    file = tmp_path / "synthetic.log"
    file.write_text("example 198.51.100.1 203.0.113.20", encoding="utf-8")
    assert audit_paths(tmp_path, ["synthetic.log"]) == []


def test_audit_ignores_removed_tracked_file(tmp_path):
    assert audit_paths(tmp_path, ["deleted.md"]) == []


def test_audit_symlink_detected(tmp_path):
    target = tmp_path / "real.md"
    target.write_text("normal", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation unavailable on host")
    assert "symbolic link" in str(audit_paths(tmp_path, ["link.md"]))


def test_audit_tracked_git_files(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git not installed")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "hello.md").write_text("test", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "hello.md"], check=True)
    assert tracked_paths(tmp_path) == ["hello.md"]
    assert audit_paths(tmp_path, tracked_paths(tmp_path)) == []


def test_documentation_diagram_files_exist():
    for name in ("architecture.mmd", "investigation.mmd", "evidence_relationships.mmd"):
        content = (ROOT / "docs/diagrams" / name).read_text(encoding="utf-8")
        assert content.startswith(("flowchart", "sequenceDiagram", "erDiagram"))


def test_manual_ci_has_no_push_trigger():
    workflow = (ROOT / ".github/workflows/manual-ci.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "push:" not in workflow


def test_readme_describes_implemented_dashboard_and_pending_acceptance():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Dashboard code implemented" in readme
    assert "browser acceptance" in readme
    assert "Phase 10" in readme


def test_audit_allows_empty_reports_gitkeep(tmp_path):
    marker = tmp_path / "reports/.gitkeep"
    marker.parent.mkdir(parents=True)
    marker.touch()
    assert audit_paths(tmp_path, ["reports/.gitkeep"]) == []


def test_audit_rejects_nonempty_reports_gitkeep(tmp_path):
    marker = tmp_path / "reports/.gitkeep"
    marker.parent.mkdir(parents=True)
    marker.write_text("potentially sensitive content", encoding="utf-8")
    issues = audit_paths(tmp_path, ["reports/.gitkeep"])
    assert any("generated/private directory" in issue for issue in issues)


def test_audit_still_rejects_tracked_report_json(tmp_path):
    report = tmp_path / "reports/investigation.json"
    report.parent.mkdir(parents=True)
    report.write_text('{"host": "example"}', encoding="utf-8")
    issues = audit_paths(tmp_path, ["reports/investigation.json"])
    assert any("generated/private directory" in issue for issue in issues)


def test_audit_does_not_exempt_nested_gitkeep(tmp_path):
    marker = tmp_path / "reports/private/.gitkeep"
    marker.parent.mkdir(parents=True)
    marker.touch()
    issues = audit_paths(tmp_path, ["reports/private/.gitkeep"])
    assert any("generated/private directory" in issue for issue in issues)


def test_audit_allows_tracked_empty_placeholder_in_git_index(tmp_path):
    if not shutil.which("git"):
        pytest.skip("Git not installed")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    marker = tmp_path / "reports/.gitkeep"
    marker.parent.mkdir(parents=True)
    marker.touch()
    subprocess.run(["git", "-C", str(tmp_path), "add", "-f", "reports/.gitkeep"], check=True)
    assert tracked_paths(tmp_path) == ["reports/.gitkeep"]
    assert audit_paths(tmp_path, tracked_paths(tmp_path)) == []
