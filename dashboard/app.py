"""Local-only Streamlit dashboard over the existing Security Log Toolkit.

Run from project root: python -m streamlit run dashboard/app.py
No network calls, account system or raw-upload persistence are implemented.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pandas as pd
import streamlit as st

# Editable installs make this unnecessary; it also makes checkout launches safe.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from security_log_toolkit import __version__
from security_log_toolkit.dashboard import (
    UploadedSource, analyze_uploaded_sources, build_dashboard_downloads,
    build_dashboard_zip, build_rule_yaml, build_correlation_yaml,
    filter_incidents, incident_detail, load_investigation_json,
    load_synthetic_demo, severity_summary, rule_summary, timeline_activity,
    top_sources,
)
from security_log_toolkit.configuration import inspect_configuration
from security_log_toolkit.quality import evaluate_scenarios, run_benchmark
from security_log_toolkit.reporting import build_report_tables, summarize_report
from security_log_toolkit.security_limits import MAX_RAW_LOG_BYTES

DETECTION_PATH = ROOT / "config/detection_rules.yaml"
CORRELATION_PATH = ROOT / "config/correlation_rules.yaml"

st.set_page_config(
    page_title="Sentinel | Security Log Toolkit",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp {background: radial-gradient(circle at 84% 4%, rgba(41,111,130,.13),transparent 32%),
    radial-gradient(circle at 4% 60%,rgba(63,74,139,.10),transparent 35%),#0a101b;
  color:#edf5ff; }
[data-testid="stSidebar"] {background: #0e1826; border-right:1px solid #1d3040;}
[data-testid="stHeader"] {background:rgba(10,16,27,.8);}
h1,h2,h3 {letter-spacing:-.035em !important;}
h1 {font-weight:750!important;}
p,small,label {letter-spacing:.003em;}
.stMetric {background:#111f2e; border:1px solid #253548; border-radius:14px;
 padding:15px 20px;}
[data-testid="stMetricLabel"] {color:#a5b6c8 !important;}
[data-testid="stMetricValue"] {color:#eaf5ff !important;}
[data-testid="stMetricDelta"] {color:#6dd6bd !important;}
[data-testid="stDataFrame"] {border:1px solid #253548;border-radius:12px;}
.stButton button[kind="primary"] {background:#35bca6; color:#092025; border:0; font-weight:750;}
.stButton button {border-radius:10px;}
[data-testid="stDownloadButton"] button {border-radius:10px;}
[data-testid="stVerticalBlockBorderWrapper"] {border-color:#26384a !important;}
.sentinel-tag {display:inline-block;color:#70e3c9;background:#112f34;border:1px solid #245a56;
 border-radius:30px;padding:5px 11px;font:700 11px sans-serif;letter-spacing:.13em;}
.sentinel-hero {padding:27px 30px;margin:6px 0 23px;border-radius:19px;
 background:linear-gradient(115deg,rgba(17,49,67,.98),rgba(15,25,45,.98) 62%,rgba(20,43,60,.9));
 border:1px solid #27475b;}
.sentinel-hero h1 {font-size:36px;margin:14px 0 7px;}
.sentinel-hero p {font-size:14px;color:#a9c5d2;margin:0;}
.sentinel-brand {color:#f0fcff;font-weight:800;font-size:22px;margin:6px 0 6px;letter-spacing:-.045em;}
.sentinel-sub {color:#849aaf;font-size:12px;margin-bottom:17px;}
.stAlert {border-radius:12px;}
</style>
""", unsafe_allow_html=True)


def _hero(title: str, description: str, tag: str = "SECURITY OPERATIONS") -> None:
    # All HTML arguments are local constants, not user-controlled input.
    st.markdown(
        '<section class="sentinel-hero"><span class="sentinel-tag">'
        + tag + '</span><h1>' + title + '</h1><p>' + description + '</p></section>',
        unsafe_allow_html=True,
    )


def _scope_label(report: dict) -> str:
    mode = report.get("dashboard_input_type")
    return {
        "bundled_synthetic_demo": "SYNTHETIC DEMO — fixed sample authentication activity",
        "user_upload": "USER UPLOAD — processed locally; no raw files retained on disk",
        "imported_report": "IMPORTED REPORT — read-only view of supplied investigation JSON",
    }.get(mode, "LOCAL INVESTIGATION")


def _current_report() -> dict | None:
    if "current_report" not in st.session_state:
        try:
            st.session_state.current_report = load_synthetic_demo(ROOT)
        except (OSError, ValueError) as exc:
            st.error(f"Bundled synthetic demonstration could not load: {exc}")
            return None
    return st.session_state.current_report


def _metrics(report: dict) -> None:
    summary = report["summary"]
    columns = st.columns(4)
    for column, (title, field) in zip(columns, (
        ("Normalized events", "events_analyzed"),
        ("Detection findings", "findings_analyzed"),
        ("Incidents opened", "total_incidents"),
        ("Linked evidence", "unique_evidence_events"),
    )):
        column.metric(title, f"{summary.get(field, 0):,}")


def _chart(data: list[dict], index: str, values: str, key: str) -> None:
    if data:
        df = pd.DataFrame(data).set_index(index)
        st.bar_chart(df[[values]], height=245, use_container_width=True)
    else:
        st.info(f"No {key} records in this report.")


def overview(report: dict) -> None:
    _hero("Security Command Center", "From authentication telemetry to actionable incident investigation.")
    st.caption(_scope_label(report))
    _metrics(report)
    st.write("")
    col1, col2 = st.columns([1, 1], gap="large")
    with col1:
        st.subheader("Incidents by severity")
        _chart(severity_summary(report), "severity", "incidents", "incident")
    with col2:
        st.subheader("Detection coverage")
        _chart(rule_summary(report), "rule", "findings", "finding")
    col3, col4 = st.columns([1, 1], gap="large")
    with col3:
        st.subheader("Top source addresses")
        _chart(top_sources(report), "source_ip", "incidents", "source")
    with col4:
        st.subheader("Linked evidence activity")
        rows = timeline_activity(report)
        if rows:
            frame = pd.DataFrame(rows)
            wide = frame.pivot_table(index="minute", columns="stage", values="events", aggfunc="sum", fill_value=0)
            st.line_chart(wide, height=245)
        else:
            st.info("No linked evidence timeline is available.")
    st.caption("Charts summarize linked detection evidence, not all source-log events. A success-after-failure finding is not proof of compromise.")


def intake(report: dict) -> None:
    _hero("Secure Log Intake", "Inspect authorized Linux SSH and Windows Security XML logs without keeping raw uploads.", "LOCAL ANALYSIS")
    st.warning("Privacy: upload only logs you're authorized to analyze. Raw files are processed in temporary storage, but analysis results stay in this browser session until cleared. Do not expose this server to a network.")
    a, b = st.columns(2, gap="large")
    with a:
        linux = st.file_uploader("Linux OpenSSH authentication logs", type=["log", "txt"], accept_multiple_files=True, key=f"linux_upload_{st.session_state.get('upload_epoch',0)}")
    with b:
        windows = st.file_uploader("Windows Security Event XML exports", type=["xml"], accept_multiple_files=True, key=f"windows_upload_{st.session_state.get('upload_epoch',0)}")
    c, d = st.columns(2)
    with c:
        year = st.number_input("Linux log year (explicit)", min_value=1970, max_value=9999, value=2026, step=1)
    with d:
        offset = st.text_input("Linux UTC offset", value="+08:00", help="For example +08:00 or +00:00. Must reflect the log's timezone.")
    files = list(linux or []) + list(windows or [])
    st.caption(f"{len(files)} file(s) selected · Limit: 4 files, 16 MiB each, 32 MiB combined. Binary .evtx is not supported; export to XML first.")
    if st.button("Analyze uploaded logs", type="primary", disabled=not files, use_container_width=True):
        try:
            # Size check before materializing bytes into Python memory.
            if len(files) > 4 or any(item.size > MAX_RAW_LOG_BYTES for item in files) or sum(item.size for item in files) > 32 * 1024 * 1024:
                raise ValueError("Upload count or size limit exceeded (4 files / 16 MiB each / 32 MiB total)")
            inputs = [UploadedSource(f.name, "linux", f.getvalue()) for f in linux or []]
            inputs += [UploadedSource(f.name, "windows", f.getvalue()) for f in windows or []]
            st.session_state.current_report = analyze_uploaded_sources(
                inputs, detection_rules=DETECTION_PATH, correlation_rules=CORRELATION_PATH,
                year=int(year), utc_offset=offset,
                detection_overrides=st.session_state.get("detection_overrides"),
                correlation_overrides=st.session_state.get("correlation_overrides"),
            )
            st.success("Analysis complete. Open the Command Center or Incident Explorer for results.")
        except (ValueError, OSError, UnicodeError) as exc:
            st.error(f"Upload rejected or analysis failed: {exc}")
    st.divider()
    st.subheader("Import an existing investigation JSON")
    st.caption("Read-only review. Use a report created by the toolkit, rather than an unrelated JSON file.")
    existing = st.file_uploader("Investigation JSON", type=["json"], key=f"report_upload_{st.session_state.get('upload_epoch',0)}")
    if st.button("Open investigation JSON", disabled=existing is None):
        try:
            if existing.size > 50 * 1024 * 1024:
                raise ValueError("Investigation JSON exceeds the 50 MiB limit")
            st.session_state.current_report = load_investigation_json(existing.getvalue())
            st.success("Investigation loaded for review.")
        except (ValueError, OSError) as exc:
            st.error(f"Import rejected: {exc}")


def explorer(report: dict) -> None:
    _hero("Incident Explorer", "Filter, investigate and validate evidence relationships for each case.", "INVESTIGATION")
    st.caption(_scope_label(report))
    one, two, three, four = st.columns([1, 1, 1.2, 2])
    severity = one.multiselect("Severity", ["critical", "high", "medium", "low"])
    platform = two.multiselect("Platform", ["linux", "windows"])
    rules = three.multiselect("Detection rule", ["brute_force", "password_spray", "success_after_failures"])
    search = four.text_input("Search IP, host, account or incident ID")
    incidents = filter_incidents(report, severity=severity, platform=platform, rule=rules, query=search)
    st.write(f"**{len(incidents)} incident(s) match your filters**")
    table = build_report_tables(report)["incidents.csv"]
    keys = {item["incident_id"] for item in incidents}
    filtered = [entry for entry in table if entry["incident_id"] in keys]
    st.dataframe(pd.DataFrame(filtered), use_container_width=True, hide_index=True)
    if not incidents:
        st.info("No matching incidents. Try adjusting the filters.")
        return
    ids = [i["incident_id"] for i in incidents]
    chosen = st.selectbox("Open incident", ids, format_func=lambda k: next(
        (f"{i.get('severity','unknown').upper()} · {i.get('source_ip','?')} · {k}" for i in incidents if i["incident_id"] == k), k))
    item = incident_detail(report, chosen)
    left, right = st.columns([1, 1], gap="large")
    with left:
        st.subheader("Case details")
        st.write({key: item.get(key) for key in ("incident_id", "classification", "severity", "source_ip", "platform", "hostname", "first_seen", "last_seen", "rule_ids", "affected_accounts")})
    with right:
        st.subheader("Analyst observation")
        timeline = item.get("timeline") or {}
        st.info(timeline.get("analyst_summary") or "No analyst narrative is available for this case.")
        st.caption("These are observed authentication events; conclusions require independent investigation.")
        st.markdown("**Recommended follow-up checks**")
        for check in timeline.get("recommended_checks", []):
            st.write("• " + str(check))
    st.subheader("Linked evidence")
    st.dataframe(pd.DataFrame([x for x in build_report_tables(report)["evidence.csv"] if x["incident_id"] == chosen]), hide_index=True, use_container_width=True)


def timelines(report: dict) -> None:
    _hero("Evidence Timeline", "Reconstruct the sequence of linked authentication evidence.", "FORENSIC CONTEXT")
    incidents = report["incidents"]
    if not incidents:
        st.info("No incident timelines available.")
        return
    options = {f"{i['incident_id']} · {i.get('source_ip')}": i["incident_id"] for i in incidents}
    key = st.selectbox("Choose investigation", list(options))
    incident = incident_detail(report, options[key])
    t = incident.get("timeline") or {}
    st.caption(t.get("analyst_summary") or "Linked evidence only; not the complete security log history.")
    rows = [r for r in build_report_tables(report)["timelines.csv"] if r["incident_id"] == incident["incident_id"]]
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        count = {}
        for entry in rows:
            stage = entry.get("stage") or "unknown"
            count[stage] = count.get(stage, 0) + 1
        _chart([{"stage": k, "linked_events": v} for k, v in count.items()], "stage", "linked_events", "timeline")
    else:
        st.info("The selected report contains no linked timeline events for this case.")
    with st.expander("Show underlying evidence IDs and source provenance"):
        st.dataframe(pd.DataFrame([x for x in build_report_tables(report)["evidence.csv"] if x["incident_id"] == incident["incident_id"]]), hide_index=True, use_container_width=True)


def detection_lab(report: dict) -> None:
    _hero("Detection Configuration", "Tune session-only thresholds while preserving your committed YAML rules.", "CONTROL PLANE")
    try:
        snapshot = inspect_configuration(DETECTION_PATH, CORRELATION_PATH)
    except (OSError, ValueError) as exc:
        st.error(f"Configuration validation failed: {exc}")
        return
    st.success("Original detection and correlation YAML: VALID")
    stored = st.session_state.get("detection_overrides", {})
    config_epoch = st.session_state.get("config_epoch", 0)
    proposed = {}
    labels = {"brute_force": "Brute-force authentication", "password_spray": "Password spraying", "success_after_failures": "Success after failures"}
    for rule_id, label in labels.items():
        original = snapshot["detection_rules"][rule_id]
        current = {**original, **stored.get(rule_id, {})}
        with st.expander(label, expanded=(rule_id == "brute_force")):
            ca, cb, cc, cd = st.columns([1, 1, 1, 1])
            enabled = ca.checkbox("Enabled", value=current["enabled"], key=f"enable_{rule_id}_{config_epoch}")
            options = ["low", "medium", "high", "critical"]
            severity = cb.selectbox("Severity", options, index=options.index(current["severity"]), key=f"sev_{rule_id}_{config_epoch}")
            minutes = int(cc.number_input("Window (minutes)", min_value=1, max_value=1440, value=current["window_minutes"], key=f"win_{rule_id}_{config_epoch}"))
            failures = int(cd.number_input("Minimum failures", min_value=1, max_value=1440, value=current["min_failures"], key=f"fail_{rule_id}_{config_epoch}"))
            proposed[rule_id] = dict(enabled=enabled, severity=severity, window_minutes=minutes, min_failures=failures)
            if rule_id == "password_spray":
                proposed[rule_id]["min_distinct_accounts"] = int(st.number_input("Distinct accounts", min_value=1, max_value=1440, value=current["min_distinct_accounts"], key=f"spray_accounts_{config_epoch}"))
    orig_corr = snapshot["correlation"]
    corr_saved = st.session_state.get("correlation_overrides", {})
    c1, c2 = st.columns(2)
    gap = int(c1.number_input("Maximum inactivity gap (minutes)", min_value=1, max_value=1440, value=corr_saved.get("max_gap_minutes", orig_corr["max_gap_minutes"]), key=f"corr_gap_{config_epoch}"))
    span = int(c2.number_input("Maximum incident span (minutes)", min_value=1, max_value=1440, value=corr_saved.get("max_incident_minutes", orig_corr["max_incident_minutes"]), key=f"corr_span_{config_epoch}"))
    correlation = dict(max_gap_minutes=gap, max_incident_minutes=span)
    if st.button("Apply thresholds for this browser session", type="primary"):
        try:
            build_rule_yaml(DETECTION_PATH, proposed)
            build_correlation_yaml(CORRELATION_PATH, correlation)
            st.session_state.detection_overrides = proposed
            st.session_state.correlation_overrides = correlation
            st.success("Session settings applied. Re-run analysis from Log Intake or reload the synthetic demo using these settings.")
        except (OSError, ValueError) as exc:
            st.error(f"Configuration rejected: {exc}")
    used = st.session_state.get("detection_overrides")
    if used:
        st.info("Customized rules are ACTIVE for new analyses only. Existing incident results are not recomputed automatically.")
    st.caption("These controls never overwrite config/detection_rules.yaml or config/correlation_rules.yaml. Download YAML for manual review if needed.")
    try:
        detection_bytes = build_rule_yaml(DETECTION_PATH, st.session_state.get("detection_overrides"))
        correlation_bytes = build_correlation_yaml(CORRELATION_PATH, st.session_state.get("correlation_overrides"))
        d1, d2 = st.columns(2)
        d1.download_button("Download detection YAML", detection_bytes, file_name="detection_rules.yaml", mime="application/x-yaml", use_container_width=True)
        d2.download_button("Download correlation YAML", correlation_bytes, file_name="correlation_rules.yaml", mime="application/x-yaml", use_container_width=True)
    except (ValueError, OSError) as exc:
        st.error(str(exc))
    if st.button("Reset session rule settings to committed defaults"):
        st.session_state.pop("detection_overrides", None)
        st.session_state.pop("correlation_overrides", None)
        st.session_state.config_epoch = config_epoch + 1
        st.rerun()
    if st.button("Re-run bundled synthetic demo with ACTIVE settings"):
        try:
            files = [UploadedSource("attack_auth.log", "linux", (ROOT / "samples/linux/attack_auth.log").read_bytes()), UploadedSource("attack_security.xml", "windows", (ROOT / "samples/windows/attack_security.xml").read_bytes())]
            report = analyze_uploaded_sources(files, detection_rules=DETECTION_PATH, correlation_rules=CORRELATION_PATH, year=2026, utc_offset="+08:00", detection_overrides=st.session_state.get("detection_overrides"), correlation_overrides=st.session_state.get("correlation_overrides"))
            report["dashboard_input_type"] = "bundled_synthetic_demo"
            st.session_state.current_report = report
            st.success(f"Demo reanalyzed: {report['summary']['total_incidents']} incidents.")
        except (OSError, ValueError) as exc:
            st.error(f"Reanalysis failed: {exc}")


def validation_lab() -> None:
    _hero("Validation & Performance", "Measure rule-label agreement on fixed synthetic scenarios and bounded local throughput.", "QUALITY LAB")
    st.warning("Synthetic scenario precision/recall does NOT measure real-world intrusion detection accuracy. Benchmarks are in-memory only and exclude disk I/O and the UI.")
    if st.button("Run labeled synthetic validation", type="primary"):
        try:
            st.session_state.validation_report = evaluate_scenarios(ROOT / "samples/validation/ground_truth.json", samples_dir=ROOT / "samples", detection_rules=DETECTION_PATH)
        except (OSError, ValueError) as exc:
            st.error(str(exc))
    if "validation_report" in st.session_state:
        result = st.session_state.validation_report
        summary = result["summary"]
        a, b, c, d = st.columns(4)
        a.metric("Precision", str(summary.get("precision")))
        b.metric("Recall", str(summary.get("recall")))
        c.metric("F1", str(summary.get("f1_score")))
        d.metric("Scenarios", summary["scenarios"])
        st.dataframe(pd.DataFrame(result["scenarios"])[["name", "events", "true_positives", "false_positives", "false_negatives"]], hide_index=True, use_container_width=True)
        st.caption(result["limitations"])
    st.divider()
    st.subheader("Synthetic throughput benchmark")
    left, right = st.columns(2)
    count = int(left.number_input("Generated events", min_value=100, max_value=5000, value=1000, step=100))
    runs = int(right.number_input("Repetitions", min_value=2, max_value=10, value=3))
    if st.button("Run benchmark"):
        try:
            st.session_state.benchmark_report = run_benchmark(event_count=count, runs=runs, detection_rules=DETECTION_PATH, correlation_rules=CORRELATION_PATH)
        except (ValueError, OSError) as exc:
            st.error(str(exc))
    if "benchmark_report" in st.session_state:
        result = st.session_state.benchmark_report
        a, b, c = st.columns(3)
        a.metric("Median processing", f"{result['median_ms']:.1f} ms")
        b.metric("P95 processing", f"{result['p95_ms']:.1f} ms")
        c.metric("Median events/s", f"{result['median_events_per_second']:,.0f}")
        st.caption(result["limitations"])


def reports(report: dict) -> None:
    _hero("Report Center", "Export investigation evidence with validated schemas and SHA-256 manifests.", "REPORTING")
    st.caption(_scope_label(report))
    st.code(summarize_report(report), language="text")
    try:
        downloads = build_dashboard_downloads(report)
        bundle = build_dashboard_zip(report)
    except (ValueError, OSError) as exc:
        st.error(f"Export validation failed: {exc}")
        return
    a, b = st.columns([1, 1])
    a.download_button("Download all 7 files (ZIP)", data=bundle, file_name="security_investigation_exports.zip", mime="application/zip", type="primary", use_container_width=True)
    b.download_button("Download full JSON", data=downloads["investigation.json"], file_name="investigation.json", mime="application/json", use_container_width=True)
    st.subheader("Individual exports")
    for name, contents in sorted(downloads.items()):
        if name != "investigation.json":
            st.download_button(f"↓ {name}", data=contents, file_name=name, mime="text/csv" if name.endswith(".csv") else "application/json", key=f"download_{name}")
    st.caption("Each generated export is in memory. SHA-256 hashes detect changes against the supplied manifest; they do not prove authorship.")


def sidebar() -> str:
    with st.sidebar:
        st.markdown('<div class="sentinel-brand">◈ SENTINEL</div><div class="sentinel-sub">SECURITY LOG TOOLKIT · LOCAL SOC</div>', unsafe_allow_html=True)
        st.caption(f"v{__version__} · 127.0.0.1 only")
        st.divider()
        selection = st.radio("WORKSPACE", ["Command center", "Log intake", "Incident explorer", "Evidence timeline", "Detection lab", "Validation & performance", "Report center"], label_visibility="collapsed")
        st.divider()
        st.caption("SESSION CONTROLS")
        if st.button("Reload synthetic demonstration", use_container_width=True):
            try:
                st.session_state.current_report = load_synthetic_demo(ROOT)
                st.session_state.pop("validation_report", None)
                st.session_state.pop("benchmark_report", None)
                st.session_state.pop("detection_overrides", None)
                st.session_state.pop("correlation_overrides", None)
                st.session_state.config_epoch = st.session_state.get("config_epoch",0) + 1
                st.success("Synthetic demo loaded with default committed configurations.")
            except (OSError, ValueError) as exc:
                st.error(str(exc))
        if st.button("Clear investigation session", use_container_width=True):
            st.session_state.current_report = None
            for key in ("validation_report", "benchmark_report", "detection_overrides", "correlation_overrides"):
                st.session_state.pop(key, None)
            st.session_state.upload_epoch = st.session_state.get("upload_epoch", 0) + 1
            st.rerun()
        st.divider()
        st.caption("Local-first · No remote API · No automatic publication")
        st.caption("The CLI remains independent of this interface.")
        return selection


def main() -> None:
    page = sidebar()
    report = _current_report()
    if page == "Log intake":
        intake(report or {})
    elif page == "Validation & performance":
        validation_lab()
    elif page == "Detection lab":
        detection_lab(report or {})
    elif report is None:
        st.warning("Load the bundled synthetic demo from the sidebar or import a report.")
    elif page == "Command center":
        overview(report)
    elif page == "Incident explorer":
        explorer(report)
    elif page == "Evidence timeline":
        timelines(report)
    else:
        reports(report)


if __name__ == "__main__":
    main()
