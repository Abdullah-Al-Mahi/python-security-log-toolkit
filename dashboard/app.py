
"""Sentinel / Prism UI — local SOC investigation dashboard.

Presentation only: all security decisions and exported data come from the
existing security_log_toolkit services. No telemetry or external assets.
"""
from __future__ import annotations

from collections import Counter
from contextlib import nullcontext
from html import escape
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

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

PAGES = (
    "Command Center", "Log Intake", "Incident Explorer", "Evidence Timeline",
    "Detection Lab", "Validation & Performance", "Report Center",
)
PAGE_ICONS = ("◫", "⇧", "◇", "≋", "⚙", "◉", "⇩")
SEVERITY_COLORS = {
    "critical": "#FF526F", "high": "#FFAB42",
    "medium": "#E1BF31", "low": "#17B9AA",
}

st.set_page_config(
    page_title="Sentinel Prism | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Local stylesheet, with no external font or API requests.
st.markdown(
    "<style>"
    + (ROOT / "dashboard/sentinel.css").read_text(encoding="utf-8")
    + "</style>",
    unsafe_allow_html=True,
)

# Browser-session appearance control.
if "ui_mode" not in st.session_state:
    st.session_state.ui_mode = "dark"

mode = "light" if st.session_state.ui_mode == "light" else "dark"
st.markdown(
    f'<span id="sentinel-{mode}-mode" hidden></span>',
    unsafe_allow_html=True,
)


# -----------------------------------------------------------
# REUSABLE PRESENTATION COMPONENTS
# -----------------------------------------------------------

def _html(value: object) -> str:
    return escape(str(value), quote=True)


def _header(title: str, subtitle: str, section: str) -> None:
    st.markdown(
        '<div class="prism-breadcrumb">'
        'SECURITY OPERATIONS <span> / '
        + _html(section.upper())
        + '</span></div>'
        '<div class="prism-pagehead"><div>'
        '<div class="prism-kicker">'
        '<span class="prism-live-dot"></span>'
        ' PRIVATE INVESTIGATION WORKSPACE</div>'
        '<h1>' + _html(title) + '</h1>'
        '<p>' + _html(subtitle) + '</p>'
        '</div>'
        '<div class="prism-header-mark">◈</div>'
        '</div>',
        unsafe_allow_html=True,
    )


def _section(title: str, subtitle: str = "") -> None:
    st.markdown(
        '<div class="prism-section">'
        '<span>' + _html(title) + '</span>'
        '<small>' + _html(subtitle) + '</small>'
        '</div>',
        unsafe_allow_html=True,
    )


def _scope(report: dict) -> None:
    mapping = {
        "bundled_synthetic_demo": (
            "SYNTHETIC DATA",
            "Bundled lab scenarios only",
        ),
        "user_upload": (
            "LOCAL UPLOAD",
            "Authorized files · temporary processing",
        ),
        "imported_report": (
            "IMPORTED JSON",
            "Existing investigation · read-only source",
        ),
    }

    tag, detail = mapping.get(
        report.get("dashboard_input_type"),
        ("LOCAL DATA", "Investigation data"),
    )

    st.markdown(
        '<div class="prism-scope">'
        '<span class="prism-scope-tag">'
        + _html(tag)
        + '</span><span>'
        + _html(detail)
        + '</span></div>',
        unsafe_allow_html=True,
    )


def _report() -> dict | None:
    if "current_report" not in st.session_state:
        try:
            st.session_state.current_report = load_synthetic_demo(ROOT)
        except (OSError, ValueError) as exc:
            st.error(
                f"Synthetic demonstration failed to load: {exc}"
            )
            return None

    return st.session_state.current_report


def _summary_cards(report: dict) -> None:
    summary = report["summary"]

    entries = (
        ("Normalized events", "events_analyzed"),
        ("Detection findings", "findings_analyzed"),
        ("Incidents opened", "total_incidents"),
        ("Linked evidence", "unique_evidence_events"),
    )

    for col, (label, key) in zip(
        st.columns(4, gap="medium"),
        entries,
    ):
        col.metric(label, str(summary.get(key, 0)))


def _panel():
    return (
        st.container(border=True)
        if hasattr(st, "container")
        else nullcontext()
    )


def _panel_title(title: str, caption: str = "") -> None:
    st.markdown(
        '<div class="prism-panel-label">'
        '<b>' + _html(title) + '</b>'
        '<small>' + _html(caption) + '</small>'
        '</div>',
        unsafe_allow_html=True,
    )


# -----------------------------------------------------------
# CHART STYLING
# -----------------------------------------------------------

def _chart_style(chart):
    light = st.session_state.ui_mode == "light"
    ink = "#52677F" if light else "#A9BCD0"
    grid = "#D9E5F0" if light else "#2A3549"

    return (
        chart.configure_view(strokeOpacity=0)
        .configure_axis(
            labelColor=ink,
            titleColor=ink,
            gridColor=grid,
            domain=False,
            ticks=False,
        )
        .configure_legend(
            labelColor=ink,
            titleColor=ink,
        )
        .configure(background="transparent")
    )


def _bar(
    data: list[dict],
    dimension: str,
    measure: str,
    color: str,
) -> None:
    frame = pd.DataFrame(data)

    if frame.empty or frame[measure].sum() == 0:
        st.info("No matching evidence in this investigation.")
        return

    if not hasattr(st, "altair_chart"):
        st.bar_chart(
            frame.set_index(dimension)[[measure]],
            height=235,
        )
        return

    import altair as alt

    chart = (
        alt.Chart(frame)
        .mark_bar(
            cornerRadiusEnd=5,
            size=22,
        )
        .encode(
            x=alt.X(
                f"{measure}:Q",
                title=None,
                axis=alt.Axis(
                    tickMinStep=1,
                    format="d",
                ),
            ),
            y=alt.Y(
                f"{dimension}:N",
                title=None,
                sort="-x",
            ),
            color=alt.value(color),
            tooltip=[
                alt.Tooltip(f"{dimension}:N"),
                alt.Tooltip(f"{measure}:Q"),
            ],
        )
        .properties(
            height=max(205, len(frame) * 38)
        )
    )

    st.altair_chart(
        _chart_style(chart),
        use_container_width=True,
        theme=None,
    )


def _donut(report: dict) -> None:
    if not hasattr(st, "altair_chart"):
        frame = pd.DataFrame(severity_summary(report))
        st.bar_chart(
            frame.set_index("severity")[["incidents"]],
            height=250,
        )
        return

    import altair as alt

    entries = [
        row
        for row in severity_summary(report)
        if row["incidents"]
    ]

    if not entries:
        st.info("No incident severity data.")
        return

    frame = pd.DataFrame(entries)

    colors = [
        SEVERITY_COLORS[key]
        for key in frame["severity"]
    ]

    chart = (
        alt.Chart(frame)
        .mark_arc(
            innerRadius=67,
            outerRadius=100,
            cornerRadius=5,
            padAngle=0.025,
        )
        .encode(
            theta=alt.Theta(
                "incidents:Q",
                stack=True,
            ),
            color=alt.Color(
                "severity:N",
                scale=alt.Scale(
                    domain=list(frame["severity"]),
                    range=colors,
                ),
                legend=alt.Legend(
                    orient="bottom",
                    title=None,
                ),
            ),
            tooltip=[
                "severity:N",
                "incidents:Q",
            ],
        )
        .properties(height=265)
    )

    st.altair_chart(
        _chart_style(chart),
        use_container_width=True,
        theme=None,
    )


def _timeline_chart(report: dict) -> None:
    data = timeline_activity(report)

    if not data:
        st.info("No linked timeline events available.")
        return

    frame = pd.DataFrame(data)

    if not hasattr(st, "altair_chart"):
        wide = frame.pivot_table(
            index="minute",
            columns="stage",
            values="events",
            aggfunc="sum",
            fill_value=0,
        )

        st.line_chart(wide, height=250)
        return

    import altair as alt

    # Only display real backend timestamps.
    frame["minute"] = pd.to_datetime(
        frame["minute"],
        utc=True,
        errors="coerce",
    )

    frame = frame.dropna(subset=["minute"])

    if frame.empty:
        st.info("No parseable evidence timestamps.")
        return

    chart = (
        alt.Chart(frame)
        .mark_line(
            point=True,
            strokeWidth=2.8,
        )
        .encode(
            x=alt.X(
                "minute:T",
                title="Event time (UTC)",
            ),
            y=alt.Y(
                "events:Q",
                title="Linked events",
                axis=alt.Axis(
                    tickMinStep=1,
                    format="d",
                ),
            ),
            color=alt.Color(
                "stage:N",
                title=None,
                scale=alt.Scale(
                    range=[
                        "#00D3C1",
                        "#947AFF",
                        "#FFAB42",
                        "#4FA9FF",
                    ],
                ),
            ),
            tooltip=[
                alt.Tooltip("minute:T"),
                "stage:N",
                "events:Q",
            ],
        )
        .properties(height=253)
    )

    st.altair_chart(
        _chart_style(chart),
        use_container_width=True,
        theme=None,
    )


# -----------------------------------------------------------
# WORKSPACE 1 — COMMAND CENTER
# -----------------------------------------------------------

def overview(report: dict) -> None:
    _header(
        "Command Center",
        "An overview of your actual authentication findings, "
        "linked evidence and priority cases.",
        "OVERVIEW",
    )

    _scope(report)
    _summary_cards(report)

    _section(
        "Security analytics",
        "DETECTION-BASED · NOT LIVE NETWORK TELEMETRY",
    )

    left, right = st.columns(
        [1.65, 1],
        gap="medium",
    )

    with left:
        with _panel():
            _panel_title(
                "Evidence activity",
                "Chronological events",
            )
            _timeline_chart(report)

    with right:
        with _panel():
            _panel_title(
                "Severity distribution",
                "All correlated incidents",
            )
            _donut(report)

    left, right = st.columns(
        2,
        gap="medium",
    )

    with left:
        with _panel():
            _panel_title(
                "Detection coverage",
                "Rule match counts",
            )
            _bar(
                rule_summary(report),
                "rule",
                "findings",
                "#947AFF",
            )

    with right:
        with _panel():
            _panel_title(
                "Source intelligence",
                "Incident counts per source IP",
            )
            _bar(
                top_sources(report),
                "source_ip",
                "incidents",
                "#00D3C1",
            )

    _section(
        "Priority investigations",
        "HIGHEST SEVERITY FIRST",
    )

    priority = filter_incidents(report)[:4]

    if not priority:
        st.info("No incidents to investigate.")

    for inc in priority:
        severity = str(
            inc.get("severity") or "unknown"
        ).lower()

        badge = (
            severity
            if severity in SEVERITY_COLORS
            else "neutral"
        )

        st.markdown(
            '<div class="prism-case">'
            '<span class="prism-case-stripe prism-b-'
            + badge
            + '"></span>'

            '<div class="prism-case-main">'
            '<div class="prism-case-id">'
            + _html(inc.get("incident_id", ""))
            + '</div>'

            '<strong>'
            + _html(inc.get("source_ip") or "Unknown source")
            + '</strong>'

            '<small>'
            + _html(inc.get("hostname") or "Unknown host")
            + ' · '
            + _html(inc.get("platform") or "unknown")
            + '</small></div>'

            '<div class="prism-sev prism-b-'
            + badge
            + '">'
            + _html(severity.upper())
            + '</div></div>',
            unsafe_allow_html=True,
        )

    st.caption(
        "Source data is synthetic until you analyze authorized logs. "
        "Findings are indicators for investigation, "
        "not confirmation of compromise."
    )


# -----------------------------------------------------------
# WORKSPACE 2 — LOG INTAKE
# -----------------------------------------------------------

def intake(_: dict) -> None:
    _header(
        "Log Intake",
        "Bring authorized Linux SSH and Windows Security XML "
        "into a private investigation session.",
        "INPUT",
    )

    st.info(
        "Privacy: raw uploads are processed in temporary storage "
        "and deleted from disk after analysis; browser session data "
        "can remain in memory. Keep this server bound to 127.0.0.1."
    )

    a, b = st.columns(2, gap="medium")

    with a:
        linux = st.file_uploader(
            "Linux SSH logs (.log, .txt)",
            type=["log", "txt"],
            accept_multiple_files=True,
            key=f"linux_{st.session_state.get('upload_epoch', 0)}",
        )

    with b:
        windows = st.file_uploader(
            "Windows Security XML (.xml)",
            type=["xml"],
            accept_multiple_files=True,
            key=f"windows_{st.session_state.get('upload_epoch', 0)}",
        )

    c, d = st.columns(2)

    with c:
        year = st.number_input(
            "Linux log year",
            min_value=1970,
            max_value=9999,
            value=2026,
            step=1,
        )

    with d:
        offset = st.text_input(
            "Explicit Linux UTC offset",
            value="+08:00",
        )

    files = list(linux or []) + list(windows or [])

    st.caption(
        f"{len(files)} selected · Max 4 files · "
        "16 MiB per file · 32 MiB combined · "
        "Binary EVTX not supported"
    )

    if st.button(
        "Analyze uploaded logs",
        type="primary",
        disabled=not files,
        use_container_width=True,
    ):
        try:
            if (
                len(files) > 4
                or any(
                    f.size > MAX_RAW_LOG_BYTES
                    for f in files
                )
                or sum(f.size for f in files)
                > 32 * 1024 * 1024
            ):
                raise ValueError(
                    "Upload limits exceeded "
                    "(4 files, 16 MiB each, 32 MiB total)"
                )

            sources = [
                UploadedSource(
                    f.name,
                    "linux",
                    f.getvalue(),
                )
                for f in linux or []
            ]

            sources += [
                UploadedSource(
                    f.name,
                    "windows",
                    f.getvalue(),
                )
                for f in windows or []
            ]

            st.session_state.current_report = analyze_uploaded_sources(
                sources,
                detection_rules=DETECTION_PATH,
                correlation_rules=CORRELATION_PATH,
                year=int(year),
                utc_offset=offset,
                detection_overrides=st.session_state.get(
                    "detection_overrides"
                ),
                correlation_overrides=st.session_state.get(
                    "correlation_overrides"
                ),
            )

            st.success(
                "Analysis complete. Explore the Command Center "
                "or Incident Explorer."
            )

        except (ValueError, OSError, UnicodeError) as exc:
            st.error(f"Analysis rejected: {exc}")

    st.divider()

    _section(
        "Import existing investigation",
        "JSON · READ ONLY",
    )

    existing = st.file_uploader(
        "Investigation JSON",
        type=["json"],
        key=f"json_{st.session_state.get('upload_epoch', 0)}",
    )

    if st.button(
        "Open investigation JSON",
        disabled=existing is None,
    ):
        try:
            if existing.size > 50 * 1024 * 1024:
                raise ValueError(
                    "Investigation JSON exceeds 50 MiB"
                )

            st.session_state.current_report = load_investigation_json(
                existing.getvalue()
            )

            st.success("Investigation report loaded.")

        except (OSError, ValueError) as exc:
            st.error(f"Import rejected: {exc}")


# -----------------------------------------------------------
# WORKSPACE 3 — INCIDENT EXPLORER
# -----------------------------------------------------------

def explorer(report: dict) -> None:
    _header(
        "Incident Explorer",
        "Filter by severity, platform, rule and identity; "
        "follow linked evidence to the source.",
        "INVESTIGATE",
    )

    _scope(report)

    a, b, c, d = st.columns(
        [1, 1, 1.3, 2]
    )

    severity = a.multiselect(
        "Severity",
        ["critical", "high", "medium", "low"],
    )

    platform = b.multiselect(
        "Platform",
        ["linux", "windows"],
    )

    rules = c.multiselect(
        "Detection rule",
        [
            "brute_force",
            "password_spray",
            "success_after_failures",
        ],
    )

    query = d.text_input(
        "Search IP, host, account or ID"
    )

    incidents = filter_incidents(
        report,
        severity=severity,
        platform=platform,
        rule=rules,
        query=query,
    )

    _section(
        f"{len(incidents)} matching incidents",
        "FILTERED INVESTIGATION QUEUE",
    )

    allowed = {
        item["incident_id"]
        for item in incidents
    }

    table = [
        row
        for row in build_report_tables(report)["incidents.csv"]
        if row["incident_id"] in allowed
    ]

    st.dataframe(
        pd.DataFrame(table),
        hide_index=True,
        use_container_width=True,
    )

    if not incidents:
        st.info("No cases match these filters.")
        return

    ids = [
        item["incident_id"]
        for item in incidents
    ]

    chosen = st.selectbox(
        "Open incident",
        ids,
        format_func=lambda k: next(
            (
                f"{item.get('severity', '?').upper()}"
                f" · {item.get('source_ip', '?')} · {k}"
                for item in incidents
                if item["incident_id"] == k
            ),
            k,
        ),
    )

    item = incident_detail(
        report,
        chosen,
    )

    a, b = st.columns(2, gap="medium")

    with a:
        with _panel():
            st.subheader("Case profile")

            st.json({
                key: item.get(key)
                for key in (
                    "incident_id",
                    "classification",
                    "severity",
                    "source_ip",
                    "platform",
                    "hostname",
                    "first_seen",
                    "last_seen",
                    "rule_ids",
                    "affected_accounts",
                )
            })

    with b:
        with _panel():
            st.subheader("Analyst observation")

            timeline = item.get("timeline") or {}

            st.info(
                timeline.get("analyst_summary")
                or "No narrative for this incident."
            )

            for check in timeline.get(
                "recommended_checks", []
            ):
                st.write("• " + str(check))

    _section(
        "Linked evidence",
        "EXACT SOURCE REFERENCES",
    )

    evidence = [
        row
        for row in build_report_tables(report)["evidence.csv"]
        if row["incident_id"] == chosen
    ]

    st.dataframe(
        pd.DataFrame(evidence),
        hide_index=True,
        use_container_width=True,
    )


# -----------------------------------------------------------
# WORKSPACE 4 — EVIDENCE TIMELINE
# -----------------------------------------------------------

def timelines(report: dict) -> None:
    _header(
        "Evidence Timeline",
        "Inspect the actual chronological authentication evidence "
        "associated with an incident.",
        "FORENSIC VIEW",
    )

    incidents = report["incidents"]

    if not incidents:
        st.info("No incident timelines available.")
        return

    options = {
        f"{item['incident_id']} · {item.get('source_ip')}":
            item["incident_id"]
        for item in incidents
    }

    selected = st.selectbox(
        "Investigation",
        list(options),
    )

    item = incident_detail(
        report,
        options[selected],
    )

    timeline = item.get("timeline") or {}

    st.caption(
        timeline.get("analyst_summary")
        or "Linked detection evidence, not complete log history."
    )

    rows = [
        row
        for row in build_report_tables(report)["timelines.csv"]
        if row["incident_id"] == item["incident_id"]
    ]

    if rows:
        st.dataframe(
            pd.DataFrame(rows),
            hide_index=True,
            use_container_width=True,
        )

        stages = Counter(
            row.get("stage") or "unknown"
            for row in rows
        )

        with _panel():
            _panel_title("Investigation stages")

            _bar(
                [
                    {"stage": key, "events": count}
                    for key, count in stages.items()
                ],
                "stage",
                "events",
                "#947AFF",
            )

    else:
        st.info(
            "No linked timeline entries for this incident."
        )

    with st.expander(
        "Evidence IDs and original source provenance"
    ):
        evidence = [
            row
            for row in build_report_tables(report)["evidence.csv"]
            if row["incident_id"] == item["incident_id"]
        ]

        st.dataframe(
            pd.DataFrame(evidence),
            hide_index=True,
            use_container_width=True,
        )


# -----------------------------------------------------------
# WORKSPACE 5 — DETECTION LAB
# -----------------------------------------------------------

def detection_lab(_: dict) -> None:
    _header(
        "Detection Lab",
        "Adjust rule thresholds in this session without "
        "modifying your project's YAML files.",
        "CONFIGURATION",
    )

    try:
        snapshot = inspect_configuration(
            DETECTION_PATH,
            CORRELATION_PATH,
        )
    except (OSError, ValueError) as exc:
        st.error(f"Configuration invalid: {exc}")
        return

    st.success(
        "Committed detection and correlation configurations are valid."
    )

    stored = st.session_state.get(
        "detection_overrides",
        {},
    )

    epoch = st.session_state.get(
        "config_epoch",
        0,
    )

    proposed = {}

    labels = {
        "brute_force": "Brute-force authentication",
        "password_spray": "Password spraying",
        "success_after_failures": "Success after failures",
    }

    for rule_id, label in labels.items():
        original = snapshot["detection_rules"][rule_id]

        current = {
            **original,
            **stored.get(rule_id, {}),
        }

        with st.expander(
            label,
            expanded=rule_id == "brute_force",
        ):
            a, b, c, d = st.columns(4)

            enabled = a.checkbox(
                "Enabled",
                value=current["enabled"],
                key=f"enable_{rule_id}_{epoch}",
            )

            choices = [
                "low",
                "medium",
                "high",
                "critical",
            ]

            severity = b.selectbox(
                "Severity",
                choices,
                index=choices.index(current["severity"]),
                key=f"sev_{rule_id}_{epoch}",
            )

            minutes = int(
                c.number_input(
                    "Window (minutes)",
                    min_value=1,
                    max_value=1440,
                    value=current["window_minutes"],
                    key=f"win_{rule_id}_{epoch}",
                )
            )

            minimum = int(
                d.number_input(
                    "Minimum failures",
                    min_value=1,
                    max_value=1440,
                    value=current["min_failures"],
                    key=f"fail_{rule_id}_{epoch}",
                )
            )

            proposed[rule_id] = dict(
                enabled=enabled,
                severity=severity,
                window_minutes=minutes,
                min_failures=minimum,
            )

            if rule_id == "password_spray":
                proposed[rule_id]["min_distinct_accounts"] = int(
                    st.number_input(
                        "Distinct accounts",
                        min_value=1,
                        max_value=1440,
                        value=current["min_distinct_accounts"],
                        key=f"accounts_{epoch}",
                    )
                )

    original_correlation = snapshot["correlation"]

    saved = st.session_state.get(
        "correlation_overrides",
        {},
    )

    a, b = st.columns(2)

    gap = int(
        a.number_input(
            "Maximum inactivity gap (minutes)",
            min_value=1,
            max_value=1440,
            value=saved.get(
                "max_gap_minutes",
                original_correlation["max_gap_minutes"],
            ),
            key=f"gap_{epoch}",
        )
    )

    span = int(
        b.number_input(
            "Maximum incident span (minutes)",
            min_value=1,
            max_value=1440,
            value=saved.get(
                "max_incident_minutes",
                original_correlation["max_incident_minutes"],
            ),
            key=f"span_{epoch}",
        )
    )

    correlation = {
        "max_gap_minutes": gap,
        "max_incident_minutes": span,
    }

    if st.button(
        "Apply session thresholds",
        type="primary",
    ):
        try:
            build_rule_yaml(
                DETECTION_PATH,
                proposed,
            )

            build_correlation_yaml(
                CORRELATION_PATH,
                correlation,
            )

            st.session_state.detection_overrides = proposed
            st.session_state.correlation_overrides = correlation

            st.success(
                "Overrides applied to new analyses only. "
                "Existing reports are unchanged."
            )

        except (OSError, ValueError) as exc:
            st.error(f"Rule update rejected: {exc}")

    if st.session_state.get("detection_overrides"):
        st.info(
            "Custom session rules active. "
            "Reanalyze logs to see their effect."
        )

    a, b = st.columns(2)

    try:
        a.download_button(
            "Download detection YAML",
            build_rule_yaml(
                DETECTION_PATH,
                st.session_state.get("detection_overrides"),
            ),
            file_name="detection_rules.yaml",
            mime="application/x-yaml",
            use_container_width=True,
        )

        b.download_button(
            "Download correlation YAML",
            build_correlation_yaml(
                CORRELATION_PATH,
                st.session_state.get("correlation_overrides"),
            ),
            file_name="correlation_rules.yaml",
            mime="application/x-yaml",
            use_container_width=True,
        )

    except (ValueError, OSError) as exc:
        st.error(str(exc))

    if st.button("Reset session rules to defaults"):
        st.session_state.pop(
            "detection_overrides",
            None,
        )
        st.session_state.pop(
            "correlation_overrides",
            None,
        )

        st.session_state.config_epoch = epoch + 1
        st.rerun()

    if st.button(
        "Re-run bundled synthetic demo with active settings"
    ):
        try:
            sources = [
                UploadedSource(
                    "attack_auth.log",
                    "linux",
                    (
                        ROOT / "samples/linux/attack_auth.log"
                    ).read_bytes(),
                ),
                UploadedSource(
                    "attack_security.xml",
                    "windows",
                    (
                        ROOT / "samples/windows/attack_security.xml"
                    ).read_bytes(),
                ),
            ]

            result = analyze_uploaded_sources(
                sources,
                detection_rules=DETECTION_PATH,
                correlation_rules=CORRELATION_PATH,
                year=2026,
                utc_offset="+08:00",
                detection_overrides=st.session_state.get(
                    "detection_overrides"
                ),
                correlation_overrides=st.session_state.get(
                    "correlation_overrides"
                ),
            )

            result["dashboard_input_type"] = (
                "bundled_synthetic_demo"
            )

            st.session_state.current_report = result

            st.success(
                "Demo reanalyzed: "
                f"{result['summary']['total_incidents']} incidents."
            )

        except (ValueError, OSError) as exc:
            st.error(f"Reanalysis failed: {exc}")


# -----------------------------------------------------------
# WORKSPACE 6 — VALIDATION AND PERFORMANCE
# -----------------------------------------------------------

def validation_lab() -> None:
    _header(
        "Validation & Performance",
        "Transparent synthetic metrics and repeatable "
        "in-memory benchmarks.",
        "QUALITY",
    )

    st.warning(
        "Synthetic test precision/recall is not real-world accuracy. "
        "Benchmark excludes raw parsing, disk and UI rendering."
    )

    if st.button(
        "Run labeled synthetic validation",
        type="primary",
    ):
        try:
            st.session_state.validation_report = evaluate_scenarios(
                ROOT / "samples/validation/ground_truth.json",
                samples_dir=ROOT / "samples",
                detection_rules=DETECTION_PATH,
            )

        except (ValueError, OSError) as exc:
            st.error(str(exc))

    if "validation_report" in st.session_state:
        result = st.session_state.validation_report
        summary = result["summary"]

        for col, (label, key) in zip(
            st.columns(4),
            (
                ("Precision", "precision"),
                ("Recall", "recall"),
                ("F1", "f1_score"),
                ("Scenarios", "scenarios"),
            ),
        ):
            col.metric(
                label,
                str(summary.get(key)),
            )

        st.dataframe(
            pd.DataFrame(result["scenarios"])[
                [
                    "name",
                    "events",
                    "true_positives",
                    "false_positives",
                    "false_negatives",
                ]
            ],
            hide_index=True,
            use_container_width=True,
        )

        st.caption(result["limitations"])

    st.divider()

    _section(
        "Synthetic throughput",
        "BOUNDED · IN-MEMORY",
    )

    a, b = st.columns(2)

    count = int(
        a.number_input(
            "Generated events",
            min_value=100,
            max_value=5000,
            value=1000,
            step=100,
        )
    )

    runs = int(
        b.number_input(
            "Runs",
            min_value=2,
            max_value=10,
            value=3,
        )
    )

    if st.button("Run benchmark"):
        try:
            st.session_state.benchmark_report = run_benchmark(
                event_count=count,
                runs=runs,
                detection_rules=DETECTION_PATH,
                correlation_rules=CORRELATION_PATH,
            )

        except (ValueError, OSError) as exc:
            st.error(str(exc))

    if "benchmark_report" in st.session_state:
        result = st.session_state.benchmark_report

        a, b, c = st.columns(3)

        a.metric(
            "Median latency",
            f"{result['median_ms']:.1f} ms",
        )

        b.metric(
            "P95 latency",
            f"{result['p95_ms']:.1f} ms",
        )

        c.metric(
            "Median events/sec",
            f"{result['median_events_per_second']:,.0f}",
        )

        st.caption(result["limitations"])


# -----------------------------------------------------------
# WORKSPACE 7 — REPORT CENTER
# -----------------------------------------------------------

def reports(report: dict) -> None:
    _header(
        "Report Center",
        "Export structured investigations without sending "
        "any data to external services.",
        "EXPORT",
    )

    _scope(report)

    st.code(
        summarize_report(report),
        language="text",
    )

    try:
        downloads = build_dashboard_downloads(report)
        bundle = build_dashboard_zip(report)

    except (ValueError, OSError) as exc:
        st.error(f"Report validation failed: {exc}")
        return

    a, b = st.columns(2)

    a.download_button(
        "Download complete ZIP (7 files)",
        data=bundle,
        file_name="sentinel_investigation_bundle.zip",
        mime="application/zip",
        type="primary",
        use_container_width=True,
    )

    b.download_button(
        "Download investigation JSON",
        data=downloads["investigation.json"],
        file_name="investigation.json",
        mime="application/json",
        use_container_width=True,
    )

    _section(
        "Individual evidence exports",
        "CSV / JSON",
    )

    for name, payload in sorted(downloads.items()):
        if name != "investigation.json":
            st.download_button(
                "↓ " + name,
                data=payload,
                file_name=name,
                mime=(
                    "text/csv"
                    if name.endswith(".csv")
                    else "application/json"
                ),
                key=f"download_{name}",
            )

    st.caption(
        "Exports are generated in memory; "
        "manifests verify file integrity, not authorship."
    )


# -----------------------------------------------------------
# SIDEBAR AND ONE-CLICK THEME SWITCH
# -----------------------------------------------------------

def sidebar() -> str:
    with st.sidebar:
        st.markdown(
            '<div class="prism-brand">'
            '<div class="prism-logo">◈</div>'
            '<div>'
            '<strong>SENTINEL'
            '<span class="prism-brand-dot">.</span>'
            '</strong>'
            '<small>PRISM SECURITY CONSOLE</small>'
            '</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div class="prism-sidebar-caption">'
            'SECURITY WORKSPACE'
            '</div>',
            unsafe_allow_html=True,
        )

        selection = st.radio(
            "Workspace",
            PAGES,
            format_func=lambda name: (
                PAGE_ICONS[PAGES.index(name)]
                + "    "
                + name
            ),
            label_visibility="collapsed",
            key="workspace_nav",
        )

        st.markdown(
            '<div class="prism-sidebar-caption">'
            'APPEARANCE'
            '</div>',
            unsafe_allow_html=True,
        )

        button_label = (
            "☀  Switch to light mode"
            if st.session_state.ui_mode == "dark"
            else "☾  Switch to dark mode"
        )

        if st.button(
            button_label,
            key="one_click_theme",
            use_container_width=True,
        ):
            st.session_state.ui_mode = (
                "light"
                if st.session_state.ui_mode == "dark"
                else "dark"
            )
            st.rerun()

        st.caption(
            "Appearance is saved for this browser session."
        )

        st.markdown(
            '<div class="prism-sidebar-caption">'
            'SESSION CONTROLS'
            '</div>',
            unsafe_allow_html=True,
        )

        if st.button(
            "↻  Reload synthetic demo",
            use_container_width=True,
        ):
            try:
                st.session_state.current_report = load_synthetic_demo(
                    ROOT
                )

                for key in (
                    "validation_report",
                    "benchmark_report",
                    "detection_overrides",
                    "correlation_overrides",
                ):
                    st.session_state.pop(key, None)

                st.session_state.config_epoch = (
                    st.session_state.get(
                        "config_epoch",
                        0,
                    )
                    + 1
                )

                st.success(
                    "Demo restored with committed settings."
                )

            except (ValueError, OSError) as exc:
                st.error(str(exc))

        if st.button(
            "✕  Clear investigation session",
            use_container_width=True,
        ):
            st.session_state.current_report = None

            for key in (
                "validation_report",
                "benchmark_report",
                "detection_overrides",
                "correlation_overrides",
            ):
                st.session_state.pop(key, None)

            st.session_state.upload_epoch = (
                st.session_state.get("upload_epoch", 0)
                + 1
            )

            st.rerun()

        st.markdown(
            '<div class="prism-side-foot">'
            '<span class="prism-live-dot"></span>'
            '<strong>LOCAL ENGINE READY</strong>'
            '<small>'
            '127.0.0.1 · No cloud sync'
            '<br>'
            'CLI independent · v'
            + _html(__version__)
            + '</small></div>',
            unsafe_allow_html=True,
        )

    return selection


# -----------------------------------------------------------
# APPLICATION ROUTER
# -----------------------------------------------------------

def main() -> None:
    page = sidebar()
    report = _report()

    if page == "Log Intake":
        intake(report or {})

    elif page == "Validation & Performance":
        validation_lab()

    elif page == "Detection Lab":
        detection_lab(report or {})

    elif report is None:
        st.warning(
            "Use Log Intake to import authorized logs, "
            "or reload the bundled demo from the sidebar."
        )

    elif page.casefold() == "command center":
        overview(report)

    elif page == "Incident Explorer":
        explorer(report)

    elif page == "Evidence Timeline":
        timelines(report)

    else:
        reports(report)

    st.markdown(
        '<div class="prism-footer">'
        'SENTINEL PRISM'
        '<span>PRIVATE · LOCAL · EVIDENCE FIRST</span>'
        '</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
