"""Command-line interface for offline security analysis and investigation."""

import argparse
import json
import sys
import platform
from pathlib import Path
from xml.etree import ElementTree as ET

from security_log_toolkit import __version__
from security_log_toolkit.configuration import inspect_configuration
from security_log_toolkit.workflow import RawLogSource, analyze_raw_logs
from security_log_toolkit.correlation import investigate
from security_log_toolkit.detection import (
    detect_events,
    detection_report,
    load_detection_config,
    load_normalized_events,
)
from security_log_toolkit.ingest import ingest_file
from security_log_toolkit.reporting import (
    build_export_artifacts, summarize_report, validate_investigation_report, write_export_bundle,
)
from security_log_toolkit.investigation import attach_timelines, investigate_with_timelines


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI without breaking older supported commands."""
    parser = argparse.ArgumentParser(
        prog="security-log",
        description=(
            "Offline Python toolkit for security log analysis, "
            "event correlation, and incident investigation."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", title="available commands")
    commands.add_parser("status", help="Display toolkit implementation status.")

    parse = commands.add_parser("parse", help="Normalize an offline authentication log file.")
    parse.add_argument("format", choices=("linux", "windows"))
    parse.add_argument("input", type=Path, help="Path to the offline log file")
    parse.add_argument("--year", type=int, help="Required for Linux syslog (which omits the year)")
    parse.add_argument(
        "--utc-offset", default="+00:00",
        help="Linux syslog timezone offset, e.g. +08:00 (default: +00:00)",
    )
    parse.add_argument("--output", type=Path, help="Optional destination for normalized JSON")

    detect = commands.add_parser(
        "detect", help="Detect suspicious logins in one or more normalized Phase 2 JSON files."
    )
    detect.add_argument("inputs", nargs="+", type=Path, help="Paths to normalized JSON files")
    detect.add_argument(
        "--rules", type=Path, default=Path("config/detection_rules.yaml"),
        help="YAML detection configuration (default: config/detection_rules.yaml)",
    )
    detect.add_argument("--output", type=Path, help="Optional destination for findings JSON")

    correlate = commands.add_parser(
        "correlate", help="Group detection findings into incident-level cases."
    )
    correlate.add_argument(
        "inputs", nargs="+", type=Path, help="Paths to normalized Phase 2 JSON files"
    )
    correlate.add_argument(
        "--rules", type=Path, default=Path("config/detection_rules.yaml"),
        help="YAML detection rules (default: config/detection_rules.yaml)",
    )
    correlate.add_argument(
        "--correlation-config", type=Path,
        default=Path("config/correlation_rules.yaml"),
        help="YAML correlation settings (default: config/correlation_rules.yaml)",
    )
    correlate.add_argument("--output", type=Path, help="Optional JSON incident report destination")
    timeline = commands.add_parser(
        "timeline", help="Generate an evidence-linked incident investigation timeline."
    )
    timeline.add_argument(
        "inputs", nargs="*", type=Path,
        help="Normalized Phase 2 JSON files (omit when using --incident-report)",
    )
    timeline.add_argument(
        "--incident-report", type=Path,
        help="Enrich an existing Phase 4 incident JSON report without re-running detection",
    )
    timeline.add_argument(
        "--rules", type=Path, default=Path("config/detection_rules.yaml"),
        help="YAML detection configuration for normalized inputs",
    )
    timeline.add_argument(
        "--correlation-config", type=Path,
        default=Path("config/correlation_rules.yaml"),
        help="YAML correlation configuration for normalized inputs",
    )
    timeline.add_argument("--output", type=Path, help="Optional timeline JSON destination")

    analyze = commands.add_parser(
        "analyze", help="Run parsing, detection, correlation and timelines directly on raw logs."
    )
    analyze.add_argument(
        "--linux", type=Path, action="append", default=[], metavar="PATH",
        help="Linux OpenSSH authentication file (repeatable; requires --year and --utc-offset)",
    )
    analyze.add_argument(
        "--windows", type=Path, action="append", default=[], metavar="PATH",
        help="Windows Security XML file (repeatable)",
    )
    analyze.add_argument("--year", type=int, help="Explicit year for Linux syslog records")
    analyze.add_argument("--utc-offset", help="Explicit Linux timezone offset, e.g. +08:00")
    analyze.add_argument(
        "--rules", type=Path, default=Path("config/detection_rules.yaml"),
        help="YAML detection rules (default: config/detection_rules.yaml)",
    )
    analyze.add_argument(
        "--correlation-config", type=Path,
        default=Path("config/correlation_rules.yaml"),
        help="YAML correlation configuration (default: config/correlation_rules.yaml)",
    )
    analyze.add_argument("--output", type=Path, help="Destination for full JSON report")
    analyze.add_argument(
        "--force", action="store_true",
        help="Allow overwriting an existing output report (never source logs or rules)",
    )
    analyze.add_argument(
        "--summary", action="store_true",
        help="Print concise text instead of JSON when no --output is specified",
    )

    config = commands.add_parser("config", help="Inspect and validate detection/correlation YAML.")
    actions = config.add_subparsers(dest="config_action", required=True)
    for action, help_text in (
        ("show", "Display validated settings as JSON"),
        ("validate", "Check both configuration files without modifying them"),
    ):
        cmd = actions.add_parser(action, help=help_text)
        cmd.add_argument(
            "--rules", type=Path, default=Path("config/detection_rules.yaml"),
            help="Path to detection_rules.yaml",
        )
        cmd.add_argument(
            "--correlation-config", type=Path,
            default=Path("config/correlation_rules.yaml"),
            help="Path to correlation_rules.yaml",
        )

    doctor = commands.add_parser("doctor", help="Check Python and local YAML configuration.")
    doctor.add_argument("--json", action="store_true", help="Machine-readable diagnostic report")
    doctor.add_argument(
        "--rules", type=Path, default=Path("config/detection_rules.yaml"),
        help="Path to detection_rules.yaml",
    )
    doctor.add_argument(
        "--correlation-config", type=Path,
        default=Path("config/correlation_rules.yaml"),
        help="Path to correlation_rules.yaml",
    )
    report = commands.add_parser("report", help="Show a readable investigation report summary.")
    report.add_argument("--input", required=True, type=Path, help="Existing Phase 4/5/6 investigation JSON")

    export = commands.add_parser("export", help="Export investigation JSON and/or CSV tables.")
    export.add_argument("--input", required=True, type=Path, help="Existing incident investigation JSON")
    export.add_argument("--output-dir", required=True, type=Path, help="New output folder for export artifacts")
    export.add_argument("--format", choices=("csv", "json", "both"), default="both")
    export.add_argument("--force", action="store_true", help="Replace only a previous toolkit export folder")
    return parser


def _write_json(output: Path, data: dict) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _assert_safe_output(output: Path | None, protected: list[Path]) -> None:
    if output and any(output.resolve() == path.resolve() for path in protected):
        raise ValueError("--output must not overwrite input files or YAML configuration files")


def main(argv: list[str] | None = None) -> int:
    """Execute one command and return a process-compatible status code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        print("Security Log Toolkit")
        print("--------------------")
        print(f"Version: {__version__}")
        print("Installation: OK")
        print("Current milestone: Phase 7")
        print("Log parsing: Linux SSH and Windows XML available")
        print("Normalization: Available")
        print("Detection engine: 3 configurable rules available")
        print("Event correlation: Incident grouping available")
        print("Investigation timelines: Evidence-linked chronological timelines available")
        print("Raw-log workflow and configuration inspection: Available")
        print("Reporting: CSV/JSON bundles and analyst summaries available")
        return 0

    if args.command in ("report", "export"):
        try:
            # Reject oversized inputs rather than loading arbitrary huge reports.
            if args.input.stat().st_size > 50 * 1024 * 1024:
                raise ValueError("Investigation report exceeds 50 MiB input limit")
            with args.input.open("r", encoding="utf-8-sig") as stream:
                data = validate_investigation_report(json.load(stream))
            if args.command == "report":
                print(summarize_report(data))
            else:
                artifacts = build_export_artifacts(data, args.format)
                paths = write_export_bundle(
                    artifacts, args.output_dir, protected_paths=[args.input], force=args.force,
                )
                print(f"Exported {len(paths)} files to {args.output_dir} ({args.format}).")
                for path in paths:
                    print(f"  {path.name}")
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "parse":
        try:
            if args.output and args.input.resolve() == args.output.resolve():
                raise ValueError("--output must not overwrite the input log file")
            result = ingest_file(
                args.format, args.input, year=args.year, utc_offset=args.utc_offset,
            )
            data = result.to_dict()
            if args.output:
                _write_json(args.output, data)
                summary = data["summary"]
                print(
                    f"Normalized {summary['normalized']} events; "
                    f"skipped {summary['skipped']} unsupported records."
                )
                print(f"Saved normalized JSON: {args.output}")
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        except (OSError, ValueError, ET.ParseError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "detect":
        try:
            _assert_safe_output(args.output, [*args.inputs, args.rules])
            settings = load_detection_config(args.rules)
            events, duplicates = load_normalized_events(args.inputs)
            findings = detect_events(events, settings)
            data = detection_report(events, findings, args.inputs, duplicates, args.rules)
            if args.output:
                _write_json(args.output, data)
                print(
                    f"Analyzed {len(events)} events; generated {len(findings)} findings "
                    f"({duplicates} duplicate events skipped)."
                )
                print(f"Saved findings JSON: {args.output}")
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        except (OSError, ValueError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "correlate":
        try:
            _assert_safe_output(
                args.output, [*args.inputs, args.rules, args.correlation_config]
            )
            data = investigate(
                args.inputs,
                detection_rules=args.rules,
                correlation_rules=args.correlation_config,
            )
            if args.output:
                _write_json(args.output, data)
                summary = data["summary"]
                print(
                    f"Analyzed {summary['events_analyzed']} events and "
                    f"{summary['findings_analyzed']} findings; "
                    f"created {summary['total_incidents']} incidents "
                    f"({summary['correlated_incidents']} correlated, "
                    f"{summary['single_finding_incidents']} single-finding)."
                )
                print(f"Saved incident JSON: {args.output}")
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        except (OSError, ValueError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "timeline":
        try:
            if bool(args.incident_report) == bool(args.inputs):
                raise ValueError(
                    "Provide either normalized input files or --incident-report, not both"
                )
            protected = (
                [args.incident_report] if args.incident_report else
                [*args.inputs, args.rules, args.correlation_config]
            )
            _assert_safe_output(args.output, protected)
            if args.incident_report:
                with args.incident_report.open("r", encoding="utf-8-sig") as stream:
                    original = json.load(stream)
                data = attach_timelines(original)
            else:
                data = investigate_with_timelines(
                    args.inputs,
                    detection_rules=args.rules,
                    correlation_rules=args.correlation_config,
                )
            if args.output:
                _write_json(args.output, data)
                summary = data["timeline_summary"]
                print(
                    f"Generated {summary['total_timelines']} incident timelines "
                    f"containing {summary['total_timeline_entries']} evidence events."
                )
                print(f"Saved timeline JSON: {args.output}")
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "config":
        try:
            snapshot = inspect_configuration(args.rules, args.correlation_config)
            if args.config_action == "show":
                print(json.dumps(snapshot, indent=2, ensure_ascii=False))
            else:
                summary = snapshot["summary"]
                print("Configuration: VALID")
                print(f"Detection rules: {summary['enabled_detection_rules']} enabled; "
                      f"{summary['disabled_detection_rules']} disabled")
                print("Correlation settings: VALID")
            return 0
        except (OSError, ValueError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "doctor":
        try:
            settings = inspect_configuration(args.rules, args.correlation_config)
            data = {
                "tool_version": __version__,
                "python_version": platform.python_version(),
                "python_compatible": sys.version_info >= (3, 13),
                "configuration_valid": settings["summary"]["configuration_valid"],
                "enabled_detection_rules": settings["summary"]["enabled_detection_rules"],
                "mode": "offline-local",
            }
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                print("Security Log Toolkit — Doctor")
                print(f"Python: {data['python_version']}")
                print(f"Tool version: {__version__}")
                print("Detection rules: VALID")
                print("Correlation configuration: VALID")
                print("Network access: Not required")
                print("Result: READY" if data["python_compatible"] else "Result: INCOMPATIBLE")
            return 0 if data["python_compatible"] else 2
        except (OSError, ValueError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    if args.command == "analyze":
        try:
            sources = [
                *(RawLogSource("linux", path) for path in args.linux),
                *(RawLogSource("windows", path) for path in args.windows),
            ]
            if not sources:
                raise ValueError("Specify at least one --linux or --windows source file")
            _assert_safe_output(
                args.output, [*(item.path for item in sources), args.rules, args.correlation_config],
            )
            if args.output and args.output.exists() and not args.force:
                raise ValueError("Output already exists; use --force to replace an existing report")
            data = analyze_raw_logs(
                sources,
                detection_rules=args.rules,
                correlation_rules=args.correlation_config,
                year=args.year,
                utc_offset=args.utc_offset,
            )
            if args.output:
                _write_json(args.output, data)
            if args.output or args.summary:
                ingested = data["raw_log_summary"]
                summary = data["summary"]
                timeline = data["timeline_summary"]
                print(f"Processed {ingested['source_files_processed']} source files; "
                      f"normalized {ingested['normalized_events']} events "
                      f"({ingested['unsupported_records_skipped']} unsupported records skipped).")
                print(f"Detected {summary['findings_analyzed']} findings; "
                      f"created {summary['total_incidents']} incidents and "
                      f"{timeline['total_timelines']} timelines "
                      f"({timeline['total_timeline_entries']} linked evidence events).")
                if args.output:
                    print(f"Saved investigation JSON: {args.output}")
            else:
                print(json.dumps(data, indent=2, ensure_ascii=False))
            return 0
        except (OSError, ValueError, ET.ParseError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
