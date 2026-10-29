"""Command-line interface for parsing, detection, correlation and timelines."""

import argparse
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from security_log_toolkit import __version__
from security_log_toolkit.correlation import investigate
from security_log_toolkit.detection import (
    detect_events,
    detection_report,
    load_detection_config,
    load_normalized_events,
)
from security_log_toolkit.ingest import ingest_file
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
        print("Current milestone: Phase 5")
        print("Log parsing: Linux SSH and Windows XML available")
        print("Normalization: Available")
        print("Detection engine: 3 configurable rules available")
        print("Event correlation: Incident grouping available")
        print("Investigation timelines: Evidence-linked chronological timelines available")
        print("Reporting: Investigation JSON available; CSV exports planned Phase 7")
        return 0

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

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
