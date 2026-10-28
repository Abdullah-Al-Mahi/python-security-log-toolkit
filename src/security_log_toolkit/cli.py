"""Command-line interface: existing parsing plus offline security detection."""

import argparse
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from security_log_toolkit import __version__
from security_log_toolkit.detection import (
    detect_events,
    detection_report,
    load_detection_config,
    load_normalized_events,
)
from security_log_toolkit.ingest import ingest_file


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser, retaining Phase 1 and Phase 2 arguments."""
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
    return parser


def _write_json(output: Path, data: dict) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return an exit code without hiding actionable errors."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        print("Security Log Toolkit")
        print("--------------------")
        print(f"Version: {__version__}")
        print("Installation: OK")
        print("Current milestone: Phase 3")
        print("Log parsing: Linux SSH and Windows XML available")
        print("Normalization: Available")
        print("Detection engine: 3 configurable rules available")
        print("Event correlation: Not implemented")
        print("Investigation reporting: Not implemented")
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
            protected = [*args.inputs, args.rules]
            if args.output and any(args.output.resolve() == file.resolve() for file in protected):
                raise ValueError("--output must not overwrite input files or the YAML rules file")
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

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
