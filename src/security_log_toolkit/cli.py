"""Command-line interface for the Security Log Toolkit."""

import argparse
import json
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

from security_log_toolkit import __version__
from security_log_toolkit.ingest import ingest_file


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI parser, preserving Phase 1 commands."""
    parser = argparse.ArgumentParser(
        prog="security-log",
        description=(
            "Offline Python toolkit for security log analysis, "
            "event correlation, and incident investigation."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command", title="available commands")
    commands.add_parser("status", help="Display toolkit implementation status.")

    parse = commands.add_parser("parse", help="Normalize an offline authentication log file.")
    parse.add_argument("format", choices=("linux", "windows"))
    parse.add_argument("input", type=Path, help="Path to the offline log file")
    parse.add_argument(
        "--year", type=int, help="Required for Linux syslog (which omits the year)"
    )
    parse.add_argument(
        "--utc-offset", default="+00:00",
        help="Linux syslog timezone offset, e.g. +08:00 (default: +00:00)",
    )
    parse.add_argument(
        "--output", type=Path, help="Optional destination for normalized JSON"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        print("Security Log Toolkit")
        print("--------------------")
        print(f"Version: {__version__}")
        print("Installation: OK")
        print("Current milestone: Phase 2")
        print("Log parsing: Linux SSH and Windows XML available")
        print("Normalization: Available")
        print("Detection engine: Not implemented")
        print("Event correlation: Not implemented")
        print("Investigation reporting: Not implemented")
        return 0

    if args.command == "parse":
        try:
            if args.output and args.input.resolve() == args.output.resolve():
                raise ValueError("--output must not overwrite the input log file")
            result = ingest_file(
                args.format,
                args.input,
                year=args.year,
                utc_offset=args.utc_offset,
            )
            payload = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(payload + "\n", encoding="utf-8")
                summary = result.to_dict()["summary"]
                print(
                    f"Normalized {summary['normalized']} events; "
                    f"skipped {summary['skipped']} unsupported records."
                )
                print(f"Saved normalized JSON: {args.output}")
            else:
                print(payload)
            return 0
        except (OSError, ValueError, ET.ParseError) as exc:
            print(f"security-log: error: {exc}", file=sys.stderr)
            return 2

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
