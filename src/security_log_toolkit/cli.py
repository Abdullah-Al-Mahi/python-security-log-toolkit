
"""Command-line interface for the Security Log Toolkit."""

import argparse
import sys

from security_log_toolkit import __version__


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="security-log",
        description=(
            "Offline Python toolkit for security log analysis, "
            "event correlation, and incident investigation."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="available commands",
    )

    subparsers.add_parser(
        "status",
        help="Display toolkit installation status.",
        description="Check the current toolkit milestone.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the command-line interface."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "status":
        print("Security Log Toolkit")
        print("--------------------")
        print(f"Version: {__version__}")
        print("Installation: OK")
        print("Current milestone: Phase 1")
        print("Log parsing: Not implemented")
        print("Detection engine: Not implemented")
        print("Event correlation: Not implemented")
        print("Reporting: Not implemented")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
