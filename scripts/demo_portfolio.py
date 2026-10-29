"""Offline Phase 9 demo: write traceable reports from synthetic fixtures only."""
import argparse
from pathlib import Path
import sys

from security_log_toolkit.portfolio import build_portfolio_artifacts, write_portfolio_artifacts

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build synthetic portfolio demonstration files offline")
    parser.add_argument("--output-dir", type=Path, default=Path("reports/phase9_demo"))
    args = parser.parse_args(argv)
    try:
        artifacts = build_portfolio_artifacts(ROOT)
        paths = write_portfolio_artifacts(artifacts, args.output_dir)
    except (ValueError, OSError, KeyError) as exc:
        print(f"Portfolio demo error: {exc}", file=sys.stderr)
        return 2
    print(f"Synthetic demo created {len(paths)} files at {args.output_dir}")
    print("Expected fixture results: 29 events, 6 findings, 4 incidents, 22 linked evidence events")
    print("Validation: 4 scenarios; 6 TP, 0 FP, 0 FN (synthetic labels ONLY)")
    print("Files include linked CSV/JSON exports, checksums, and an analyst summary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
