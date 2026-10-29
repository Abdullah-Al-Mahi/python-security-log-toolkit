"""Bounded synthetic in-memory throughput benchmark for investigation services.

Timings depend on machine load and hardware, and do not include raw-file I/O.
"""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from time import perf_counter

from security_log_toolkit.correlation.service import investigate_events
from security_log_toolkit.events import SecurityEvent
from security_log_toolkit.detection.config import load_detection_config
from security_log_toolkit.correlation.config import load_correlation_config


def generate_benchmark_events(count: int) -> list[SecurityEvent]:
    """Create deterministic, offline-only data, without touching real logs."""
    if type(count) is not int or not 100 <= count <= 5_000:
        raise ValueError("Benchmark --events must be between 100 and 5000")
    origin = datetime(2026, 1, 1, tzinfo=timezone.utc)
    items: list[SecurityEvent] = []
    for index in range(count):
        group, within = divmod(index, 20)
        items.append(SecurityEvent(
            timestamp=origin + timedelta(seconds=index),
            platform="linux",
            event_type="login_success" if within == 19 else "login_failure",
            hostname="synthetic-benchmark-host",
            username=f"bench_account_{within % 7}",
            source_ip=f"198.51.100.{group % 250 + 1}",
            source_port=40000 + within,
            authentication_method="password",
            event_id="sshd",
            record_id=None,
            source_file="synthetic-benchmark-no-real-logs",
            source_line=index + 1,
        ))
    return items


def run_benchmark(
    *, event_count: int, runs: int, detection_rules: Path, correlation_rules: Path,
) -> dict:
    """Measure shared in-memory detection + correlation + serialization.

    Does not measure source parsing, CSV disk writing, or production workloads.
    """
    if type(runs) is not int or not 2 <= runs <= 10:
        raise ValueError("Benchmark --runs must be between 2 and 10")
    events = generate_benchmark_events(event_count)
    dconf = load_detection_config(detection_rules)
    cconf = load_correlation_config(correlation_rules)
    timings_ms: list[float] = []
    sample_summary: dict | None = None
    for _ in range(runs):
        start = perf_counter()
        result = investigate_events(
            events,
            input_files=[],
            detection_rules=detection_rules,
            correlation_rules=correlation_rules,
            detection_config=dconf,
            correlation_config=cconf,
        )
        timings_ms.append((perf_counter() - start) * 1000)
        sample_summary = result["summary"]
    sorted_ms = sorted(timings_ms)
    p95_index = (95 * len(sorted_ms) + 99) // 100 - 1  # nearest-rank p95
    p50 = median(sorted_ms)
    return {
        "assessment": "synthetic_in_memory_benchmark",
        "limitations": (
            "In-memory event detection/correlation/serialization only, excluding raw parsing, "
            "disk I/O and CSV generation. Host-dependent measurement; not a performance guarantee."
        ),
        "event_count": event_count,
        "runs": runs,
        "median_ms": round(p50, 3),
        "p95_ms": round(sorted_ms[p95_index], 3),
        "min_ms": round(sorted_ms[0], 3),
        "max_ms": round(sorted_ms[-1], 3),
        "median_events_per_second": round(event_count / (p50 / 1000), 1) if p50 > 0 else None,
        "sample_findings": sample_summary["findings_analyzed"],
        "sample_incidents": sample_summary["total_incidents"],
    }
