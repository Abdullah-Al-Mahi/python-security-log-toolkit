"""Strict, safe YAML configuration for incident correlation."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    """Maximum inactivity gap and total span used to group related findings."""

    max_gap_minutes: int
    max_incident_minutes: int


def _positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def load_correlation_config(path: Path) -> CorrelationConfig:
    """Parse a versioned YAML configuration, rejecting unexpected fields."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML configuration in {path}: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"version", "correlation"}:
        raise ValueError("Correlation configuration must contain exactly 'version' and 'correlation'")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("Only correlation configuration version 1 is supported")
    options = data["correlation"]
    required = {"max_gap_minutes", "max_incident_minutes"}
    if not isinstance(options, dict) or set(options) != required:
        raise ValueError("correlation must contain exactly max_gap_minutes and max_incident_minutes")
    return CorrelationConfig(
        max_gap_minutes=_positive_integer(options["max_gap_minutes"], "correlation.max_gap_minutes"),
        max_incident_minutes=_positive_integer(options["max_incident_minutes"], "correlation.max_incident_minutes"),
    )
