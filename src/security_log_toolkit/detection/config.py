"""Validated, YAML-configured detection rules (no arbitrary code execution)."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


RULE_FIELDS = {
    "brute_force": frozenset({"enabled", "severity", "window_minutes", "min_failures"}),
    "password_spray": frozenset({
        "enabled", "severity", "window_minutes", "min_failures", "min_distinct_accounts"
    }),
    "success_after_failures": frozenset({
        "enabled", "severity", "window_minutes", "min_failures"
    }),
}
SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True, slots=True)
class RuleSettings:
    enabled: bool
    severity: str
    window_minutes: int
    min_failures: int
    min_distinct_accounts: int = 0


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    brute_force: RuleSettings
    password_spray: RuleSettings
    success_after_failures: RuleSettings


def _positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _load_one(name: str, data: Any) -> RuleSettings:
    if not isinstance(data, dict):
        raise ValueError(f"rules.{name} must be a mapping")
    expected = RULE_FIELDS[name]
    extra = set(data) - expected
    missing = expected - set(data)
    if extra:
        raise ValueError(f"rules.{name} has unknown settings: {', '.join(sorted(map(str, extra)))}")
    if missing:
        raise ValueError(f"rules.{name} is missing: {', '.join(sorted(missing))}")
    if type(data["enabled"]) is not bool:
        raise ValueError(f"rules.{name}.enabled must be true or false")
    severity = data["severity"]
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ValueError(f"rules.{name}.severity must be low, medium, high, or critical")
    window = _positive_int(data["window_minutes"], f"rules.{name}.window_minutes")
    failures = _positive_int(data["min_failures"], f"rules.{name}.min_failures")
    distinct = (
        _positive_int(data["min_distinct_accounts"], f"rules.{name}.min_distinct_accounts")
        if name == "password_spray" else 0
    )
    return RuleSettings(data["enabled"], severity, window, failures, distinct)


def load_detection_config(path: Path) -> DetectionConfig:
    """Load only basic YAML types; reject ambiguous or incomplete rule definitions."""
    try:
        content = path.read_text(encoding="utf-8-sig")
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML configuration in {path}: {exc}") from exc

    if not isinstance(data, dict) or set(data) != {"version", "rules"}:
        raise ValueError("Configuration must contain exactly 'version' and 'rules'")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("Only detection configuration version 1 is supported")
    rules = data["rules"]
    if not isinstance(rules, dict) or set(rules) != set(RULE_FIELDS):
        raise ValueError("Configuration must define brute_force, password_spray, and success_after_failures")
    return DetectionConfig(**{
        name: _load_one(name, rules[name]) for name in RULE_FIELDS
    })
