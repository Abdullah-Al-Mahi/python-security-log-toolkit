"""Framework-neutral configuration inspection for CLI and future web UI.

Configuration is read through the same strict validators used by detection
and correlation. The returned dictionaries contain ordinary JSON-safe data.
"""

from dataclasses import asdict
from pathlib import Path

from security_log_toolkit.detection.config import load_detection_config
from security_log_toolkit.correlation.config import load_correlation_config


def inspect_configuration(detection_rules: Path, correlation_rules: Path) -> dict:
    """Validate both YAML documents and return a display-safe snapshot.

    Raises ValueError or OSError if either configuration is invalid or absent.
    No input files are modified.
    """
    detection = load_detection_config(Path(detection_rules))
    correlation = load_correlation_config(Path(correlation_rules))
    rule_data = asdict(detection)
    return {
        "config_version": 1,
        "detection_rules_file": str(detection_rules),
        "correlation_rules_file": str(correlation_rules),
        "detection_rules": rule_data,
        "correlation": asdict(correlation),
        "summary": {
            "total_detection_rules": len(rule_data),
            "enabled_detection_rules": sum(rule["enabled"] for rule in rule_data.values()),
            "disabled_detection_rules": sum(not rule["enabled"] for rule in rule_data.values()),
            "configuration_valid": True,
        },
    }
