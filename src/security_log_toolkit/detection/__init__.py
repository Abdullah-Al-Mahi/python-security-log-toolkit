"""Rule configuration and offline authentication-pattern detection."""

from security_log_toolkit.detection.config import load_detection_config
from security_log_toolkit.detection.engine import (
    detect_events,
    detection_report,
    load_normalized_events,
)

__all__ = ["load_detection_config", "detect_events", "detection_report", "load_normalized_events"]
