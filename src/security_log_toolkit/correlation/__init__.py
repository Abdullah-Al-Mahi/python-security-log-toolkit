"""Incident grouping, configuration, and framework-independent investigation API."""

from security_log_toolkit.correlation.config import (
    CorrelationConfig, load_correlation_config,
)
from security_log_toolkit.correlation.engine import Incident, correlate_findings
from security_log_toolkit.correlation.service import investigate

__all__ = [
    "CorrelationConfig", "load_correlation_config", "Incident",
    "correlate_findings", "investigate",
]
