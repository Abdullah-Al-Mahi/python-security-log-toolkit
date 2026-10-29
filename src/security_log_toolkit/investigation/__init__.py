"""Evidence-linked incident timelines shared by CLI and future local web dashboard."""

from security_log_toolkit.investigation.service import attach_timelines, investigate_with_timelines
from security_log_toolkit.investigation.timeline import build_incident_timeline

__all__ = ["attach_timelines", "investigate_with_timelines", "build_incident_timeline"]
