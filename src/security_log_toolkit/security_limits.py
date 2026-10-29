"""Conservative offline input bounds shared by CLI and backend services.

These protect the beginner-friendly local workflow against accidental huge inputs,
not against every form of resource exhaustion or a hostile multi-user server.
"""
from pathlib import Path

MAX_RAW_LOG_BYTES = 16 * 1024 * 1024
MAX_NORMALIZED_JSON_BYTES = 32 * 1024 * 1024
MAX_INVESTIGATION_JSON_BYTES = 50 * 1024 * 1024
MAX_LINUX_LINE_CHARS = 65_536


def require_bounded_file(path: Path, maximum: int, label: str) -> int:
    """Reject missing, nonregular, or oversized input before reading content."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {path}")
    size = path.stat().st_size
    if size > maximum:
        raise ValueError(f"{label} exceeds {maximum // (1024 * 1024)} MiB input limit: {path}")
    return size
