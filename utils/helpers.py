"""Small, dependency-free helper functions."""
from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path


def project_root() -> Path:
    """Return the absolute path of the project root directory."""
    return Path(__file__).resolve().parent.parent


def is_windows() -> bool:
    """True when running on Windows."""
    return os.name == "nt"


def now_iso() -> str:
    """Current local time as an ISO-8601 string (seconds precision)."""
    return datetime.now().replace(microsecond=0).isoformat()


def configure_stdio() -> None:
    """Make stdout/stderr tolerant to characters the console cannot encode."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass
