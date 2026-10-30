"""Style definitions shared by the UI layer (Rich style strings)."""
from __future__ import annotations

STYLES = {
    "success": "bold green",
    "error": "bold red",
    "warning": "bold yellow",
    "info": "cyan",
    "muted": "dim",
    "title": "bold cyan",
    "accent": "bold magenta",
    "key": "bold yellow",
    "banner": "bold cyan",
}

PORT_STATE_STYLES = {
    "open": "bold green",
    "closed": "red",
    "filtered": "yellow",
    "unknown": "dim",
}


def resolve_style(name: str) -> str:
    """Return the Rich style for a semantic name (or the name itself)."""
    return STYLES.get(name, name)
