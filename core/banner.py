"""ASCII banner for EXAMINER (pure ASCII: safe for Windows CMD/PowerShell)."""
from __future__ import annotations

from typing import List

from .constants import APP_AUTHOR, APP_NAME, APP_TAGLINE, APP_VERSION

BANNER_LINES: List[str] = [
    ' _____ __  __    _     __  __  ___  _   _  _____  ____',
    '| ____|\\ \\/ /   / \\   |  \\/  ||_ _|| \\ | || ____||  _ \\',
    '|  _|   \\  /   / _ \\  | |\\/| | | | |  \\| ||  _|  | |_) |',
    '| |___  /  \\  / ___ \\ | |  | | | | | |\\  || |___ |  _ <',
    '|_____|/_/\\_\\/_/   \\_\\|_|  |_||___||_| \\_||_____||_| \\_\\',
]


def banner_width() -> int:
    """Return the width of the widest banner line."""
    return max(len(line) for line in BANNER_LINES)


def show_banner(ui) -> None:
    """Print the startup banner using the given UI object."""
    width = banner_width()
    ui.print()
    for line in BANNER_LINES:
        ui.print(line, style="banner")
    ui.print()
    ui.print(APP_TAGLINE.center(width), style="title")
    ui.print(f"Developed by: {APP_AUTHOR}".center(width), style="accent")
    ui.print(f"Version {APP_VERSION}".center(width), style="muted")
    ui.print()
