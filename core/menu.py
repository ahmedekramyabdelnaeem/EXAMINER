"""Generic, crash-proof menu system."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from utils.output import UserCancelled


@dataclass
class MenuItem:
    """One selectable menu entry."""

    key: str
    label: str
    handler: Optional[Callable[[], None]] = None
    submenu: bool = False  # submenus manage their own screen; no "press Enter"


class Menu:
    """Interactive menu that survives invalid input, Ctrl+C, EOF and handler errors."""

    def __init__(self, ui, title: str, items: List[MenuItem], *,
                 exit_key: str = "0", exit_label: str = "Back",
                 header: Optional[Callable[[], None]] = None,
                 logger: Optional[logging.Logger] = None) -> None:
        self.ui = ui
        self.title = title
        self.items = list(items)
        self.exit_key = exit_key
        self.exit_label = exit_label
        self.header = header
        self.logger = logger or logging.getLogger("examiner.menu")
        self._index: Dict[str, MenuItem] = {}
        for item in self.items:
            key = item.key.strip().lower()
            if key == exit_key.lower() or key in self._index:
                raise ValueError(f"Duplicate menu key: {item.key}")
            self._index[key] = item

    def _render(self) -> None:
        self.ui.clear()
        if self.header is not None:
            self.header()
        self.ui.rule(self.title)
        for item in self.items:
            self.ui.menu_item(item.key, item.label)
        self.ui.menu_item(self.exit_key, self.exit_label)
        self.ui.print()

    def run(self) -> None:
        """Run the menu loop until the user goes back/exits."""
        needs_render = True
        while True:
            if needs_render:
                self._render()
            try:
                choice = self.ui.ask("Select an option").strip().lower()
            except (UserCancelled, KeyboardInterrupt):
                self.ui.print()
                return
            if choice == self.exit_key.lower():
                return
            if not choice:
                self.ui.warning("No option entered. Please type a number from the menu.")
                needs_render = False
                continue
            item = self._index.get(choice)
            if item is None:
                valid = ", ".join([i.key for i in self.items] + [self.exit_key])
                self.ui.error(f"Invalid option '{choice}'. Valid options: {valid}")
                needs_render = False
                continue
            self._execute(item)
            needs_render = True

    def _execute(self, item: MenuItem) -> None:
        if item.handler is None:
            self.ui.warning(f"'{item.label}' is not available.")
        else:
            try:
                item.handler()
            except (KeyboardInterrupt, UserCancelled):
                self.ui.print()
                self.ui.warning("Operation cancelled.")
            except Exception as exc:  # noqa: BLE001 - the UI must never crash
                self.logger.exception("Unhandled error in menu item '%s'", item.label)
                self.ui.error(f"Unexpected error in '{item.label}': {exc}")
        if not item.submenu:
            self.ui.pause()
