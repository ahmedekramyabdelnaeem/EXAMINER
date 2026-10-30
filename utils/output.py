"""Terminal output layer. Uses Rich when available, plain text otherwise."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator, Optional, Sequence, Tuple, Union

from .colors import resolve_style

try:  # Rich is optional: the tool must never crash because it is missing.
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without Rich
    RICH_AVAILABLE = False

Cell = Union[str, Tuple[str, str]]


class UserCancelled(Exception):
    """Raised when input is closed (EOF) and no more answers can be read."""


class UI:
    """Presentation helpers (colors, tables, prompts, progress)."""

    def __init__(self, color: bool = True) -> None:
        self.color = color
        self.console = None
        if RICH_AVAILABLE:
            self.console = Console(
                highlight=False,
                color_system="auto" if color else None,
            )

    # ------------------------------------------------------------ basics
    def clear(self) -> None:
        """Clear the screen when attached to a real terminal."""
        if self.console is not None and self.console.is_terminal:
            self.console.clear()

    def print(self, message: str = "", style: str = "") -> None:
        """Print text literally (no markup interpretation)."""
        if self.console is not None:
            self.console.print(Text(str(message), style=resolve_style(style)))
        else:
            print(message)

    def _tagged(self, tag: str, tag_style: str, message: str) -> None:
        if self.console is not None:
            line = Text()
            line.append(tag + " ", style=resolve_style(tag_style))
            line.append(str(message))
            self.console.print(line)
        else:
            print(f"{tag} {message}")

    def success(self, message: str) -> None:
        self._tagged("[+]", "success", message)

    def error(self, message: str) -> None:
        self._tagged("[-]", "error", message)

    def warning(self, message: str) -> None:
        self._tagged("[!]", "warning", message)

    def info(self, message: str) -> None:
        self._tagged("[*]", "info", message)

    def rule(self, title: str = "") -> None:
        if self.console is not None:
            self.console.rule(Text(title, style=resolve_style("title")))
        else:
            print(f"----- {title} -----")

    def menu_item(self, key: str, label: str) -> None:
        """Render one numbered menu entry such as '[1] Port Scanning'."""
        if self.console is not None:
            line = Text("  [")
            line.append(key, style=resolve_style("key"))
            line.append("] " + label)
            self.console.print(line)
        else:
            print(f"  [{key}] {label}")

    def panel(self, body: str, title: str = "", style: str = "info") -> None:
        if self.console is not None:
            self.console.print(
                Panel(Text(str(body)), title=Text(title) if title else None,
                      border_style=resolve_style(style))
            )
        else:
            print(f"=== {title} ===" if title else "===")
            print(body)
            print("===")

    def table(self, title: str, columns: Sequence[str],
              rows: Sequence[Sequence[Cell]]) -> None:
        """Render a table. A cell may be 'text' or ('text', 'style')."""
        if self.console is None:
            if title:
                print(title)
            print(" | ".join(columns))
            for row in rows:
                print(" | ".join(self._plain(c) for c in row))
            return
        table = Table(title=Text(title) if title else None,
                      header_style=resolve_style("title"))
        for column in columns:
            table.add_column(Text(column))
        for row in rows:
            table.add_row(*[self._cell(c) for c in row])
        self.console.print(table)

    @staticmethod
    def _plain(cell: Cell) -> str:
        return str(cell[0]) if isinstance(cell, tuple) else str(cell)

    @staticmethod
    def _cell(cell: Cell):
        if isinstance(cell, tuple):
            return Text(str(cell[0]), style=resolve_style(cell[1]))
        return Text(str(cell))

    # ------------------------------------------------------------- input
    def _input(self, prompt: str) -> str:
        try:
            if self.console is not None:
                return self.console.input(Text(prompt, style=resolve_style("accent")))
            return input(prompt)
        except EOFError:
            raise UserCancelled() from None

    def ask(self, prompt: str, default: Optional[str] = None) -> str:
        """Ask a question; returns stripped text (or the default if empty)."""
        suffix = f" [{default}]" if default is not None else ""
        answer = self._input(f"{prompt}{suffix}: ").strip()
        if not answer and default is not None:
            return default
        return answer

    def confirm(self, prompt: str, default: bool = False) -> bool:
        """Ask a yes/no question until a valid answer is given."""
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            answer = self.ask(f"{prompt} {hint}").lower()
            if not answer:
                return default
            if answer in ("y", "yes"):
                return True
            if answer in ("n", "no"):
                return False
            self.warning("Please answer 'y' or 'n'.")

    def pause(self, message: str = "Press Enter to continue...") -> None:
        try:
            self._input(f"\n{message}")
        except (KeyboardInterrupt, UserCancelled):
            pass

    # ---------------------------------------------------------- progress
    @contextmanager
    def spinner(self, message: str) -> Iterator[None]:
        """Show a spinner while a long operation runs."""
        if self.console is not None and self.console.is_terminal:
            with self.console.status(Text(message, style=resolve_style("info"))):
                yield
        else:
            self.info(message)
            yield

    @contextmanager
    def progress(self, description: str, total: int) -> Iterator[Callable[[int], None]]:
        """Progress bar context manager yielding an ``advance(n=1)`` callable."""
        if self.console is not None and self.console.is_terminal:
            from rich.progress import (BarColumn, Progress, TaskProgressColumn,
                                       TextColumn, TimeElapsedColumn)
            with Progress(TextColumn("{task.description}"), BarColumn(),
                          TaskProgressColumn(), TimeElapsedColumn(),
                          console=self.console, transient=True) as bar:
                task = bar.add_task(escape(description), total=total)
                yield lambda step=1: bar.advance(task, step)
        else:
            self.info(description)
            yield lambda step=1: None
