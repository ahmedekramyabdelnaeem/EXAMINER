"""Application engine: wires config, UI, logging, dependencies and menus."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from utils.output import RICH_AVAILABLE, UI

from .banner import show_banner
from .config import ConfigManager
from .constants import APP_NAME, APP_VERSION
from .dependency_manager import ComponentStatus, DependencyManager
from .logger import file_logging_active, setup_logging
from .menu import Menu, MenuItem
from modules.information_gathering.module import InformationGatheringModule
from modules.port_scanner import PortScannerModule


class Engine:
    """Central application object shared by all modules."""

    def __init__(self, root: Path, no_color: bool = False,
                 config_path: Optional[Path] = None) -> None:
        self.root = Path(root)
        self.config = ConfigManager(config_path or self.root / "config" / "settings.json",
                                    self.root)
        self.startup_warnings: List[str] = list(self.config.load())
        color = (bool(self.config.get("colors_enabled")) and not no_color
                 and "NO_COLOR" not in os.environ)
        self.ui = UI(color=color)
        if not RICH_AVAILABLE:
            self.startup_warnings.append(
                "The 'rich' package is not installed; running in basic text mode. "
                "Install it with: python -m pip install rich")
        self.logger = self._init_logging()
        self.deps = DependencyManager(self.config)
        self.logger.info("%s v%s starting on %s", APP_NAME, APP_VERSION,
                         self.deps.system.os_name)

    # ---------------------------------------------------------- setup
    def _init_logging(self) -> logging.Logger:
        try:
            log_dir: Optional[Path] = self.config.subdir("logs")
        except OSError as exc:
            log_dir = None
            self.startup_warnings.append(f"File logging disabled (cannot create log directory: {exc}).")
        logger = setup_logging(log_dir, bool(self.config.get("logging_enabled")),
                               str(self.config.get("log_level")))
        return logger

    # ---------------------------------------------------- shared services
    def confirm_scope(self, target: str, active: bool = True) -> bool:
        """Ask the user to explicitly confirm authorization for ``target``."""
        kind = "ACTIVE scan" if active else "information gathering"
        self.ui.panel(
            f"You are about to run an {kind} against: {target}\n\n"
            "Only continue if you own this target or have explicit written "
            "permission to test it. Unauthorized scanning may be illegal.",
            title="Authorization Required", style="warning")
        answer = self.ui.ask("Type 'yes' to confirm you are authorized")
        confirmed = answer.strip().lower() == "yes"
        self.logger.info("Scope confirmation for %s (%s): %s", target, kind,
                         "confirmed" if confirmed else "declined")
        if not confirmed:
            self.ui.warning("Scope not confirmed. Operation aborted.")
        return confirmed

    # ------------------------------------------------------------ views
    def show_dependencies(self) -> None:
        """Display system information and dependency status."""
        ui, system = self.ui, self.deps.system
        distro = f" ({system.distro})" if system.distro else ""
        ui.panel(
            f"OS:         {system.os_name} {system.os_release}{distro}\n"
            f"Machine:    {system.machine}\n"
            f"Python:     {system.python_version}\n"
            f"Privileges: {self.deps.privilege_note()}",
            title="System", style="info")
        with ui.spinner("Checking dependencies..."):
            components = self.deps.check_all()
        rows = []
        for comp in components:
            status = ("OK", "success") if comp.available else ("MISSING", "warning")
            details = comp.path or comp.detail
            if comp.path and comp.detail:
                details = f"{comp.path} - {comp.detail}"
            rows.append([comp.name, status, comp.version or "-", details or "-"])
        ui.table("Dependencies", ["Component", "Status", "Version", "Details"], rows)
        missing = [c for c in components if not c.available]
        if missing:
            ui.print()
            ui.warning("Some optional components are missing. How to install them:")
            for comp in missing:
                ui.print(f"  {comp.name}: {comp.install_hint}")
        else:
            ui.success("All components are available.")

    def print_dependency_report(self) -> int:
        self.show_dependencies()
        return 0

    # ------------------------------------------------------------- menus
    def _stub_menu(self, title: str, stage: str, entries: Sequence[str]) -> Callable[[], None]:
        """Numbered submenu for a module that is not implemented yet (no fake results)."""
        def not_ready(name: str) -> Callable[[], None]:
            def handler() -> None:
                self.ui.warning(f"'{name}' is not implemented yet (planned for {stage}).")
            return handler

        def open_menu() -> None:
            items = [MenuItem(str(i), name, not_ready(name))
                     for i, name in enumerate(entries, start=1)]
            Menu(self.ui, title, items, exit_label="Back to Main Menu",
                 logger=self.logger).run()
        return open_menu

    def _port_scanning(self) -> None:
        PortScannerModule(self).menu()

    def _information_gathering(self) -> None:
        InformationGatheringModule(self).menu()

    def _build_main_menu(self) -> Menu:
        items = [
            MenuItem("1", "Port Scanning", self._port_scanning, submenu=True),
            MenuItem("2", "Information Gathering", self._information_gathering, submenu=True),
            MenuItem("3", "Vulnerability Assessment", self._stub_menu(
                "Vulnerability Assessment", "Stage 5", [
                    "Outdated Service Versions / CVE Indicators", "HTTP Security Headers Check",
                    "Exposed Services Check", "Basic Misconfiguration Check"]), submenu=True),
            MenuItem("4", "Network Discovery", self._stub_menu(
                "Network Discovery", "Stage 5", [
                    "Discover Active Hosts", "Show Network Information"]), submenu=True),
        ]
        return Menu(self.ui, "Main Menu", items, exit_label="Exit",
                    header=lambda: show_banner(self.ui), logger=self.logger)

    # --------------------------------------------------------------- run
    def run(self) -> int:
        if self.startup_warnings:
            for warning in self.startup_warnings:
                self.ui.warning(warning)
                self.logger.warning(warning)
            self.ui.pause()
        self._build_main_menu().run()
        self.ui.print()
        self.ui.info("Thank you for using EXAMINER. Stay ethical. Goodbye!")
        self.logger.info("EXAMINER exited normally")
        return 0
