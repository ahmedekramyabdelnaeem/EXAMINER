"""Interactive Port Scanning module (menus and workflow)."""
from __future__ import annotations

import math
from typing import Callable, List, Optional, Tuple

from core.menu import Menu, MenuItem
from core.validator import (ValidationError, parse_ports, validate_choice,
                            validate_target, validate_timeout)

from .models import ScanError, ScanRequest
from .native_scanner import worker_count
from .results import render_result
from .scanner import choose_engine, resolve_host, run_scan
from .services import COMMON_TCP_PORTS, COMMON_UDP_PORTS

SPEEDS = ("slow", "normal", "fast")
ENGINES = ("auto", "nmap", "native")


class PortScannerModule:
    """Port scanning menus. Options changed here apply to the current session."""

    def __init__(self, engine) -> None:
        self.app = engine
        self.ui = engine.ui
        cfg = engine.config
        self.timeout: float = float(cfg.get("default_timeout"))
        self.speed: str = str(cfg.get("default_speed"))
        self.engine_pref: str = str(cfg.get("preferred_engine"))
        self.service_detection: bool = True
        self.os_detection: bool = False

    # ------------------------------------------------------------ menus
    def menu(self) -> None:
        Menu(self.ui, "Port Scanning", [
            MenuItem("1", f"Quick TCP Scan  (~{len(COMMON_TCP_PORTS)} common ports)",
                     lambda: self.scan("quick")),
            MenuItem("2", "Full TCP Scan   (all 65535 ports - slow)", lambda: self.scan("full")),
            MenuItem("3", f"UDP Scan        (~{len(COMMON_UDP_PORTS)} common UDP ports)",
                     lambda: self.scan("udp")),
            MenuItem("4", "Custom Scan     (choose ports and protocol)", lambda: self.scan("custom")),
            MenuItem("5", "Scan Options    (timeout, speed, engine, detection)",
                     self.options_menu, submenu=True),
        ], exit_label="Back to Main Menu", header=self._header,
            logger=self.app.logger).run()

    def _header(self) -> None:
        self.ui.print()
        self.ui.print(
            f"Options: engine={self.engine_pref}  timeout={self.timeout}s  "
            f"speed={self.speed}  service-detection={'on' if self.service_detection else 'off'}  "
            f"os-detection={'on' if self.os_detection else 'off'}", style="muted")

    def options_menu(self) -> None:
        Menu(self.ui, "Scan Options (this session)", [
            MenuItem("1", "Set timeout (seconds per probe)", self._set_timeout),
            MenuItem("2", "Set scan speed (slow / normal / fast)", self._set_speed),
            MenuItem("3", "Set scanning engine (auto / nmap / native)", self._set_engine),
            MenuItem("4", "Toggle service/version detection", self._toggle_service),
            MenuItem("5", "Toggle OS fingerprinting (Nmap + admin/root)", self._toggle_os),
        ], exit_label="Back", header=self._header, logger=self.app.logger).run()

    def _set_timeout(self) -> None:
        raw = self.ui.ask("Timeout in seconds (0.1 - 300)", default=str(self.timeout))
        try:
            self.timeout = validate_timeout(raw)
            self.ui.success(f"Timeout set to {self.timeout}s")
        except ValidationError as exc:
            self.ui.error(str(exc))

    def _set_speed(self) -> None:
        raw = self.ui.ask(f"Speed ({'/'.join(SPEEDS)})", default=self.speed)
        try:
            self.speed = validate_choice(raw, SPEEDS, "speed")
            self.ui.success(f"Speed set to {self.speed}")
        except ValidationError as exc:
            self.ui.error(str(exc))

    def _set_engine(self) -> None:
        raw = self.ui.ask(f"Engine ({'/'.join(ENGINES)})", default=self.engine_pref)
        try:
            self.engine_pref = validate_choice(raw, ENGINES, "engine")
            self.ui.success(f"Engine set to {self.engine_pref}")
        except ValidationError as exc:
            self.ui.error(str(exc))

    def _toggle_service(self) -> None:
        self.service_detection = not self.service_detection
        self.ui.success(f"Service detection {'enabled' if self.service_detection else 'disabled'}")

    def _toggle_os(self) -> None:
        self.os_detection = not self.os_detection
        self.ui.success(f"OS fingerprinting {'enabled' if self.os_detection else 'disabled'}")
        if self.os_detection and not self.app.deps.system.is_admin:
            self.ui.warning("You are not running with Administrator/root privileges; "
                            "OS fingerprinting will be skipped.")

    # ---------------------------------------------------------- prompts
    def _ask_until_valid(self, prompt: str, parse: Callable[[str], object],
                         default: Optional[str] = None):
        """Ask until valid. Blank input (without default) cancels and returns None."""
        while True:
            raw = self.ui.ask(prompt, default=default)
            if not raw:
                return None
            try:
                return parse(raw)
            except ValidationError as exc:
                self.ui.error(str(exc))

    def _choose_ports(self, scan_type: str) -> Optional[Tuple[List[int], str]]:
        """Return (ports, protocol) for the scan type, or None if cancelled."""
        if scan_type == "quick":
            return list(COMMON_TCP_PORTS), "tcp"
        if scan_type == "full":
            return list(range(1, 65536)), "tcp"
        if scan_type == "udp":
            raw = self.ui.ask("UDP ports (Enter = common UDP ports)", default="")
            if not raw:
                return list(COMMON_UDP_PORTS), "udp"
            try:
                return parse_ports(raw), "udp"
            except ValidationError as exc:
                self.ui.error(str(exc))
                return None
        ports = self._ask_until_valid("Ports (e.g. 22,80,443 or 1-1024; blank to cancel)", parse_ports)
        if ports is None:
            return None
        protocol = self._ask_until_valid("Protocol (tcp/udp)",
                                         lambda v: validate_choice(v, ("tcp", "udp"), "protocol"),
                                         default="tcp")
        if protocol is None:
            return None
        return ports, protocol  # type: ignore[return-value]

    # ------------------------------------------------------------- scan
    def scan(self, scan_type: str) -> None:
        ui = self.ui
        target = self._ask_until_valid("Target IP or hostname (blank to cancel)", validate_target)
        if target is None:
            ui.warning("Cancelled.")
            return
        try:
            ip, version = resolve_host(target)
        except ScanError as exc:
            ui.error(str(exc))
            return
        if ip != target.value:
            ui.info(f"{target.value} resolved to {ip}")

        chosen = self._choose_ports(scan_type)
        if chosen is None:
            ui.warning("Cancelled.")
            return
        ports, protocol = chosen

        nmap_status = self.app.deps.check_nmap()
        try:
            plan = choose_engine(self.engine_pref, protocol, self.os_detection,
                                 nmap_status, self.app.deps.system.is_admin)
        except ScanError as exc:
            ui.error(str(exc))
            return

        request = ScanRequest(
            target=target.value, ip=ip, ip_version=version, scan_type=scan_type,
            protocol=protocol, ports=ports, timeout=self.timeout, speed=self.speed,
            service_detection=self.service_detection, os_detection=plan.os_detection,
            engine=plan.engine)

        lines = [f"Target:   {target.value} ({ip})",
                 f"Scan:     {scan_type.upper()} / {protocol.upper()}, {len(ports)} ports",
                 f"Engine:   {plan.engine}   Timeout: {self.timeout}s   Speed: {self.speed}"]
        if plan.engine == "native" and len(ports) >= 1000:
            workers = worker_count(self.speed, protocol, len(ports))
            worst = math.ceil(len(ports) / workers) * self.timeout
            lines.append(f"Worst case duration (every port filtered): ~{int(worst)}s")
        elif len(ports) > 20000:
            lines.append("A full scan can take a long time. Press Ctrl+C to cancel.")
        ui.panel("\n".join(lines), title="Scan Plan", style="info")
        for note in plan.notes:
            ui.warning(note)

        if not self.app.confirm_scope(f"{target.value} ({ip})", active=True):
            return

        self.app.logger.info("Starting %s/%s scan of %s (%s) with %s engine, %d ports",
                             scan_type, protocol, target.value, ip, plan.engine, len(ports))
        ui.info("Scanning... press Ctrl+C to cancel.")
        try:
            if plan.engine == "nmap":
                with ui.spinner("Running Nmap..."):
                    result = run_scan(request, nmap_status.path, plan_notes=plan.notes)
            else:
                with ui.progress("Scanning ports", total=len(ports)) as advance:
                    result = run_scan(request, None, advance=advance, plan_notes=plan.notes)
        except ScanError as exc:
            ui.error(str(exc))
            self.app.logger.error("Scan failed: %s", exc)
            return

        ui.print()
        render_result(ui, result)
        self.app.logger.info("Scan finished: %s open ports, %ss%s", len(result.open_ports()),
                             result.duration_seconds, " (cancelled)" if result.cancelled else "")
