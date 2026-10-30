"""Scan orchestration: target resolution, engine selection and execution."""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, List, Optional, Tuple

from core.validator import Target

from .models import ScanCancelled, ScanError, ScanRequest, ScanResult
from .native_scanner import scan_native
from .nmap_scanner import run_nmap


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def resolve_host(target: Target) -> Tuple[str, int]:
    """Return (ip, ip_version) for a validated target, preferring IPv4."""
    if target.kind == "ip":
        ip = ipaddress.ip_address(target.value)
        return str(ip), ip.version
    try:
        infos = socket.getaddrinfo(target.value, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise ScanError(f"Cannot resolve '{target.value}': {exc}") from None
    if not infos:
        raise ScanError(f"'{target.value}' did not resolve to any address.")
    chosen = next((i for i in infos if i[0] == socket.AF_INET), infos[0])
    address = str(chosen[4][0]).split("%")[0]
    return address, ipaddress.ip_address(address).version


@dataclass
class EnginePlan:
    engine: str  # "nmap" | "native"
    os_detection: bool
    notes: List[str]


def choose_engine(preferred: str, protocol: str, want_os: bool,
                  nmap_status, is_admin: bool) -> EnginePlan:
    """Decide which engine runs the scan. Never falls back silently."""
    notes: List[str] = []
    nmap_ok = bool(nmap_status.available)
    udp_needs_admin = protocol == "udp" and not is_admin

    if preferred == "nmap":
        if not nmap_ok:
            raise ScanError(f"Nmap engine selected but Nmap is not available. "
                            f"{nmap_status.detail} {nmap_status.install_hint}".strip())
        if udp_needs_admin:
            raise ScanError("Nmap UDP scans require Administrator/root privileges. "
                            "Restart EXAMINER with elevated privileges or choose the "
                            "native engine (limited UDP support).")
        engine = "nmap"
    elif preferred == "native":
        engine = "native"
    else:  # auto
        if nmap_ok and not udp_needs_admin:
            engine = "nmap"
        else:
            engine = "native"
            if not nmap_ok:
                notes.append("Nmap not found - using the built-in native engine "
                             "(reduced accuracy). " + nmap_status.install_hint)
            else:
                notes.append("UDP via Nmap needs Administrator/root - using the limited "
                             "native UDP probe instead.")

    os_detection = want_os
    if want_os:
        if engine == "native":
            os_detection = False
            notes.append("OS fingerprinting is not supported by the native engine; skipped.")
        elif not is_admin:
            os_detection = False
            notes.append("OS fingerprinting requires Administrator/root privileges; skipped.")
    return EnginePlan(engine, os_detection, notes)


def run_scan(request: ScanRequest, nmap_path: Optional[str],
             advance: Optional[Callable[[int], None]] = None,
             plan_notes: Optional[List[str]] = None) -> ScanResult:
    """Execute a scan with the engine given in ``request.engine``."""
    result = ScanResult(
        target=request.target, ip=request.ip, scan_type=request.scan_type,
        protocol=request.protocol, engine=request.engine,
        ports_requested=len(request.ports), timeout=request.timeout, speed=request.speed,
        service_detection=request.service_detection, os_detection=request.os_detection,
        started=now_iso())
    result.notes.extend(plan_notes or [])
    began = time.monotonic()
    try:
        if request.engine == "nmap":
            if not nmap_path:
                raise ScanError("Nmap path is unknown.")
            run_nmap(nmap_path, request, result)
        else:
            scan_native(request, result, advance=advance)
            if request.protocol == "udp":
                result.notes.append("Native UDP probing is unreliable: 'unknown' means no "
                                    "response (open or filtered). Use Nmap for accuracy.")
            result.notes.append("Native engine guesses service names from port numbers and "
                                "short banners only; it does not perform real version detection.")
    except ScanCancelled:
        result.cancelled = True
    finally:
        result.duration_seconds = round(time.monotonic() - began, 2)
        result.finished = now_iso()
    if result.cancelled:
        result.notes.append("Scan was cancelled; results are partial.")
    return result
