"""Nmap integration: command building, execution and XML parsing."""
from __future__ import annotations

import os
import shlex
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from core.validator import ports_to_spec

from .models import (STATE_CLOSED, STATE_FILTERED, STATE_OPEN, STATE_UNKNOWN,
                     PortResult, ScanCancelled, ScanError, ScanRequest, ScanResult)

TIMING = {"slow": "-T2", "normal": "-T3", "fast": "-T4"}
_STATE_MAP = {"open": STATE_OPEN, "closed": STATE_CLOSED, "filtered": STATE_FILTERED}


def build_command(nmap_path: str, request: ScanRequest) -> List[str]:
    """Build the Nmap argument list (never passed through a shell)."""
    cmd = [
        nmap_path, "-oX", "-", "-n", "-Pn", TIMING.get(request.speed, "-T3"),
        "--max-retries", "2",
        "--max-rtt-timeout", f"{max(100, int(request.timeout * 1000))}ms",
    ]
    if request.protocol == "udp":
        cmd.append("-sU")
    cmd += ["-p", ports_to_spec(request.ports)]
    if request.service_detection:
        cmd.append("-sV")
    if request.os_detection:
        cmd.append("-O")
    if request.ip_version == 6:
        cmd.append("-6")
    cmd.append(request.ip)
    return cmd


def _normalize_state(raw: str) -> str:
    return _STATE_MAP.get(raw, STATE_UNKNOWN)


def parse_xml(xml_text: str, result: ScanResult) -> None:
    """Parse Nmap XML output into ``result``. Raises ScanError on malformed XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError(f"Could not parse Nmap output: {exc}") from None
    if root.tag != "nmaprun":
        raise ScanError("Unexpected Nmap output format.")

    host = root.find("host")
    if host is None:
        result.host_up = None
        result.notes.append("Nmap reported no host results.")
        return
    status = host.find("status")
    if status is not None:
        result.host_up = status.get("state") == "up"
    name = host.find("hostnames/hostname")
    if name is not None:
        result.hostname = name.get("name", "")

    for elem in host.findall("ports/extraports"):
        try:
            count = int(elem.get("count", "0"))
        except ValueError:
            continue
        state = _normalize_state(elem.get("state", ""))
        result.extra_counts[state] = result.extra_counts.get(state, 0) + count

    for elem in host.findall("ports/port"):
        try:
            number = int(elem.get("portid", ""))
        except ValueError:
            continue
        state_elem = elem.find("state")
        raw_state = state_elem.get("state", "") if state_elem is not None else ""
        reason = state_elem.get("reason", "") if state_elem is not None else ""
        state = _normalize_state(raw_state)
        if state == STATE_UNKNOWN and raw_state:
            reason = f"{raw_state} ({reason})" if reason else raw_state
        service = version = ""
        svc = elem.find("service")
        if svc is not None:
            service = svc.get("name", "")
            if svc.get("tunnel") == "ssl" and service:
                service = f"ssl/{service}"
            version = " ".join(x for x in (svc.get("product", ""), svc.get("version", "")) if x)
            extra = svc.get("extrainfo", "")
            if extra:
                version = f"{version} ({extra})".strip()
        result.ports.append(PortResult(number, elem.get("protocol", result.protocol),
                                       state, service, version, reason))
    result.ports.sort(key=lambda p: (p.protocol, p.port))

    for match in host.findall("os/osmatch")[:3]:
        result.os_matches.append({"name": match.get("name", ""),
                                  "accuracy": match.get("accuracy", "")})


def _format_command(cmd: List[str]) -> str:
    return subprocess.list2cmdline(cmd) if os.name == "nt" else shlex.join(cmd)


def run_nmap(nmap_path: str, request: ScanRequest, result: ScanResult) -> None:
    """Run Nmap and fill ``result``. Raises ScanError / ScanCancelled."""
    cmd = build_command(nmap_path, request)
    result.command = _format_command(cmd)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                errors="replace")
    except OSError as exc:
        raise ScanError(f"Could not start Nmap: {exc}") from None
    try:
        out, err = proc.communicate()
    except KeyboardInterrupt:
        proc.terminate()
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        raise ScanCancelled() from None

    err_lines = [ln.strip() for ln in (err or "").splitlines() if ln.strip()]
    if proc.returncode != 0:
        detail = " ".join(err_lines[:3]) or "no error output"
        raise ScanError(f"Nmap failed (exit code {proc.returncode}): {detail}")
    parse_xml(out, result)
    for line in err_lines[:5]:
        result.notes.append(f"Nmap: {line}")
