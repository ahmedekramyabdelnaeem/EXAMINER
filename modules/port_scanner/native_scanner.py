"""Pure-Python scanning engine (TCP connect scan, basic UDP probe, banner grabbing)."""
from __future__ import annotations

import errno
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Optional

from .models import (STATE_CLOSED, STATE_FILTERED, STATE_OPEN, STATE_UNKNOWN,
                     PortResult, ScanRequest, ScanResult)
from .services import service_from_banner, service_name

SPEED_WORKERS = {"slow": 25, "normal": 100, "fast": 300}
UDP_MAX_WORKERS = 50  # many OSes rate-limit ICMP errors; more workers adds nothing
HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8888}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}
UDP_PAYLOADS: Dict[int, bytes] = {
    53: (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01"),
    123: b"\x1b" + b"\x00" * 47,
}
_UNREACHABLE = {getattr(errno, name) for name in
                ("ENETUNREACH", "EHOSTUNREACH", "ENETDOWN", "EHOSTDOWN", "ETIMEDOUT")
                if hasattr(errno, name)} | {10051, 10060, 10065}


def worker_count(speed: str, protocol: str, total: int) -> int:
    """Number of worker threads for a given speed (bounded by OS limits)."""
    workers = SPEED_WORKERS.get(speed, SPEED_WORKERS["normal"])
    if protocol == "udp":
        workers = min(workers, UDP_MAX_WORKERS)
    try:  # POSIX only: respect the open-file limit
        import resource
        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if soft not in (-1, resource.RLIM_INFINITY):
            workers = min(workers, max(4, soft - 64))
    except (ImportError, ValueError, OSError):
        pass
    return max(1, min(workers, total))


def probe_tcp(ip: str, port: int, timeout: float, family: int) -> PortResult:
    """TCP connect probe. Classifies the port as open/closed/filtered/unknown."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return PortResult(port, "tcp", STATE_OPEN, reason="connection accepted")
    except ConnectionRefusedError:
        return PortResult(port, "tcp", STATE_CLOSED, reason="connection refused")
    except (socket.timeout, TimeoutError):
        return PortResult(port, "tcp", STATE_FILTERED, reason="no response (timeout)")
    except OSError as exc:
        if exc.errno in _UNREACHABLE:
            return PortResult(port, "tcp", STATE_FILTERED, reason=f"unreachable ({exc.strerror})")
        return PortResult(port, "tcp", STATE_UNKNOWN, reason=str(exc.strerror or exc))
    finally:
        sock.close()


def probe_udp(ip: str, port: int, timeout: float, family: int) -> PortResult:
    """UDP probe. Only a reply (open) or ICMP unreachable (closed) is conclusive."""
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.send(UDP_PAYLOADS.get(port, b""))
        sock.recv(1024)
        return PortResult(port, "udp", STATE_OPEN, reason="reply received")
    except ConnectionError:  # ICMP port unreachable (refused on Linux, reset on Windows)
        return PortResult(port, "udp", STATE_CLOSED, reason="ICMP port unreachable")
    except (socket.timeout, TimeoutError):
        return PortResult(port, "udp", STATE_UNKNOWN, reason="no response (open|filtered)")
    except OSError as exc:
        return PortResult(port, "udp", STATE_UNKNOWN, reason=str(exc.strerror or exc))
    finally:
        sock.close()


def _clean_banner(data: bytes, http: bool) -> str:
    text = data.decode("latin-1", errors="replace")
    lines = [ln for ln in text.replace("\r", "\n").split("\n") if ln.strip()]
    if not lines:
        return ""
    chosen = lines[0]
    if http:
        for line in lines:
            if line.lower().startswith("server:"):
                chosen = line
                break
    cleaned = "".join(ch for ch in chosen if ch.isprintable()).strip()
    return cleaned[:80]


def grab_banner(ip: str, port: int, timeout: float, family: int) -> str:
    """Read a short banner from an open TCP port (empty string if none).

    Services that speak first (SSH, FTP, SMTP...) are read passively. If the
    service stays silent, a single harmless HTTP HEAD request is tried.
    """
    if port in TLS_PORTS:
        return ""
    wait = min(timeout, 1.5)
    host = f"[{ip}]" if ":" in ip else ip
    head = f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii")
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(wait)
            sock.connect((ip, port))
            data = b""
            if port not in HTTP_PORTS:
                try:
                    data = sock.recv(512)
                except (socket.timeout, TimeoutError):
                    data = b""
            if not data:
                sock.sendall(head)
                try:
                    data = sock.recv(512)
                except (socket.timeout, TimeoutError):
                    data = b""
    except OSError:
        return ""
    return _clean_banner(data, http=data.upper().startswith(b"HTTP/"))


def scan_native(request: ScanRequest, result: ScanResult,
                advance: Optional[Callable[[int], None]] = None,
                cancel: Optional[threading.Event] = None) -> None:
    """Run the native scan and fill ``result`` in place.

    ``advance`` is called (from the calling thread) once per finished port.
    A KeyboardInterrupt stops the scan and marks the result as cancelled.
    """
    cancel = cancel or threading.Event()
    family = socket.AF_INET6 if request.ip_version == 6 else socket.AF_INET
    probe = probe_tcp if request.protocol == "tcp" else probe_udp
    workers = worker_count(request.speed, request.protocol, len(request.ports))

    def run_one(port: int) -> Optional[PortResult]:
        if cancel.is_set():
            return None
        try:
            return probe(request.ip, port, request.timeout, family)
        except Exception as exc:  # noqa: BLE001 - one bad probe must not kill the scan
            return PortResult(port, request.protocol, STATE_UNKNOWN, reason=f"probe error: {exc}")

    found: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run_one, port) for port in request.ports]
        try:
            for future in as_completed(futures):
                outcome = future.result()
                if outcome is not None:
                    found.append(outcome)
                if advance is not None:
                    advance(1)
        except KeyboardInterrupt:
            cancel.set()
            for future in futures:
                future.cancel()

    if cancel.is_set():
        result.cancelled = True

    for item in found:
        if item.state == STATE_OPEN:
            item.service = service_name(item.port, item.protocol)

    if request.service_detection and request.protocol == "tcp" and not result.cancelled:
        _detect_services([p for p in found if p.state == STATE_OPEN], request, family)

    result.ports = sorted(found, key=lambda p: p.port)
    result.host_up = True if any(p.state in (STATE_OPEN, STATE_CLOSED) for p in found) else None


def _detect_services(open_ports: List[PortResult], request: ScanRequest, family: int) -> None:
    if not open_ports:
        return
    with ThreadPoolExecutor(max_workers=min(20, len(open_ports))) as pool:
        banners = list(pool.map(
            lambda p: grab_banner(request.ip, p.port, request.timeout, family), open_ports))
    for item, banner in zip(open_ports, banners):
        if banner:
            item.version = banner
            guessed = service_from_banner(banner)
            if guessed:
                item.service = guessed
