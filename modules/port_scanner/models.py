"""Data models for the port scanning module."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_FILTERED = "filtered"
STATE_UNKNOWN = "unknown"
STATES = (STATE_OPEN, STATE_CLOSED, STATE_FILTERED, STATE_UNKNOWN)


class ScanError(Exception):
    """A scan could not be performed (message is safe to show to the user)."""


class ScanCancelled(Exception):
    """The user cancelled the scan."""


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    reason: str = ""


@dataclass
class ScanRequest:
    target: str
    ip: str
    ip_version: int
    scan_type: str  # quick | full | udp | custom
    protocol: str  # tcp | udp
    ports: List[int]
    timeout: float
    speed: str
    service_detection: bool
    os_detection: bool
    engine: str  # resolved engine: nmap | native


@dataclass
class ScanResult:
    target: str
    ip: str
    scan_type: str
    protocol: str
    engine: str
    ports_requested: int
    timeout: float
    speed: str
    service_detection: bool
    os_detection: bool
    started: str = ""
    finished: str = ""
    duration_seconds: float = 0.0
    command: str = ""
    host_up: Optional[bool] = None
    hostname: str = ""
    ports: List[PortResult] = field(default_factory=list)
    extra_counts: Dict[str, int] = field(default_factory=dict)
    os_matches: List[Dict[str, str]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    cancelled: bool = False

    def state_counts(self) -> Dict[str, int]:
        counts = {state: 0 for state in STATES}
        for port in self.ports:
            counts[port.state] = counts.get(port.state, 0) + 1
        for state, number in self.extra_counts.items():
            counts[state] = counts.get(state, 0) + number
        return counts

    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == STATE_OPEN]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["schema_version"] = 1
        data["module"] = "port_scanner"
        data["state_counts"] = self.state_counts()
        return data
