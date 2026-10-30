"""Input validation for targets, networks, ports and numeric values."""
from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from typing import Iterable, List, Union
from urllib.parse import urlparse

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

MAX_PORT = 65535
DEFAULT_MAX_HOSTS = 65536

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DIGITS_RE = re.compile(r"^[0-9]+$")


class ValidationError(ValueError):
    """Raised when user input fails validation."""


@dataclass(frozen=True)
class Target:
    """A validated scan target."""

    kind: str  # "ip" or "domain"
    value: str


def normalize_input(value: object) -> str:
    """Strip whitespace and reduce a URL to its host name."""
    if not isinstance(value, str):
        raise ValidationError("Input must be text.")
    text = value.strip()
    if not text:
        raise ValidationError("Input cannot be empty.")
    if "://" in text:
        try:
            host = urlparse(text).hostname
        except ValueError:
            raise ValidationError(f"'{text}' is not a valid URL.") from None
        if not host:
            raise ValidationError(f"Could not find a host name in '{text}'.")
        text = host
    return text


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def validate_ip(value: str) -> IPAddress:
    """Validate a single IPv4/IPv6 address."""
    text = normalize_input(value)
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError(f"'{text}' is not a valid IP address.") from None


def validate_domain(value: str, allow_single_label: bool = False) -> str:
    """Validate a DNS name and return it normalized (lowercase, ASCII/IDNA)."""
    text = normalize_input(value).rstrip(".").lower()
    if not text:
        raise ValidationError("Domain cannot be empty.")
    if _is_ip(text):
        raise ValidationError(f"'{text}' is an IP address; a domain name is expected.")
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValidationError(f"'{text}' contains invalid characters or labels.") from None
    if len(ascii_name) > 253:
        raise ValidationError("Domain name is too long (max 253 characters).")
    labels = ascii_name.split(".")
    if len(labels) < 2 and not allow_single_label:
        raise ValidationError(f"'{text}' must contain a dot (example: example.com).")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValidationError(f"'{text}' is not a valid domain name (bad label '{label}').")
    if len(labels) > 1 and labels[-1].isdigit():
        raise ValidationError(f"'{text}' is not a valid domain name (numeric TLD).")
    return ascii_name


def validate_target(value: str) -> Target:
    """Validate a scan target: an IP address or a host name."""
    text = normalize_input(value)
    if _is_ip(text):
        ip = ipaddress.ip_address(text)
        if (ip.is_unspecified or ip.is_multicast
                or ip == ipaddress.IPv4Address("255.255.255.255")):
            raise ValidationError(f"{ip} is not a scannable unicast address.")
        return Target("ip", str(ip))
    try:
        return Target("domain", validate_domain(text, allow_single_label=True))
    except ValidationError:
        raise ValidationError(f"'{text}' is not a valid IP address or host name.") from None


def validate_network(value: str, max_hosts: int = DEFAULT_MAX_HOSTS) -> IPNetwork:
    """Validate a CIDR network (or single IP) and enforce a maximum scope size."""
    text = normalize_input(value)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValidationError(
            f"'{text}' is not a valid IP address or CIDR network (example: 192.168.1.0/24)."
        ) from None
    if network.num_addresses > max_hosts:
        raise ValidationError(
            f"Network {network} has {network.num_addresses} addresses; the maximum "
            f"allowed scope is {max_hosts}. Please use a smaller range."
        )
    return network


def _parse_port(text: str) -> int:
    text = text.strip()
    if not _DIGITS_RE.match(text):
        raise ValidationError(f"'{text}' is not a valid port number.")
    port = int(text)
    if not 1 <= port <= MAX_PORT:
        raise ValidationError(f"Port {port} is out of range (1-{MAX_PORT}).")
    return port


def parse_ports(spec: str) -> List[int]:
    """Parse a port specification like '22,80,443,8000-8100' into a sorted list."""
    if not isinstance(spec, str) or not spec.strip():
        raise ValidationError("Port specification cannot be empty.")
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            raise ValidationError("Empty entry in port list (check for stray commas).")
        if "-" in part:
            low_text, _, high_text = part.partition("-")
            low, high = _parse_port(low_text), _parse_port(high_text)
            if low > high:
                raise ValidationError(f"Invalid range '{part}': start is greater than end.")
            ports.update(range(low, high + 1))
        else:
            ports.add(_parse_port(part))
    return sorted(ports)


def validate_timeout(value: object, minimum: float = 0.1, maximum: float = 300.0) -> float:
    """Validate a timeout in seconds."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise ValidationError(f"'{value}' is not a valid number.") from None
    if not math.isfinite(number):
        raise ValidationError("Timeout must be a finite number.")
    if not minimum <= number <= maximum:
        raise ValidationError(f"Timeout must be between {minimum} and {maximum} seconds.")
    return number


def validate_choice(value: object, choices: Iterable[str], name: str = "value") -> str:
    """Validate that ``value`` (case-insensitive) is one of ``choices``."""
    options = list(choices)
    text = str(value).strip().lower()
    if text not in options:
        raise ValidationError(f"Invalid {name} '{value}'. Choose one of: {', '.join(options)}.")
    return text


def ports_to_spec(ports: Iterable[int]) -> str:
    """Compact a list of ports into a spec such as '22,80,8000-8100'."""
    ordered = sorted(set(ports))
    if not ordered:
        raise ValidationError("No ports to scan.")
    parts: List[str] = []
    start = prev = ordered[0]
    for port in ordered[1:] + [None]:  # type: ignore[list-item]
        if port is not None and port == prev + 1:
            prev = port
            continue
        parts.append(str(start) if start == prev else f"{start}-{prev}")
        if port is not None:
            start = prev = port
    return ",".join(parts)
