"""Port lists and service-name lookup."""
from __future__ import annotations

import socket
from typing import Dict, List, Optional, Tuple

COMMON_TCP_PORTS: List[int] = sorted(set([
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1110,
    1433, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
    3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 5985, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9200, 9999, 10000, 11211, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]))

COMMON_UDP_PORTS: List[int] = sorted(set([
    53, 67, 68, 69, 88, 111, 123, 135, 137, 138, 139, 161, 162, 389, 445, 500, 514, 520,
    623, 631, 1434, 1900, 4500, 5060, 5353, 11211,
]))

SERVICE_NAMES: Dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 53: "domain", 67: "dhcps", 68: "dhcpc",
    69: "tftp", 79: "finger", 80: "http", 81: "http-alt", 88: "kerberos-sec", 110: "pop3",
    111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
    179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 500: "isakmp",
    513: "login", 514: "shell", 515: "printer", 520: "rip", 548: "afp", 554: "rtsp",
    587: "submission", 623: "asf-rmcp", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "ms-sql-s", 1434: "ms-sql-m",
    1521: "oracle", 1723: "pptp", 1900: "upnp", 2049: "nfs", 3128: "squid-http",
    3306: "mysql", 3389: "ms-wbt-server", 4500: "ipsec-nat-t", 5060: "sip", 5353: "mdns",
    5432: "postgresql", 5900: "vnc", 5985: "wsman", 6379: "redis", 8000: "http-alt",
    8008: "http", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9100: "jetdirect", 9200: "elasticsearch", 11211: "memcache", 27017: "mongodb",
}
_OVERRIDES: Dict[Tuple[int, str], str] = {(514, "udp"): "syslog"}


def service_name(port: int, protocol: str = "tcp") -> str:
    """Best-effort service name for a port number (a guess, not a detection)."""
    override = _OVERRIDES.get((port, protocol))
    if override:
        return override
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(port, protocol)
    except (OSError, OverflowError):
        return "unknown"


def service_from_banner(banner: str) -> Optional[str]:
    """Identify a service from the first bytes it sent, if recognisable."""
    text = banner.strip()
    upper = text.upper()
    if upper.startswith("SSH-"):
        return "ssh"
    if upper.startswith("HTTP/") or upper.startswith("SERVER:"):
        return "http"
    if upper.startswith("220") and "FTP" in upper:
        return "ftp"
    if upper.startswith("220") and ("SMTP" in upper or "ESMTP" in upper):
        return "smtp"
    if upper.startswith("+OK"):
        return "pop3"
    if upper.startswith("* OK") and "IMAP" in upper:
        return "imap"
    return None
