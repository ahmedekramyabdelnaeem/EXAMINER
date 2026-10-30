"""Low-impact, authorized information-gathering workflows."""
from __future__ import annotations

import ipaddress
import socket
import ssl
from typing import List, Optional, Tuple

from core.menu import Menu, MenuItem
from core.validator import ValidationError, Target, validate_domain, validate_target
from modules.port_scanner.scanner import resolve_host

try:
    import dns.resolver  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    dns = None  # type: ignore

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore

try:
    import whois  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    whois = None  # type: ignore


DNS_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


class InformationGatheringModule:
    """Interactive passive/low-impact recon menu.

    These actions do not exploit services, brute-force credentials, or evade controls.
    """

    def __init__(self, engine) -> None:
        self.app = engine
        self.ui = engine.ui
        self.timeout = float(engine.config.get("default_timeout"))

    def menu(self) -> None:
        Menu(self.ui, "Information Gathering", [
            MenuItem("1", "DNS Records", self.dns_records),
            MenuItem("2", "WHOIS Lookup", self.whois_lookup),
            MenuItem("3", "IP / Host Information", self.ip_information),
            MenuItem("4", "HTTP Response Headers", self.http_headers),
            MenuItem("5", "TLS Certificate Summary", self.tls_summary),
            MenuItem("6", "Subdomain Enumeration (not enabled)", self.not_implemented),
        ], exit_label="Back to Main Menu", header=self._header,
            logger=self.app.logger).run()

    def _header(self) -> None:
        self.ui.print("Only use these checks on assets you own or are authorized to assess.",
                      style="muted")

    def _target(self) -> Optional[Target]:
        while True:
            raw = self.ui.ask("Target IP, hostname, or URL (blank to cancel)")
            if not raw:
                return None
            try:
                return validate_target(raw)
            except ValidationError as exc:
                self.ui.error(str(exc))

    def _authorized(self, target: Target) -> bool:
        return self.app.confirm_scope(target.value, active=False)

    def _resolve(self, target: Target) -> Tuple[str, int]:
        try:
            return resolve_host(target)
        except Exception as exc:  # normalize resolver errors for UI
            raise RuntimeError(str(exc)) from None

    def dns_records(self) -> None:
        target = self._target()
        if target is None or not self._authorized(target):
            return
        if target.kind != "domain":
            self.ui.warning("DNS record enumeration requires a domain name, not a raw IP.")
            return
        if dns is None:
            self.ui.error("dnspython is not installed. Run: python -m pip install dnspython")
            return
        rows: List[List[str]] = []
        resolver = dns.resolver.Resolver()  # type: ignore[union-attr]
        resolver.lifetime = self.timeout
        for record_type in DNS_TYPES:
            try:
                answers = resolver.resolve(target.value, record_type)
                for answer in answers:
                    rows.append([record_type, str(answer).strip()])
            except Exception as exc:  # DNS NXDOMAIN, timeout, or unsupported record
                self.app.logger.debug("DNS %s lookup failed for %s: %s", record_type,
                                      target.value, exc)
        if rows:
            self.ui.table("DNS Records", ["Type", "Value"], rows)
        else:
            self.ui.warning("No DNS records were returned for this target.")

    def whois_lookup(self) -> None:
        target = self._target()
        if target is None or not self._authorized(target):
            return
        if target.kind != "domain":
            self.ui.warning("WHOIS lookup requires a domain name.")
            return
        if whois is None:
            self.ui.error("python-whois is not installed. Run: python -m pip install python-whois")
            return
        try:
            with self.ui.spinner("Querying WHOIS..."):
                data = whois.whois(target.value)
            rows = []
            for key in ("domain_name", "registrar", "creation_date", "expiration_date",
                        "name_servers", "status"):
                value = data.get(key) if hasattr(data, "get") else getattr(data, key, None)
                if value:
                    rows.append([key.replace("_", " ").title(), str(value)])
            self.ui.table("WHOIS", ["Field", "Value"], rows or [["Result", "No data returned"]])
        except Exception as exc:
            self.ui.error(f"WHOIS lookup failed: {exc}")

    def ip_information(self) -> None:
        target = self._target()
        if target is None or not self._authorized(target):
            return
        try:
            ip, version = self._resolve(target)
            address = ipaddress.ip_address(ip)
            reverse = socket.gethostbyaddr(ip)[0]
        except (RuntimeError, ValueError, socket.herror, socket.gaierror, OSError) as exc:
            self.ui.error(f"Could not resolve target information: {exc}")
            return
        self.ui.table("IP / Host Information", ["Field", "Value"], [
            ["Input", target.value], ["Resolved IP", ip], ["IP version", str(version)],
            ["Address class", "private" if address.is_private else "public"],
            ["Reverse DNS", reverse],
        ])

    def http_headers(self) -> None:
        target = self._target()
        if target is None or not self._authorized(target):
            return
        if requests is None:
            self.ui.error("requests is not installed. Run: python -m pip install requests")
            return
        scheme = self.ui.ask("Scheme (https/http)", default="https").lower()
        if scheme not in ("http", "https"):
            self.ui.error("Scheme must be http or https.")
            return
        url = f"{scheme}://{target.value}/"
        try:
            with self.ui.spinner("Requesting response headers..."):
                response = requests.head(url, timeout=self.timeout, allow_redirects=False,
                                         headers={"User-Agent": "EXAMINER/1.0"})
            rows = [[key, value] for key, value in response.headers.items()]
            self.ui.panel(f"URL: {url}\nStatus: {response.status_code}",
                          title="HTTP Response", style="info")
            self.ui.table("Headers", ["Header", "Value"], rows or [["-", "none"]])
            if 300 <= response.status_code < 400:
                self.ui.info("Redirect returned; no automatic follow-up request was made.")
        except requests.RequestException as exc:
            self.ui.error(f"HTTP request failed: {exc}")

    def tls_summary(self) -> None:
        target = self._target()
        if target is None or not self._authorized(target):
            return
        try:
            host = target.value
            context = ssl.create_default_context()
            with self.ui.spinner("Connecting to TLS service on port 443..."):
                with socket.create_connection((host, 443), timeout=self.timeout) as raw:
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                        cipher = tls.cipher()
                        version = tls.version() or "unknown"
            subject = dict(item[0] for item in cert.get("subject", ()))
            issuer = dict(item[0] for item in cert.get("issuer", ()))
            self.ui.table("TLS Certificate", ["Field", "Value"], [
                ["TLS version", version], ["Cipher", str(cipher[0] if cipher else "unknown")],
                ["Subject CN", subject.get("commonName", "unknown")],
                ["Issuer CN", issuer.get("commonName", "unknown")],
                ["Valid from", cert.get("notBefore", "unknown")],
                ["Valid until", cert.get("notAfter", "unknown")],
            ])
        except (OSError, ssl.SSLError, ValueError) as exc:
            self.ui.error(f"TLS inspection failed: {exc}")

    def not_implemented(self) -> None:
        self.ui.warning("Subdomain enumeration is intentionally not enabled in this build.")
