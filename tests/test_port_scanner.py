import socket
import threading
import unittest
from types import SimpleNamespace

from core.validator import ValidationError, parse_ports, ports_to_spec, validate_target
from modules.port_scanner.models import (STATE_CLOSED, STATE_FILTERED, STATE_OPEN,
                                         STATE_UNKNOWN, ScanError, ScanRequest, ScanResult)
from modules.port_scanner.native_scanner import (probe_tcp, probe_udp, scan_native,
                                                 worker_count, _clean_banner)
from modules.port_scanner.nmap_scanner import build_command, parse_xml
from modules.port_scanner.scanner import choose_engine, resolve_host, run_scan
from modules.port_scanner.services import (COMMON_TCP_PORTS, service_from_banner,
                                           service_name)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap" start="1700000000" version="7.94">
<host><status state="up" reason="user-set"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<hostnames><hostname name="router.local" type="PTR"/></hostnames>
<ports>
<extraports state="closed" count="995"><extrareasons reason="conn-refused" count="995"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux"/></port>
<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" tunnel="ssl" product="nginx"/></port>
<port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/></port>
<port protocol="udp" portid="161"><state state="open|filtered" reason="no-response"/></port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="96"/><osmatch name="Linux 4.15" accuracy="90"/></os>
</host></nmaprun>"""


def blank_result(**kw):
    base = dict(target="t", ip="127.0.0.1", scan_type="custom", protocol="tcp", engine="native",
                ports_requested=1, timeout=1.0, speed="normal", service_detection=True,
                os_detection=False)
    base.update(kw)
    return ScanResult(**base)


def make_request(ports, protocol="tcp", **kw):
    base = dict(target="127.0.0.1", ip="127.0.0.1", ip_version=4, scan_type="custom",
                protocol=protocol, ports=ports, timeout=1.0, speed="normal",
                service_detection=True, os_detection=False, engine="native")
    base.update(kw)
    return ScanRequest(**base)


class TcpServer:
    def __init__(self, banner=b""):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(50)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                if self.banner:
                    conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self):
        self.running = False
        self.sock.close()


def free_tcp_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestHelpers(unittest.TestCase):
    def test_ports_to_spec(self):
        self.assertEqual(ports_to_spec([80, 22, 23, 24, 443, 22]), "22-24,80,443")
        self.assertEqual(ports_to_spec(range(1, 65536)), "1-65535")
        self.assertEqual(ports_to_spec([5]), "5")
        with self.assertRaises(ValidationError):
            ports_to_spec([])
        self.assertEqual(parse_ports(ports_to_spec([1, 2, 3, 9, 11])), [1, 2, 3, 9, 11])

    def test_service_lookup(self):
        self.assertEqual(service_name(22), "ssh")
        self.assertEqual(service_name(514, "udp"), "syslog")
        self.assertEqual(service_from_banner("SSH-2.0-OpenSSH_9.6"), "ssh")
        self.assertIsNone(service_from_banner("garbage"))

    def test_port_lists(self):
        self.assertEqual(COMMON_TCP_PORTS, sorted(set(COMMON_TCP_PORTS)))
        self.assertTrue(all(1 <= p <= 65535 for p in COMMON_TCP_PORTS))

    def test_clean_banner(self):
        self.assertEqual(_clean_banner(b"SSH-2.0-X\r\nmore", http=False), "SSH-2.0-X")
        http = b"HTTP/1.0 200 OK\r\nServer: nginx/1.2\r\n\r\n"
        self.assertEqual(_clean_banner(http, http=True), "Server: nginx/1.2")
        self.assertEqual(_clean_banner(b"\x00\x01\x02", http=False), "")
        self.assertEqual(len(_clean_banner(b"A" * 500, http=False)), 80)

    def test_resolve_host(self):
        self.assertEqual(resolve_host(validate_target("127.0.0.1")), ("127.0.0.1", 4))
        self.assertEqual(resolve_host(validate_target("::1")), ("::1", 6))
        ip, ver = resolve_host(validate_target("localhost"))
        self.assertIn(ip, ("127.0.0.1", "::1"))
        with self.assertRaises(ScanError):
            resolve_host(validate_target("this-host-does-not-exist.invalid"))

    def test_worker_count(self):
        self.assertEqual(worker_count("fast", "tcp", 5), 5)
        self.assertLessEqual(worker_count("fast", "udp", 1000), 50)
        self.assertGreaterEqual(worker_count("slow", "tcp", 1000), 1)


class TestNativeScanner(unittest.TestCase):
    def test_open_and_closed(self):
        server = TcpServer()
        self.addCleanup(server.close)
        self.assertEqual(probe_tcp("127.0.0.1", server.port, 1, socket.AF_INET).state, STATE_OPEN)
        self.assertEqual(probe_tcp("127.0.0.1", free_tcp_port(), 1, socket.AF_INET).state, STATE_CLOSED)

    def test_filtered_on_timeout(self):
        from unittest import mock
        with mock.patch("socket.socket.connect", side_effect=socket.timeout()):
            self.assertEqual(probe_tcp("10.255.255.1", 80, 0.1, socket.AF_INET).state, STATE_FILTERED)
        with mock.patch("socket.socket.connect", side_effect=OSError(113, "No route to host")):
            self.assertEqual(probe_tcp("10.255.255.1", 80, 0.1, socket.AF_INET).state, STATE_FILTERED)
        with mock.patch("socket.socket.connect", side_effect=OSError(13, "Permission denied")):
            self.assertEqual(probe_tcp("10.255.255.1", 80, 0.1, socket.AF_INET).state, STATE_UNKNOWN)

    def test_scan_with_banner(self):
        server = TcpServer(b"SSH-2.0-TestSSH_1.0\r\n")
        self.addCleanup(server.close)
        closed = free_tcp_port()
        request = make_request([server.port, closed])
        result = blank_result(ports_requested=2)
        advanced = []
        scan_native(request, result, advance=advanced.append)
        self.assertEqual(len(advanced), 2)
        by_port = {p.port: p for p in result.ports}
        self.assertEqual(by_port[server.port].state, STATE_OPEN)
        self.assertEqual(by_port[server.port].service, "ssh")
        self.assertIn("TestSSH", by_port[server.port].version)
        self.assertEqual(by_port[closed].state, STATE_CLOSED)
        self.assertTrue(result.host_up)
        self.assertFalse(result.cancelled)

    def test_many_ports_all_reported(self):
        ports = list(range(40000, 40200))
        result = blank_result(ports_requested=len(ports))
        scan_native(make_request(ports, service_detection=False), result)
        self.assertEqual(len(result.ports), 200)
        self.assertEqual([p.port for p in result.ports], ports)

    def test_cancel(self):
        cancel = threading.Event()
        cancel.set()
        result = blank_result()
        scan_native(make_request([1, 2, 3]), result, cancel=cancel)
        self.assertTrue(result.cancelled)
        self.assertEqual(result.ports, [])

    def test_udp(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def echo():
            server.settimeout(2)
            try:
                data, addr = server.recvfrom(100)
                server.sendto(b"pong", addr)
            except OSError:
                pass
        threading.Thread(target=echo, daemon=True).start()
        self.assertEqual(probe_udp("127.0.0.1", port, 1, socket.AF_INET).state, STATE_OPEN)
        server.close()
        self.assertEqual(probe_udp("127.0.0.1", port, 1, socket.AF_INET).state, STATE_CLOSED)

    def test_udp_silent_is_unknown(self):
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        self.addCleanup(silent.close)
        res = probe_udp("127.0.0.1", silent.getsockname()[1], 0.3, socket.AF_INET)
        self.assertEqual(res.state, STATE_UNKNOWN)

    def test_run_scan_wrapper(self):
        server = TcpServer()
        self.addCleanup(server.close)
        result = run_scan(make_request([server.port], service_detection=False), None)
        self.assertEqual(result.open_ports()[0].port, server.port)
        self.assertTrue(result.started and result.finished)
        data = result.to_dict()
        self.assertEqual(data["state_counts"]["open"], 1)
        self.assertEqual(data["schema_version"], 1)


class TestNmap(unittest.TestCase):
    def test_parse_xml(self):
        result = blank_result(protocol="tcp")
        parse_xml(SAMPLE_XML, result)
        by_key = {(p.protocol, p.port): p for p in result.ports}
        self.assertEqual(by_key[("tcp", 22)].version, "OpenSSH 8.9p1 (Ubuntu Linux)")
        self.assertEqual(by_key[("tcp", 443)].service, "ssl/http")
        self.assertEqual(by_key[("tcp", 80)].state, STATE_FILTERED)
        self.assertEqual(by_key[("udp", 161)].state, STATE_UNKNOWN)
        self.assertIn("open|filtered", by_key[("udp", 161)].reason)
        self.assertEqual(result.extra_counts, {STATE_CLOSED: 995})
        self.assertEqual(result.state_counts()[STATE_CLOSED], 995)
        self.assertEqual(result.hostname, "router.local")
        self.assertTrue(result.host_up)
        self.assertEqual(result.os_matches[0]["name"], "Linux 5.4")

    def test_parse_bad_xml(self):
        for bad in ("", "<nmaprun>", "<html/>"):
            with self.assertRaises(ScanError):
                parse_xml(bad, blank_result())

    def test_parse_no_host(self):
        result = blank_result()
        parse_xml("<nmaprun></nmaprun>", result)
        self.assertIsNone(result.host_up)
        self.assertTrue(result.notes)

    def test_build_command(self):
        cmd = build_command("nmap", make_request([22, 80, 81], protocol="udp", speed="fast",
                                                 os_detection=True, ip_version=6, ip="::1", timeout=2))
        self.assertEqual(cmd[0], "nmap")
        self.assertIn("-sU", cmd)
        self.assertIn("-O", cmd)
        self.assertIn("-sV", cmd)
        self.assertIn("-6", cmd)
        self.assertIn("-T4", cmd)
        self.assertEqual(cmd[cmd.index("-p") + 1], "22,80-81")
        self.assertIn("2000ms", cmd)
        self.assertEqual(cmd[-1], "::1")
        tcp = build_command("nmap", make_request([80], service_detection=False))
        self.assertNotIn("-sU", tcp)
        self.assertNotIn("-sV", tcp)


class TestEngineChoice(unittest.TestCase):
    OK = SimpleNamespace(available=True, detail="", install_hint="hint")
    MISSING = SimpleNamespace(available=False, detail="Not found.", install_hint="install nmap")

    def test_auto(self):
        self.assertEqual(choose_engine("auto", "tcp", False, self.OK, False).engine, "nmap")
        plan = choose_engine("auto", "tcp", False, self.MISSING, False)
        self.assertEqual(plan.engine, "native")
        self.assertTrue(plan.notes)
        plan = choose_engine("auto", "udp", False, self.OK, False)
        self.assertEqual(plan.engine, "native")
        self.assertEqual(choose_engine("auto", "udp", False, self.OK, True).engine, "nmap")

    def test_explicit_nmap_never_falls_back(self):
        with self.assertRaises(ScanError):
            choose_engine("nmap", "tcp", False, self.MISSING, True)
        with self.assertRaises(ScanError):
            choose_engine("nmap", "udp", False, self.OK, False)

    def test_os_detection(self):
        self.assertTrue(choose_engine("nmap", "tcp", True, self.OK, True).os_detection)
        plan = choose_engine("nmap", "tcp", True, self.OK, False)
        self.assertFalse(plan.os_detection)
        self.assertTrue(plan.notes)
        self.assertFalse(choose_engine("native", "tcp", True, self.OK, True).os_detection)


if __name__ == "__main__":
    unittest.main()
