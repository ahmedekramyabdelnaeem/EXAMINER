import unittest

from core.validator import (ValidationError, parse_ports, validate_choice, validate_domain,
                            validate_ip, validate_network, validate_target, validate_timeout)


class TestTargets(unittest.TestCase):
    def test_valid_ips(self):
        self.assertEqual(str(validate_ip(" 192.168.1.10 ")), "192.168.1.10")
        self.assertEqual(str(validate_ip("::1")), "::1")

    def test_invalid_ips(self):
        for bad in ("999.1.1.1", "abc", "", "   ", "1.2.3"):
            with self.assertRaises(ValidationError, msg=bad):
                validate_ip(bad)

    def test_non_string(self):
        with self.assertRaises(ValidationError):
            validate_ip(None)  # type: ignore[arg-type]

    def test_domains(self):
        self.assertEqual(validate_domain("Example.COM."), "example.com")
        self.assertEqual(validate_domain("https://Sub.Example.com:8443/path"), "sub.example.com")
        self.assertTrue(validate_domain("münchen.de").startswith("xn--"))
        for bad in ("localhost", "-a.com", "a-.com", "a..com", "exa mple.com",
                    "example.123", "a" * 64 + ".com", "1.2.3.4", "exa_mple.com"):
            with self.assertRaises(ValidationError, msg=bad):
                validate_domain(bad)

    def test_single_label_allowed_when_requested(self):
        self.assertEqual(validate_domain("localhost", allow_single_label=True), "localhost")

    def test_validate_target(self):
        self.assertEqual(validate_target("10.0.0.1").kind, "ip")
        self.assertEqual(validate_target("scanme.nmap.org").kind, "domain")
        self.assertEqual(validate_target("myhost").kind, "domain")
        for bad in ("0.0.0.0", "224.0.0.1", "255.255.255.255", "999.1.1.1", "a b", ""):
            with self.assertRaises(ValidationError, msg=bad):
                validate_target(bad)


class TestNetworkAndPorts(unittest.TestCase):
    def test_network(self):
        self.assertEqual(str(validate_network("192.168.1.5/24")), "192.168.1.0/24")
        self.assertEqual(str(validate_network("10.0.0.1")), "10.0.0.1/32")
        with self.assertRaises(ValidationError):
            validate_network("10.0.0.0/8")
        with self.assertRaises(ValidationError):
            validate_network("nonsense")

    def test_ports(self):
        self.assertEqual(parse_ports("80"), [80])
        self.assertEqual(parse_ports("443, 22,80,22"), [22, 80, 443])
        self.assertEqual(parse_ports("1-3,10"), [1, 2, 3, 10])
        self.assertEqual(len(parse_ports("1-65535")), 65535)
        for bad in ("", "  ", "0", "65536", "80,", "a", "5-1", "1-2-3", "-5", "80;22", "²"):
            with self.assertRaises(ValidationError, msg=bad):
                parse_ports(bad)

    def test_timeout(self):
        self.assertEqual(validate_timeout("2.5"), 2.5)
        for bad in ("abc", "0", "-1", "1000", "nan", "inf", None):
            with self.assertRaises(ValidationError, msg=str(bad)):
                validate_timeout(bad)

    def test_choice(self):
        self.assertEqual(validate_choice("FAST", ["slow", "fast"]), "fast")
        with self.assertRaises(ValidationError):
            validate_choice("x", ["slow", "fast"])


if __name__ == "__main__":
    unittest.main()
