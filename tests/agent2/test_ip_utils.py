"""Unit tests for IP address validation, classification, and routing utilities."""

import unittest

from dark_trace.common.ip_utils import (
    IPCategory,
    classify_ip,
    is_public_ip,
    is_rfc1918_private,
    is_rfc4193_unique_local,
    is_routable_public_indicator,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    parse_ip_address,
)


class TestIPUtils(unittest.TestCase):
    """Test suite covering IPv4/IPv6 classification and cybersecurity utility functions."""

    def test_valid_ipv4(self):
        """Test IPv4 format validation."""
        self.assertTrue(is_valid_ipv4("192.168.1.1"))
        self.assertTrue(is_valid_ipv4("8.8.8.8"))
        self.assertTrue(is_valid_ipv4("10.0.0.1"))
        self.assertFalse(is_valid_ipv4("2001:db8::1"))
        self.assertFalse(is_valid_ipv4("999.999.999.999"))
        self.assertFalse(is_valid_ipv4("not-an-ip"))
        self.assertFalse(is_valid_ipv4(""))
        self.assertFalse(is_valid_ipv4(None))

    def test_valid_ipv6(self):
        """Test IPv6 format validation."""
        self.assertTrue(is_valid_ipv6("2001:db8::1"))
        self.assertTrue(is_valid_ipv6("fe80::1"))
        self.assertTrue(is_valid_ipv6("::1"))
        self.assertFalse(is_valid_ipv6("192.168.1.1"))
        self.assertFalse(is_valid_ipv6("invalid:ipv6:xyz"))
        self.assertFalse(is_valid_ipv6(""))
        self.assertFalse(is_valid_ipv6(None))

    def test_rfc1918_private_ipv4(self):
        """Test RFC 1918 private IPv4 identification."""
        # 10.0.0.0/8
        self.assertTrue(is_rfc1918_private("10.0.0.1"))
        self.assertTrue(is_rfc1918_private("10.255.255.254"))

        # 172.16.0.0/12
        self.assertTrue(is_rfc1918_private("172.16.0.1"))
        self.assertTrue(is_rfc1918_private("172.31.255.254"))
        self.assertFalse(is_rfc1918_private("172.15.255.255"))
        self.assertFalse(is_rfc1918_private("172.32.0.1"))

        # 192.168.0.0/16
        self.assertTrue(is_rfc1918_private("192.168.0.1"))
        self.assertTrue(is_rfc1918_private("192.168.254.254"))

        # Non-RFC1918 addresses must return False
        self.assertFalse(is_rfc1918_private("8.8.8.8"))
        self.assertFalse(is_rfc1918_private("1.1.1.1"))
        self.assertFalse(is_rfc1918_private("127.0.0.1"))  # Loopback is not RFC 1918
        self.assertFalse(is_rfc1918_private("169.254.1.1"))  # Link-local is not RFC 1918
        self.assertFalse(is_rfc1918_private("2001:db8::1"))  # IPv6

    def test_rfc4193_unique_local_ipv6(self):
        """Test RFC 4193 unique-local IPv6 identification (fc00::/7)."""
        self.assertTrue(is_rfc4193_unique_local("fc00::1"))
        self.assertTrue(is_rfc4193_unique_local("fd00:abcd:1234::1"))
        self.assertTrue(is_rfc4193_unique_local("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))

        # Non-RFC 4193 addresses
        self.assertFalse(is_rfc4193_unique_local("2001:4860:4860::8888"))  # Global unicast
        self.assertFalse(is_rfc4193_unique_local("fe80::1"))  # Link-local
        self.assertFalse(is_rfc4193_unique_local("::1"))  # Loopback
        self.assertFalse(is_rfc4193_unique_local("192.168.1.1"))  # IPv4

    def test_public_ip_identification(self):
        """Test identification of globally routable public IPs."""
        # Genuine Public IPv4
        self.assertTrue(is_public_ip("8.8.8.8"))
        self.assertTrue(is_public_ip("1.1.1.1"))
        self.assertTrue(is_public_ip("93.184.216.34"))

        # Public IPv6
        self.assertTrue(is_public_ip("2001:4860:4860::8888"))

        # Internal/Special/Documentation IPs must NOT be marked public
        self.assertFalse(is_public_ip("10.0.0.1"))
        self.assertFalse(is_public_ip("172.16.1.1"))
        self.assertFalse(is_public_ip("192.168.1.1"))
        self.assertFalse(is_public_ip("127.0.0.1"))
        self.assertFalse(is_public_ip("169.254.1.1"))
        self.assertFalse(is_public_ip("224.0.0.1"))
        self.assertFalse(is_public_ip("100.64.0.1"))  # CGNAT
        self.assertFalse(is_public_ip("198.51.100.23"))  # RFC 5737 TEST-NET-2 (documentation)
        self.assertFalse(is_public_ip("0.0.0.0"))
        self.assertFalse(is_public_ip("255.255.255.255"))
        self.assertFalse(is_public_ip("::1"))
        self.assertFalse(is_public_ip("fe80::1"))
        self.assertFalse(is_public_ip("fc00::1"))
        self.assertFalse(is_public_ip("invalid-ip"))

    def test_routable_public_indicator(self):
        """Test indicator guardrail for external threat intelligence (TinyFish)."""
        # Valid public external indicators
        self.assertTrue(is_routable_public_indicator("93.184.216.34"))
        self.assertTrue(is_routable_public_indicator("2606:2800:220:1:248:1893:25c8:1946"))

        # Must never query private/internal addresses to external threat intel
        self.assertFalse(is_routable_public_indicator("10.10.10.10"))
        self.assertFalse(is_routable_public_indicator("192.168.50.1"))
        self.assertFalse(is_routable_public_indicator("127.0.0.1"))
        self.assertFalse(is_routable_public_indicator("fe80::1"))
        self.assertFalse(is_routable_public_indicator(""))

    def test_classify_ip_comprehensive(self):
        """Test detailed classification across all categories."""
        self.assertEqual(classify_ip("8.8.8.8"), IPCategory.PUBLIC)
        self.assertEqual(classify_ip("10.0.0.5"), IPCategory.RFC1918_PRIVATE)
        self.assertEqual(classify_ip("172.20.0.1"), IPCategory.RFC1918_PRIVATE)
        self.assertEqual(classify_ip("192.168.100.1"), IPCategory.RFC1918_PRIVATE)
        self.assertEqual(classify_ip("127.0.0.1"), IPCategory.LOOPBACK)
        self.assertEqual(classify_ip("169.254.10.20"), IPCategory.LINK_LOCAL)
        self.assertEqual(classify_ip("224.0.0.251"), IPCategory.MULTICAST)
        self.assertEqual(classify_ip("100.64.0.5"), IPCategory.CARRIER_GRADE_NAT)
        self.assertEqual(classify_ip("0.0.0.0"), IPCategory.UNSPECIFIED)
        self.assertEqual(classify_ip("255.255.255.255"), IPCategory.RESERVED)

        # IPv6 classifications
        self.assertEqual(classify_ip("2001:4860:4860::8888"), IPCategory.PUBLIC)
        self.assertEqual(classify_ip("fd00::1"), IPCategory.RFC4193_UNIQUE_LOCAL)
        self.assertEqual(classify_ip("::1"), IPCategory.LOOPBACK)
        self.assertEqual(classify_ip("fe80::1"), IPCategory.LINK_LOCAL)
        self.assertEqual(classify_ip("ff02::1"), IPCategory.MULTICAST)
        self.assertEqual(classify_ip("::"), IPCategory.UNSPECIFIED)

        # Invalid strings
        self.assertEqual(classify_ip("not.an.ip"), IPCategory.INVALID)
        self.assertEqual(classify_ip(""), IPCategory.INVALID)
        self.assertEqual(classify_ip(None), IPCategory.INVALID)


if __name__ == "__main__":
    unittest.main()
