"""IP address validation, classification, and routing categorization utilities.

This module provides cybersecurity-aware IP address parsing and classification
based on Python's standard library `ipaddress`. It distinguishes between RFC 1918
private addresses, RFC 4193 unique-local IPv6 addresses, loopback, link-local,
multicast, and globally routable public addresses.

Cybersecurity design notes:
- Private network addresses are standard, valid internal traffic and are never rejected.
- Address classification is decoupled from threat scoring (private != benign, public != malicious).
- Loopback, link-local, and multicast addresses are categorized separately from standard RFC 1918 networks.
- External threat intelligence lookup engines (such as TinyFish) must only be queried
  with validated, globally routable public indicators.
"""

from enum import Enum
import ipaddress
from typing import Optional, Union


class IPCategory(str, Enum):
    """Categorical classification of an IP address."""

    PUBLIC = "PUBLIC"
    RFC1918_PRIVATE = "RFC1918_PRIVATE"
    RFC4193_UNIQUE_LOCAL = "RFC4193_UNIQUE_LOCAL"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    CARRIER_GRADE_NAT = "CARRIER_GRADE_NAT"
    RESERVED = "RESERVED"
    UNSPECIFIED = "UNSPECIFIED"
    INVALID = "INVALID"


# Pre-computed network objects for high-throughput classification
_RFC1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

_RFC4193_NETWORK = ipaddress.IPv6Network("fc00::/7")
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")


def parse_ip_address(
    address: Union[str, int, ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Safely parse an address into an ipaddress object without raising exceptions.

    Args:
        address: The candidate IP address string, int, or IP object.

    Returns:
        IPv4Address or IPv6Address if valid, otherwise None.
    """
    if address is None:
        return None
    if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return address
    try:
        clean_str = str(address).strip()
        if not clean_str:
            return None
        return ipaddress.ip_address(clean_str)
    except (ValueError, TypeError, AttributeError):
        return None


def is_valid_ip(address: Union[str, int]) -> bool:
    """Check if the provided input is a valid IPv4 or IPv6 address."""
    return parse_ip_address(address) is not None


def is_valid_ipv4(address: Union[str, int]) -> bool:
    """Check if the input is a valid IPv4 address."""
    obj = parse_ip_address(address)
    return isinstance(obj, ipaddress.IPv4Address)


def is_valid_ipv6(address: Union[str, int]) -> bool:
    """Check if the input is a valid IPv6 address."""
    obj = parse_ip_address(address)
    return isinstance(obj, ipaddress.IPv6Address)


def is_rfc1918_private(address: Union[str, int]) -> bool:
    """Check if an IPv4 address falls within RFC 1918 private ranges.

    Ranges:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

    Returns False for IPv6, loopback, link-local, multicast, or invalid addresses.
    """
    obj = parse_ip_address(address)
    if not isinstance(obj, ipaddress.IPv4Address):
        return False
    return any(obj in net for net in _RFC1918_NETWORKS)


def is_rfc4193_unique_local(address: Union[str, int]) -> bool:
    """Check if an IPv6 address is an RFC 4193 Unique Local Address (fc00::/7).

    Returns False for IPv4 or non-RFC4193 addresses.
    """
    obj = parse_ip_address(address)
    if not isinstance(obj, ipaddress.IPv6Address):
        return False
    return obj in _RFC4193_NETWORK


def is_public_ip(address: Union[str, int]) -> bool:
    """Check if an IP address is globally routable on the public Internet.

    Excludes:
    - RFC 1918 private IPv4 networks
    - RFC 4193 unique-local IPv6 networks
    - Loopback (127.0.0.0/8, ::1)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Carrier-grade NAT (100.64.0.0/10)
    - Reserved and unspecified addresses (0.0.0.0, 255.255.255.255, ::, etc.)
    - Invalid addresses
    """
    category = classify_ip(address)
    return category == IPCategory.PUBLIC


def is_routable_public_indicator(address: Union[str, int]) -> bool:
    """Determine whether an IP address is an external indicator suitable for threat intel.

    This is an alias with clear semantic intent for external threat intelligence
    enrichment workflows (e.g. TinyFish). It guarantees that internal, private,
    loopback, or reserved IPs are never sent to external investigation services.
    """
    return is_public_ip(address)


def classify_ip(address: Union[str, int]) -> IPCategory:
    """Categorize an IP address into its specific networking class.

    Args:
        address: Candidate IP address representation.

    Returns:
        IPCategory member indicating the classification.
    """
    obj = parse_ip_address(address)
    if obj is None:
        return IPCategory.INVALID

    # Unspecified (0.0.0.0 or ::)
    if obj.is_unspecified:
        return IPCategory.UNSPECIFIED

    # Loopback (127.0.0.0/8 or ::1)
    if obj.is_loopback:
        return IPCategory.LOOPBACK

    # Link-local (169.254.0.0/16 or fe80::/10)
    if obj.is_link_local:
        return IPCategory.LINK_LOCAL

    # Multicast (224.0.0.0/4 or ff00::/8)
    if obj.is_multicast:
        return IPCategory.MULTICAST

    # IPv4-specific classifications
    if isinstance(obj, ipaddress.IPv4Address):
        if any(obj in net for net in _RFC1918_NETWORKS):
            return IPCategory.RFC1918_PRIVATE
        if obj in _CGNAT_NETWORK:
            return IPCategory.CARRIER_GRADE_NAT
        if obj.is_reserved or str(obj) == "255.255.255.255":
            return IPCategory.RESERVED
        if obj.is_global:
            return IPCategory.PUBLIC
        return IPCategory.RESERVED

    # IPv6-specific classifications
    if isinstance(obj, ipaddress.IPv6Address):
        if obj in _RFC4193_NETWORK:
            return IPCategory.RFC4193_UNIQUE_LOCAL
        if obj.is_reserved:
            return IPCategory.RESERVED
        if obj.is_global:
            return IPCategory.PUBLIC
        return IPCategory.RESERVED

    return IPCategory.INVALID

