"""
Deterministic, offline IP address and hostname analyzer.
Strictly relies on lexical/syntactic checks using Python's ipaddress module.
NEVER performs DNS lookups or creates network sockets.
"""
from dataclasses import dataclass
import ipaddress
import re
from typing import Optional


@dataclass(frozen=True)
class HostClassification:
    """Represents the deterministic classification of a raw hostname string."""
    raw_host: Optional[str]
    normalized_host: Optional[str]
    is_ipv4: bool
    is_ipv6: bool
    is_domain: bool
    is_missing_or_invalid: bool


# RFC 1035 / RFC 1123 Hostname Label Regex
# Each label: 1-63 chars, alphanumeric, internal hyphens allowed.
_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Standard dotted-quad IPv4 pattern (4 integer octets)
_IPV4_STRICT_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def strip_brackets(host: str) -> str:
    """Strip surrounding square brackets from IPv6 literal hostnames."""
    if host.startswith("[") and host.endswith("]") and len(host) >= 2:
        return host[1:-1]
    return host


def classify_host(raw_host: Optional[str]) -> HostClassification:
    """
    Deterministically classifies a hostname string into:
    - IPv4
    - IPv6 (including bracketed [::1])
    - Domain Name (RFC 1035 / RFC 1123 compliant)
    - Missing or Invalid

    Guarantees:
    - Pure syntactic analysis.
    - Zero network calls.
    - Zero DNS queries.
    """
    if raw_host is None:
        return HostClassification(
            raw_host=None,
            normalized_host=None,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid=True,
        )

    clean_host = raw_host.strip()
    if not clean_host:
        return HostClassification(
            raw_host=raw_host,
            normalized_host="",
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid=True,
        )

    # 1. Check for IPv6 (bracketed or raw)
    unbracketed = strip_brackets(clean_host)
    try:
        ipv6_obj = ipaddress.IPv6Address(unbracketed)
        return HostClassification(
            raw_host=raw_host,
            normalized_host=str(ipv6_obj),
            is_ipv4=False,
            is_ipv6=True,
            is_domain=False,
            is_missing_or_invalid=False,
        )
    except ValueError:
        pass

    # 2. Check for IPv4
    if _IPV4_STRICT_PATTERN.match(clean_host):
        try:
            ipv4_obj = ipaddress.IPv4Address(clean_host)
            return HostClassification(
                raw_host=raw_host,
                normalized_host=str(ipv4_obj),
                is_ipv4=True,
                is_ipv6=False,
                is_domain=False,
                is_missing_or_invalid=False,
            )
        except ValueError:
            # Matches pattern but octet > 255 (e.g. 999.999.999.999) -> invalid host
            return HostClassification(
                raw_host=raw_host,
                normalized_host=clean_host.lower(),
                is_ipv4=False,
                is_ipv6=False,
                is_domain=False,
                is_missing_or_invalid=True,
            )

    # 3. Check for Domain Name
    normalized = clean_host.lower()

    # Reject if whitespace or forbidden control / URI reserved characters in hostname
    if any(ch in normalized for ch in " /\\?#@:!$&'()*+,;=\"<>`{}|^[]"):
        return HostClassification(
            raw_host=raw_host,
            normalized_host=normalized,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid=True,
        )

    # Hostname overall length limit: 253 characters (RFC 1035)
    if len(normalized) > 253:
        return HostClassification(
            raw_host=raw_host,
            normalized_host=normalized,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid=True,
        )

    # Split domain into labels
    labels = normalized.split(".")
    # Trailing dot (e.g., example.com.) is valid in DNS, but strip for validation if present
    if len(labels) > 1 and labels[-1] == "":
        labels = labels[:-1]

    valid_labels = True
    for label in labels:
        if not label:
            valid_labels = False
            break
        # Allow punycode labels (xn--...) or standard RFC 1123 labels
        if not _DOMAIN_LABEL_REGEX.match(label):
            valid_labels = False
            break

    if valid_labels:
        return HostClassification(
            raw_host=raw_host,
            normalized_host=normalized,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=True,
            is_missing_or_invalid=False,
        )

    return HostClassification(
        raw_host=raw_host,
        normalized_host=normalized,
        is_ipv4=False,
        is_ipv6=False,
        is_domain=False,
        is_missing_or_invalid=True,
    )
