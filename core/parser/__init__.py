"""
Deterministic Offline URL Parser module conforming to RFC 3986.
"""
from core.parser.rfc_parser import ParsedURL, parse_url
from core.parser.ip_detector import classify_host, HostClassification

__all__ = ["ParsedURL", "parse_url", "classify_host", "HostClassification"]
