"""
Deterministic, offline RFC 3986 URL Parser.
Strictly performs lexical and syntactic decomposition.
Never makes network connections, DNS queries, or system calls.
"""
from dataclasses import dataclass
import re
from typing import Optional
from urllib.parse import urlsplit

from core.parser.ip_detector import classify_host, HostClassification, strip_brackets


# RFC 3986 Scheme pattern: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")

# Standard Web Schemes
_STANDARD_WEB_SCHEMES = frozenset({"http", "https"})

# Known dangerous / abnormal / non-web schemes
_ABNORMAL_SCHEMES = frozenset({
    "javascript",
    "data",
    "file",
    "vbscript",
    "blob",
    "about",
    "ftp",
    "sftp",
    "ws",
    "wss",
    "view-source",
    "chrome",
    "edge",
    "ms-windows-store",
})


@dataclass(frozen=True)
class ParsedURL:
    """
    Structured, immutable representation of a parsed URL.
    Contains all lexical components and deterministic classification flags.
    """
    original_url: str
    scheme: str
    hostname: Optional[str]
    port: Optional[int]
    username: Optional[str]
    password: Optional[str]
    pathname: str
    query: str
    fragment: str
    authority: str
    is_valid: bool

    # Host classification flags
    is_ipv4: bool
    is_ipv6: bool
    is_domain: bool
    is_missing_or_invalid_host: bool

    # Scheme classification flags
    is_standard_web_scheme: bool
    is_abnormal_scheme: bool

    @property
    def has_userinfo(self) -> bool:
        """Returns True if the authority section contains a userinfo delimiter ('@')."""
        return "@" in self.authority


def _extract_authority_components(authority: str) -> tuple[Optional[str], Optional[str], Optional[str], Optional[int]]:
    """
    Deterministically decomposes an authority string [userinfo@]host[:port].
    Returns (username, password, raw_host, port).
    """
    if not authority:
        return None, None, None, None

    # Handle userinfo if '@' is present
    userinfo = None
    host_port = authority
    if "@" in authority:
        # According to RFC 3986, host is after the last '@' in authority
        userinfo, host_port = authority.rsplit("@", 1)

    username = None
    password = None
    if userinfo is not None:
        if ":" in userinfo:
            username, password = userinfo.split(":", 1)
        else:
            username = userinfo

    # Parse host_port
    raw_host = None
    port = None

    if host_port.startswith("["):
        # Bracketed IPv6: e.g. [::1] or [::1]:8080
        closing_idx = host_port.find("]")
        if closing_idx != -1:
            raw_host = host_port[:closing_idx + 1]
            remainder = host_port[closing_idx + 1:]
            if remainder.startswith(":"):
                port_str = remainder[1:]
                if port_str.isdigit():
                    port_val = int(port_str)
                    if 1 <= port_val <= 65535:
                        port = port_val
        else:
            # Malformed bracketed host
            raw_host = host_port
    else:
        # Normal host or IPv4
        if ":" in host_port:
            host_candidate, port_str = host_port.rsplit(":", 1)
            raw_host = host_candidate
            if port_str.isdigit():
                port_val = int(port_str)
                if 1 <= port_val <= 65535:
                    port = port_val
        else:
            raw_host = host_port

    return username, password, raw_host, port


def parse_url(url: str) -> ParsedURL:
    """
    Lexically decomposes a URL string into a ParsedURL structure.
    Never executes network calls or DNS resolutions.
    """
    if url is None:
        url = ""

    cleaned_url = url.strip()

    # Empty string is invalid
    if not cleaned_url:
        return ParsedURL(
            original_url=url,
            scheme="",
            hostname=None,
            port=None,
            username=None,
            password=None,
            pathname="",
            query="",
            fragment="",
            authority="",
            is_valid=False,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid_host=True,
            is_standard_web_scheme=False,
            is_abnormal_scheme=False,
        )

    # Check for whitespace inside URL (RFC 3986 forbids raw unencoded whitespace)
    if any(ch in cleaned_url for ch in " \t\r\n"):
        return ParsedURL(
            original_url=url,
            scheme="",
            hostname=None,
            port=None,
            username=None,
            password=None,
            pathname="",
            query="",
            fragment="",
            authority="",
            is_valid=False,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid_host=True,
            is_standard_web_scheme=False,
            is_abnormal_scheme=False,
        )

    try:
        split_result = urlsplit(cleaned_url)
    except Exception:
        return ParsedURL(
            original_url=url,
            scheme="",
            hostname=None,
            port=None,
            username=None,
            password=None,
            pathname="",
            query="",
            fragment="",
            authority="",
            is_valid=False,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid_host=True,
            is_standard_web_scheme=False,
            is_abnormal_scheme=False,
        )

    scheme = split_result.scheme.lower()

    # Validate scheme format
    if not scheme or not _SCHEME_PATTERN.match(scheme):
        return ParsedURL(
            original_url=url,
            scheme=scheme,
            hostname=None,
            port=None,
            username=None,
            password=None,
            pathname=split_result.path,
            query=split_result.query,
            fragment=split_result.fragment,
            authority=split_result.netloc,
            is_valid=False,
            is_ipv4=False,
            is_ipv6=False,
            is_domain=False,
            is_missing_or_invalid_host=True,
            is_standard_web_scheme=False,
            is_abnormal_scheme=bool(scheme),
        )

    is_standard_web = scheme in _STANDARD_WEB_SCHEMES
    is_abnormal = (scheme in _ABNORMAL_SCHEMES) or (not is_standard_web)

    authority = split_result.netloc
    pathname = split_result.path
    query = split_result.query
    fragment = split_result.fragment

    # Extract userinfo, host, port
    username, password, raw_host, port = _extract_authority_components(authority)

    # Classify Host
    host_class = classify_host(raw_host)

    # Determine URL validity
    # For standard web schemes, a valid host is mandatory.
    # For non-web/abnormal schemes (e.g. javascript:, data:, mailto:), missing host may be syntactically valid for that URI scheme.
    is_valid = True
    if is_standard_web and host_class.is_missing_or_invalid:
        is_valid = False

    return ParsedURL(
        original_url=url,
        scheme=scheme,
        hostname=host_class.normalized_host,
        port=port,
        username=username,
        password=password,
        pathname=pathname,
        query=query,
        fragment=fragment,
        authority=authority,
        is_valid=is_valid,
        is_ipv4=host_class.is_ipv4,
        is_ipv6=host_class.is_ipv6,
        is_domain=host_class.is_domain,
        is_missing_or_invalid_host=host_class.is_missing_or_invalid,
        is_standard_web_scheme=is_standard_web,
        is_abnormal_scheme=is_abnormal,
    )
