"""
Phase 1 Unit Tests: Deterministic Offline URL Parser.
Strictly verifies RFC 3986 lexical decomposition, IP classification, and ZERO network calls.
"""
import pytest
import socket
from core.parser import parse_url, ParsedURL


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """
    Enforces the zero-network constraint.
    Raises RuntimeError if any socket/DNS/network call is attempted.
    """
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "gethostbyname_ex", forbidden)
    monkeypatch.setattr(socket, "gethostbyaddr", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


# Test 1: Standard HTTPS URL
def test_case_01_standard_https():
    url = "https://example.com"
    p = parse_url(url)
    assert p.original_url == url
    assert p.scheme == "https"
    assert p.hostname == "example.com"
    assert p.port is None
    assert p.username is None
    assert p.password is None
    assert p.pathname in ("", "/")
    assert p.query == ""
    assert p.fragment == ""
    assert p.authority == "example.com"
    assert p.is_valid is True
    assert p.is_domain is True
    assert p.is_ipv4 is False
    assert p.is_ipv6 is False
    assert p.is_missing_or_invalid_host is False
    assert p.is_standard_web_scheme is True
    assert p.is_abnormal_scheme is False
    assert p.has_userinfo is False


# Test 2: Standard HTTP URL
def test_case_02_standard_http():
    url = "http://example.com"
    p = parse_url(url)
    assert p.original_url == url
    assert p.scheme == "http"
    assert p.hostname == "example.com"
    assert p.port is None
    assert p.username is None
    assert p.password is None
    assert p.pathname in ("", "/")
    assert p.query == ""
    assert p.fragment == ""
    assert p.authority == "example.com"
    assert p.is_valid is True
    assert p.is_domain is True
    assert p.is_ipv4 is False
    assert p.is_ipv6 is False
    assert p.is_missing_or_invalid_host is False
    assert p.is_standard_web_scheme is True
    assert p.is_abnormal_scheme is False


# Test 3: HTTPS with non-standard port and path
def test_case_03_https_with_port_and_path():
    url = "https://example.com:8080/path"
    p = parse_url(url)
    assert p.scheme == "https"
    assert p.hostname == "example.com"
    assert p.port == 8080
    assert p.pathname == "/path"
    assert p.authority == "example.com:8080"
    assert p.is_valid is True
    assert p.is_domain is True
    assert p.is_standard_web_scheme is True


# Test 4: Query string and fragment
def test_case_04_query_and_fragment():
    url = "https://example.com/login?user=test#section"
    p = parse_url(url)
    assert p.scheme == "https"
    assert p.hostname == "example.com"
    assert p.pathname == "/login"
    assert p.query == "user=test"
    assert p.fragment == "section"
    assert p.is_valid is True
    assert p.is_domain is True


# Test 5: Credentials in authority
def test_case_05_credentials_in_authority():
    url = "https://user:pass@example.com/login"
    p = parse_url(url)
    assert p.scheme == "https"
    assert p.username == "user"
    assert p.password == "pass"
    assert p.hostname == "example.com"
    assert p.authority == "user:pass@example.com"
    assert p.pathname == "/login"
    assert p.has_userinfo is True
    assert p.is_valid is True
    assert p.is_domain is True


# Test 6: IPv4 Hostname
def test_case_06_ipv4_hostname():
    url = "http://192.168.1.10/login"
    p = parse_url(url)
    assert p.scheme == "http"
    assert p.hostname == "192.168.1.10"
    assert p.is_ipv4 is True
    assert p.is_ipv6 is False
    assert p.is_domain is False
    assert p.is_missing_or_invalid_host is False
    assert p.pathname == "/login"
    assert p.is_valid is True


# Test 7: IPv6 Hostname with Port
def test_case_07_ipv6_hostname_with_port():
    url = "http://[::1]:8080/test"
    p = parse_url(url)
    assert p.scheme == "http"
    assert p.hostname == "::1"
    assert p.port == 8080
    assert p.is_ipv6 is True
    assert p.is_ipv4 is False
    assert p.is_domain is False
    assert p.is_missing_or_invalid_host is False
    assert p.pathname == "/test"
    assert p.is_valid is True


# Test 8: Non-Web Scheme (FTP)
def test_case_08_ftp_scheme():
    url = "ftp://example.com/file"
    p = parse_url(url)
    assert p.scheme == "ftp"
    assert p.hostname == "example.com"
    assert p.pathname == "/file"
    assert p.is_standard_web_scheme is False
    assert p.is_abnormal_scheme is True


# Test 9: Abnormal / Dangerous Scheme (javascript:)
def test_case_09_javascript_scheme():
    url = "javascript:alert(1)"
    p = parse_url(url)
    assert p.scheme == "javascript"
    assert p.hostname is None
    assert p.pathname == "alert(1)"
    assert p.is_standard_web_scheme is False
    assert p.is_abnormal_scheme is True
    assert p.is_missing_or_invalid_host is True


# Test 10: Malformed URL (spaces / no scheme)
def test_case_10_malformed_url():
    url = "malformed URL"
    p = parse_url(url)
    assert p.is_valid is False
    assert p.is_missing_or_invalid_host is True


# Test 11: Missing Hostname in HTTP URL
def test_case_11_missing_hostname():
    url = "http:///path"
    p = parse_url(url)
    assert p.scheme == "http"
    assert p.hostname is None or p.hostname == ""
    assert p.is_missing_or_invalid_host is True
    assert p.is_valid is False


# Test 12: URL with @ in Authority (Userinfo Phishing Pattern)
def test_case_12_at_in_authority():
    url = "https://google.com@attacker.com/login"
    p = parse_url(url)
    assert p.scheme == "https"
    assert p.authority == "google.com@attacker.com"
    assert p.username == "google.com"
    assert p.hostname == "attacker.com"
    assert p.has_userinfo is True
    assert p.pathname == "/login"
    assert p.is_valid is True


# Test 13: Strict Verification of Zero Network Calls
def test_zero_network_calls_safeguard():
    """Confirms that our test harness strictly prevents and detects any network attempts."""
    with pytest.raises(RuntimeError, match="SECURITY VIOLATION"):
        socket.gethostbyname("example.com")
