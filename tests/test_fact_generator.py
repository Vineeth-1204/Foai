"""
Phase 2 Unit Tests: Deterministic Feature & Fact Generator.
Verifies the extraction of the 12 base characteristics into positive propositional facts,
evidence gathering, zero network calls, and absence of risk classification.
"""
import pytest
import socket
from core.parser import parse_url
from core.features import extract_features, FeatureResult


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard: raises exception on any network/DNS attempt."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def test_standard_https_clean_url():
    """Verify clean HTTPS URL produces all positive baseline clean facts."""
    url = "https://example.com"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert isinstance(res, FeatureResult)
    expected_facts = {
        "hostname_is_domain_name",
        "no_userinfo_delimiter",
        "scheme_is_https",
        "scheme_is_standard_web",
        "path_has_no_sensitive_keyword",
        "has_standard_port",
        "normal_subdomain_depth",
        "has_standard_encoding",
        "no_open_redirect_parameter",
        "no_double_extension",
        "no_brand_typosquatting",
        "valid_url_syntax",
    }
    assert res.facts == expected_facts
    assert res.evidence["scheme"] == "https"
    assert res.evidence["hostname"] == "example.com"
    assert res.evidence["is_ip"] is False
    assert res.evidence["has_userinfo"] is False
    assert res.evidence["sensitive_keywords"] == []


def test_standard_http():
    """Verify HTTP scheme generates scheme_is_http."""
    url = "http://example.com"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "scheme_is_http" in res.facts
    assert "scheme_is_standard_web" in res.facts
    assert "scheme_is_https" not in res.facts


def test_ip_and_sensitive_keyword():
    """Verify IP hostname and path sensitive keyword extraction."""
    url = "https://192.168.1.1/login"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "hostname_is_ip_address" in res.facts
    assert "hostname_is_domain_name" not in res.facts
    assert "path_contains_sensitive_keyword" in res.facts
    assert "path_has_no_sensitive_keyword" not in res.facts
    assert res.evidence["is_ip"] is True
    assert "login" in res.evidence["sensitive_keywords"]


def test_userinfo_in_authority():
    """Verify credentials and userinfo delimiter detection."""
    url = "https://user:pass@example.com/login"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "has_userinfo_delimiter" in res.facts
    assert "no_userinfo_delimiter" not in res.facts
    assert res.evidence["has_userinfo"] is True


def test_userinfo_phishing_pattern():
    """Verify userinfo @ masking detection."""
    url = "https://google.com@attacker.com/login"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "has_userinfo_delimiter" in res.facts
    assert "path_contains_sensitive_keyword" in res.facts
    assert res.evidence["hostname"] == "attacker.com"
    assert res.evidence["has_userinfo"] is True


def test_non_standard_port():
    """Verify non-standard port detection."""
    url = "https://example.com:8080/test"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "has_non_standard_port" in res.facts
    assert "has_standard_port" not in res.facts
    assert res.evidence["non_standard_port"] == 8080


def test_deep_path_is_not_subdomain():
    """Verify deep path /a/b/c/d/e does not trigger excessive subdomain depth."""
    url = "https://example.com/a/b/c/d/e"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "normal_subdomain_depth" in res.facts
    assert "excessive_subdomain_depth" not in res.facts
    assert res.evidence["subdomain_depth"] == 0


def test_excessive_subdomain_depth():
    """Verify host with >3 subdomains triggers excessive_subdomain_depth."""
    url = "https://a.b.c.d.example.com"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "excessive_subdomain_depth" in res.facts
    assert "normal_subdomain_depth" not in res.facts
    assert res.evidence["subdomain_depth"] == 4


def test_open_redirect_parameter():
    """Verify open redirect query parameter detection."""
    url = "https://example.com/login?redirect=https://other.com"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "has_open_redirect_parameter" in res.facts
    assert "no_open_redirect_parameter" not in res.facts
    assert res.evidence["redirect_info"] is not None
    assert res.evidence["redirect_info"]["param"] == "redirect"


def test_double_extension_detected():
    """Verify malicious double extension .pdf.exe detection."""
    url = "https://example.com/document.pdf.exe"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "has_double_extension" in res.facts
    assert "no_double_extension" not in res.facts
    assert res.evidence["double_extension"] == ".pdf.exe"


def test_single_extension_not_double_extension():
    """Verify normal file.pdf does NOT trigger double extension."""
    url = "https://example.com/file.pdf"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "no_double_extension" in res.facts
    assert "has_double_extension" not in res.facts


def test_abnormal_scheme_javascript():
    """Verify abnormal scheme javascript: detection."""
    url = "javascript:alert(1)"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "scheme_is_abnormal" in res.facts
    assert "scheme_is_standard_web" not in res.facts
    assert res.evidence["abnormal_scheme"] == "javascript"


def test_abnormal_scheme_data():
    """Verify abnormal scheme data: detection."""
    url = "data:text/html,test"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "scheme_is_abnormal" in res.facts
    assert "scheme_is_standard_web" not in res.facts


def test_non_web_scheme_ftp():
    """Verify ftp:// scheme is abnormal / non-web."""
    url = "ftp://example.com/file"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "scheme_is_abnormal" in res.facts
    assert "scheme_is_standard_web" not in res.facts


def test_punycode_detection():
    """Verify punycode xn-- detection."""
    url = "https://xn--example-9za.com"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "has_punycode" in res.facts
    assert "has_standard_encoding" not in res.facts
    assert res.evidence["has_punycode"] is True


def test_brand_typosquatting_passthrough():
    """Verify brand typosquatting external flag passthrough."""
    url = "https://paypa1.com"
    parsed = parse_url(url)

    # When False
    res_false = extract_features(parsed, brand_typosquatting=False)
    assert "no_brand_typosquatting" in res_false.facts
    assert "brand_typosquatting_detected" not in res_false.facts

    # When True (as supplied from Phase 7)
    res_true = extract_features(parsed, brand_typosquatting=True)
    assert "brand_typosquatting_detected" in res_true.facts
    assert "no_brand_typosquatting" not in res_true.facts


def test_multiple_sensitive_keywords_in_path():
    """Verify multiple sensitive keywords (e.g. account and verify)."""
    url = "https://example.com/account/verify"
    parsed = parse_url(url)
    res = extract_features(parsed)

    assert "path_contains_sensitive_keyword" in res.facts
    assert "account" in res.evidence["sensitive_keywords"]
    assert "verify" in res.evidence["sensitive_keywords"]


def test_absence_of_inference_and_verdicts():
    """Verify strict phase boundary: NO risk verdict or scoring exists in FeatureResult."""
    url = "https://192.168.1.1/login"
    parsed = parse_url(url)
    res = extract_features(parsed)

    # Confirm result object has only facts, evidence, and parsed_url
    assert hasattr(res, "facts")
    assert hasattr(res, "evidence")
    assert hasattr(res, "parsed_url")
    assert not hasattr(res, "verdict")
    assert not hasattr(res, "score")
    assert not hasattr(res, "risk_level")
    for f in res.facts:
        assert f not in {"SAFE", "REVIEW", "SUSPICIOUS", "HIGH RISK"}
