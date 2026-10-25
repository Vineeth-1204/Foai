"""
Phase 8 Unit Tests: Application Orchestration Service.
Verifies analyze_url() end-to-end for all required academic benchmark cases.
"""
import pytest
import socket
from core.application.analyze import analyze_url, AnalysisReport


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def test_01_app_legitimate_url_safe():
    """Test 1: https://example.com -> SAFE"""
    report = analyze_url("https://example.com")
    assert isinstance(report, AnalysisReport)
    assert report.verdict == "SAFE"
    assert report.highest_severity == "NONE"
    assert report.safe_disclaimer is not None
    assert "Destination legitimacy cannot be guaranteed" in report.safe_disclaimer
    assert report.astar_evidence is None


def test_02_app_ip_phishing_high_risk():
    """Test 2: https://192.168.1.10/login -> HIGH RISK"""
    report = analyze_url("https://192.168.1.10/login")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_credential_harvesting_on_ip" in report.triggered_patterns
    assert any(r["rule_id"] == "RULE_IP_AND_SENSITIVE_KEYWORD" for r in report.triggered_rules)


def test_03_app_userinfo_masking_high_risk():
    """Test 3: https://google.com@attacker.com/login -> HIGH RISK"""
    report = analyze_url("https://google.com@attacker.com/login")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_credential_masking" in report.triggered_patterns


def test_04_app_port_and_http_review():
    """Test 4: http://example.com:8080/browse -> REVIEW"""
    report = analyze_url("http://example.com:8080/browse")
    assert report.verdict == "REVIEW"
    assert report.highest_severity == "MEDIUM"
    assert "pattern_unconventional_endpoint" in report.triggered_patterns
    assert "pattern_insecure_transport_only" in report.triggered_patterns


def test_05_app_astar_typosquatting_phishing_high_risk():
    """
    Test 5: https://g00gle.com/login -> HIGH RISK
    Demonstrates A* -> brand_typosquatting_detected -> Forward Chaining -> pattern_targeted_brand_phishing -> HIGH RISK.
    """
    report = analyze_url("https://g00gle.com/login")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_targeted_brand_phishing" in report.triggered_patterns

    # Verify structured A* evidence is exposed
    assert report.astar_evidence is not None
    assert report.astar_evidence["observed_label"] == "g00gle"
    assert report.astar_evidence["matched_brand"] == "google"
    assert report.astar_evidence["edit_cost"] == 2
    assert len(report.astar_evidence["operations"]) > 0


def test_06_app_astar_insecure_brand_suspicious():
    """
    Test 6: http://paypa1.com/index -> SUSPICIOUS
    Demonstrates A* -> brand_typosquatting_detected -> Forward Chaining -> pattern_insecure_brand_impersonation -> SUSPICIOUS.
    """
    report = analyze_url("http://paypa1.com/index")
    assert report.verdict == "SUSPICIOUS"
    assert report.highest_severity == "HIGH"
    assert "pattern_insecure_brand_impersonation" in report.triggered_patterns
    assert report.astar_evidence is not None
    assert report.astar_evidence["matched_brand"] == "paypal"


def test_07_app_empty_input_handling():
    """Test 7: Empty or whitespace input handled cleanly without crashing."""
    report = analyze_url("   ")
    assert report.is_valid is False
    assert report.error is not None
    assert "URL input cannot be empty" in report.error
