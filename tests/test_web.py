"""
Phase 8 Unit Tests: Flask Web Presentation Layer.
Verifies HTTP endpoints, JSON responses, error handling, and zero network calls.
"""
import pytest
import socket
from web.app import create_app


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


@pytest.fixture
def client():
    """Flask test client fixture."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_web_index_page(client):
    """Verify GET / renders the main HTML dashboard."""
    res = client.get("/")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Explainable URL & QR Risk Screening" in html
    assert "Offline Classical AI-based security analysis" in html
    assert "PL-FC-Entails (Primary)" in html


def test_web_api_analyze_safe(client):
    """Verify POST /api/analyze for safe URL."""
    res = client.post("/api/analyze", json={"url": "https://example.com"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] == "SAFE"
    assert data["highest_severity"] == "NONE"
    assert "Destination legitimacy cannot be guaranteed" in data["safe_disclaimer"]


def test_web_api_analyze_phishing(client):
    """Verify POST /api/analyze for phishing URL."""
    res = client.post("/api/analyze", json={"url": "https://192.168.1.10/login"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] == "HIGH RISK"
    assert data["highest_severity"] == "CRITICAL"
    assert "pattern_credential_harvesting_on_ip" in data["triggered_patterns"]


def test_web_api_analyze_astar_typosquatting(client):
    """Verify POST /api/analyze preserves structured A* evidence."""
    res = client.post("/api/analyze", json={"url": "https://g00gle.com/login"})
    assert res.status_code == 200
    data = res.get_json()
    assert data["verdict"] == "HIGH RISK"
    assert data["astar_evidence"] is not None
    assert data["astar_evidence"]["observed_label"] == "g00gle"
    assert data["astar_evidence"]["matched_brand"] == "google"
    assert data["astar_evidence"]["edit_cost"] == 2


def test_web_api_empty_input(client):
    """Verify POST /api/analyze handles empty input gracefully without 500 error."""
    res = client.post("/api/analyze", json={"url": ""})
    assert res.status_code == 200
    data = res.get_json()
    assert data["is_valid"] is False
    assert "URL input cannot be empty" in data["error"]
