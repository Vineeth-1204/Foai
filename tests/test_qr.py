"""
Phase 9 Unit Tests: Offline QR Code Decoding.
Verifies offline local decoding using OpenCV:
- Accurate extraction of URLs from QR images
- Routing of decoded URLs into analyze_url()
- Detection of A* typosquatting and forward-chaining security patterns from QR payloads
- Non-URL content validation (not classified as safe)
- Rejection of ambiguous multi-code images
- Graceful handling of corrupted/blank images
- Determinism and zero network calls
"""
import io
import pytest
import socket
import numpy as np
from PIL import Image
import qrcode

from core.qr.decoder import decode_qr_image, QRDecodeResult
from core.application.analyze import analyze_qr_image, analyze_url


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def generate_qr_bytes(content: str) -> bytes:
    """Helper to synthesize in-memory QR code image bytes for testing."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(content)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def generate_multi_qr_bytes(text1: str, text2: str) -> bytes:
    """Helper to synthesize an image containing two distinct QR codes side-by-side."""
    qr1 = qrcode.make(text1).get_image()
    qr2 = qrcode.make(text2).get_image()
    w1, h1 = qr1.size
    w2, h2 = qr2.size
    combined = Image.new("RGB", (w1 + w2 + 60, max(h1, h2)), (255, 255, 255))
    combined.paste(qr1, (0, 0))
    combined.paste(qr2, (w1 + 60, 0))
    buf = io.BytesIO()
    combined.save(buf, format="PNG")
    return buf.getvalue()


# Test 1: Valid QR containing https://example.com -> exact text and SAFE
def test_01_valid_qr_example_com():
    url = "https://example.com"
    img_bytes = generate_qr_bytes(url)

    decoded = decode_qr_image(img_bytes)
    assert isinstance(decoded, QRDecodeResult)
    assert decoded.success is True
    assert decoded.decoded_text == url
    assert decoded.error is None

    # Full pipeline test
    _, report = analyze_qr_image(img_bytes)
    assert report is not None
    assert report.verdict == "SAFE"
    assert report.highest_severity == "NONE"


# Test 2: Valid QR containing https://192.168.1.10/login -> HIGH RISK
def test_02_valid_qr_ip_login_high_risk():
    url = "https://192.168.1.10/login"
    img_bytes = generate_qr_bytes(url)

    decoded, report = analyze_qr_image(img_bytes)
    assert decoded.success is True
    assert decoded.decoded_text == url
    assert report is not None
    assert report.verdict == "HIGH RISK"
    assert "pattern_credential_harvesting_on_ip" in report.triggered_patterns


# Test 3: Valid QR containing https://g00gle.com/login -> A* Typosquatting Phishing -> HIGH RISK
def test_03_valid_qr_typosquatting_phish_high_risk():
    url = "https://g00gle.com/login"
    img_bytes = generate_qr_bytes(url)

    decoded, report = analyze_qr_image(img_bytes)
    assert decoded.success is True
    assert decoded.decoded_text == url
    assert report is not None
    assert report.verdict == "HIGH RISK"
    assert "pattern_targeted_brand_phishing" in report.triggered_patterns
    assert report.astar_evidence is not None
    assert report.astar_evidence["matched_brand"] == "google"


# Test 4: Valid QR containing http://paypa1.com/index -> A* Insecure Brand -> SUSPICIOUS
def test_04_valid_qr_typosquatting_insecure_suspicious():
    url = "http://paypa1.com/index"
    img_bytes = generate_qr_bytes(url)

    decoded, report = analyze_qr_image(img_bytes)
    assert decoded.success is True
    assert report is not None
    assert report.verdict == "SUSPICIOUS"
    assert "pattern_insecure_brand_impersonation" in report.triggered_patterns


# Test 5: Invalid / Corrupted Image
def test_05_invalid_corrupted_image():
    corrupted_bytes = b"NOT_A_VALID_IMAGE_FILE_HEADER"
    decoded = decode_qr_image(corrupted_bytes)
    assert decoded.success is False
    assert decoded.decoded_text is None
    assert "Could not process image file" in decoded.error


# Test 6: Image with No QR Code (Blank White Image)
def test_06_blank_image_no_qr():
    blank = Image.new("RGB", (300, 300), (255, 255, 255))
    buf = io.BytesIO()
    blank.save(buf, format="PNG")

    decoded = decode_qr_image(buf.getvalue())
    assert decoded.success is False
    assert decoded.decoded_text is None
    assert "No valid QR code detected" in decoded.error


# Test 7: Non-URL QR Content (e.g. Plain Text)
def test_07_non_url_qr_content():
    plain_text = "Hello, this is a plain message not a URL"
    img_bytes = generate_qr_bytes(plain_text)

    decoded, report = analyze_qr_image(img_bytes)
    assert decoded.success is True
    assert decoded.decoded_text == plain_text
    assert decoded.error is not None
    assert "not a URL that this analyzer can process" in decoded.error
    assert report is None  # Analysis was NOT performed


# Test 8: Multiple QR Codes in Single Image -> Ambiguous Policy Rejection
def test_08_multiple_qr_codes_rejected():
    img_bytes = generate_multi_qr_bytes("https://example1.com", "https://example2.com")
    decoded = decode_qr_image(img_bytes)
    assert decoded.success is False
    assert "multiple QR codes detected" in decoded.error


# Test 9: Determinism Across Repeated Decodes
def test_09_determinism_of_qr_decoder():
    url = "https://g00gle.com/login"
    img_bytes = generate_qr_bytes(url)

    runs = [decode_qr_image(img_bytes) for _ in range(5)]
    first_text = runs[0].decoded_text
    for r in runs[1:]:
        assert r.success is True
        assert r.decoded_text == first_text
        assert r.error is None


# Test 10: Explicit End-to-End Test (QR Image -> Proof Tree Provenance)
def test_10_end_to_end_qr_pipeline():
    """
    Verifies full integration:
    QR Image
      -> Decoded: https://g00gle.com/login
      -> analyze_url()
      -> A* (g00gle -> google)
      -> brand_typosquatting_detected
      -> Forward Chaining (PL-FC-Entails)
      -> pattern_targeted_brand_phishing
      -> CRITICAL
      -> HIGH RISK
      -> Proof Tree
    """
    url = "https://g00gle.com/login"
    img_bytes = generate_qr_bytes(url)

    decoded, report = analyze_qr_image(img_bytes)
    assert decoded.success is True
    assert report is not None
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_targeted_brand_phishing" in report.triggered_patterns
    assert "A* Match: 'g00gle' -> 'google'" in report.proof_tree_text
