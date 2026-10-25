"""
Phase 10: Complete End-to-End Test Matrix & Cross-Phase Provenance Verification.
Validates the full benchmark matrix defined in Section 3 of Phase 10:
  Case 1: Clean HTTPS (https://example.com -> SAFE)
  Case 2: Direct IP + Login (https://192.168.1.10/login -> HIGH RISK)
  Case 3: Userinfo Masking (https://google.com@attacker.com/login -> HIGH RISK)
  Case 4: HTTP + Non-Standard Port (http://example.com:8080/browse -> REVIEW)
  Case 5: Typosquatting + Sensitive Path (https://g00gle.com/login -> HIGH RISK)
  Case 6: Typosquatting + HTTP (http://paypa1.com/index -> SUSPICIOUS)
  Case 7: Abnormal Scheme (javascript:alert(1) -> HIGH RISK)
  Case 8: Non-Standard Port (https://example.com:8443/browse -> REVIEW)
  Case 9: QR Clean URL (https://example.com via QR -> SAFE)
  Case 10: QR High-Risk URL (https://g00gle.com/login via QR -> HIGH RISK)
  Case 11: Non-URL QR Content (plain text -> Rejected from security analysis)

Also verifies Cross-Phase Provenance and Determinism under strict Zero-Network constraints.
"""
import io
import socket
import pytest
import qrcode

from core.application.analyze import analyze_url, analyze_qr_image, AnalysisReport
from core.parser.rfc_parser import parse_url
from core.features.fact_generator import extract_features
from core.logic.knowledge_base import KnowledgeBase
from core.logic.forward_chaining import pl_fc_entails
from core.risk.evaluator import evaluate_risk
from core.explanation.proof_tree import build_explanation
from core.search.astar import astar_string_distance, detect_brand_typosquatting
from core.search.brand_lexicon import BRAND_LEXICON


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Enforce strict offline operation across all benchmark tests."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def make_qr_bytes(text: str) -> bytes:
    """Helper to synthesize in-memory QR code bytes without network or disk."""
    qr = qrcode.QRCode(box_size=10, border=4)
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ==============================================================================
# BENCHMARK CASES 1 TO 11
# ==============================================================================

def test_case_01_clean_https():
    """
    CASE 1 — CLEAN HTTPS
    URL: https://example.com
    Expected:
      Verdict: SAFE
      Highest severity: NONE
      Expected behavior:
        - clean baseline rule fires
        - no anomaly patterns
        - SAFE disclaimer present
        - proof tree explains the clean baseline
        - no A* typosquatting evidence
    """
    report = analyze_url("https://example.com")
    assert report.verdict == "SAFE"
    assert report.highest_severity == "NONE"
    assert len(report.triggered_patterns) == 0
    assert report.safe_disclaimer is not None
    assert "Destination legitimacy cannot be guaranteed" in report.safe_disclaimer
    assert "No significant suspicious indicators were detected" in report.explanation

    # Verify clean baseline rule fired and is explained in proof tree
    assert "RULE_CLEAN_BASELINE" in report.proof_tree_text
    assert "zero_suspicious_indicators_present" in report.proof_tree_text
    assert len(report.triggered_rules) == 0  # No anomaly rules triggered

    # Verify no A* typosquatting evidence
    assert report.astar_evidence is None


def test_case_02_direct_ip_plus_login():
    """
    CASE 2 — DIRECT IP + LOGIN
    URL: https://192.168.1.10/login
    Expected:
      Verdict: HIGH RISK
      Highest severity: CRITICAL
      Expected rule: RULE_IP_AND_SENSITIVE_KEYWORD
      Expected pattern: pattern_credential_harvesting_on_ip
      Proof must contain: hostname_is_ip_address, path_contains_sensitive_keyword
    """
    report = analyze_url("https://192.168.1.10/login")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_credential_harvesting_on_ip" in report.triggered_patterns

    rule_ids = [r["rule_id"] for r in report.triggered_rules]
    assert "RULE_IP_AND_SENSITIVE_KEYWORD" in rule_ids

    # Proof must contain required premises
    assert "hostname_is_ip_address" in report.proof_tree_text
    assert "path_contains_sensitive_keyword" in report.proof_tree_text


def test_case_03_userinfo_masking():
    """
    CASE 3 — USERINFO MASKING
    URL: https://google.com@attacker.com/login
    Expected:
      Verdict: HIGH RISK
      Expected rule: RULE_USERINFO_DELIMITER
      Expected pattern: pattern_credential_masking
      Verify that the actual hostname is: attacker.com (not google.com)
      Verify that has_userinfo_delimiter is present.
    """
    report = analyze_url("https://google.com@attacker.com/login")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_credential_masking" in report.triggered_patterns

    rule_ids = [r["rule_id"] for r in report.triggered_rules]
    assert "RULE_USERINFO_DELIMITER" in rule_ids

    # Lexical decomposition verification: actual hostname is attacker.com
    assert report.parsed_components["hostname"] == "attacker.com"
    assert report.parsed_components["hostname"] != "google.com"

    # Verify has_userinfo_delimiter in proof tree and premises
    userinfo_rule = next(r for r in report.triggered_rules if r["rule_id"] == "RULE_USERINFO_DELIMITER")
    assert "has_userinfo_delimiter" in userinfo_rule["premises"]
    assert "has_userinfo_delimiter" in report.proof_tree_text


def test_case_04_http_non_standard_port():
    """
    CASE 4 — HTTP + NON-STANDARD PORT
    URL: http://example.com:8080/browse
    Expected:
      Verdict: REVIEW
      Highest severity: MEDIUM
      Expected patterns: pattern_unconventional_endpoint, pattern_insecure_transport_only
      Verify both proof branches remain visible.
      Verify MEDIUM determines the final verdict while LOW evidence is preserved.
    """
    report = analyze_url("http://example.com:8080/browse")
    assert report.verdict == "REVIEW"
    assert report.highest_severity == "MEDIUM"

    # Both patterns present
    assert "pattern_unconventional_endpoint" in report.triggered_patterns
    assert "pattern_insecure_transport_only" in report.triggered_patterns

    # Verify both proof branches remain visible
    assert "RULE_NON_STANDARD_PORT" in report.proof_tree_text
    assert "RULE_HTTP_INSECURE_TRANSPORT" in report.proof_tree_text

    # Verify MEDIUM determines final verdict while LOW evidence is preserved
    severities = [r["severity"] for r in report.triggered_rules]
    assert "MEDIUM" in severities
    assert "LOW" in severities


def test_case_05_typosquatting_sensitive_path():
    """
    CASE 5 — TYPOSQUATTING + SENSITIVE PATH
    URL: https://g00gle.com/login
    Expected:
      Verdict: HIGH RISK
      Expected chain:
        g00gle -> A* -> google -> brand_typosquatting_detected ->
        RULE_TYPOSQUATTING_SENSITIVE_KEYWORD -> pattern_targeted_brand_phishing ->
        CRITICAL -> HIGH RISK
      Verify A* evidence is present.
    """
    report = analyze_url("https://g00gle.com/login")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_targeted_brand_phishing" in report.triggered_patterns

    rule_ids = [r["rule_id"] for r in report.triggered_rules]
    assert "RULE_TYPOSQUATTING_SENSITIVE_KEYWORD" in rule_ids

    # Verify A* evidence
    assert report.astar_evidence is not None
    assert report.astar_evidence["observed_label"] == "g00gle"
    assert report.astar_evidence["matched_brand"] == "google"
    assert report.astar_evidence["edit_cost"] == 2
    assert "A* Heuristic Search (f(n) = g(n) + h(n))" in report.astar_evidence["algorithm"]


def test_case_06_typosquatting_http():
    """
    CASE 6 — TYPOSQUATTING + HTTP
    URL: http://paypa1.com/index
    Expected:
      Verdict: SUSPICIOUS
      Expected chain:
        paypa1 -> A* -> paypal -> brand_typosquatting_detected ->
        RULE_TYPOSQUATTING_INSECURE_HTTP -> pattern_insecure_brand_impersonation ->
        HIGH -> SUSPICIOUS
    """
    report = analyze_url("http://paypa1.com/index")
    assert report.verdict == "SUSPICIOUS"
    assert report.highest_severity == "HIGH"
    assert "pattern_insecure_brand_impersonation" in report.triggered_patterns

    rule_ids = [r["rule_id"] for r in report.triggered_rules]
    assert "RULE_TYPOSQUATTING_INSECURE_HTTP" in rule_ids

    assert report.astar_evidence is not None
    assert report.astar_evidence["observed_label"] == "paypa1"
    assert report.astar_evidence["matched_brand"] == "paypal"
    assert report.astar_evidence["edit_cost"] == 1


def test_case_07_abnormal_scheme():
    """
    CASE 7 — ABNORMAL SCHEME
    Test: javascript:alert(1)
    Verify:
      scheme_is_abnormal -> RULE_ABNORMAL_SCHEME -> pattern_abnormal_scheme ->
      CRITICAL -> HIGH RISK
    """
    report = analyze_url("javascript:alert(1)")
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_abnormal_scheme" in report.triggered_patterns

    rule_ids = [r["rule_id"] for r in report.triggered_rules]
    assert "RULE_ABNORMAL_SCHEME" in rule_ids
    assert "scheme_is_abnormal" in report.proof_tree_text


def test_case_08_non_standard_port():
    """
    CASE 8 — NON-STANDARD PORT
    Test: https://example.com:8443/browse
    Verify:
      has_non_standard_port -> RULE_NON_STANDARD_PORT ->
      pattern_unconventional_endpoint -> MEDIUM -> REVIEW
    """
    report = analyze_url("https://example.com:8443/browse")
    assert report.verdict == "REVIEW"
    assert report.highest_severity == "MEDIUM"
    assert "pattern_unconventional_endpoint" in report.triggered_patterns

    rule_ids = [r["rule_id"] for r in report.triggered_rules]
    assert "RULE_NON_STANDARD_PORT" in rule_ids
    assert "has_non_standard_port" in report.proof_tree_text


def test_case_09_qr_clean_url():
    """
    CASE 9 — QR CLEAN URL
    Valid QR containing: https://example.com
    Verify:
      QR -> decoder -> https://example.com -> analyze_url() -> SAFE
      The QR path must produce the same analysis semantics as direct URL input.
    """
    qr_data = make_qr_bytes("https://example.com")
    decode_res, report = analyze_qr_image(qr_data)

    assert decode_res.success is True
    assert decode_res.decoded_text == "https://example.com"
    assert report is not None
    assert report.verdict == "SAFE"
    assert report.highest_severity == "NONE"

    # Compare semantics directly with direct URL analyze_url()
    direct_report = analyze_url("https://example.com")
    assert report.verdict == direct_report.verdict
    assert report.highest_severity == direct_report.highest_severity
    assert report.triggered_patterns == direct_report.triggered_patterns


def test_case_10_qr_high_risk_url():
    """
    CASE 10 — QR HIGH-RISK URL
    Valid QR containing: https://g00gle.com/login
    Verify:
      QR -> decode -> A* -> brand_typosquatting_detected -> Forward Chaining ->
      pattern_targeted_brand_phishing -> HIGH RISK
    """
    qr_data = make_qr_bytes("https://g00gle.com/login")
    decode_res, report = analyze_qr_image(qr_data)

    assert decode_res.success is True
    assert decode_res.decoded_text == "https://g00gle.com/login"
    assert report is not None
    assert report.verdict == "HIGH RISK"
    assert report.highest_severity == "CRITICAL"
    assert "pattern_targeted_brand_phishing" in report.triggered_patterns
    assert report.astar_evidence is not None
    assert report.astar_evidence["matched_brand"] == "google"


def test_case_11_non_url_qr_content():
    """
    CASE 11 — NON-URL QR CONTENT
    QR containing ordinary text.
    Verify:
      QR decoding succeeds BUT security analysis is NOT performed.
      The system must NOT classify the content as SAFE.
      Expected behavior:
      "QR code decoded successfully, but the content is not a URL that this analyzer can process."
    """
    qr_data = make_qr_bytes("This is plain contact information, not a URL.")
    decode_res, report = analyze_qr_image(qr_data)

    assert decode_res.success is True
    assert decode_res.decoded_text == "This is plain contact information, not a URL."
    assert report is None
    assert decode_res.error == "QR code decoded successfully, but the content is not a URL that this analyzer can process."


# ==============================================================================
# CROSS-PHASE PROVENANCE & DETERMINISM
# ==============================================================================

def test_provenance_full_pipeline_trace():
    """
    Section 4 Cross-Phase Provenance:
    Verifies that initial facts, Horn rules, derived patterns, severities,
    and proof tree match exact DerivationStep records without invented deductions.
    """
    target_url = "https://192.168.1.10/login"
    parsed = parse_url(target_url)
    features = extract_features(parsed)
    kb = KnowledgeBase()
    kb.load_default_rules()
    inference = pl_fc_entails(kb, features.facts)
    assessment = evaluate_risk(inference, kb)
    explanation = build_explanation(assessment, inference, kb, features.evidence)

    # Initial facts must contain positive literals
    assert "hostname_is_ip_address" in features.facts
    assert "path_contains_sensitive_keyword" in features.facts

    # Forward chaining derivations
    assert len(inference.fired_rules) > 0
    step = next(s for s in inference.fired_rules if s.rule_id == "RULE_IP_AND_SENSITIVE_KEYWORD")
    assert step.conclusion == "pattern_credential_harvesting_on_ip"
    assert step.severity == "CRITICAL"
    assert "hostname_is_ip_address" in step.premises
    assert "path_contains_sensitive_keyword" in step.premises

    # Proof tree root node should reflect the highest severity pattern
    root = explanation.root_nodes[0]
    assert root.fact == "pattern_credential_harvesting_on_ip"
    assert root.rule_id == "RULE_IP_AND_SENSITIVE_KEYWORD"
    assert root.severity == "CRITICAL"


def test_determinism_multi_run_consistency():
    """
    Section 13 Determinism Audit:
    Runs parser, feature generator, Forward Chaining, A*, risk evaluator,
    proof tree, and complete analyze_url repeatedly.
    Verifies identical outputs across multiple invocations.
    """
    test_urls = [
        "https://example.com",
        "https://192.168.1.10/login",
        "https://g00gle.com/login",
        "http://paypa1.com/index",
        "http://example.com:8080/browse",
        "javascript:alert(1)",
    ]

    for url in test_urls:
        first_report = analyze_url(url)
        for _ in range(5):
            subsequent_report = analyze_url(url)
            assert subsequent_report.verdict == first_report.verdict
            assert subsequent_report.highest_severity == first_report.highest_severity
            assert subsequent_report.triggered_patterns == first_report.triggered_patterns
            assert subsequent_report.proof_tree_text == first_report.proof_tree_text
            assert subsequent_report.astar_evidence == first_report.astar_evidence
