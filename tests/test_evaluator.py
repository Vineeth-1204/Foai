"""
Phase 5 Unit Tests: Deterministic Risk Evaluator.
Verifies categorical mapping (SAFE, REVIEW, SUSPICIOUS, HIGH RISK),
severity resolution (highest severity wins), end-to-end pipeline execution,
safe disclaimers, and absence of probabilities or machine learning.
"""
import pytest
import socket
from core.parser import parse_url
from core.features import extract_features
from core.logic.clauses import HornClause, SeverityLevel
from core.logic.knowledge_base import KnowledgeBase
from core.logic.forward_chaining import pl_fc_entails
from core.risk.evaluator import (
    RiskAssessment,
    RiskVerdict,
    evaluate_risk,
    SAFE_DISCLAIMER,
)


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def run_pipeline(url: str, brand_typosquatting: bool = False) -> RiskAssessment:
    """Helper running the complete deterministic pipeline from Phase 1 through Phase 5."""
    parsed = parse_url(url)
    features = extract_features(parsed, brand_typosquatting=brand_typosquatting)
    kb = KnowledgeBase()
    kb.load_default_rules()
    inference = pl_fc_entails(kb, features.facts)
    return evaluate_risk(inference, kb)


# Test 1: Clean Baseline -> SAFE
def test_01_clean_baseline_evaluates_to_safe():
    assessment = run_pipeline("https://example.com")
    assert assessment.verdict == RiskVerdict.SAFE
    assert assessment.highest_severity == SeverityLevel.NONE
    assert assessment.triggered_patterns == []
    assert assessment.safe_disclaimer == SAFE_DISCLAIMER
    assert "No significant suspicious indicators" in assessment.explanation


# Test 2: LOW Pattern Only -> REVIEW
def test_02_low_pattern_only():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_LOW",
        name="Low Risk Rule",
        premises=("fact_low",),
        conclusion="pattern_low",
        severity=SeverityLevel.LOW,
        explanation="Low explanation",
    ))
    inference = pl_fc_entails(kb, ["fact_low"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.REVIEW
    assert assessment.highest_severity == SeverityLevel.LOW
    assert "pattern_low" in assessment.triggered_patterns


# Test 3: MEDIUM Pattern Only -> REVIEW
def test_03_medium_pattern_only():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_MED",
        name="Medium Risk Rule",
        premises=("fact_med",),
        conclusion="pattern_medium",
        severity=SeverityLevel.MEDIUM,
        explanation="Medium explanation",
    ))
    inference = pl_fc_entails(kb, ["fact_med"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.REVIEW
    assert assessment.highest_severity == SeverityLevel.MEDIUM


# Test 4: HIGH Pattern Only -> SUSPICIOUS
def test_04_high_pattern_only():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_HIGH",
        name="High Risk Rule",
        premises=("fact_high",),
        conclusion="pattern_high",
        severity=SeverityLevel.HIGH,
        explanation="High explanation",
    ))
    inference = pl_fc_entails(kb, ["fact_high"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.SUSPICIOUS
    assert assessment.highest_severity == SeverityLevel.HIGH


# Test 5: CRITICAL Pattern Only -> HIGH RISK
def test_05_critical_pattern_only():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_CRIT",
        name="Critical Risk Rule",
        premises=("fact_crit",),
        conclusion="pattern_critical",
        severity=SeverityLevel.CRITICAL,
        explanation="Critical explanation",
    ))
    inference = pl_fc_entails(kb, ["fact_crit"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.HIGH_RISK
    assert assessment.highest_severity == SeverityLevel.CRITICAL


# Test 6: LOW + MEDIUM -> REVIEW
def test_06_low_plus_medium_yields_review():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_LOW",
        name="Low Rule",
        premises=("fact_low",),
        conclusion="pattern_low",
        severity=SeverityLevel.LOW,
        explanation="Low",
    ))
    kb.add_rule(HornClause(
        rule_id="R_MED",
        name="Med Rule",
        premises=("fact_med",),
        conclusion="pattern_med",
        severity=SeverityLevel.MEDIUM,
        explanation="Med",
    ))
    inference = pl_fc_entails(kb, ["fact_low", "fact_med"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.REVIEW
    assert assessment.highest_severity == SeverityLevel.MEDIUM
    assert len(assessment.triggered_patterns) == 2


# Test 7: MEDIUM + HIGH -> SUSPICIOUS
def test_07_medium_plus_high_yields_suspicious():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_MED",
        name="Med Rule",
        premises=("fact_med",),
        conclusion="pattern_med",
        severity=SeverityLevel.MEDIUM,
        explanation="Med",
    ))
    kb.add_rule(HornClause(
        rule_id="R_HIGH",
        name="High Rule",
        premises=("fact_high",),
        conclusion="pattern_high",
        severity=SeverityLevel.HIGH,
        explanation="High",
    ))
    inference = pl_fc_entails(kb, ["fact_med", "fact_high"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.SUSPICIOUS
    assert assessment.highest_severity == SeverityLevel.HIGH


# Test 8: HIGH + CRITICAL -> HIGH RISK
def test_08_high_plus_critical_yields_high_risk():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_HIGH",
        name="High Rule",
        premises=("fact_high",),
        conclusion="pattern_high",
        severity=SeverityLevel.HIGH,
        explanation="High",
    ))
    kb.add_rule(HornClause(
        rule_id="R_CRIT",
        name="Crit Rule",
        premises=("fact_crit",),
        conclusion="pattern_crit",
        severity=SeverityLevel.CRITICAL,
        explanation="Crit",
    ))
    inference = pl_fc_entails(kb, ["fact_high", "fact_crit"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.HIGH_RISK
    assert assessment.highest_severity == SeverityLevel.CRITICAL


# Test 9: Multiple Risks -> Highest Severity Wins
def test_09_multiple_risks_highest_wins():
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R1", name="R1", premises=("f1",), conclusion="p1", severity=SeverityLevel.LOW, explanation="e1"
    ))
    kb.add_rule(HornClause(
        rule_id="R2", name="R2", premises=("f2",), conclusion="p2", severity=SeverityLevel.MEDIUM, explanation="e2"
    ))
    kb.add_rule(HornClause(
        rule_id="R3", name="R3", premises=("f3",), conclusion="p3", severity=SeverityLevel.CRITICAL, explanation="e3"
    ))
    inference = pl_fc_entails(kb, ["f1", "f2", "f3"])
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict == RiskVerdict.HIGH_RISK
    assert assessment.highest_severity == SeverityLevel.CRITICAL
    assert len(assessment.triggered_patterns) == 3


# Test 10: Triggered Rule Provenance is Preserved
def test_10_rule_provenance_preserved():
    kb = KnowledgeBase()
    kb.load_default_rules()
    inference = pl_fc_entails(kb, ["hostname_is_ip_address", "path_contains_sensitive_keyword"])
    assessment = evaluate_risk(inference, kb)

    assert len(assessment.triggered_rules) == 1
    assert assessment.triggered_rules[0].rule_id == "RULE_IP_AND_SENSITIVE_KEYWORD"
    assert assessment.triggered_rules[0].conclusion == "pattern_credential_harvesting_on_ip"


# Test 11: SAFE Disclaimer Exists on Safe Verdict
def test_11_safe_disclaimer():
    assessment = run_pipeline("https://example.com")
    assert assessment.verdict == RiskVerdict.SAFE
    assert assessment.safe_disclaimer is not None
    assert "Destination legitimacy cannot be guaranteed" in assessment.safe_disclaimer


# Test 12: No Floating-Point Confidence or Probability
def test_12_no_floating_confidence_scores():
    assessment = run_pipeline("https://192.168.1.10/login")
    assert not hasattr(assessment, "confidence")
    assert not hasattr(assessment, "probability")
    assert not hasattr(assessment, "score")


# ==============================================================================
# End-to-End Project Pipeline Tests
# ==============================================================================

def test_e2e_a_legitimate_url_is_safe():
    """End-to-End A: https://example.com -> SAFE"""
    assessment = run_pipeline("https://example.com")
    assert assessment.verdict == RiskVerdict.SAFE
    assert assessment.highest_severity == SeverityLevel.NONE


def test_e2e_b_ip_with_login_is_high_risk():
    """End-to-End B: https://192.168.1.10/login -> HIGH RISK (Credential harvesting via raw IP)"""
    assessment = run_pipeline("https://192.168.1.10/login")
    assert assessment.verdict == RiskVerdict.HIGH_RISK
    assert assessment.highest_severity == SeverityLevel.CRITICAL
    assert "pattern_credential_harvesting_on_ip" in assessment.triggered_patterns


def test_e2e_c_userinfo_masking_is_high_risk():
    """End-to-End C: https://google.com@attacker.com/login -> HIGH RISK (Userinfo masking)"""
    assessment = run_pipeline("https://google.com@attacker.com/login")
    assert assessment.verdict == RiskVerdict.HIGH_RISK
    assert assessment.highest_severity == SeverityLevel.CRITICAL
    assert "pattern_credential_masking" in assessment.triggered_patterns


def test_e2e_d_http_non_standard_port_is_review():
    """
    End-to-End D: http://example.com:8080/browse -> REVIEW
    (Fires non-standard port [MEDIUM] and plain http transport [LOW] -> max severity MEDIUM -> REVIEW)
    """
    assessment = run_pipeline("http://example.com:8080/browse")
    assert assessment.verdict == RiskVerdict.REVIEW
    assert assessment.highest_severity == SeverityLevel.MEDIUM
    assert "pattern_unconventional_endpoint" in assessment.triggered_patterns
    assert "pattern_insecure_transport_only" in assessment.triggered_patterns


def test_e2e_e_typosquatting_with_insecure_http_is_suspicious():
    """
    End-to-End E: Typosquatted brand on HTTP -> SUSPICIOUS
    (Manually supplying brand_typosquatting=True until Phase 7 A* is built)
    """
    assessment = run_pipeline("http://paypa1.com/index", brand_typosquatting=True)
    assert assessment.verdict == RiskVerdict.SUSPICIOUS
    assert assessment.highest_severity == SeverityLevel.HIGH
    assert "pattern_insecure_brand_impersonation" in assessment.triggered_patterns


def test_e2e_f_double_extension_is_high_risk():
    """Double extension payload -> HIGH RISK"""
    assessment = run_pipeline("https://example.com/invoice.pdf.exe")
    assert assessment.verdict == RiskVerdict.HIGH_RISK
    assert assessment.highest_severity == SeverityLevel.CRITICAL
    assert "pattern_executable_masquerading" in assessment.triggered_patterns
