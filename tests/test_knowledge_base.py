"""
Phase 3 Unit Tests: Knowledge Base & Horn Clause Representation.
Verifies pure positive Horn clause validation, schema integrity, default rule loading,
rejection of malformed rules/negation, and absence of inference execution.
"""
import pytest
import socket
from core.logic.clauses import HornClause, SeverityLevel
from core.logic.knowledge_base import KnowledgeBase, RuleValidationError, validate_horn_clause


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def test_load_default_rules():
    """Verify loading default anomaly and clean baseline rules."""
    kb = KnowledgeBase()
    count = kb.load_default_rules()

    # 9 anomaly rules + 1 clean rule = 10 rules
    assert count == 10
    assert len(kb) == 10


def test_rule_ids_are_unique():
    """Verify that all default rules have unique IDs."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    rule_ids = [r.rule_id for r in kb.rules]
    assert len(rule_ids) == len(set(rule_ids))


def test_all_premises_and_conclusions_are_positive_literals():
    """Verify that all premises and conclusions are pure positive literals (no negation)."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    for rule in kb.rules:
        for premise in rule.premises:
            assert "not" not in premise.lower()
            assert "!" not in premise
            assert premise.isidentifier()
        assert "not" not in rule.conclusion.lower()
        assert "!" not in rule.conclusion
        assert rule.conclusion.isidentifier()


def test_r1_to_r9_structure():
    """Verify specific structures and severities of R1-R9."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    # R1
    r1 = kb.get_rule("RULE_IP_AND_SENSITIVE_KEYWORD")
    assert r1 is not None
    assert set(r1.premises) == {"hostname_is_ip_address", "path_contains_sensitive_keyword"}
    assert r1.conclusion == "pattern_credential_harvesting_on_ip"
    assert r1.severity == SeverityLevel.CRITICAL

    # R2
    r2 = kb.get_rule("RULE_USERINFO_DELIMITER")
    assert r2 is not None
    assert r2.premises == ("has_userinfo_delimiter",)
    assert r2.conclusion == "pattern_credential_masking"
    assert r2.severity == SeverityLevel.CRITICAL

    # R3
    r3 = kb.get_rule("RULE_TYPOSQUATTING_INSECURE_HTTP")
    assert r3 is not None
    assert set(r3.premises) == {"brand_typosquatting_detected", "scheme_is_http"}
    assert r3.conclusion == "pattern_insecure_brand_impersonation"
    assert r3.severity == SeverityLevel.HIGH

    # R4
    r4 = kb.get_rule("RULE_TYPOSQUATTING_SENSITIVE_KEYWORD")
    assert r4 is not None
    assert set(r4.premises) == {"brand_typosquatting_detected", "path_contains_sensitive_keyword"}
    assert r4.conclusion == "pattern_targeted_brand_phishing"
    assert r4.severity == SeverityLevel.CRITICAL

    # R5
    r5 = kb.get_rule("RULE_REDIRECT_EXCESSIVE_SUBDOMAINS")
    assert r5 is not None
    assert set(r5.premises) == {"has_open_redirect_parameter", "excessive_subdomain_depth"}
    assert r5.conclusion == "pattern_obfuscated_redirect_chain"
    assert r5.severity == SeverityLevel.HIGH

    # R6
    r6 = kb.get_rule("RULE_DOUBLE_EXTENSION")
    assert r6 is not None
    assert r6.premises == ("has_double_extension",)
    assert r6.conclusion == "pattern_executable_masquerading"
    assert r6.severity == SeverityLevel.CRITICAL

    # R7
    r7 = kb.get_rule("RULE_ABNORMAL_SCHEME")
    assert r7 is not None
    assert r7.premises == ("scheme_is_abnormal",)
    assert r7.conclusion == "pattern_abnormal_scheme"
    assert r7.severity == SeverityLevel.CRITICAL

    # R8
    r8 = kb.get_rule("RULE_HTTP_INSECURE_TRANSPORT")
    assert r8 is not None
    assert set(r8.premises) == {"scheme_is_http", "path_has_no_sensitive_keyword"}
    assert r8.conclusion == "pattern_insecure_transport_only"
    assert r8.severity == SeverityLevel.LOW

    # R9
    r9 = kb.get_rule("RULE_NON_STANDARD_PORT")
    assert r9 is not None
    assert r9.premises == ("has_non_standard_port",)
    assert r9.conclusion == "pattern_unconventional_endpoint"
    assert r9.severity == SeverityLevel.MEDIUM


def test_clean_baseline_rule_structure():
    """Verify clean baseline rule structure, premises, conclusion, and severity NONE."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    r_clean = kb.get_rule("RULE_CLEAN_BASELINE")
    assert r_clean is not None
    expected_clean_premises = {
        "valid_url_syntax",
        "hostname_is_domain_name",
        "no_userinfo_delimiter",
        "scheme_is_https",
        "path_has_no_sensitive_keyword",
        "has_standard_port",
        "normal_subdomain_depth",
        "has_standard_encoding",
        "no_open_redirect_parameter",
        "no_double_extension",
        "no_brand_typosquatting",
    }
    assert set(r_clean.premises) == expected_clean_premises
    assert r_clean.conclusion == "zero_suspicious_indicators_present"
    assert r_clean.severity == SeverityLevel.NONE


def test_reject_empty_premises():
    """Verify that a rule with empty premises is rejected."""
    kb = KnowledgeBase()
    with pytest.raises(RuleValidationError, match="at least one premise"):
        rule = HornClause(
            rule_id="RULE_EMPTY",
            name="Empty Premises Rule",
            premises=(),
            conclusion="some_fact",
            severity=SeverityLevel.LOW,
            explanation="Test explanation",
        )
        kb.add_rule(rule)


def test_reject_negation_in_premise():
    """Verify that negation syntax like NOT or ! is rejected."""
    kb = KnowledgeBase()

    # With 'not '
    with pytest.raises(RuleValidationError, match="contains negation"):
        rule1 = HornClause(
            rule_id="RULE_NEG_1",
            name="Negation Rule 1",
            premises=("not_safe",),
            conclusion="unsafe_fact",
            severity=SeverityLevel.HIGH,
            explanation="Test explanation",
        )
        kb.add_rule(rule1)

    # With '!'
    with pytest.raises(RuleValidationError, match="contains negation"):
        rule2 = HornClause(
            rule_id="RULE_NEG_2",
            name="Negation Rule 2",
            premises=("!is_secure",),
            conclusion="unsafe_fact",
            severity=SeverityLevel.HIGH,
            explanation="Test explanation",
        )
        kb.add_rule(rule2)


def test_reject_invalid_severity():
    """Verify that an invalid severity raises an error."""
    with pytest.raises(ValueError, match="Invalid severity"):
        HornClause(
            rule_id="RULE_BAD_SEV",
            name="Bad Severity Rule",
            premises=("valid_premise",),
            conclusion="valid_conclusion",
            severity="SUPER_CRITICAL",  # Not in SeverityLevel
            explanation="Test explanation",
        )


def test_reject_duplicate_rule_id():
    """Verify that duplicate rule IDs are rejected."""
    kb = KnowledgeBase()
    rule1 = HornClause(
        rule_id="RULE_DUP",
        name="Rule First",
        premises=("premise_a",),
        conclusion="fact_x",
        severity=SeverityLevel.LOW,
        explanation="First explanation",
    )
    rule2 = HornClause(
        rule_id="RULE_DUP",
        name="Rule Second",
        premises=("premise_b",),
        conclusion="fact_y",
        severity=SeverityLevel.MEDIUM,
        explanation="Second explanation",
    )
    kb.add_rule(rule1)
    with pytest.raises(RuleValidationError, match="Duplicate rule_id"):
        kb.add_rule(rule2)


def test_kb_does_not_perform_inference():
    """
    Verify Knowledge Base does NOT evaluate facts or perform inference.
    Loading KB yields 0 derived facts and no verdict attributes.
    """
    kb = KnowledgeBase()
    kb.load_default_rules()

    # KB only provides rule query and indexing methods
    assert not hasattr(kb, "infer")
    assert not hasattr(kb, "evaluate")
    assert not hasattr(kb, "verdict")
    assert not hasattr(kb, "forward_chain")

    # Confirm symbols extracted
    symbols = kb.symbols()
    assert "hostname_is_ip_address" in symbols
    assert "pattern_credential_harvesting_on_ip" in symbols

    # Confirm indexing
    rules_for_ip = kb.get_rules_triggered_by("hostname_is_ip_address")
    assert len(rules_for_ip) == 1
    assert rules_for_ip[0].rule_id == "RULE_IP_AND_SENSITIVE_KEYWORD"
