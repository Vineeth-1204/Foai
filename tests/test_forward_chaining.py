"""
Phase 4 Unit Tests: PL-FC-Entails Forward-Chaining Inference Engine.
Verifies textbook forward-chaining mechanics:
- Agenda queue and count-table operations
- Single-premise, multi-premise, and multi-hop chained inferences
- Determinism, monotonicity, and cycle safety
- Default KB derivations (anomaly patterns and clean baseline)
- Derivation provenance tracking
- Absence of risk verdicts and zero network calls
"""
import pytest
import socket
from core.logic.clauses import HornClause, SeverityLevel
from core.logic.knowledge_base import KnowledgeBase
from core.logic.forward_chaining import pl_fc_entails, InferenceResult, DerivationStep


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def test_01_single_premise_rule():
    """Verify single-premise rule: A -> B."""
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_A_TO_B",
        name="A to B",
        premises=("fact_a",),
        conclusion="fact_b",
        severity=SeverityLevel.LOW,
        explanation="A implies B",
    ))

    res = pl_fc_entails(kb, ["fact_a"])
    assert "fact_b" in res.derived_facts
    assert res.all_inferred_facts == {"fact_a", "fact_b"}
    assert res.derivation_trace["fact_b"].rule_id == "R_A_TO_B"
    assert res.derivation_trace["fact_b"].premises == ("fact_a",)


def test_02_multi_premise_rule():
    """Verify multi-premise rule: A ^ B -> C."""
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_AB_TO_C",
        name="A and B to C",
        premises=("fact_a", "fact_b"),
        conclusion="fact_c",
        severity=SeverityLevel.MEDIUM,
        explanation="A and B imply C",
    ))

    # A alone should NOT infer C
    res_a = pl_fc_entails(kb, ["fact_a"])
    assert "fact_c" not in res_a.derived_facts
    assert "fact_c" not in res_a.all_inferred_facts

    # B alone should NOT infer C
    res_b = pl_fc_entails(kb, ["fact_b"])
    assert "fact_c" not in res_b.derived_facts

    # A + B together MUST infer C
    res_ab = pl_fc_entails(kb, ["fact_a", "fact_b"])
    assert "fact_c" in res_ab.derived_facts
    assert res_ab.all_inferred_facts == {"fact_a", "fact_b", "fact_c"}
    assert res_ab.derivation_trace["fact_c"].rule_id == "R_AB_TO_C"


def test_03_chained_multi_hop_inference():
    """Verify chained multi-hop inference: A -> B, B -> C."""
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_A_TO_B",
        name="A to B",
        premises=("fact_a",),
        conclusion="fact_b",
        severity=SeverityLevel.LOW,
        explanation="Step 1",
    ))
    kb.add_rule(HornClause(
        rule_id="R_B_TO_C",
        name="B to C",
        premises=("fact_b",),
        conclusion="fact_c",
        severity=SeverityLevel.HIGH,
        explanation="Step 2",
    ))

    res = pl_fc_entails(kb, ["fact_a"])
    assert res.all_inferred_facts == {"fact_a", "fact_b", "fact_c"}
    assert res.derived_facts == {"fact_b", "fact_c"}

    # Check chronological firing order
    step_b = res.derivation_trace["fact_b"]
    step_c = res.derivation_trace["fact_c"]
    assert step_b.fired_order == 1
    assert step_c.fired_order == 2


def test_04_multiple_independent_rules():
    """Verify multiple independent rules from the same premise: A -> B, A -> C."""
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_A_TO_B",
        name="A to B",
        premises=("fact_a",),
        conclusion="fact_b",
        severity=SeverityLevel.LOW,
        explanation="A to B",
    ))
    kb.add_rule(HornClause(
        rule_id="R_A_TO_C",
        name="A to C",
        premises=("fact_a",),
        conclusion="fact_c",
        severity=SeverityLevel.LOW,
        explanation="A to C",
    ))

    res = pl_fc_entails(kb, ["fact_a"])
    assert res.all_inferred_facts == {"fact_a", "fact_b", "fact_c"}
    assert len(res.fired_rules) == 2


def test_05_project_credential_harvesting_rule():
    """Verify R1: hostname_is_ip_address ^ path_contains_sensitive_keyword -> pattern_credential_harvesting_on_ip."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    percepts = {"hostname_is_ip_address", "path_contains_sensitive_keyword"}
    res = pl_fc_entails(kb, percepts)

    assert "pattern_credential_harvesting_on_ip" in res.derived_facts
    step = res.derivation_trace["pattern_credential_harvesting_on_ip"]
    assert step.rule_id == "RULE_IP_AND_SENSITIVE_KEYWORD"
    assert set(step.premises) == percepts
    assert step.severity == "CRITICAL"


def test_06_project_userinfo_rule():
    """Verify R2: has_userinfo_delimiter -> pattern_credential_masking."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    res = pl_fc_entails(kb, ["has_userinfo_delimiter"])
    assert "pattern_credential_masking" in res.derived_facts
    step = res.derivation_trace["pattern_credential_masking"]
    assert step.rule_id == "RULE_USERINFO_DELIMITER"
    assert step.severity == "CRITICAL"


def test_07_clean_baseline_complete():
    """Verify clean baseline derives zero_suspicious_indicators_present when all clean facts present."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    clean_facts = {
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
    res = pl_fc_entails(kb, clean_facts)

    assert "zero_suspicious_indicators_present" in res.derived_facts
    step = res.derivation_trace["zero_suspicious_indicators_present"]
    assert step.rule_id == "RULE_CLEAN_BASELINE"
    assert step.severity == "NONE"


def test_08_clean_baseline_incomplete():
    """Verify clean baseline does NOT fire if even one clean fact is missing."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    # Remove 'scheme_is_https'
    incomplete_facts = {
        "valid_url_syntax",
        "hostname_is_domain_name",
        "no_userinfo_delimiter",
        # missing: "scheme_is_https"
        "path_has_no_sensitive_keyword",
        "has_standard_port",
        "normal_subdomain_depth",
        "has_standard_encoding",
        "no_open_redirect_parameter",
        "no_double_extension",
        "no_brand_typosquatting",
    }
    res = pl_fc_entails(kb, incomplete_facts)
    assert "zero_suspicious_indicators_present" not in res.derived_facts


def test_09_cycle_safety_terminates():
    """Verify that cyclic dependencies terminate safely without infinite loops: A -> B, B -> C, C -> A."""
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_A_TO_B",
        name="A to B",
        premises=("fact_a",),
        conclusion="fact_b",
        severity=SeverityLevel.LOW,
        explanation="Cycle 1",
    ))
    kb.add_rule(HornClause(
        rule_id="R_B_TO_C",
        name="B to C",
        premises=("fact_b",),
        conclusion="fact_c",
        severity=SeverityLevel.LOW,
        explanation="Cycle 2",
    ))
    kb.add_rule(HornClause(
        rule_id="R_C_TO_A",
        name="C to A",
        premises=("fact_c",),
        conclusion="fact_a",
        severity=SeverityLevel.LOW,
        explanation="Cycle 3",
    ))

    # Must terminate cleanly and infer {fact_a, fact_b, fact_c}
    res = pl_fc_entails(kb, ["fact_a"])
    assert res.all_inferred_facts == {"fact_a", "fact_b", "fact_c"}
    # fact_a was in initial facts, so derived_facts should only contain b and c
    assert res.derived_facts == {"fact_b", "fact_c"}
    # Each rule fired at most once
    assert len(res.fired_rules) == 2


def test_10_duplicate_initial_facts_handled():
    """Verify duplicate initial facts in input list do not cause duplicate processing."""
    kb = KnowledgeBase()
    kb.add_rule(HornClause(
        rule_id="R_A_TO_B",
        name="A to B",
        premises=("fact_a",),
        conclusion="fact_b",
        severity=SeverityLevel.LOW,
        explanation="A to B",
    ))

    res = pl_fc_entails(kb, ["fact_a", "fact_a", "fact_a"])
    assert res.all_inferred_facts == {"fact_a", "fact_b"}
    assert len(res.fired_rules) == 1


def test_11_monotonicity():
    """Verify monotonicity: inferred facts are never removed or overwritten."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    facts = ["has_userinfo_delimiter", "scheme_is_abnormal"]
    res = pl_fc_entails(kb, facts)

    for f in facts:
        assert f in res.all_inferred_facts
    assert "pattern_credential_masking" in res.all_inferred_facts
    assert "pattern_abnormal_scheme" in res.all_inferred_facts


def test_12_determinism_across_runs():
    """Verify that multiple repeated runs produce identical outputs, steps, and firing orders."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    input_facts = [
        "has_open_redirect_parameter",
        "excessive_subdomain_depth",
        "has_double_extension",
        "scheme_is_abnormal",
    ]

    runs = [pl_fc_entails(kb, input_facts) for _ in range(5)]

    first_res = runs[0]
    for r in runs[1:]:
        assert r.derived_facts == first_res.derived_facts
        assert r.all_inferred_facts == first_res.all_inferred_facts
        assert [s.rule_id for s in r.fired_rules] == [s.rule_id for s in first_res.fired_rules]
        assert [s.fired_order for s in r.fired_rules] == [s.fired_order for s in first_res.fired_rules]


def test_13_no_verdicts_generated():
    """Strict Phase 4 check: verify NO verdict tokens (SAFE, REVIEW, SUSPICIOUS, HIGH RISK) exist."""
    kb = KnowledgeBase()
    kb.load_default_rules()

    res = pl_fc_entails(kb, ["hostname_is_ip_address", "path_contains_sensitive_keyword"])

    assert not hasattr(res, "verdict")
    assert not hasattr(res, "risk_level")
    assert not hasattr(res, "verdict_rule")

    for f in res.all_inferred_facts:
        assert f not in {"SAFE", "REVIEW", "SUSPICIOUS", "HIGH RISK"}
