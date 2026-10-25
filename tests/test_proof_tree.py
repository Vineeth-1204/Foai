"""
Phase 6 Unit Tests: Explanation & Proof Tree Synthesis.
Verifies recursive proof tree construction, multi-hop chaining, multi-premise resolution,
rendering of deduction DAGs, preservation of multiple risk branches, and zero network calls.
"""
import pytest
import socket
from core.parser import parse_url
from core.features import extract_features
from core.logic.clauses import HornClause, SeverityLevel
from core.logic.knowledge_base import KnowledgeBase
from core.logic.forward_chaining import pl_fc_entails
from core.risk.evaluator import evaluate_risk
from core.explanation.proof_tree import (
    ProofNode,
    ExplanationResult,
    build_proof_tree,
    build_explanation,
    render_proof_tree,
)


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def run_full_pipeline(url: str, brand_typosquatting: bool = False):
    """Runs pipeline through Phase 6."""
    parsed = parse_url(url)
    features = extract_features(parsed, brand_typosquatting=brand_typosquatting)
    kb = KnowledgeBase()
    kb.load_default_rules()
    inference = pl_fc_entails(kb, features.facts)
    assessment = evaluate_risk(inference, kb)
    explanation = build_explanation(assessment, inference, kb, evidence_map=features.evidence)
    return parsed, features, kb, inference, assessment, explanation


# Test 1: Clean URL Proof (https://example.com)
def test_01_clean_url_proof_tree():
    _, _, _, _, assessment, explanation = run_full_pipeline("https://example.com")

    assert explanation.verdict == "SAFE"
    assert explanation.highest_severity == "NONE"
    assert len(explanation.root_nodes) == 1

    root = explanation.root_nodes[0]
    assert root.fact == "zero_suspicious_indicators_present"
    assert root.rule_id == "RULE_CLEAN_BASELINE"
    assert root.node_type == "DERIVED_FACT"
    assert len(root.children) == 11

    # Verify all children are INITIAL_FACT
    child_facts = {c.fact for c in root.children}
    assert "hostname_is_domain_name" in child_facts
    assert "scheme_is_https" in child_facts
    assert "no_userinfo_delimiter" in child_facts
    for child in root.children:
        assert child.node_type == "INITIAL_FACT"

    # Verify disclaimer is included
    assert explanation.disclaimer is not None
    assert "Destination legitimacy cannot be guaranteed" in explanation.disclaimer

    # Verify rendered output
    rendered = explanation.rendered_trees
    assert "zero_suspicious_indicators_present" in rendered
    assert "RULE_CLEAN_BASELINE" in rendered


# Test 2: Direct IP Credential Phishing (https://192.168.1.10/login)
def test_02_direct_ip_phishing_proof_tree():
    _, _, _, _, assessment, explanation = run_full_pipeline("https://192.168.1.10/login")

    assert explanation.verdict == "HIGH RISK"
    assert explanation.highest_severity == "CRITICAL"
    assert len(explanation.root_nodes) == 1

    root = explanation.root_nodes[0]
    assert root.fact == "pattern_credential_harvesting_on_ip"
    assert root.rule_id == "RULE_IP_AND_SENSITIVE_KEYWORD"
    assert root.severity == "CRITICAL"
    assert len(root.children) == 2

    child_facts = {c.fact for c in root.children}
    assert child_facts == {"hostname_is_ip_address", "path_contains_sensitive_keyword"}
    for child in root.children:
        assert child.node_type == "INITIAL_FACT"
        assert child.evidence is not None  # Evidence formatted

    rendered = render_proof_tree(root)
    assert "pattern_credential_harvesting_on_ip [CRITICAL]" in rendered
    assert "hostname_is_ip_address [INITIAL FACT]" in rendered
    assert "path_contains_sensitive_keyword [INITIAL FACT]" in rendered


# Test 3: Userinfo Masking (https://google.com@attacker.com/login)
def test_03_userinfo_masking_proof_tree():
    _, _, _, _, assessment, explanation = run_full_pipeline("https://google.com@attacker.com/login")

    assert explanation.verdict == "HIGH RISK"
    assert "pattern_credential_masking" in explanation.triggered_patterns

    matching_roots = [r for r in explanation.root_nodes if r.fact == "pattern_credential_masking"]
    assert len(matching_roots) == 1
    root = matching_roots[0]
    assert root.rule_id == "RULE_USERINFO_DELIMITER"
    assert len(root.children) == 1
    assert root.children[0].fact == "has_userinfo_delimiter"
    assert root.children[0].node_type == "INITIAL_FACT"


# Test 4: Multiple Risk Branches (http://example.com:8080/browse)
def test_04_multiple_risk_branches_preserved():
    _, _, _, _, assessment, explanation = run_full_pipeline("http://example.com:8080/browse")

    assert explanation.verdict == "REVIEW"
    assert explanation.highest_severity == "MEDIUM"

    # Both branches must be present as roots
    assert len(explanation.root_nodes) == 2
    root_facts = {r.fact for r in explanation.root_nodes}
    assert "pattern_unconventional_endpoint" in root_facts
    assert "pattern_insecure_transport_only" in root_facts

    # Verify MEDIUM branch is preserved
    med_node = next(r for r in explanation.root_nodes if r.fact == "pattern_unconventional_endpoint")
    assert med_node.severity == "MEDIUM"
    assert med_node.rule_id == "RULE_NON_STANDARD_PORT"

    # Verify LOW branch is preserved
    low_node = next(r for r in explanation.root_nodes if r.fact == "pattern_insecure_transport_only")
    assert low_node.severity == "LOW"
    assert low_node.rule_id == "RULE_HTTP_INSECURE_TRANSPORT"


# Test 5: Synthetic Multi-Hop Inference Proof (A -> B -> C -> D)
def test_05_synthetic_multi_hop_proof():
    kb = KnowledgeBase()
    kb.add_rule(HornClause("R1", "A to B", ("fact_a",), "fact_b", SeverityLevel.LOW, "Step 1"))
    kb.add_rule(HornClause("R2", "B to C", ("fact_b",), "fact_c", SeverityLevel.MEDIUM, "Step 2"))
    kb.add_rule(HornClause("R3", "C to D", ("fact_c",), "fact_d", SeverityLevel.HIGH, "Step 3"))

    inference = pl_fc_entails(kb, ["fact_a"])
    assessment = evaluate_risk(inference, kb)
    explanation = build_explanation(assessment, inference, kb)

    assert len(explanation.root_nodes) == 1
    root = explanation.root_nodes[0]
    assert root.fact == "fact_d"
    assert root.rule_id == "R3"

    # Hop 1: D -> C
    assert len(root.children) == 1
    node_c = root.children[0]
    assert node_c.fact == "fact_c"
    assert node_c.rule_id == "R2"

    # Hop 2: C -> B
    assert len(node_c.children) == 1
    node_b = node_c.children[0]
    assert node_b.fact == "fact_b"
    assert node_b.rule_id == "R1"

    # Hop 3: B -> A (Initial Fact)
    assert len(node_b.children) == 1
    node_a = node_b.children[0]
    assert node_a.fact == "fact_a"
    assert node_a.node_type == "INITIAL_FACT"
    assert node_a.children == ()


# Test 6: Synthetic Multi-Premise Proof (A + B -> C)
def test_06_synthetic_multi_premise_proof():
    kb = KnowledgeBase()
    kb.add_rule(HornClause("R_AB", "AB to C", ("fact_a", "fact_b"), "fact_c", SeverityLevel.HIGH, "Rule AB"))

    inference = pl_fc_entails(kb, ["fact_a", "fact_b"])
    assessment = evaluate_risk(inference, kb)
    explanation = build_explanation(assessment, inference, kb)

    assert len(explanation.root_nodes) == 1
    root = explanation.root_nodes[0]
    assert root.fact == "fact_c"
    assert len(root.children) == 2

    child_facts = {c.fact for c in root.children}
    assert child_facts == {"fact_a", "fact_b"}
    for child in root.children:
        assert child.node_type == "INITIAL_FACT"


# Test 7: Determinism Across Repeated Runs
def test_07_determinism_of_proof_tree():
    url = "https://192.168.1.10/login"
    runs = [run_full_pipeline(url)[5] for _ in range(5)]

    first_rendered = runs[0].rendered_trees
    first_summary = runs[0].summary

    for r in runs[1:]:
        assert r.rendered_trees == first_rendered
        assert r.summary == first_summary
        assert r.verdict == runs[0].verdict
        assert r.highest_severity == runs[0].highest_severity
