"""
Phase 7 Unit Tests: A* Typosquatting Search.
Verifies textbook A* string distance search:
- State space transitions: Match, Substitute, Insert, Delete, Transpose
- Admissible heuristic f(n) = g(n) + h(n)
- Safeguards (exact match exclusion, threshold MAX_TYPO_EDIT_COST = 2)
- Brand lexicon queries and hostname label tokenization
- End-to-end pipeline integration through Forward Chaining and Proof Tree
- Determinism and zero network calls
"""
import pytest
import socket
from core.parser import parse_url
from core.features import extract_features
from core.logic.knowledge_base import KnowledgeBase
from core.logic.forward_chaining import pl_fc_entails
from core.risk.evaluator import evaluate_risk
from core.explanation.proof_tree import build_explanation
from core.search.astar import (
    astar_string_distance,
    detect_brand_typosquatting,
    admissible_heuristic,
    MAX_TYPO_EDIT_COST,
)
from core.search.brand_lexicon import BRAND_LEXICON


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Zero-network safeguard."""
    def forbidden(*args, **kwargs):
        raise RuntimeError("SECURITY VIOLATION: Network or DNS operation attempted!")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


# Test 1: Exact Match (cost 0, valid path, but NOT typosquatting)
def test_01_exact_match():
    res = astar_string_distance("google", "google")
    assert res.total_cost == 0
    assert res.found is True
    assert all(op.op_type == "MATCH" for op in res.operations)

    # Safeguard check: exact match against brand must NOT trigger typosquatting
    match = detect_brand_typosquatting("google.com")
    assert match is None


# Test 2: Single Substitution (cost 1)
def test_02_single_substitution():
    res = astar_string_distance("go0gle", "google")
    assert res.total_cost == 1
    sub_ops = [op for op in res.operations if op.op_type == "SUBSTITUTE"]
    assert len(sub_ops) == 1
    assert sub_ops[0].source_char == "0"
    assert sub_ops[0].target_char == "o"


# Test 3: Double Substitution (cost 2)
def test_03_double_substitution():
    res = astar_string_distance("g00gle", "google")
    assert res.total_cost == 2
    sub_ops = [op for op in res.operations if op.op_type == "SUBSTITUTE"]
    assert len(sub_ops) == 2


# Test 4: Single Insertion (cost 1)
def test_04_insertion():
    res = astar_string_distance("gooogle", "google")
    assert res.total_cost == 1
    ins_or_del = [op for op in res.operations if op.op_type in ("INSERT", "DELETE")]
    assert len(ins_or_del) == 1


# Test 5: Single Deletion (cost 1)
def test_05_deletion():
    res = astar_string_distance("gogle", "google")
    assert res.total_cost == 1


# Test 6: Transposition / Swap (cost 1)
def test_06_transposition():
    res = astar_string_distance("goolge", "google")
    assert res.total_cost == 1
    trans_ops = [op for op in res.operations if op.op_type == "TRANSPOSITION"]
    assert len(trans_ops) == 1


# Test 7: Unrelated Strings Exceed Threshold
def test_07_unrelated_strings():
    res = astar_string_distance("weather", "google")
    assert res.total_cost > MAX_TYPO_EDIT_COST


# Test 8: Threshold Enforcement (cost <= 2 triggers candidate, cost > 2 does not)
def test_08_threshold_enforcement():
    # 2 edits (paypa11 -> paypal: cost 2)
    res_2 = astar_string_distance("paypa11", "paypal")
    assert res_2.total_cost <= MAX_TYPO_EDIT_COST

    # 3 edits (p0ypa11 -> paypal: cost 3)
    res_3 = astar_string_distance("p0ypa11", "paypal")
    assert res_3.total_cost > MAX_TYPO_EDIT_COST


# Test 9: Case Normalization
def test_09_case_normalization():
    res = astar_string_distance("Go0Gle", "google")
    assert res.total_cost == 1


# Test 10: Best Matching Brand from Multiple Candidates
def test_10_best_matching_brand():
    match = detect_brand_typosquatting("g00gle.com")
    assert match is not None
    assert match.target == "google"
    assert match.total_cost == 2


# Test 11: Hostname Integration (https://g00gle.com/login)
def test_11_hostname_integration():
    parsed = parse_url("https://g00gle.com/login")
    features = extract_features(parsed)

    assert "brand_typosquatting_detected" in features.facts
    assert "no_brand_typosquatting" not in features.facts
    assert features.evidence["astar_result"] is not None
    assert features.evidence["astar_result"]["target"] == "google"


# Test 12: Legitimate Non-Brand Hostname (example.com)
def test_12_non_brand_hostname():
    parsed = parse_url("https://example.com")
    features = extract_features(parsed)

    assert "no_brand_typosquatting" in features.facts
    assert "brand_typosquatting_detected" not in features.facts


# Test 13: Determinism across Repeated Runs
def test_13_determinism_of_astar():
    runs = [astar_string_distance("g00gle", "google") for _ in range(5)]
    first = runs[0]
    for r in runs[1:]:
        assert r.total_cost == first.total_cost
        assert r.states_expanded == first.states_expanded
        assert [str(op) for op in r.operations] == [str(op) for op in first.operations]


# Test 14: Admissible Heuristic Validation
def test_14_admissible_heuristic_never_overestimates():
    pairs = [
        ("g00gle", "google"),
        ("paypa1", "paypal"),
        ("app", "apple"),
        ("micros0ft", "microsoft"),
        ("netflix", "netflix"),
    ]
    for s, t in pairs:
        h_val = admissible_heuristic(0, 0, len(s), len(t))
        actual = astar_string_distance(s, t)
        assert h_val <= actual.total_cost


# Test 15: End-to-End Pipeline Integration with Forward Chaining and Proof Tree
def test_15_end_to_end_pipeline_integration():
    """
    End-to-End: https://g00gle.com/login
    Pipeline:
      Parser -> FactGen (runs A*) -> KB -> PL-FC-Entails -> Evaluator -> Proof Tree
    Expectation:
      - A* detects g00gle -> google (cost 2)
      - Asserts brand_typosquatting_detected
      - Forward Chaining fires:
        R4: brand_typosquatting_detected ^ path_contains_sensitive_keyword => pattern_targeted_brand_phishing [CRITICAL]
      - Evaluator maps CRITICAL to HIGH RISK
      - Proof Tree renders full provenance including A* evidence
    """
    url = "https://g00gle.com/login"
    parsed = parse_url(url)
    features = extract_features(parsed)
    kb = KnowledgeBase()
    kb.load_default_rules()
    inference = pl_fc_entails(kb, features.facts)
    assessment = evaluate_risk(inference, kb)
    explanation = build_explanation(assessment, inference, kb, evidence_map=features.evidence)

    assert assessment.verdict.value == "HIGH RISK"
    assert "pattern_targeted_brand_phishing" in assessment.triggered_patterns
    assert "A* Match: 'g00gle' -> 'google'" in explanation.rendered_trees


# Test 16: Insecure HTTP Brand Impersonation Pipeline Test
def test_16_http_brand_impersonation_pipeline():
    """
    End-to-End: http://paypa1.com/index
    Expectation:
      - A* detects paypa1 -> paypal (cost 1)
      - Forward Chaining fires:
        R3: brand_typosquatting_detected ^ scheme_is_http => pattern_insecure_brand_impersonation [HIGH]
      - Evaluator maps HIGH to SUSPICIOUS
    """
    url = "http://paypa1.com/index"
    parsed = parse_url(url)
    features = extract_features(parsed)
    kb = KnowledgeBase()
    kb.load_default_rules()
    inference = pl_fc_entails(kb, features.facts)
    assessment = evaluate_risk(inference, kb)

    assert assessment.verdict.value == "SUSPICIOUS"
    assert "pattern_insecure_brand_impersonation" in assessment.triggered_patterns
