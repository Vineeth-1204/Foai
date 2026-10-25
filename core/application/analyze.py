"""
Application-Level Orchestration Service.
Unifies Parser -> Feature Generator (with A*) -> Knowledge Base ->
Forward Chaining -> Risk Evaluator -> Explanation into a single entry point.
Contains ZERO duplicate AI or analysis algorithms.
"""
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from core.explanation.proof_tree import (
    ExplanationResult,
    ProofNode,
    build_explanation,
)
from core.features.fact_generator import FeatureResult, extract_features
from core.logic.forward_chaining import pl_fc_entails
from core.logic.knowledge_base import KnowledgeBase
from core.parser.rfc_parser import ParsedURL, parse_url
from core.qr.decoder import QRDecodeResult, decode_qr_image
from core.risk.evaluator import RiskAssessment, evaluate_risk


def serialize_proof_node(node: ProofNode) -> Dict[str, Any]:
    """Recursively serializes a ProofNode into a JSON-compatible dictionary."""
    return {
        "fact": node.fact,
        "node_type": node.node_type,
        "rule_id": node.rule_id,
        "rule_name": node.rule_name,
        "severity": node.severity,
        "premises": list(node.premises),
        "evidence": node.evidence,
        "children": [serialize_proof_node(child) for child in node.children],
    }


@dataclass(frozen=True)
class AnalysisReport:
    """
    Complete structured report returned by the application analysis layer.
    Directly consumed by the Web UI presentation layer.
    """
    raw_url: str
    is_valid: bool
    error: Optional[str]
    parsed_components: Dict[str, Any]
    verdict: str
    highest_severity: str
    triggered_patterns: List[str]
    triggered_rules: List[Dict[str, Any]]
    risk_factors: List[str]
    explanation: str
    safe_disclaimer: Optional[str]
    proof_tree_text: str
    proof_tree_nodes: List[Dict[str, Any]]
    astar_evidence: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        """Converts the report to a dictionary for JSON API responses."""
        return asdict(self)


def analyze_url(raw_url: str) -> AnalysisReport:
    """
    Single unified application entry point for offline URL risk analysis.

    Orchestrates:
      1. Parser: RFC 3986 lexical decomposition
      2. Feature Generator + A*: Positive propositional facts & A* typosquatting check
      3. Knowledge Base: Horn clause axiom registry
      4. Forward Chaining: PL-FC-Entails derivation
      5. Risk Evaluator: Categorical verdict mapping
      6. Explanation: Recursive proof tree synthesis
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return AnalysisReport(
            raw_url="" if raw_url is None else str(raw_url),
            is_valid=False,
            error="URL input cannot be empty. Please enter a valid URL.",
            parsed_components={},
            verdict="REVIEW",
            highest_severity="NONE",
            triggered_patterns=[],
            triggered_rules=[],
            risk_factors=["Empty or blank URL input provided."],
            explanation="The provided URL input was empty or whitespace only.",
            safe_disclaimer=None,
            proof_tree_text="(No proof tree available for empty input)",
            proof_tree_nodes=[],
            astar_evidence=None,
        )

    # 1. Lexical Parsing (RFC 3986)
    parsed = parse_url(raw_url)

    # 2. Fact Extraction (integrating A* heuristic search)
    features = extract_features(parsed)

    # 3. Knowledge Base
    kb = KnowledgeBase()
    kb.load_default_rules()

    # 4. PL-FC-Entails Forward Chaining
    inference = pl_fc_entails(kb, features.facts)

    # 5. Deterministic Risk Evaluation
    assessment = evaluate_risk(inference, kb)

    # 6. Explanation and Proof Tree Synthesis
    explanation = build_explanation(
        risk_assessment=assessment,
        inference_result=inference,
        kb=kb,
        evidence_map=features.evidence,
    )

    # Format parsed components for UI inspection
    parsed_components = {
        "scheme": parsed.scheme or "(none)",
        "hostname": parsed.hostname or "(none)",
        "port": parsed.port if parsed.port is not None else "(default)",
        "pathname": parsed.pathname or "/",
        "query": parsed.query or "(none)",
        "fragment": parsed.fragment or "(none)",
        "authority": parsed.authority or "(none)",
        "is_ipv4": parsed.is_ipv4,
        "is_ipv6": parsed.is_ipv6,
        "is_domain": parsed.is_domain,
        "is_valid": parsed.is_valid,
    }

    # Format triggered rules
    formatted_rules = []
    for step in assessment.triggered_rules:
        formatted_rules.append({
            "rule_id": step.rule_id,
            "rule_name": step.rule_name,
            "severity": step.severity,
            "premises": list(step.premises),
            "conclusion": step.conclusion,
            "fired_order": step.fired_order,
        })

    # Format A* evidence if detected
    astar_evidence = None
    astar_raw = features.evidence.get("astar_result")
    if astar_raw:
        astar_evidence = {
            "observed_label": astar_raw.get("source"),
            "matched_brand": astar_raw.get("target"),
            "edit_cost": astar_raw.get("cost"),
            "operations": astar_raw.get("operations", []),
            "algorithm": "A* Heuristic Search (f(n) = g(n) + h(n))",
        }

    # Serialize proof tree nodes
    proof_tree_nodes = [serialize_proof_node(node) for node in explanation.root_nodes]

    return AnalysisReport(
        raw_url=raw_url,
        is_valid=parsed.is_valid,
        error=None if parsed.is_valid else "URL syntax was invalid or incomplete according to RFC 3986.",
        parsed_components=parsed_components,
        verdict=assessment.verdict.value,
        highest_severity=assessment.highest_severity.value,
        triggered_patterns=list(assessment.triggered_patterns),
        triggered_rules=formatted_rules,
        risk_factors=list(assessment.risk_factors),
        explanation=explanation.summary,
        safe_disclaimer=assessment.safe_disclaimer,
        proof_tree_text=explanation.rendered_trees,
        proof_tree_nodes=proof_tree_nodes,
        astar_evidence=astar_evidence,
    )


def analyze_qr_image(image_source: Any) -> tuple[QRDecodeResult, Optional[AnalysisReport]]:
    """
    Decodes an offline QR image and routes the extracted URL into analyze_url().
    Returns (QRDecodeResult, Optional[AnalysisReport]).
    If the decoded text is not an analyzable URL (e.g. plain text, contact card),
    returns a clear validation error without running URL security analysis.
    """
    decoded = decode_qr_image(image_source)
    if not decoded.success:
        return decoded, None

    text = (decoded.decoded_text or "").strip()

    # Validate whether decoded text is an analyzable URL
    parsed = parse_url(text)
    if not parsed.scheme or not parsed.is_valid:
        # Non-URL QR content (e.g. "hello world", "BEGIN:VCARD...", etc.)
        return (
            QRDecodeResult(
                success=True,
                decoded_text=text,
                error="QR code decoded successfully, but the content is not a URL that this analyzer can process.",
            ),
            None,
        )

    # Route into existing application analysis pipeline
    report = analyze_url(text)
    return decoded, report

