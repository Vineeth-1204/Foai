"""
Deterministic Proof Tree and Logical Explanation Generator.
Reconstructs the logical deduction chain from Phase 4 DerivationSteps and Phase 5 RiskAssessment.
Strictly deterministic: zero machine learning, zero probabilities, zero LLM text.
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from core.logic.clauses import SeverityLevel
from core.logic.forward_chaining import DerivationStep, InferenceResult
from core.logic.knowledge_base import KnowledgeBase
from core.risk.evaluator import RiskAssessment, RiskVerdict, SAFE_DISCLAIMER


@dataclass(frozen=True)
class ProofNode:
    """
    Node in the logical deduction proof tree.
    Represents an initial ground fact (leaf) or an entailed conclusion (internal node).
    """
    fact: str
    node_type: str  # 'INITIAL_FACT' or 'DERIVED_FACT'
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    premises: Tuple[str, ...] = ()
    children: Tuple["ProofNode", ...] = ()
    evidence: Optional[str] = None


@dataclass(frozen=True)
class ExplanationResult:
    """
    Structured outcome of the explanation synthesis layer.
    Connects the risk verdict directly to the deduction proof trees and initial evidence.
    """
    verdict: str
    highest_severity: str
    root_nodes: Tuple[ProofNode, ...]
    triggered_patterns: Tuple[str, ...]
    triggered_rules: Tuple[str, ...]
    summary: str
    disclaimer: Optional[str]
    rendered_trees: str


def _format_evidence_value(fact: str, evidence_map: Optional[Dict[str, Any]]) -> Optional[str]:
    """Helper to associate ground facts with extracted URL tokens."""
    if not evidence_map:
        return None

    if fact == "hostname_is_ip_address" and "hostname" in evidence_map:
        return f"hostname='{evidence_map['hostname']}'"
    if fact == "path_contains_sensitive_keyword" and "sensitive_keywords" in evidence_map:
        return f"keywords={evidence_map['sensitive_keywords']}"
    if fact == "has_userinfo_delimiter" and "authority" in evidence_map:
        return f"authority='{evidence_map['authority']}'"
    if fact == "has_non_standard_port" and "non_standard_port" in evidence_map:
        return f"port={evidence_map['non_standard_port']}"
    if fact == "has_double_extension" and "double_extension" in evidence_map:
        return f"extension='{evidence_map['double_extension']}'"
    if fact == "excessive_subdomain_depth" and "subdomain_depth" in evidence_map:
        return f"subdomain_depth={evidence_map['subdomain_depth']}"
    if fact == "has_open_redirect_parameter" and "redirect_info" in evidence_map:
        return f"redirect={evidence_map['redirect_info']}"
    if fact == "scheme_is_http":
        return "scheme='http'"
    if fact == "scheme_is_https":
        return "scheme='https'"
    if fact == "scheme_is_abnormal" and "abnormal_scheme" in evidence_map:
        return f"scheme='{evidence_map['abnormal_scheme']}'"
    if fact == "brand_typosquatting_detected" and "astar_result" in evidence_map and evidence_map["astar_result"]:
        res = evidence_map["astar_result"]
        return f"A* Match: '{res['source']}' -> '{res['target']}' (edit_cost={res['cost']})"

    return None


def build_proof_tree(
    fact: str,
    derivation_trace: Dict[str, DerivationStep],
    kb: Optional[KnowledgeBase] = None,
    evidence_map: Optional[Dict[str, Any]] = None,
    visited: Optional[Set[str]] = None,
) -> ProofNode:
    """
    Recursively builds a ProofNode tree for a specific fact using the
    derivation trace provenance from Phase 4.
    """
    if visited is None:
        visited = set()

    step = derivation_trace.get(fact)

    # 1. Base Case: Ground Percept Fact (Leaf Node)
    if step is None or step.rule_id == "PERCEPT_EXTRACTION":
        evidence_str = _format_evidence_value(fact, evidence_map)
        return ProofNode(
            fact=fact,
            node_type="INITIAL_FACT",
            rule_id=None,
            rule_name=None,
            severity=None,
            premises=(),
            children=(),
            evidence=evidence_str,
        )

    # 2. Cycle prevention safeguard
    if fact in visited:
        return ProofNode(
            fact=fact,
            node_type="DERIVED_FACT",
            rule_id=step.rule_id,
            rule_name=step.rule_name,
            severity=step.severity,
            premises=step.premises,
            children=(),
            evidence="[Cycle Detected / Memoized]",
        )

    visited_next = visited | {fact}

    # 3. Recursive Case: Entailed Conclusion (Internal Node)
    # Look up registered rule name in KB if available
    rule_name = step.rule_name
    if kb:
        registered_rule = kb.get_rule(step.rule_id)
        if registered_rule:
            rule_name = registered_rule.name

    child_nodes: List[ProofNode] = []
    for premise in step.premises:
        child_node = build_proof_tree(
            fact=premise,
            derivation_trace=derivation_trace,
            kb=kb,
            evidence_map=evidence_map,
            visited=visited_next,
        )
        child_nodes.append(child_node)

    return ProofNode(
        fact=fact,
        node_type="DERIVED_FACT",
        rule_id=step.rule_id,
        rule_name=rule_name,
        severity=step.severity,
        premises=step.premises,
        children=tuple(child_nodes),
        evidence=None,
    )


def render_proof_tree(node: ProofNode, prefix: str = "", is_last: bool = True) -> str:
    """
    Deterministically renders a ProofNode hierarchy into a clean text tree.
    """
    connector = "└── " if is_last else "├── "
    evidence_suffix = f" ({node.evidence})" if node.evidence else ""

    if node.node_type == "INITIAL_FACT":
        line = f"{prefix}{connector}{node.fact} [INITIAL FACT]{evidence_suffix}"
    else:
        sev_tag = f" [{node.severity}]" if node.severity and node.severity != "NONE" else ""
        rule_tag = f" (via {node.rule_id})" if node.rule_id else ""
        line = f"{prefix}{connector}{node.fact}{sev_tag}{rule_tag}"

    lines = [line]
    new_prefix = prefix + ("    " if is_last else "│   ")

    for idx, child in enumerate(node.children):
        child_is_last = (idx == len(node.children) - 1)
        lines.append(render_proof_tree(child, prefix=new_prefix, is_last=child_is_last))

    return "\n".join(lines)


def build_explanation(
    risk_assessment: RiskAssessment,
    inference_result: InferenceResult,
    kb: KnowledgeBase,
    evidence_map: Optional[Dict[str, Any]] = None,
) -> ExplanationResult:
    """
    Constructs the complete ExplanationResult connecting RiskAssessment to
    the recursive proof trees of all triggered patterns or the clean baseline.
    """
    root_nodes: List[ProofNode] = []
    triggered_rules: List[str] = []

    # Case A: Anomaly rules fired
    if risk_assessment.triggered_patterns:
        # Filter to terminal patterns (those not consumed as premises by other triggered rules)
        # to prevent intermediate premises from being rendered as redundant separate root trees.
        consumed_premises: Set[str] = set()
        for step in risk_assessment.triggered_rules:
            consumed_premises.update(step.premises)

        terminal_patterns = [
            p for p in risk_assessment.triggered_patterns if p not in consumed_premises
        ]
        if not terminal_patterns:
            terminal_patterns = list(risk_assessment.triggered_patterns)

        for pattern in terminal_patterns:
            root_node = build_proof_tree(
                fact=pattern,
                derivation_trace=inference_result.derivation_trace,
                kb=kb,
                evidence_map=evidence_map,
            )
            root_nodes.append(root_node)
            if root_node.rule_id and root_node.rule_id not in triggered_rules:
                triggered_rules.append(root_node.rule_id)

    # Case B: Clean baseline fired
    elif "zero_suspicious_indicators_present" in inference_result.all_inferred_facts:
        root_node = build_proof_tree(
            fact="zero_suspicious_indicators_present",
            derivation_trace=inference_result.derivation_trace,
            kb=kb,
            evidence_map=evidence_map,
        )
        root_nodes.append(root_node)
        if root_node.rule_id:
            triggered_rules.append(root_node.rule_id)

    # Render proof trees
    rendered_blocks: List[str] = []
    for node in root_nodes:
        rendered_blocks.append(render_proof_tree(node))
    rendered_trees = "\n\n".join(rendered_blocks) if rendered_blocks else "(No proof tree available)"

    # Synthesize human-readable explanation summary
    summary_lines = [
        f"Verdict: {risk_assessment.verdict.value}.",
        f"Highest Triggered Severity: {risk_assessment.highest_severity.value}."
    ]

    if risk_assessment.verdict == RiskVerdict.SAFE:
        summary_lines.append(
            "Evaluation: No significant suspicious indicators were detected by the current local rule set."
        )
        disclaimer = risk_assessment.safe_disclaimer or SAFE_DISCLAIMER
    else:
        disclaimer = None
        summary_lines.append(
            f"The verdict was established because {len(risk_assessment.triggered_patterns)} "
            "security pattern(s) were logically derived by forward chaining:"
        )
        for step in risk_assessment.triggered_rules:
            antecedents_str = " AND ".join(step.premises)
            summary_lines.append(
                f"- Pattern '{step.conclusion}' [{step.severity}] was derived via rule {step.rule_id} "
                f"('{step.rule_name}') after proving premises: ({antecedents_str})."
            )

    summary = "\n".join(summary_lines)

    return ExplanationResult(
        verdict=risk_assessment.verdict.value,
        highest_severity=risk_assessment.highest_severity.value,
        root_nodes=tuple(root_nodes),
        triggered_patterns=tuple(risk_assessment.triggered_patterns),
        triggered_rules=tuple(triggered_rules),
        summary=summary,
        disclaimer=disclaimer,
        rendered_trees=rendered_trees,
    )
