"""
Deterministic Risk Evaluator.
Consumes InferenceResult from Phase 4 and maps inferred logical patterns
to categorical risk verdicts (SAFE, REVIEW, SUSPICIOUS, HIGH RISK).
Strictly deterministic: zero machine learning, zero probabilities, zero confidence scores.
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from core.logic.clauses import SeverityLevel
from core.logic.forward_chaining import DerivationStep, InferenceResult
from core.logic.knowledge_base import KnowledgeBase


class RiskVerdict(str, Enum):
    """Categorical risk verdict derived from logical pattern inference."""
    SAFE = "SAFE"
    REVIEW = "REVIEW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"


# Severity rank ordering: NONE < LOW < MEDIUM < HIGH < CRITICAL
_SEVERITY_RANK = {
    SeverityLevel.NONE: 0,
    SeverityLevel.LOW: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.HIGH: 3,
    SeverityLevel.CRITICAL: 4,
}

# Mandatory disclaimer for local offline screening
SAFE_DISCLAIMER = (
    "Destination legitimacy cannot be guaranteed because the URL was "
    "analyzed locally without contacting the destination."
)


@dataclass(frozen=True)
class RiskAssessment:
    """
    Structured outcome of deterministic risk evaluation.
    Contains categorical verdict, maximum severity, triggered rules, and explanation.
    Guarantees zero floating-point confidence or probabilistic weights.
    """
    verdict: RiskVerdict
    highest_severity: SeverityLevel
    triggered_patterns: List[str]
    triggered_rules: List[DerivationStep]
    risk_factors: List[str]
    explanation: str
    safe_disclaimer: Optional[str]

    @property
    def is_safe(self) -> bool:
        return self.verdict == RiskVerdict.SAFE


def evaluate_risk(
    inference_result: InferenceResult,
    kb: KnowledgeBase,
) -> RiskAssessment:
    """
    Deterministically determines the final categorical verdict based on
    all fired rules and inferred patterns from the forward-chaining engine.

    Resolution:
    - Inspects ALL inferred patterns (does NOT stop after the first match).
    - Resolves to the maximum severity among triggered anomaly patterns.
      CRITICAL -> HIGH RISK
      HIGH     -> SUSPICIOUS
      MEDIUM   -> REVIEW
      LOW      -> REVIEW
      NONE     -> SAFE (if zero_suspicious_indicators_present derived)
    """
    # 1. Collect all fired anomaly rules (severity != NONE)
    anomaly_steps: List[DerivationStep] = []
    triggered_patterns: List[str] = []
    risk_factors: List[str] = []

    for step in inference_result.fired_rules:
        # Match step rule in KB to obtain registered description and explanation
        kb_rule = kb.get_rule(step.rule_id)
        severity = SeverityLevel(step.severity)

        if severity != SeverityLevel.NONE:
            anomaly_steps.append(step)
            triggered_patterns.append(step.conclusion)
            if kb_rule:
                risk_factors.append(f"[{severity.value}] {kb_rule.name}: {kb_rule.explanation}")
            else:
                risk_factors.append(f"[{severity.value}] {step.rule_name} fired.")

    # 2. If anomaly patterns were inferred, find the maximum severity
    if anomaly_steps:
        # Sort by severity rank descending, then by fired order
        sorted_steps = sorted(
            anomaly_steps,
            key=lambda s: (_SEVERITY_RANK[SeverityLevel(s.severity)], -s.fired_order),
            reverse=True,
        )
        highest_severity = SeverityLevel(sorted_steps[0].severity)

        # Map highest severity to categorical verdict
        if highest_severity == SeverityLevel.CRITICAL:
            verdict = RiskVerdict.HIGH_RISK
            explanation = (
                f"Verdict: HIGH RISK. Inferred {len(anomaly_steps)} security pattern(s) with "
                f"highest severity CRITICAL. Dominant factor: {sorted_steps[0].rule_name}."
            )
        elif highest_severity == SeverityLevel.HIGH:
            verdict = RiskVerdict.SUSPICIOUS
            explanation = (
                f"Verdict: SUSPICIOUS. Inferred {len(anomaly_steps)} security pattern(s) with "
                f"highest severity HIGH. Dominant factor: {sorted_steps[0].rule_name}."
            )
        elif highest_severity in (SeverityLevel.MEDIUM, SeverityLevel.LOW):
            verdict = RiskVerdict.REVIEW
            explanation = (
                f"Verdict: REVIEW. Inferred {len(anomaly_steps)} security pattern(s) with "
                f"highest severity {highest_severity.value}. Dominant factor: {sorted_steps[0].rule_name}."
            )
        else:
            verdict = RiskVerdict.REVIEW
            explanation = "Verdict: REVIEW. Unusual indicators detected requiring manual review."

        return RiskAssessment(
            verdict=verdict,
            highest_severity=highest_severity,
            triggered_patterns=triggered_patterns,
            triggered_rules=anomaly_steps,
            risk_factors=risk_factors,
            explanation=explanation,
            safe_disclaimer=None,
        )

    # 3. No anomaly rules fired. Check if clean baseline was inferred.
    if "zero_suspicious_indicators_present" in inference_result.all_inferred_facts:
        return RiskAssessment(
            verdict=RiskVerdict.SAFE,
            highest_severity=SeverityLevel.NONE,
            triggered_patterns=[],
            triggered_rules=[],
            risk_factors=[],
            explanation="No significant suspicious indicators were detected by the current local rule set.",
            safe_disclaimer=SAFE_DISCLAIMER,
        )

    # 4. Fallback: No anomaly fired, but clean baseline was not fully satisfied (e.g. invalid syntax)
    return RiskAssessment(
        verdict=RiskVerdict.REVIEW,
        highest_severity=SeverityLevel.LOW,
        triggered_patterns=[],
        triggered_rules=[],
        risk_factors=["URL syntax was incomplete or unparseable, failing the baseline clean profile."],
        explanation="Verdict: REVIEW. No explicit threat pattern fired, but the clean baseline profile was not fully established.",
        safe_disclaimer=None,
    )
