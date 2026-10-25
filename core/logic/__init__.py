"""
Logic package for Explainable QR & Link Risk Screening.
Defines Propositional Horn clauses, the declarative Knowledge Base,
and the PL-FC-Entails forward-chaining inference engine.
"""
from core.logic.clauses import HornClause, SeverityLevel, Rule
from core.logic.knowledge_base import KnowledgeBase, RuleValidationError, validate_horn_clause
from core.logic.forward_chaining import pl_fc_entails, InferenceResult, DerivationStep

__all__ = [
    "HornClause",
    "Rule",
    "SeverityLevel",
    "KnowledgeBase",
    "RuleValidationError",
    "validate_horn_clause",
    "pl_fc_entails",
    "InferenceResult",
    "DerivationStep",
]
