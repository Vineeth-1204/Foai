"""
Risk assessment package.
Maps inferred propositional patterns and rule severities to categorical verdicts.
"""
from core.risk.evaluator import RiskAssessment, RiskVerdict, evaluate_risk

__all__ = ["RiskAssessment", "RiskVerdict", "evaluate_risk"]
