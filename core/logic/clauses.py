"""
Representation of Propositional Definite Horn Clauses.
Each clause strictly adheres to: P1 ^ P2 ^ ... ^ Pn => Q
where P_i and Q are pure positive propositional literals.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Tuple


class SeverityLevel(str, Enum):
    """Categorical severity for security risk patterns."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class HornClause:
    """
    Immutable representation of a Propositional Definite Horn Clause.
    Antecedents (premises) strictly conjoin positive literals to derive a positive conclusion.
    """
    rule_id: str
    name: str
    premises: Tuple[str, ...]
    conclusion: str
    severity: SeverityLevel
    explanation: str

    def __post_init__(self):
        # Ensure premises is an immutable tuple
        if not isinstance(self.premises, tuple):
            object.__setattr__(self, "premises", tuple(self.premises))

        # Ensure severity is an instance of SeverityLevel
        if not isinstance(self.severity, SeverityLevel):
            try:
                object.__setattr__(self, "severity", SeverityLevel(str(self.severity).upper()))
            except ValueError:
                valid_levels = [s.value for s in SeverityLevel]
                raise ValueError(
                    f"Invalid severity '{self.severity}' for rule '{self.rule_id}'. "
                    f"Must be one of: {valid_levels}"
                )

    def as_horn_expression(self) -> str:
        """Returns standard logical Horn clause notation: P1 ^ P2 ^ ... => Q."""
        antecedent = " ^ ".join(self.premises)
        return f"{antecedent} => {self.conclusion}"

    def __str__(self) -> str:
        return f"[{self.rule_id}] {self.as_horn_expression()} ({self.severity.value})"


# Alias HornClause as Rule
Rule = HornClause
