"""
Declarative Knowledge Base for Propositional Horn Clauses.
Manages rule registration, schema integrity, and syntactic Horn clause validation.
Contains ZERO inference logic or rule evaluation execution.
"""
from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Dict, List, Optional, Set

from core.logic.clauses import HornClause, SeverityLevel


class RuleValidationError(ValueError):
    """Raised when a rule violates propositional Horn clause structural requirements."""
    pass


# Strict regex for positive propositional literals (alphanumeric and underscores only)
_POSITIVE_LITERAL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*$")

# Disallowed negation patterns
_NEGATION_SUBSTRINGS = ("not ", "not_", "! ", "!", "~", " not", "(not")


def validate_horn_clause(rule: HornClause) -> None:
    """
    Syntactically validates that a HornClause conforms strictly to:
    P1 ^ P2 ^ ... ^ Pn => Q
    where all P_i and Q are pure positive propositional literals.
    """
    # 1. Validate rule_id
    if not rule.rule_id or not isinstance(rule.rule_id, str) or not rule.rule_id.strip():
        raise RuleValidationError("Rule must have a non-empty string 'rule_id'.")

    # 2. Validate premises exist
    if not rule.premises:
        raise RuleValidationError(f"Rule '{rule.rule_id}' must contain at least one premise.")

    # 3. Validate each premise is a positive literal
    for idx, premise in enumerate(rule.premises):
        if not isinstance(premise, str) or not premise.strip():
            raise RuleValidationError(
                f"Rule '{rule.rule_id}' premise #{idx} must be a non-empty string."
            )
        premise_clean = premise.strip()

        # Reject negation keywords or symbols
        premise_lower = premise_clean.lower()
        if any(neg in premise_lower for neg in _NEGATION_SUBSTRINGS) or premise_clean.startswith("!"):
            raise RuleValidationError(
                f"Rule '{rule.rule_id}' violates Horn clause constraints: premise '{premise}' contains negation."
            )

        # Check positive literal naming
        if not _POSITIVE_LITERAL_REGEX.match(premise_clean):
            raise RuleValidationError(
                f"Rule '{rule.rule_id}' premise '{premise}' is not a valid positive literal. "
                "Must be alphanumeric/underscore without operators."
            )

    # 4. Validate conclusion is a positive literal
    if not rule.conclusion or not isinstance(rule.conclusion, str) or not rule.conclusion.strip():
        raise RuleValidationError(f"Rule '{rule.rule_id}' must have a non-empty conclusion.")

    conclusion_clean = rule.conclusion.strip()
    conclusion_lower = conclusion_clean.lower()
    if any(neg in conclusion_lower for neg in _NEGATION_SUBSTRINGS) or conclusion_clean.startswith("!"):
        raise RuleValidationError(
            f"Rule '{rule.rule_id}' conclusion '{rule.conclusion}' contains negation."
        )

    if not _POSITIVE_LITERAL_REGEX.match(conclusion_clean):
        raise RuleValidationError(
            f"Rule '{rule.rule_id}' conclusion '{rule.conclusion}' is not a valid positive literal."
        )

    # 5. Validate severity is a recognized SeverityLevel
    if not isinstance(rule.severity, SeverityLevel):
        raise RuleValidationError(
            f"Rule '{rule.rule_id}' has invalid severity '{rule.severity}'."
        )

    # 6. Validate explanation
    if not rule.explanation or not isinstance(rule.explanation, str) or not rule.explanation.strip():
        raise RuleValidationError(f"Rule '{rule.rule_id}' must have a non-empty explanation.")


class KnowledgeBase:
    """
    In-memory registry of declarative Horn clauses.
    Validates, indexes, and inspects rules.
    Does NOT evaluate rules or perform inference (strictly delegated to Phase 4).
    """

    def __init__(self):
        self._rules: Dict[str, HornClause] = {}
        self._premise_index: Dict[str, List[HornClause]] = {}

    def add_rule(self, rule: HornClause) -> None:
        """
        Validates and registers a HornClause.
        Rejects duplicates and malformed clauses.
        """
        validate_horn_clause(rule)

        if rule.rule_id in self._rules:
            raise RuleValidationError(f"Duplicate rule_id '{rule.rule_id}' already registered in Knowledge Base.")

        self._rules[rule.rule_id] = rule

        # Index premises for O(1) lookup during future forward chaining
        for premise in rule.premises:
            if premise not in self._premise_index:
                self._premise_index[premise] = []
            self._premise_index[premise].append(rule)

    def get_rule(self, rule_id: str) -> Optional[HornClause]:
        """Retrieves a rule by its unique identifier."""
        return self._rules.get(rule_id)

    @property
    def rules(self) -> List[HornClause]:
        """Returns a list of all registered Horn clauses."""
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)

    def symbols(self) -> Set[str]:
        """Returns the set of all unique propositional symbols in premises and conclusions."""
        syms = set()
        for r in self._rules.values():
            syms.update(r.premises)
            syms.add(r.conclusion)
        return syms

    def get_rules_triggered_by(self, symbol: str) -> List[HornClause]:
        """Returns all rules that declare 'symbol' as one of their premises."""
        return list(self._premise_index.get(symbol, []))

    def load_from_json_file(self, file_path: Path | str) -> int:
        """
        Loads and validates Horn clauses from a JSON array file.
        Returns the number of loaded rules.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Rule file not found at: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise RuleValidationError(f"Root of rule file '{path}' must be a JSON array of rule objects.")

        count = 0
        for entry in data:
            rule = HornClause(
                rule_id=entry["rule_id"],
                name=entry["name"],
                premises=tuple(entry["premises"]),
                conclusion=entry["conclusion"],
                severity=SeverityLevel(entry["severity"].upper()),
                explanation=entry["explanation"],
            )
            self.add_rule(rule)
            count += 1

        return count

    def load_default_rules(self) -> int:
        """
        Loads both anomaly rules (R1-R9) and the clean baseline rule from core/rules.
        """
        rules_dir = Path(__file__).resolve().parent.parent / "rules"
        anomaly_file = rules_dir / "anomaly_rules.json"
        clean_file = rules_dir / "clean_rules.json"

        loaded = 0
        loaded += self.load_from_json_file(anomaly_file)
        loaded += self.load_from_json_file(clean_file)
        return loaded
