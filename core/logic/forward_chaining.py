"""
Propositional Logic Forward-Chaining Inference Engine (PL-FC-Entails).
Implements textbook forward chaining using:
- FIFO agenda queue
- Premise count table
- Inferred symbol tracking (monotonicity & cycle safety)
- Rule premise indexing
- Chronological derivation history / proof provenance
"""
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from core.logic.clauses import HornClause
from core.logic.knowledge_base import KnowledgeBase


@dataclass(frozen=True)
class DerivationStep:
    """
    Provenance record for a single true fact.
    Identifies whether the fact came from percept extraction or rule derivation.
    """
    rule_id: str
    rule_name: str
    premises: Tuple[str, ...]
    conclusion: str
    fired_order: int
    severity: str

    def __str__(self) -> str:
        if self.rule_id == "PERCEPT_EXTRACTION":
            return f"Fact '{self.conclusion}' asserted via Percept Extraction."
        antecedents = " ^ ".join(self.premises)
        return (
            f"Step {self.fired_order}: [{self.rule_id}] {antecedents} => "
            f"'{self.conclusion}' ({self.severity})"
        )


@dataclass(frozen=True)
class InferenceResult:
    """
    Outcome of forward-chaining inference.
    Contains initial percept facts, newly derived facts, complete closure,
    and the step-by-step derivation history.
    Does NOT contain risk verdicts (SAFE/REVIEW/SUSPICIOUS/HIGH RISK).
    """
    initial_facts: Set[str]
    derived_facts: Set[str]
    all_inferred_facts: Set[str]
    derivation_trace: Dict[str, DerivationStep]
    fired_rules: List[DerivationStep]

    def has_fact(self, fact: str) -> bool:
        """Returns True if the fact was either initial or derived."""
        return fact in self.all_inferred_facts


def pl_fc_entails(
    kb: KnowledgeBase,
    initial_facts: Set[str] | List[str],
) -> InferenceResult:
    """
    Textbook Propositional Logic Forward-Chaining algorithm (PL-FC-Entails).

    Parameters:
        kb: Declarative KnowledgeBase containing definite Horn clauses.
        initial_facts: Iterable of positive propositional symbols (percept facts).

    Returns:
        InferenceResult containing all inferred symbols and derivation provenance.

    Complexity:
        - Time: O(P_total + |F_inferred|), where P_total is the total number of
          premises across all rules in KB, and |F_inferred| is the number of
          inferred facts. Linear in the size of the Knowledge Base.
        - Space: O(|Rules| + |F_inferred|) for count table, agenda, and derivation trace.
    """
    # Deterministic normalization of initial facts
    sorted_initial = sorted(set(initial_facts))

    # 1. count[rule] = number of premises in rule
    count: Dict[str, int] = {rule.rule_id: len(rule.premises) for rule in kb.rules}

    # 2. inferred table: tracks symbols already entailed (guarantees monotonicity & cycle termination)
    inferred: Set[str] = set()

    # 3. Derivation trace and firing sequence tracking
    derivation_trace: Dict[str, DerivationStep] = {}
    fired_rules: List[DerivationStep] = []
    firing_counter = 0

    # 4. agenda: FIFO queue containing initial facts
    agenda: deque[str] = deque()

    for fact in sorted_initial:
        inferred.add(fact)
        derivation_trace[fact] = DerivationStep(
            rule_id="PERCEPT_EXTRACTION",
            rule_name="Percept Extraction",
            premises=(),
            conclusion=fact,
            fired_order=0,
            severity="NONE",
        )
        agenda.append(fact)

    derived_facts: Set[str] = set()

    # 5. Inference loop
    while agenda:
        p = agenda.popleft()

        # O(1) premise lookup using the KnowledgeBase premise index
        candidate_rules = kb.get_rules_triggered_by(p)

        # Deterministic rule evaluation order: sorted by rule_id
        sorted_rules = sorted(candidate_rules, key=lambda r: r.rule_id)

        for rule in sorted_rules:
            # Decrement count of unsatisfied premises for this rule
            count[rule.rule_id] -= 1

            # When all premises are satisfied
            if count[rule.rule_id] == 0:
                q = rule.conclusion

                # Monotonicity & Cycle Safety: only process if conclusion not already inferred
                if q not in inferred:
                    inferred.add(q)
                    derived_facts.add(q)
                    firing_counter += 1

                    step = DerivationStep(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        premises=rule.premises,
                        conclusion=q,
                        fired_order=firing_counter,
                        severity=rule.severity.value,
                    )
                    derivation_trace[q] = step
                    fired_rules.append(step)

                    # Push newly inferred fact to agenda
                    agenda.append(q)

    return InferenceResult(
        initial_facts=set(sorted_initial),
        derived_facts=derived_facts,
        all_inferred_facts=inferred,
        derivation_trace=derivation_trace,
        fired_rules=fired_rules,
    )
