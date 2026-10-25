# Algorithmic Specification: Classical AI Foundations

This document provides a comprehensive technical specification of the algorithms implemented within the system. The project strictly utilizes **Classical/Symbolic Artificial Intelligence**; no machine learning, neural networks, or probabilistic models are employed.

---

## 1. URL Parsing Architecture (RFC 3986 Lexical Decomposition)

The parsing engine (`core/parser/rfc_parser.py`, `ip_detector.py`) implements deterministic lexical decomposition in compliance with RFC 3986 without making network calls or performing DNS lookups:

1. **Scheme Extraction**: Identified by searching for the leading `^[a-zA-Z][a-zA-Z0-9+.-]*:`. Distinguishes web protocols (`http`, `https`) from abnormal schemes (`javascript`, `data`, `file`, `ftp`).
2. **Authority Partitioning**: Isolates `//<userinfo>@<host>:<port>`. Explicitly splits user credentials from the destination host to identify credential masking tricks.
3. **IP Detection**: Hostnames are inspected via `ipaddress.ip_address` to detect raw IPv4 and IPv6 targets without contacting network services.
4. **Path & Component Splitting**: Paths are normalized and tokenized; query parameters and URI fragments are segregated.

---

## 2. Feature & Ground Fact Generation

The feature extractor (`core/features/fact_generator.py`) maps the lexical components of a `ParsedURL` into an immutable set of **positive propositional Horn literals**. Each feature corresponds to an observable boolean condition:

- `hostname_is_ip_address` vs `hostname_is_domain_name`
- `has_userinfo_delimiter` vs `no_userinfo_delimiter`
- `scheme_is_http`, `scheme_is_https`, or `scheme_is_abnormal`
- `path_contains_sensitive_keyword` vs `path_has_no_sensitive_keyword`
- `has_non_standard_port` vs `has_standard_port`
- `excessive_subdomain_depth` vs `normal_subdomain_depth`
- `has_open_redirect_parameter` vs `no_open_redirect_parameter`
- `has_double_extension` vs `no_double_extension`
- `brand_typosquatting_detected` vs `no_brand_typosquatting` (derived via A*)

Each positive literal is paired with structured lexical evidence stored in an `evidence_map` (e.g. matched keywords, port numbers, or A* search traces).

---

## 3. Knowledge Representation: Positive Definite Horn Clauses

Knowledge is formalized using **Propositional Definite Horn Clauses** (`core/logic/clauses.py`, `knowledge_base.py`):

$$\bigwedge_{i=1}^n P_i \implies Q$$

Where:
- Every premise $P_i$ is a strictly positive atomic proposition.
- The conclusion $Q$ is a single positive atomic proposition.
- No negation ($\neg$), disjunction ($\lor$), or existential quantifiers are permitted in rule bodies.
- Each rule is annotated with an immutable `SeverityLevel` (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).

The Knowledge Base (`KnowledgeBase`) acts as an in-memory declarative registry providing indexing from premises to dependent rules.

---

## 4. Primary AI Algorithm: PL-FC-Entails (Forward Chaining)

The system implements textbook **`PL-FC-Entails`** (Russell & Norvig, *Artificial Intelligence: A Modern Approach*) in `core/logic/forward_chaining.py`.

### Mathematical Formulation & State Data Structures

1. **Agenda ($A$)**: A strict First-In-First-Out (`collections.deque`) queue containing symbols known to be true but not yet processed.
2. **Count Table ($\text{count}[rule]$)**: An integer array initialized to the number of premises of each rule:
   $$\text{count}[r] = |\text{premises}(r)|$$
3. **Inferred Table ($\text{inferred}[p]$)**: A boolean hash set tracking whether atomic proposition $p$ has already been processed to guarantee termination and monotonicity.
4. **Premise Index ($\text{premise\_to\_rules}[p]$)**: Inverted index mapping each propositional symbol $p$ to all rules where $p \in \text{premises}(r)$.
5. **Derivation Trace ($\text{derivation\_trace}[Q]$)**: Maps each entailed conclusion to its exact `DerivationStep` provenance record (rule ID, rule name, ordered premises, severity, and fired order).

### Step-by-Step Algorithm Walkthrough

```python
def pl_fc_entails(kb, initial_facts):
    count = {rule: len(rule.premises) for rule in kb.rules}
    inferred = set()
    agenda = deque(initial_facts)
    trace = {}
    fired_rules = []
    fired_order = 1

    while agenda:
        p = agenda.popleft()
        if p in inferred:
            continue
        inferred.add(p)

        for rule in kb.premise_to_rules.get(p, []):
            count[rule] -= 1
            if count[rule] == 0:
                conclusion = rule.conclusion
                step = DerivationStep(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    premises=rule.premises,
                    conclusion=conclusion,
                    fired_order=fired_order,
                    severity=rule.severity.value
                )
                fired_order += 1
                fired_rules.append(step)
                trace[conclusion] = step
                
                if conclusion not in inferred:
                    agenda.append(conclusion)

    return InferenceResult(initial_facts, derived_facts, inferred, trace, fired_rules)
```

### Theoretical Guarantees
- **Soundness**: Every derived proposition $Q$ logically follows from $KB \cup \text{initial\_facts}$.
- **Completeness**: If $KB \cup \text{initial\_facts} \models Q$ within the Horn clause theory, PL-FC-Entails is guaranteed to derive $Q$.
- **Time Complexity**: Runs in linear time $O(N)$ with respect to the total number of premises across all rules in the Knowledge Base.

---

## 5. Secondary AI Algorithm: A* Heuristic Search

Brand typosquatting detection is modeled as an **optimal pathfinding search** through a discrete string-edit state space (`core/search/astar.py`).

### State Representation
A state is a 2-tuple:
$$n = (i, j)$$
where:
- $i \in [0, |source|]$ represents the number of characters consumed from the observed hostname label.
- $j \in [0, |target|]$ represents the number of characters generated toward the target brand name.

### State Space & Transitions
- **Initial State**: $s_0 = (0, 0)$
- **Goal State**: $s_{goal} = (|source|, |target|)$
- **Transitions (Edit Operations)**:
  1. **Match**: $(i, j) \to (i+1, j+1)$ if $source[i] == target[j]$, $\text{cost} = 0$.
  2. **Substitute**: $(i, j) \to (i+1, j+1)$ if $source[i] \ne target[j]$, $\text{cost} = 1$.
  3. **Transposition (Damerau Swap)**: $(i, j) \to (i+2, j+2)$ if $source[i:i+2] == target[j+1:j-1:-1]$, $\text{cost} = 1$.
  4. **Delete**: $(i, j) \to (i+1, j)$, $\text{cost} = 1$.
  5. **Insert**: $(i, j) \to (i, j+1)$, $\text{cost} = 1$.

### Priority Function
$$f(n) = g(n) + h(n)$$
- $g(n)$: Exact cumulative cost from $s_0$ to $n$.
- $h(n)$: Estimated cost from $n$ to $s_{goal}$.
- Deterministic tie-breaking is enforced using a strictly monotonic counter to preserve search determinism.

---

## 6. Heuristic Function & Admissibility Proof

### Mathematical Definition
The heuristic implemented in `admissible_heuristic(i, j, len_s, len_t)` is defined as:

$$h(i, j) = \big|(|source| - i) - (|target| - j)\big|$$

### Admissibility Proof
**Theorem**: The heuristic $h(i, j) = \big|(|source| - i) - (|target| - j)\big|$ is strictly admissible for the state space and operation costs defined above.

**Proof**:
1. Let $L_s = |source| - i$ be the number of remaining characters in the source label.
2. Let $L_t = |target| - j$ be the number of remaining characters in the target brand.
3. Every operation in the state space alters the length discrepancy $|L_s - L_t|$ by at most 1 unit:
   - Match: decreases both $L_s$ and $L_t$ by 1 $\implies \Delta |L_s - L_t| = 0$, cost $= 0$.
   - Substitute: decreases both $L_s$ and $L_t$ by 1 $\implies \Delta |L_s - L_t| = 0$, cost $= 1$.
   - Transposition: decreases both $L_s$ and $L_t$ by 2 $\implies \Delta |L_s - L_t| = 0$, cost $= 1$.
   - Insertion: decreases $L_t$ by 1 $\implies \Delta (L_s - L_t) = +1$, cost $= 1$.
   - Deletion: decreases $L_s$ by 1 $\implies \Delta (L_s - L_t) = -1$, cost $= 1$.
4. At the goal state, the remaining lengths must both be 0, requiring the length discrepancy to reach 0.
5. Because no single operation costing 1 can reduce the magnitude $|L_s - L_t|$ by more than 1, the minimum number of edit operations required to equalize lengths is at least $|L_s - L_t|$.
6. Let $h^*(n)$ denote the true minimal cost to transform the remaining suffix of $source$ into $target$. It follows that:
   $$h(n) = |L_s - L_t| \le h^*(n)$$
7. Therefore, $h(n)$ never overestimates the true remaining cost to the goal, proving that $h(n)$ is **strictly admissible**. $\blacksquare$

---

## 7. Deterministic Risk Evaluation & Resolution

Risk evaluation (`core/risk/evaluator.py`) is completely deterministic:
- Inspects **all** fired Horn rules (does not stop at the first match).
- Orders triggered anomaly rules by severity rank:
  $$\text{CRITICAL} > \text{HIGH} > \text{MEDIUM} > \text{LOW} > \text{NONE}$$
- Categorical Mapping:
  - Any $\text{CRITICAL} \implies \textbf{HIGH RISK}$
  - Any $\text{HIGH} \implies \textbf{SUSPICIOUS}$
  - Any $\text{MEDIUM} \text{ or } \text{LOW} \implies \textbf{REVIEW}$
  - All clean baseline facts satisfied $\implies \textbf{SAFE}$

No floating-point probabilities, weights, or confidence scores are introduced.

---

## 8. Proof Tree & Explainability Synthesis

The explanation module (`core/explanation/proof_tree.py`) traverses the `derivation_trace` produced by Phase 4. For every top-level security pattern or clean baseline conclusion, it recursively constructs a Directed Acyclic Graph (`ProofNode`) linking conclusions to rules, and rules to their antecedent premises. Ground facts are annotated with concrete lexical evidence extracted during Phase 2 (e.g. `hostname='192.168.1.10'`, `edit_cost=2`). This guarantees that every output verdict is 100% transparent and formally explainable.
