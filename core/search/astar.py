"""
A* Heuristic Search for String Edit Distance and Brand Typosquatting Detection.
Implements textbook A* search: f(n) = g(n) + h(n)
over the transformation state space between an observed hostname label and a target brand.
Strictly offline, deterministic, and classical AI-based.
"""
from dataclasses import dataclass
import heapq
from typing import List, Optional, Tuple

from core.search.brand_lexicon import BRAND_LEXICON, EXCLUDED_TLDS

# Deterministic Edit Operation Costs
COST_MATCH = 0
COST_SUBSTITUTE = 1
COST_INSERT = 1
COST_DELETE = 1
COST_TRANSPOSITION = 1

# Maximum edit cost to trigger typosquatting suspicion
MAX_TYPO_EDIT_COST = 2


@dataclass(frozen=True)
class EditOperation:
    """Represents a discrete string-edit step in the transformation path."""
    op_type: str  # MATCH, SUBSTITUTE, INSERT, DELETE, TRANSPOSITION
    source_char: Optional[str]
    target_char: Optional[str]
    cost: int

    def __str__(self) -> str:
        if self.op_type == "MATCH":
            return f"MATCH '{self.source_char}'"
        elif self.op_type == "SUBSTITUTE":
            return f"SUBSTITUTE '{self.source_char}' -> '{self.target_char}'"
        elif self.op_type == "INSERT":
            return f"INSERT '{self.target_char}'"
        elif self.op_type == "DELETE":
            return f"DELETE '{self.source_char}'"
        elif self.op_type == "TRANSPOSITION":
            return f"TRANSPOSE '{self.source_char}' <-> '{self.target_char}'"
        return self.op_type


@dataclass(frozen=True)
class AStarResult:
    """Outcome of the A* heuristic search over string transformation space."""
    source: str
    target: str
    total_cost: int
    operations: Tuple[EditOperation, ...]
    states_expanded: int
    path: Tuple[Tuple[int, int], ...]
    found: bool


def admissible_heuristic(i: int, j: int, len_s: int, len_t: int) -> int:
    """
    Admissible Heuristic h(i, j):
    Calculates the absolute difference between remaining source and target lengths:
    h(i, j) = |(len_s - i) - (len_t - j)|

    Proof of Admissibility:
    Any valid transformation must reconcile the length difference between the remaining
    substrings (len_s - i) and (len_t - j). Each single edit operation (insertion or deletion)
    can change the length difference by at most 1, while substitutions and matches do not change
    the length difference. Because each insertion/deletion has a cost of at least 1, at least
    |(len_s - i) - (len_t - j)| operations are strictly required to reach the goal state.
    Therefore, h(i, j) <= h*(i, j) for all states (it never overestimates the true remaining cost).
    """
    return abs((len_s - i) - (len_t - j))


def astar_string_distance(source: str, target: str) -> AStarResult:
    """
    Computes the minimum edit distance between source and target strings using A* search.

    State: (i, j) where i is index in source (0..len_s) and j is index in target (0..len_t).
    Start state: (0, 0)
    Goal state: (len_s, len_t)
    Evaluation function: f(n) = g(n) + h(n)
    """
    s = source.lower()
    t = target.lower()
    len_s = len(s)
    len_t = len(t)

    start_state = (0, 0)
    goal_state = (len_s, len_t)

    # Priority queue entry: (f_score, g_score, tie_breaker, state, operations, path)
    tie_breaker = 0
    start_h = admissible_heuristic(0, 0, len_s, len_t)
    open_heap = [(start_h, 0, tie_breaker, start_state, (), (start_state,))]

    best_g: dict[Tuple[int, int], int] = {start_state: 0}
    states_expanded = 0

    while open_heap:
        f, g, _, current_state, ops, path = heapq.heappop(open_heap)
        i, j = current_state

        # If we reached the goal state, return the optimal path
        if current_state == goal_state:
            return AStarResult(
                source=source,
                target=target,
                total_cost=g,
                operations=ops,
                states_expanded=states_expanded,
                path=path,
                found=True,
            )

        # If current g is worse than best recorded g for this state, skip
        if g > best_g.get(current_state, float("inf")):
            continue

        states_expanded += 1

        # Generate successors in deterministic order:
        # 1. Match (cost 0)
        if i < len_s and j < len_t and s[i] == t[j]:
            next_state = (i + 1, j + 1)
            next_g = g + COST_MATCH
            if next_g < best_g.get(next_state, float("inf")):
                best_g[next_state] = next_g
                h_val = admissible_heuristic(next_state[0], next_state[1], len_s, len_t)
                tie_breaker += 1
                op = EditOperation("MATCH", s[i], t[j], COST_MATCH)
                heapq.heappush(
                    open_heap,
                    (next_g + h_val, next_g, tie_breaker, next_state, ops + (op,), path + (next_state,))
                )

        # 2. Substitution (cost 1)
        if i < len_s and j < len_t and s[i] != t[j]:
            next_state = (i + 1, j + 1)
            next_g = g + COST_SUBSTITUTE
            if next_g < best_g.get(next_state, float("inf")):
                best_g[next_state] = next_g
                h_val = admissible_heuristic(next_state[0], next_state[1], len_s, len_t)
                tie_breaker += 1
                op = EditOperation("SUBSTITUTE", s[i], t[j], COST_SUBSTITUTE)
                heapq.heappush(
                    open_heap,
                    (next_g + h_val, next_g, tie_breaker, next_state, ops + (op,), path + (next_state,))
                )

        # 3. Transposition / Swap (cost 1)
        if (
            i + 1 < len_s
            and j + 1 < len_t
            and s[i] == t[j + 1]
            and s[i + 1] == t[j]
            and s[i] != s[i + 1]
        ):
            next_state = (i + 2, j + 2)
            next_g = g + COST_TRANSPOSITION
            if next_g < best_g.get(next_state, float("inf")):
                best_g[next_state] = next_g
                h_val = admissible_heuristic(next_state[0], next_state[1], len_s, len_t)
                tie_breaker += 1
                op = EditOperation("TRANSPOSITION", s[i:i+2], t[j:j+2], COST_TRANSPOSITION)
                heapq.heappush(
                    open_heap,
                    (next_g + h_val, next_g, tie_breaker, next_state, ops + (op,), path + (next_state,))
                )

        # 4. Deletion from source (cost 1)
        if i < len_s:
            next_state = (i + 1, j)
            next_g = g + COST_DELETE
            if next_g < best_g.get(next_state, float("inf")):
                best_g[next_state] = next_g
                h_val = admissible_heuristic(next_state[0], next_state[1], len_s, len_t)
                tie_breaker += 1
                op = EditOperation("DELETE", s[i], None, COST_DELETE)
                heapq.heappush(
                    open_heap,
                    (next_g + h_val, next_g, tie_breaker, next_state, ops + (op,), path + (next_state,))
                )

        # 5. Insertion into source / matching target (cost 1)
        if j < len_t:
            next_state = (i, j + 1)
            next_g = g + COST_INSERT
            if next_g < best_g.get(next_state, float("inf")):
                best_g[next_state] = next_g
                h_val = admissible_heuristic(next_state[0], next_state[1], len_s, len_t)
                tie_breaker += 1
                op = EditOperation("INSERT", None, t[j], COST_INSERT)
                heapq.heappush(
                    open_heap,
                    (next_g + h_val, next_g, tie_breaker, next_state, ops + (op,), path + (next_state,))
                )

    # Fallback if no path (theoretically unreachable in edit distance)
    return AStarResult(source, target, total_cost=-1, operations=(), states_expanded=states_expanded, path=(), found=False)


def detect_brand_typosquatting(
    hostname: Optional[str],
    lexicon: Tuple[str, ...] = BRAND_LEXICON,
    max_edit_cost: int = MAX_TYPO_EDIT_COST,
) -> Optional[AStarResult]:
    """
    Analyzes hostname labels against the curated brand lexicon using A* search.

    Safeguards:
    1. Ignores empty hosts and IP addresses.
    2. Ignores common TLDs (e.g. .com, .org, .net).
    3. Requires 1 <= edit_cost <= max_edit_cost (exact match cost 0 is NOT typosquatting).
    4. Requires label length >= 3 to prevent single-letter noise.

    Returns the best matching AStarResult if typosquatting is established, else None.
    """
    if not hostname:
        return None

    clean_host = hostname.strip().lower()

    # Skip IP addresses
    if any(ch in clean_host for ch in ":") or clean_host.replace(".", "").isdigit():
        return None

    labels = [lbl for lbl in clean_host.split(".") if lbl]
    if not labels:
        return None

    # Exclude the TLD if there are at least 2 labels
    candidate_labels = labels[:-1] if len(labels) >= 2 else labels

    best_match: Optional[AStarResult] = None
    lowest_cost = float("inf")

    for label in candidate_labels:
        # Skip labels that are too short or in excluded TLD set
        if len(label) < 3 or label in EXCLUDED_TLDS:
            continue

        for brand in lexicon:
            # Safeguard 1: Exact matches are legitimate brand domains, not typosquatting
            if label == brand:
                continue

            result = astar_string_distance(label, brand)

            # Safeguard 2: Must satisfy 1 <= edit_cost <= max_edit_cost
            if 1 <= result.total_cost <= max_edit_cost:
                if result.total_cost < lowest_cost:
                    lowest_cost = result.total_cost
                    best_match = result

    return best_match
