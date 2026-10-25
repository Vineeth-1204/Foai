"""
Informed Heuristic Search package.
Implements A* string distance search for brand typosquatting detection.
"""
from core.search.brand_lexicon import BRAND_LEXICON, EXCLUDED_TLDS
from core.search.astar import (
    AStarResult,
    EditOperation,
    astar_string_distance,
    detect_brand_typosquatting,
    admissible_heuristic,
    MAX_TYPO_EDIT_COST,
)

__all__ = [
    "BRAND_LEXICON",
    "EXCLUDED_TLDS",
    "AStarResult",
    "EditOperation",
    "astar_string_distance",
    "detect_brand_typosquatting",
    "admissible_heuristic",
    "MAX_TYPO_EDIT_COST",
]
