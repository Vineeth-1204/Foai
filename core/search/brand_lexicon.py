"""
Curated local brand lexicon for demonstration of A* typosquatting heuristic search.
100% offline, deterministic, and static.
"""

BRAND_LEXICON = (
    "google",
    "amazon",
    "apple",
    "microsoft",
    "paypal",
    "facebook",
    "instagram",
    "netflix",
)

# Common Top-Level Domains to exclude from brand comparison
EXCLUDED_TLDS = frozenset({
    "com", "org", "net", "edu", "gov", "mil", "int",
    "io", "co", "ai", "app", "dev", "info", "biz",
    "uk", "us", "ca", "de", "fr", "jp", "au", "in",
})
