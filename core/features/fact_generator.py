"""
Deterministic Feature and Fact Generator.
Consumes ParsedURL objects from Phase 1 and converts URL characteristics
into positive propositional facts (Horn literals) and structured evidence.
Never performs inference, risk scoring, network calls, or DNS lookups.
"""
from dataclasses import dataclass, field
import re
from typing import Any, Optional, Set
from urllib.parse import parse_qsl, unquote

from core.parser.rfc_parser import ParsedURL
from core.search.astar import detect_brand_typosquatting


# Sensitive security and authentication keywords in URL path
_SENSITIVE_KEYWORDS = frozenset({
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "wallet",
    "bank",
    "payment",
    "secure",
})

# Suspicious open redirect parameter names
_REDIRECT_PARAM_NAMES = frozenset({
    "redirect",
    "url",
    "target",
    "next",
    "return",
    "returnurl",
    "redirect_uri",
    "dest",
    "destination",
    "goto",
    "out",
})

# Document and media file extensions
_DOCUMENT_EXTENSIONS = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp4",
    "zip", "rar", "csv", "tar", "gz"
})

# Executable and script file extensions
_EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "bat", "cmd", "vbs", "js", "ps1",
    "sh", "msi", "com", "pif", "hta", "jar", "wsf"
})

# Known multi-part TLD suffixes for subdomain depth calculation
_TWO_PART_TLDS = frozenset({
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in",
    "co.nz", "net.nz", "org.nz",
    "co.za", "org.za",
    "com.br", "net.br", "org.br",
    "com.sg", "edu.sg",
    "co.jp", "ne.jp", "or.jp",
})


@dataclass(frozen=True)
class FeatureResult:
    """
    Structured outcome of feature and fact extraction.
    Contains the positive Horn literals (facts), detailed evidence, and the parsed URL.
    """
    facts: Set[str]
    evidence: dict[str, Any]
    parsed_url: ParsedURL


def _calculate_subdomain_depth(hostname: Optional[str]) -> int:
    """
    Calculates the subdomain depth of a hostname.
    Example:
      'example.com' -> depth 0
      'sub.example.com' -> depth 1
      'a.b.c.d.example.com' -> depth 4
      'a.b.c.d.example.co.uk' -> depth 4
    """
    if not hostname:
        return 0

    clean = hostname.strip().lower()
    # IPs have 0 subdomain depth
    if any(ch in clean for ch in ":") or clean.replace(".", "").isdigit():
        return 0

    labels = [l for l in clean.split(".") if l]
    if len(labels) <= 2:
        return 0

    # Check for known 2-part TLD (e.g. co.uk)
    suffix = f"{labels[-2]}.{labels[-1]}"
    if suffix in _TWO_PART_TLDS:
        base_domain_labels = 3  # name + 2-part tld
    else:
        base_domain_labels = 2  # name + tld

    subdomain_count = len(labels) - base_domain_labels
    return max(0, subdomain_count)


def _detect_sensitive_keywords_in_path(pathname: str) -> list[str]:
    """
    Detects sensitive authentication / security keywords in the URL pathname.
    Handles delimiters like '/', '-', '_', '.', and percent-decoding.
    """
    if not pathname:
        return []

    decoded_path = unquote(pathname).lower()

    # Tokenize path into words and hyphenated segments
    # Keep hyphenated words intact (e.g. 'sign-in') as well as split tokens ('sign', 'in')
    tokens = set()
    raw_segments = re.findall(r"[a-z0-9-]+", decoded_path)
    for seg in raw_segments:
        tokens.add(seg)
        # Also add parts split by hyphen
        if "-" in seg:
            for part in seg.split("-"):
                if part:
                    tokens.add(part)

    matched = [kw for kw in _SENSITIVE_KEYWORDS if kw in tokens]
    return sorted(matched)


def _detect_open_redirect(query: str) -> Optional[dict[str, str]]:
    """
    Detects if any query parameter targets an external redirect URL.
    """
    if not query:
        return None

    try:
        params = parse_qsl(query, keep_blank_values=True)
    except Exception:
        return None

    for key, val in params:
        key_lower = key.strip().lower()
        val_clean = unquote(val).strip()

        # Check if parameter name is a known redirect param
        is_redirect_name = key_lower in _REDIRECT_PARAM_NAMES

        # Check if value looks like a URL
        val_lower = val_clean.lower()
        looks_like_url = (
            val_lower.startswith("http://")
            or val_lower.startswith("https://")
            or val_lower.startswith("//")
            or ("://" in val_lower)
        )

        if is_redirect_name and looks_like_url:
            return {"param": key, "target": val_clean, "reason": "redirect_param_and_target_url"}
        elif looks_like_url:
            return {"param": key, "target": val_clean, "reason": "target_url_in_param_value"}

    return None


def _detect_double_extension(pathname: str) -> Optional[tuple[str, str]]:
    """
    Detects dangerous double extensions where an executable extension
    follows a document/media extension (e.g. 'invoice.docx.exe').
    """
    if not pathname:
        return None

    filename = pathname.rsplit("/", 1)[-1]
    if not filename or "." not in filename:
        return None

    parts = filename.lower().split(".")
    # Must have at least name, doc_ext, exec_ext -> >= 3 parts
    if len(parts) >= 3:
        second_last = parts[-2]
        last = parts[-1]
        if second_last in _DOCUMENT_EXTENSIONS and last in _EXECUTABLE_EXTENSIONS:
            return (second_last, last)

    return None


def extract_features(
    parsed_url: ParsedURL,
    brand_typosquatting: Optional[bool] = None,
) -> FeatureResult:
    """
    Extracts the 12 base characteristics from a ParsedURL and converts them into
    pure positive propositional facts (Horn literals).
    Uses A* heuristic search for brand typosquatting detection if not explicitly overridden.
    """
    facts: set[str] = set()
    evidence: dict[str, Any] = {
        "original_url": parsed_url.original_url,
        "scheme": parsed_url.scheme,
        "hostname": parsed_url.hostname,
        "port": parsed_url.port,
    }

    # 1. Hostname is IP address
    if parsed_url.is_ipv4 or parsed_url.is_ipv6:
        facts.add("hostname_is_ip_address")
        evidence["is_ip"] = True
    else:
        facts.add("hostname_is_domain_name")
        evidence["is_ip"] = False

    # 2. Userinfo delimiter '@' in authority
    if parsed_url.has_userinfo:
        facts.add("has_userinfo_delimiter")
        evidence["has_userinfo"] = True
        evidence["authority"] = parsed_url.authority
    else:
        facts.add("no_userinfo_delimiter")
        evidence["has_userinfo"] = False

    # 3. Scheme: HTTP vs HTTPS
    if parsed_url.scheme == "http":
        facts.add("scheme_is_http")
    elif parsed_url.scheme == "https":
        facts.add("scheme_is_https")

    # 4. Abnormal Scheme
    if parsed_url.is_abnormal_scheme:
        facts.add("scheme_is_abnormal")
        evidence["abnormal_scheme"] = parsed_url.scheme
    else:
        facts.add("scheme_is_standard_web")
        evidence["abnormal_scheme"] = None

    # 5. Sensitive Path Keywords
    matched_keywords = _detect_sensitive_keywords_in_path(parsed_url.pathname)
    if matched_keywords:
        facts.add("path_contains_sensitive_keyword")
        evidence["sensitive_keywords"] = matched_keywords
    else:
        facts.add("path_has_no_sensitive_keyword")
        evidence["sensitive_keywords"] = []

    # 6. Port Standardness
    # Standard: http -> 80, https -> 443, or port is None
    is_non_standard_port = False
    if parsed_url.port is not None:
        if parsed_url.scheme == "http" and parsed_url.port != 80:
            is_non_standard_port = True
        elif parsed_url.scheme == "https" and parsed_url.port != 443:
            is_non_standard_port = True
        elif parsed_url.scheme not in ("http", "https"):
            is_non_standard_port = True

    if is_non_standard_port:
        facts.add("has_non_standard_port")
        evidence["non_standard_port"] = parsed_url.port
    else:
        facts.add("has_standard_port")
        evidence["non_standard_port"] = None

    # 7. Subdomain Depth
    subdomain_depth = _calculate_subdomain_depth(parsed_url.hostname)
    evidence["subdomain_depth"] = subdomain_depth
    if subdomain_depth > 3:
        facts.add("excessive_subdomain_depth")
    else:
        facts.add("normal_subdomain_depth")

    # 8. Punycode
    hostname_clean = (parsed_url.hostname or "").lower()
    has_puny = "xn--" in hostname_clean
    evidence["has_punycode"] = has_puny
    if has_puny:
        facts.add("has_punycode")
    else:
        facts.add("has_standard_encoding")

    # 9. Open Redirect Parameter
    redirect_info = _detect_open_redirect(parsed_url.query)
    if redirect_info:
        facts.add("has_open_redirect_parameter")
        evidence["redirect_info"] = redirect_info
    else:
        facts.add("no_open_redirect_parameter")
        evidence["redirect_info"] = None

    # 10. Double Extension
    double_ext = _detect_double_extension(parsed_url.pathname)
    if double_ext:
        facts.add("has_double_extension")
        evidence["double_extension"] = f".{double_ext[0]}.{double_ext[1]}"
    else:
        facts.add("no_double_extension")
        evidence["double_extension"] = None

    # 11. Brand Typosquatting (Phase 7: A* Heuristic Search)
    if brand_typosquatting is True:
        facts.add("brand_typosquatting_detected")
        evidence["brand_typosquatting"] = True
        evidence["astar_result"] = None
    elif brand_typosquatting is False:
        facts.add("no_brand_typosquatting")
        evidence["brand_typosquatting"] = False
        evidence["astar_result"] = None
    else:
        # brand_typosquatting is None: execute A* search over brand lexicon
        astar_match = detect_brand_typosquatting(parsed_url.hostname)
        if astar_match is not None:
            facts.add("brand_typosquatting_detected")
            evidence["brand_typosquatting"] = True
            evidence["astar_result"] = {
                "source": astar_match.source,
                "target": astar_match.target,
                "cost": astar_match.total_cost,
                "operations": [str(op) for op in astar_match.operations],
            }
        else:
            facts.add("no_brand_typosquatting")
            evidence["brand_typosquatting"] = False
            evidence["astar_result"] = None

    # 12. URL Syntax Validity
    if parsed_url.is_valid:
        facts.add("valid_url_syntax")
        evidence["is_valid_syntax"] = True
    else:
        facts.add("invalid_url_syntax")
        evidence["is_valid_syntax"] = False

    return FeatureResult(
        facts=facts,
        evidence=evidence,
        parsed_url=parsed_url,
    )
