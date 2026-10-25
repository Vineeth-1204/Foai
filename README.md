# Explainable QR & Link Risk Screening

An offline, deterministic, and explainable **Classical Symbolic Artificial Intelligence** system for screening web links and QR codes.

Built as an academic AI project demonstrating:
- **Intelligent Agents & Problem-Solving**
- **A* Heuristic Search** for string-edit brand typosquatting detection
- **Knowledge-Based Agents & Propositional Definite Horn Logic**
- **`PL-FC-Entails` Forward-Chaining Inference**
- **Explainable AI (XAI)** via proof-tree derivation DAGs

---

## 1. System Overview

Modern URL safety screening typically depends on external cloud services, remote threat intelligence APIs, live DNS lookups, or opaque machine learning classifiers. 

This system takes an alternative, transparent approach designed for privacy-preserving, air-gapped, and low-latency environments:
- **100% Offline**: Zero external network requests, zero DNS resolutions, zero external APIs, and zero tracking.
- **Classical Symbolic AI**: Completely transparent propositional Horn logic and A* search. Zero machine learning, deep learning, computer vision classifiers, or large language models (LLMs).
- **Fully Explainable**: Every risk verdict is justified by a complete proof tree linking conclusions back to observable lexical facts.
- **Deterministic**: Categorical verdicts only (`SAFE`, `REVIEW`, `SUSPICIOUS`, `HIGH RISK`). No floating-point confidence weights or statistical probabilities.

---

## 2. Core AI Algorithms

### Primary AI: `PL-FC-Entails` Forward Chaining
Logical deduction is governed by classical **Forward Chaining** over a Knowledge Base of positive definite Horn clauses ($P_1 \land \dots \land P_n \implies Q$):
- **Agenda**: FIFO queue managing newly asserted symbols.
- **Count Table**: Decremented dynamically as premise symbols are established.
- **Inverted Index**: Maps premises to candidate Horn clauses.
- **Derivation Trace**: Retains full causal provenance for each deduction.

### Secondary AI: A* Heuristic Search
Brand typosquatting is formulated as an optimal pathfinding problem in a discrete string-edit state space:
- **Priority Function**: $f(n) = g(n) + h(n)$
- **Path Cost $g(n)$**: Exact accumulated edit distance across Match, Substitute, Insert, Delete, and Transposition operations.
- **Heuristic $h(n)$**: Admissible length-discrepancy heuristic $h(i, j) = |(|source| - i) - (|target| - j)|$, mathematically proven to never overestimate the remaining edit distance.
- **Ground Fact Production**: If $1 \le g(n) \le 2$ against a curated brand dictionary, A* asserts `brand_typosquatting_detected`, which feeds into Forward Chaining.

---

## 3. Architecture & Data Flow

```
Input (Direct URL or Offline QR Image)
               ↓
[QR Decoder] (Offline OpenCV Matrix Extraction — QR Only)
               ↓
`analyze_url()` Orchestrator
               ↓
Phase 1: RFC 3986 Lexical Parser
               ↓
Phase 2: Fact Generator ───→ A* Heuristic Search (Secondary AI)
               ↓                           ↓
Knowledge Base (Horn Clauses) ← `brand_typosquatting_detected`
               ↓
Phase 4: PL-FC-Entails Forward Chaining (Primary AI)
               ↓
Phase 5: Deterministic Risk Evaluator
               ↓
Phase 6: Proof Tree Synthesizer
               ↓
AnalysisReport DTO
               ↓
Phase 8: Web UI Presentation Dashboard
```

---

## 4. Installation & Requirements

### Prerequisites
- Python 3.10+ (Tested under Python 3.11.9)
- Standard pip environment

### Dependencies
The system relies on minimal, vetted open-source libraries:
- `flask`: Web presentation server
- `opencv-python`: Offline 2D matrix decoding for QR codes
- `pillow`: Image processing utilities
- `qrcode`: In-memory QR code generation for automated testing
- `pytest`: Automated test runner

Install dependencies:
```bash
pip install flask opencv-python pillow qrcode pytest
```

---

## 5. Running the Application

Start the local web dashboard:
```bash
python web/app.py
```
Then navigate to `http://127.0.0.1:5000` in your browser.

The interface supports both:
1. **Direct URL Analysis**: Enter any link to inspect components, triggered rules, and proof trees.
2. **Offline QR Code Scanner**: Upload any QR image to extract and analyze its destination URL offline.

---

## 6. Running the Test Suite

Execute the complete automated test suite:
```bash
python -m pytest -v
```

All 130 tests run with an active **zero-network safeguard** that intercepts and blocks all socket and network connections:
```
============================ 130 passed in 1.14s =============================
```

---

## 7. Example Scenarios

| Category | Example Input | Expected Verdict | Primary Evidence / Rule |
| :--- | :--- | :---: | :--- |
| **Clean Baseline** | `https://example.com` | `SAFE` | Satisfies all 11 clean profile facts (`RULE_CLEAN_BASELINE`) |
| **Credential Harvesting** | `https://192.168.1.10/login` | `HIGH RISK` | Raw IP host + `/login` path (`RULE_IP_AND_SENSITIVE_KEYWORD`) |
| **Credential Masking** | `https://google.com@attacker.com/login` | `HIGH RISK` | `@` authority delimiter (`RULE_USERINFO_DELIMITER`) |
| **Targeted Brand Phish** | `https://g00gle.com/login` | `HIGH RISK` | A* search matched `google` ($g=2$) + `/login` path |
| **Insecure Impersonation** | `http://paypa1.com/index` | `SUSPICIOUS` | A* search matched `paypal` ($g=1$) + unencrypted HTTP |
| **Unconventional Endpoint**| `http://example.com:8080/browse` | `REVIEW` | Non-standard port 8080 (`RULE_NON_STANDARD_PORT`) |

---

## 8. Limitations & Operational Scope

1. **Air-Gapped & Local-Only**: The analyzer does not contact destination servers and cannot observe dynamically served server-side payloads.
2. **No Live Threat Intelligence**: Does not query external feeds (VirusTotal, Google Safe Browsing, PhishTank).
3. **No DNS Resolution**: Cannot verify whether domain names currently resolve or detect DNS fast-flux.
4. **Semantics of `SAFE`**: A verdict of `SAFE` indicates that **no significant suspicious indicators were detected by the current local rule set**. It does not provide an absolute guarantee of website legitimacy.
5. **Curated Lexicon**: Upstream A* typosquatting detection is bounded by the static local brand lexicon.
6. **QR Decoding Constraints**: Requires legible QR codes with standard formatting; non-URL payloads are rejected from security analysis.

---

## 9. Academic Documentation

Detailed technical documentation is available in the `docs/` directory:
- [docs/ARCHITECTURE.md](file:///d:/Projects/FOAI/urlparser/docs/ARCHITECTURE.md): System architecture, module boundaries, and data flows.
- [docs/ALGORITHMS.md](file:///d:/Projects/FOAI/urlparser/docs/ALGORITHMS.md): Algorithm mechanics, pseudocode, and mathematical proof of heuristic admissibility.
- [docs/RULES.md](file:///d:/Projects/FOAI/urlparser/docs/RULES.md): Catalog of all Horn clauses and clean baseline rules.
- [docs/TESTING.md](file:///d:/Projects/FOAI/urlparser/docs/TESTING.md): Test methodology, benchmark matrix, and zero-network verification.
- [docs/LIMITATIONS.md](file:///d:/Projects/FOAI/urlparser/docs/LIMITATIONS.md): Formal analysis of system boundaries and operational constraints.
- [docs/DEMO.md](file:///d:/Projects/FOAI/urlparser/docs/DEMO.md): Step-by-step viva presentation script.
