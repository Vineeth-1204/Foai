# System Architecture: Explainable QR & Link Risk Screening

## 1. Problem Statement & Academic Context

Modern phishing and malicious distribution techniques exploit subtle lexical modifications, obfuscation delimiters, and mobile QR code delivery vectors. Traditional defensive systems often rely on external cloud threat intelligence, live DNS queries, or opaque "black-box" machine learning classifiers. These approaches suffer from severe drawbacks in privacy-sensitive, isolated, or air-gapped environments, and provide zero transparent justification for why a link was classified as hazardous.

This system is an **offline, deterministic, explainable Classical/Symbolic Artificial Intelligence system** designed for rapid local URL and QR screening. It achieves complete transparency by coupling **Propositional Definite Horn Logic** with the textbook **`PL-FC-Entails` Forward-Chaining Inference Engine** as its primary reasoning engine, augmented upstream by **A* Heuristic Search** for string-edit brand typosquatting detection. Every risk verdict is backed by an inspectable derivation proof tree tracing deductions directly back to observable lexical facts.

---

## 2. End-to-End System Architecture

```
                          +------------------------+
                          |   User Inputs Link:    |
                          |  Direct URL / QR Image  |
                          +-----------+------------+
                                      |
                      [QR Image]      |      [Direct URL Text]
                           |          |
                           v          |
               +----------------------+
               | Offline QR Decoder   | (OpenCV Local Matrix Extraction)
               | (Input Adapter Only) |
               +-----------+----------+
                           |
             Decoded URL   |
             Validated     |
                           v
               +----------------------+
               |   `analyze_url()`    | Application Orchestration Layer
               +-----------+----------+
                           |
                           v
               +----------------------+
               |   Phase 1: Parser    | RFC 3986 Lexical Decomposition
               +-----------+----------+
                           | ParsedURL
                           v
               +----------------------+
               |  Phase 2: Features   | Feature / Ground Fact Generation
               +-----+----------+-----+
                     |          |
   Candidate Labels  |          | Ground Propositional Facts
                     v          |
         +-----------------+    |
         | Phase 7: A*     |    |
         | Heuristic Search|    |
         +-------+---------+    |
                 |              |
   `brand_typosquatting_detected`
                 |              |
                 v              v
           +--------------------------+
           | Phase 3: Knowledge Base  | Declarative Positive Horn Clauses
           +-------------+------------+
                         |
                         v
           +--------------------------+
           |  Phase 4: PL-FC-Entails  | Classical Forward Chaining
           +-------------+------------+
                         | Inferred Patterns & Derivation Trace
                         v
           +--------------------------+
           | Phase 5: Risk Evaluator  | Deterministic Max-Severity Mapping
           +-------------+------------+
                         | RiskAssessment
                         v
           +--------------------------+
           | Phase 6: Proof Tree      | Explainable Derivation Tree Synthesis
           +-------------+------------+
                         |
                         v
           +--------------------------+
           |  AnalysisReport (DTO)    |
           +-------------+------------+
                         |
                         v
           +--------------------------+
           |     Phase 8: Web UI      | Presentation Layer (Flask + Vanilla CSS/JS)
           +--------------------------+
```

---

## 3. Module Responsibilities & System Boundaries

| Module | Location | Core Responsibility | AI Role |
| :--- | :--- | :--- | :--- |
| **URL Parser** | `core/parser/rfc_parser.py`, `ip_detector.py` | Strict RFC 3986 lexical decomposition without network access. Detects IPv4, IPv6, ports, schemes, authority userinfo. | Lexical Preprocessing |
| **Feature Generator** | `core/features/fact_generator.py` | Converts parsed components into positive propositional facts (e.g. `hostname_is_ip_address`, `scheme_is_http`). | Fact Extraction |
| **A* Typosquatting Search** | `core/search/astar.py`, `brand_lexicon.py` | State-space heuristic search exploring string edit operations against a curated local brand lexicon. Emits `brand_typosquatting_detected`. | **Secondary AI Algorithm** |
| **Knowledge Base** | `core/logic/knowledge_base.py`, `clauses.py` | Registry of declarative definite Horn clauses ($P_1 \land \dots \land P_n \to Q$) representing cybersecurity axioms. | Knowledge Representation |
| **Forward Chaining Engine** | `core/logic/forward_chaining.py` | Textbook `PL-FC-Entails` with FIFO agenda, count table, premise indexing, and derivation provenance records. | **Primary AI Algorithm** |
| **Risk Evaluator** | `core/risk/evaluator.py` | Resolves inferred security patterns to categorical verdicts (`SAFE`, `REVIEW`, `SUSPICIOUS`, `HIGH RISK`) via max-severity ordering. | Decision Logic |
| **Explanation Synthesizer**| `core/explanation/proof_tree.py` | Synthesizes explainable Proof Tree DAGs answering "Why was this verdict assigned?". | Explainable AI (XAI) |
| **Application Service** | `core/application/analyze.py` | Single orchestrator coordinating the entire pipeline into a clean `AnalysisReport`. | Application Orchestration |
| **Offline QR Decoder** | `core/qr/decoder.py` | Offline image decoding using OpenCV matrix extraction; rejects non-URL payloads cleanly. | Input Adapter |
| **Web Presentation** | `web/app.py`, `templates/`, `static/` | Browser interface displaying components, verdicts, proof trees, and A* search evidence. | Presentation Only |

---

## 4. Complete Data Flows

### A. Direct URL Flow
1. User supplies a raw URL string (e.g., `https://g00gle.com/login`).
2. Input is passed directly to `analyze_url(raw_url)` in `core.application.analyze`.
3. `parse_url` partitions the URL into scheme, authority, userinfo, hostname, port, path, query, and fragment.
4. `extract_features` observes components and queries `detect_brand_typosquatting(hostname)`:
   - A* search runs between `g00gle` and `google`, returning total edit cost = 2 (`SUBSTITUTE '0'->'o'`, `SUBSTITUTE '0'->'o'`).
   - Ground fact `brand_typosquatting_detected` is asserted alongside `path_contains_sensitive_keyword` and `scheme_is_https`.
5. `pl_fc_entails` receives the ground facts and KB rules:
   - Initial agenda pushes ground facts.
   - Decrements count table for `RULE_TYPOSQUATTING_SENSITIVE_KEYWORD` ($2 \to 0$).
   - Fires rule and derives `pattern_targeted_brand_phishing` with `DerivationStep` provenance.
6. `evaluate_risk` inspects fired steps:
   - Identifies highest severity: `CRITICAL`.
   - Maps categorical verdict: `HIGH RISK`.
7. `build_explanation` traverses derivation trace from sink to source facts, constructing an inspectable Proof Tree.
8. `AnalysisReport` is emitted and returned to the caller or serialized to JSON for the Web UI.

### B. QR Code Flow
1. User uploads an image file (PNG, JPG, WebP) or in-memory byte buffer.
2. `analyze_qr_image` routes data to `decode_qr_image` (`core.qr.decoder`).
3. Local OpenCV `cv2.QRCodeDetector` isolates finder patterns and reconstructs the decoded payload completely offline.
4. Multi-code ambiguities or corrupted/blank images are rejected.
5. If decoded text is plain text or non-URL data, the system returns a validation message and **does not** run security analysis or mark it `SAFE`.
6. If the payload is a valid URL, it is routed into `analyze_url()`, yielding identical analysis semantics to direct URL input.

---

## 5. Relationship Between A* Search and Forward Chaining

A critical architectural principle of this system is the strict separation between search-based fact discovery and logical deduction:
- **A* Search is NOT a risk classifier**: A* does not produce a verdict or assign severity. It only solves the state-space string-alignment problem to ascertain whether a hostname label closely resembles a known brand within a strict threshold ($g(n) \le 2$).
- **A* supplies ground percepts**: If and only if A* establishes a low-cost transformation path, the ground literal `brand_typosquatting_detected` is asserted into the fact set.
- **Forward Chaining performs all reasoning**: Forward chaining evaluates `brand_typosquatting_detected` in conjunction with other contextual facts:
  - If paired with `scheme_is_http`, Forward Chaining deduces `pattern_insecure_brand_impersonation` (`HIGH` severity $\to$ `SUSPICIOUS`).
  - If paired with `path_contains_sensitive_keyword`, Forward Chaining deduces `pattern_targeted_brand_phishing` (`CRITICAL` severity $\to$ `HIGH RISK`).
  - If isolated without anomaly factors, typosquatting alone does not trigger critical credential harvesting rules.

---

## 6. Application / UI Decoupling

The web interface (`web/app.py`, `templates/index.html`, `static/js/app.js`) is strictly a presentation layer:
- The UI contains **zero parsing, zero inference, zero heuristics, and zero risk evaluation**.
- The frontend interacts exclusively via HTTP `POST /api/analyze` or `POST /api/analyze-qr`.
- All visual widgets (severity badges, pattern cards, collapsible proof trees, A* step timelines) render structured data directly from the immutable `AnalysisReport` DTO.
