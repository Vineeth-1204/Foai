# Viva & Faculty Presentation Demonstration Script

This document provides a step-by-step demonstration walkthrough for viva examinations, faculty evaluations, and technical demonstrations. The entire demonstration runs **100% offline** and is **completely deterministic**.

---

## Preparation & Starting the Application

1. Open PowerShell or a terminal inside the project root: `d:\Projects\FOAI\urlparser`.
2. Start the local presentation server:
   ```bash
   python web/app.py
   ```
3. Open a modern web browser to `http://127.0.0.1:5000`.
4. Observe the dashboard interface featuring dual input modes: **Manual URL Inspection** and **Offline QR Code Scanner**.

---

## Step-by-Step Viva Presentation Walkthrough

### Part 1: Clean Baseline Legitimate Link
1. In the URL input field, enter:
   ```
   https://example.com
   ```
2. Click **"Run Offline Analysis"**.
3. **Point out to Faculty**:
   - **Verdict**: `SAFE` with `NONE` severity.
   - **Baseline Rule**: Notice that `SAFE` is not an unproven default; the proof tree proves `zero_suspicious_indicators_present` via `RULE_CLEAN_BASELINE` across all 11 clean indicators.
   - **Safe Disclaimer**: Point out the prominent legal/operational disclaimer:
     *"Destination legitimacy cannot be guaranteed because the URL was analyzed locally without contacting the destination."*
   - **A* Evidence Card**: Remains hidden because no typosquatting was detected.

---

### Part 2: Direct IP Credential Harvesting
1. In the URL input field, enter:
   ```
   https://192.168.1.10/login
   ```
2. Click **"Run Offline Analysis"**.
3. **Point out to Faculty**:
   - **Verdict**: `HIGH RISK` with `CRITICAL` severity.
   - **Triggered Rule**: `RULE_IP_AND_SENSITIVE_KEYWORD` ("Credential Harvesting Pattern via Direct IP").
   - **Triggered Pattern**: `pattern_credential_harvesting_on_ip`.
   - **Proof Tree**: Click to expand the Proof Tree DAG:
     - Ground fact 1: `hostname_is_ip_address` (with evidence `hostname='192.168.1.10'`).
     - Ground fact 2: `path_contains_sensitive_keyword` (with evidence `keyword='login'`).
     - Derivation: Shows both facts feeding into `RULE_IP_AND_SENSITIVE_KEYWORD` to derive the critical pattern.

---

### Part 3: Secondary AI in Action — A* Typosquatting Search
1. In the URL input field, enter:
   ```
   https://g00gle.com/login
   ```
2. Click **"Run Offline Analysis"**.
3. **Point out to Faculty**:
   - **Verdict**: `HIGH RISK` with `CRITICAL` severity.
   - **A* Typosquatting Evidence Card**:
     - Observed Label: `g00gle`
     - Matched Brand: `google`
     - Optimal Edit Distance ($g(n)$): `2`
     - Discrete Edit Operations:
       1. `SUBSTITUTE '0' -> 'o'` (Cost 1)
       2. `SUBSTITUTE '0' -> 'o'` (Cost 1)
     - Heuristic Used: $f(n) = g(n) + h(n)$ with admissible Manhattan-length heuristic.
   - **Forward Chaining Deduction**:
     - A* asserted the ground literal `brand_typosquatting_detected`.
     - Forward Chaining evaluated the Horn clause `brand_typosquatting_detected ^ path_contains_sensitive_keyword => pattern_targeted_brand_phishing`.
     - Emphasize that A* is purely upstream feature discovery; Forward Chaining performs the security reasoning!

---

### Part 4: Insecure Brand Impersonation (HTTP vs HTTPS contrast)
1. In the URL input field, enter:
   ```
   http://paypa1.com/index
   ```
2. Click **"Run Offline Analysis"**.
3. **Point out to Faculty**:
   - **Verdict**: `SUSPICIOUS` with `HIGH` severity.
   - **A* Evidence**: `paypa1` $\to$ `paypal` (Cost 1, `SUBSTITUTE '1' -> 'l'`).
   - Contrast with previous example: Here, without a sensitive keyword like `/login`, the Horn rule `RULE_TYPOSQUATTING_INSECURE_HTTP` fires instead, assigning `HIGH` severity (`SUSPICIOUS`) rather than `CRITICAL`. This demonstrates fine-grained, contextual logic.

---

### Part 5: Offline QR Decoding & Semantic Parity
1. Switch to the **"Scan QR Code"** tab in the dashboard.
2. Synthesize or upload a QR image containing `https://g00gle.com/login`.
   *(A QR can be generated in 2 seconds via python: `import qrcode; qrcode.make('https://g00gle.com/login').save('demo_phish.png')`)*
3. Select the file and click **"Decode & Analyze QR"**.
4. **Point out to Faculty**:
   - **QR Decoder Status**: Displays decoded payload `https://g00gle.com/login` extracted locally via OpenCV matrix detection.
   - **Semantic Equivalence**: The resulting `AnalysisReport`, proof tree, A* evidence, and `HIGH RISK` verdict match the direct URL input identically, proving that the QR pipeline is an input adapter with zero duplicate logic.

---

### Part 6: Non-URL QR Payload Validation
1. Upload a QR code containing plain text, such as:
   `"Meeting room schedule: Room 402 at 3:00 PM"`
2. Click **"Decode & Analyze QR"**.
3. **Point out to Faculty**:
   - The QR decodes successfully.
   - **Crucial Security Behavior**: The system **does NOT classify this as SAFE**.
   - Instead, the validator warns: *"QR code decoded successfully, but the content is not a URL that this analyzer can process."*
   - Explains that non-URL strings cannot be evaluated by URL security rules.

---

## Summary for Viva Defense

- **Primary AI**: Propositional Definite Horn Logic + `PL-FC-Entails` Forward Chaining.
- **Secondary AI**: A* Heuristic Search ($f(n) = g(n) + h(n)$) with mathematically proven admissible heuristic.
- **Explainability**: Complete derivation DAG proof trees.
- **Privacy & Security**: 100% air-gapped, zero network queries, zero external telemetry.
- **Soundness**: Zero black-box machine learning; completely deterministic and verifiable.
