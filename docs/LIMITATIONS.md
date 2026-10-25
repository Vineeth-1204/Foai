# System Limitations & Operational Boundaries

This document provides a candid evaluation of the system's operational boundaries, assumptions, and security limitations. In accordance with sound engineering practice, these constraints are explicitly stated and must be understood when interpreting analysis outcomes.

---

## 1. Strictly Local, Air-Gapped Analysis
The system operates **completely offline** and performs zero network transmission. It does not send HTTP requests, inspect TLS certificates, or retrieve remote web content. Consequently, malicious payloads delivered purely via server-side logic (e.g. content served dynamically based on user-agent or geolocation) cannot be observed or analyzed.

---

## 2. Absence of Live Threat Intelligence Feeds
The analyzer does not query commercial or community threat intelligence databases (such as Google Safe Browsing, VirusTotal, or PhishTank). Newly registered domains, ephemeral phishing infrastructure, or compromised legitimate websites not exhibiting structural anomalies in their URL syntax will not trigger rules.

---

## 3. Absence of Live DNS Resolution & Verification
The system does not perform DNS lookups. As a result:
- It cannot detect whether a domain name actually resolves to an IP address or NXDOMAIN.
- It cannot detect DNS fast-flux or newly minted domain registrations.
- It cannot verify whether an IP address belongs to a residential proxy, hosting provider, or corporate ASN.

---

## 4. Semantics of the `SAFE` Verdict
A verdict of **`SAFE` does NOT guarantee that a destination website is legitimate, authentic, or benevolent**. 

The system strictly enforces the following semantic definitions:
> **Evaluation**: *"No significant suspicious indicators were detected by the current local rule set."*  
> **Mandatory Disclaimer**: *"Destination legitimacy cannot be guaranteed because the URL was analyzed locally without contacting the destination."*

A benign rating simply denotes that the URL conforms to the clean baseline indicator profile and triggers zero known anomaly rules in the local Knowledge Base.

---

## 5. Curated Local Brand Lexicon
The upstream A* typosquatting detector operates against a curated, finite in-memory brand dictionary (`core/search/brand_lexicon.py`). Brands, financial institutions, or localized services not included in this static dictionary will not trigger `brand_typosquatting_detected`.

---

## 6. Threshold-Bounded A* Edit Distance
A* search identifies typosquatting using a maximum edit distance threshold ($g(n) \le 2$). Phishing domains that alter brand names by 3 or more characters (e.g. `google-account-verify-login-portal.com`) will exceed the threshold for direct brand label comparison and rely instead on other structural rules (such as subdomains or keywords).

---

## 7. Knowledge Base Coverage Boundaries
The inference engine is bounded by the specific definite Horn rules encoded in the Knowledge Base (`core/rules/anomaly_rules.json`). Novel obfuscation techniques or attack vectors that do not match the premise combinations of rules R1 through R9 will not be inferred.

---

## 8. Offline QR Decoding Constraints
Offline QR code decoding via OpenCV's `QRCodeDetector` relies on image quality, resolution, contrast, and standard 2D matrix geometry:
- Severely blurred, torn, distorted, or low-contrast QR images may fail extraction.
- Non-standard, stylized, or proprietary QR formats may not be decoded.
- Images containing multiple distinct QR codes are rejected intentionally to prevent ambiguous routing.
- QR payloads containing non-URL data (e.g. vCards, WiFi configurations, plain text) are correctly validated and rejected from URL security analysis rather than falsely reported as safe.
