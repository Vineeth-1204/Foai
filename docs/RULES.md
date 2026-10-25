# Knowledge Base Rule Catalog

This document catalogs every Horn clause currently registered in the system's declarative Knowledge Base (`core/rules/anomaly_rules.json` and `core/rules/clean_rules.json`).

Every rule conforms strictly to positive definite Horn clause logic:
$$P_1 \land P_2 \land \dots \land P_n \implies Q$$

---

## 1. Anomaly Horn Rules

### RULE_IP_AND_SENSITIVE_KEYWORD
- **Rule ID**: `RULE_IP_AND_SENSITIVE_KEYWORD`
- **Name**: Credential Harvesting Pattern via Direct IP
- **Premises**:
  1. `hostname_is_ip_address`
  2. `path_contains_sensitive_keyword`
- **Conclusion**: `pattern_credential_harvesting_on_ip`
- **Severity**: `CRITICAL`
- **Purpose**: Identifies attack URLs directing users to raw IP addresses (bypassing DNS domain reputation) while targeting authentication or verification paths (`/login`, `/signin`, `/verify`, etc.).

---

### RULE_USERINFO_DELIMITER
- **Rule ID**: `RULE_USERINFO_DELIMITER`
- **Name**: Credential Masking via Authority Userinfo
- **Premises**:
  1. `has_userinfo_delimiter`
- **Conclusion**: `pattern_credential_masking`
- **Severity**: `CRITICAL`
- **Purpose**: Flags URLs that exploit the `@` delimiter in the authority component (`https://google.com@attacker.com`) to visually deceive users into believing the target is a legitimate domain.

---

### RULE_TYPOSQUATTING_INSECURE_HTTP
- **Rule ID**: `RULE_TYPOSQUATTING_INSECURE_HTTP`
- **Name**: Insecure Brand Impersonation
- **Premises**:
  1. `brand_typosquatting_detected`
  2. `scheme_is_http`
- **Conclusion**: `pattern_insecure_brand_impersonation`
- **Severity**: `HIGH`
- **Purpose**: Detects URLs where a hostname label closely resembles a trusted protected brand (identified via upstream A* search) and utilizes unencrypted HTTP transport.

---

### RULE_TYPOSQUATTING_SENSITIVE_KEYWORD
- **Rule ID**: `RULE_TYPOSQUATTING_SENSITIVE_KEYWORD`
- **Name**: Targeted Brand Phishing
- **Premises**:
  1. `brand_typosquatting_detected`
  2. `path_contains_sensitive_keyword`
- **Conclusion**: `pattern_targeted_brand_phishing`
- **Severity**: `CRITICAL`
- **Purpose**: Detects deceptive domain names that mimic known brands (e.g. `g00gle.com`) combined with sensitive authentication paths (e.g. `/login`), characteristic of targeted credential harvesting.

---

### RULE_REDIRECT_EXCESSIVE_SUBDOMAINS
- **Rule ID**: `RULE_REDIRECT_EXCESSIVE_SUBDOMAINS`
- **Name**: Obfuscated Redirect Chain
- **Premises**:
  1. `has_open_redirect_parameter`
  2. `excessive_subdomain_depth`
- **Conclusion**: `pattern_obfuscated_redirect_chain`
- **Severity**: `HIGH`
- **Purpose**: Catches URLs employing deep subdomain layering (depth $\ge 4$) together with open redirect parameters (`redirect`, `url`, `dest`, etc.) to bounce targets to unvetted third-party destinations.

---

### RULE_DOUBLE_EXTENSION
- **Rule ID**: `RULE_DOUBLE_EXTENSION`
- **Name**: Executable Masquerading via Double Extension
- **Premises**:
  1. `has_double_extension`
- **Conclusion**: `pattern_executable_masquerading`
- **Severity**: `CRITICAL`
- **Purpose**: Identifies disguised downloadable payloads where an executable extension (`.exe`, `.scr`, `.bat`) follows a benign document extension (`.pdf.exe`, `.doc.vbs`).

---

### RULE_ABNORMAL_SCHEME
- **Rule ID**: `RULE_ABNORMAL_SCHEME`
- **Name**: Abnormal or Non-Web URI Scheme
- **Premises**:
  1. `scheme_is_abnormal`
- **Conclusion**: `pattern_abnormal_scheme`
- **Severity**: `CRITICAL`
- **Purpose**: Flags dangerous non-web schemes capable of local script execution, client privilege abuse, or out-of-browser protocol handling (`javascript:`, `data:`, `file:`, `ftp:`).

---

### RULE_HTTP_INSECURE_TRANSPORT
- **Rule ID**: `RULE_HTTP_INSECURE_TRANSPORT`
- **Name**: Insecure Transport on Unauthenticated Path
- **Premises**:
  1. `scheme_is_http`
  2. `path_has_no_sensitive_keyword`
- **Conclusion**: `pattern_insecure_transport_only`
- **Severity**: `LOW`
- **Purpose**: Highlights unencrypted plain HTTP transport for benign paths that lack authentication keywords, leaving communications vulnerable to interception and tampering.

---

### RULE_NON_STANDARD_PORT
- **Rule ID**: `RULE_NON_STANDARD_PORT`
- **Name**: Unconventional Port Endpoint
- **Premises**:
  1. `has_non_standard_port`
- **Conclusion**: `pattern_unconventional_endpoint`
- **Severity**: `MEDIUM`
- **Purpose**: Identifies web links targeting non-standard communication ports outside of standard HTTP (80) and HTTPS (443) (e.g. 8080, 8443, 8888).

---

## 2. Clean Baseline Rule

### RULE_CLEAN_BASELINE
- **Rule ID**: `RULE_CLEAN_BASELINE`
- **Name**: Clean Baseline Indicator Profile
- **Premises**:
  1. `valid_url_syntax`
  2. `hostname_is_domain_name`
  3. `no_userinfo_delimiter`
  4. `scheme_is_https`
  5. `path_has_no_sensitive_keyword`
  6. `has_standard_port`
  7. `normal_subdomain_depth`
  8. `has_standard_encoding`
  9. `no_open_redirect_parameter`
  10. `no_double_extension`
  11. `no_brand_typosquatting`
- **Conclusion**: `zero_suspicious_indicators_present`
- **Severity**: `NONE`
- **Purpose**: Establishes a formal, provable baseline for legitimate links. Rather than assuming links are safe by default, the system requires all 11 clean indicators to be positively asserted before concluding `zero_suspicious_indicators_present`.
