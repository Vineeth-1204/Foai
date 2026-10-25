# Live Demo Test Links and QR Images

Use these pre-tested URLs and QR code images in the web dashboard at http://127.0.0.1:5000

| Sample ID | Expected Verdict | Link / URL | Generated QR Code Image |
|---|---|---|---|
| **Legitimate Clean Website (HTTPS)** | `SAFE` (NONE) | `https://www.google.com/search?q=symbolic+artificial+intelligence` | [`01_safe_legitimate.png`](01_safe_legitimate.png) |
| **Credential Masking via '@' Authority** | `HIGH RISK` (CRITICAL) | `http://paypal.com@192.168.1.100/account/verify` | [`02_credential_masking_at_symbol.png`](02_credential_masking_at_symbol.png) |
| **Brand Typosquatting (A* Match: 'paypa1' -> 'paypal')** | `HIGH RISK` (CRITICAL) | `http://paypa1.com/login` | [`03_brand_typosquatting_phishing.png`](03_brand_typosquatting_phishing.png) |
| **Direct IP Targeting Sensitive Endpoint** | `HIGH RISK` (CRITICAL) | `http://185.220.101.5/banking/login` | [`04_ip_and_sensitive_keyword.png`](04_ip_and_sensitive_keyword.png) |
| **Malware Delivery via Double Extension** | `HIGH RISK` (CRITICAL) | `https://cloud-share-files.org/annual_report.pdf.exe` | [`05_executable_masquerading.png`](05_executable_masquerading.png) |
| **Non-Standard Network Port** | `REVIEW` (MEDIUM) | `https://portal-portal.org:8443/status` | [`06_unconventional_port.png`](06_unconventional_port.png) |
| **Unencrypted HTTP Transport** | `REVIEW` (LOW) | `http://my-personal-travel-blog.com/about` | [`07_insecure_http_transport.png`](07_insecure_http_transport.png) |


## Detailed Scenarios

### Legitimate Clean Website (HTTPS)
- **URL:** `https://www.google.com/search?q=symbolic+artificial+intelligence`
- **AI Verdict:** `SAFE`
- **Triggered Rules:** `None (Clean Baseline)`
- **QR Image:** `demo_samples\01_safe_legitimate.png`
- **Explanation:** Verdict: SAFE.
Highest Triggered Severity: NONE.
Evaluation: No significant suspicious indicators were detected by the current local rule set.

### Credential Masking via '@' Authority
- **URL:** `http://paypal.com@192.168.1.100/account/verify`
- **AI Verdict:** `HIGH RISK`
- **Triggered Rules:** `RULE_USERINFO_DELIMITER, RULE_IP_AND_SENSITIVE_KEYWORD`
- **QR Image:** `demo_samples\02_credential_masking_at_symbol.png`
- **Explanation:** Verdict: HIGH RISK.
Highest Triggered Severity: CRITICAL.
The verdict was established because 2 security pattern(s) were logically derived by forward chaining:
- Pattern 'pattern_credential_masking' [CRITICAL] was derived via rule RULE_USERINFO_DELIMITER ('Credential Masking via Authority Userinfo') after proving premises: (has_userinfo_delimiter).
- Pattern 'pattern_credential_harvesting_on_ip' [CRITICAL] was derived via rule RULE_IP_AND_SENSITIVE_KEYWORD ('Credential Harvesting Pattern via Direct IP') after proving premises: (hostname_is_ip_address AND path_contains_sensitive_keyword).

### Brand Typosquatting (A* Match: 'paypa1' -> 'paypal')
- **URL:** `http://paypa1.com/login`
- **AI Verdict:** `HIGH RISK`
- **Triggered Rules:** `RULE_TYPOSQUATTING_SENSITIVE_KEYWORD, RULE_TYPOSQUATTING_INSECURE_HTTP`
- **QR Image:** `demo_samples\03_brand_typosquatting_phishing.png`
- **Explanation:** Verdict: HIGH RISK.
Highest Triggered Severity: CRITICAL.
The verdict was established because 2 security pattern(s) were logically derived by forward chaining:
- Pattern 'pattern_targeted_brand_phishing' [CRITICAL] was derived via rule RULE_TYPOSQUATTING_SENSITIVE_KEYWORD ('Targeted Brand Phishing') after proving premises: (brand_typosquatting_detected AND path_contains_sensitive_keyword).
- Pattern 'pattern_insecure_brand_impersonation' [HIGH] was derived via rule RULE_TYPOSQUATTING_INSECURE_HTTP ('Insecure Brand Impersonation') after proving premises: (brand_typosquatting_detected AND scheme_is_http).

### Direct IP Targeting Sensitive Endpoint
- **URL:** `http://185.220.101.5/banking/login`
- **AI Verdict:** `HIGH RISK`
- **Triggered Rules:** `RULE_IP_AND_SENSITIVE_KEYWORD`
- **QR Image:** `demo_samples\04_ip_and_sensitive_keyword.png`
- **Explanation:** Verdict: HIGH RISK.
Highest Triggered Severity: CRITICAL.
The verdict was established because 1 security pattern(s) were logically derived by forward chaining:
- Pattern 'pattern_credential_harvesting_on_ip' [CRITICAL] was derived via rule RULE_IP_AND_SENSITIVE_KEYWORD ('Credential Harvesting Pattern via Direct IP') after proving premises: (hostname_is_ip_address AND path_contains_sensitive_keyword).

### Malware Delivery via Double Extension
- **URL:** `https://cloud-share-files.org/annual_report.pdf.exe`
- **AI Verdict:** `HIGH RISK`
- **Triggered Rules:** `RULE_DOUBLE_EXTENSION`
- **QR Image:** `demo_samples\05_executable_masquerading.png`
- **Explanation:** Verdict: HIGH RISK.
Highest Triggered Severity: CRITICAL.
The verdict was established because 1 security pattern(s) were logically derived by forward chaining:
- Pattern 'pattern_executable_masquerading' [CRITICAL] was derived via rule RULE_DOUBLE_EXTENSION ('Executable Masquerading via Double Extension') after proving premises: (has_double_extension).

### Non-Standard Network Port
- **URL:** `https://portal-portal.org:8443/status`
- **AI Verdict:** `REVIEW`
- **Triggered Rules:** `RULE_NON_STANDARD_PORT`
- **QR Image:** `demo_samples\06_unconventional_port.png`
- **Explanation:** Verdict: REVIEW.
Highest Triggered Severity: MEDIUM.
The verdict was established because 1 security pattern(s) were logically derived by forward chaining:
- Pattern 'pattern_unconventional_endpoint' [MEDIUM] was derived via rule RULE_NON_STANDARD_PORT ('Unconventional Port Endpoint') after proving premises: (has_non_standard_port).

### Unencrypted HTTP Transport
- **URL:** `http://my-personal-travel-blog.com/about`
- **AI Verdict:** `REVIEW`
- **Triggered Rules:** `RULE_HTTP_INSECURE_TRANSPORT`
- **QR Image:** `demo_samples\07_insecure_http_transport.png`
- **Explanation:** Verdict: REVIEW.
Highest Triggered Severity: LOW.
The verdict was established because 1 security pattern(s) were logically derived by forward chaining:
- Pattern 'pattern_insecure_transport_only' [LOW] was derived via rule RULE_HTTP_INSECURE_TRANSPORT ('Insecure Transport on Unauthenticated Path') after proving premises: (scheme_is_http AND path_has_no_sensitive_keyword).

