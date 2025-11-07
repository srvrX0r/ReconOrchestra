# Responsible Disclosure Report

**Summary:**  
(A 2–3 sentence non-actionable summary.)

**Scope & Authorization:**  
- Target(s): (list domains / IPs in-scope)
- Authorization proof: (e.g., signed PDF filename or ticket reference)

**Affected URLs / Artifacts (sanitized)**  
- https://example.com/path — (do not include tokens or secrets)

**Severity:** informational / low / medium / high / critical

**High-level Impact:**  
(Conceptual impact without exploit details)

**How to reproduce (skeleton, non-actionable):**  
1. Make a GET request to `https://target/endpoint` with parameter `X` set to `A` and observe server response 302 (no payloads, no exploit strings).  
2. Observe header `X-Example`.

**Suggested Fixes:**  
- Validate and sanitize input `X` at server-side.  
- Harden header parsing.  
- Add WAF rule: block suspicious payload shapes (example: long query strings).

**Contact & Proof-of-Authorization:**  
- Name:  
- Email:  
- Link to authorization doc:  

**Request:** Please acknowledge receipt and provide an estimated remediation timeline.
