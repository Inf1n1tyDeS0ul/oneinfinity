"""
Shared reporting constants and mapping tables for oneinfinity.
Includes CWE, OWASP Top 10, Bugcrowd VRT, and remediation guidance.
"""

# CWE mapping
CWE_MAP = {
    "sqli":               ("CWE-89",  "Improper Neutralization of Special Elements used in an SQL Command"),
    "xss":                ("CWE-79",  "Improper Neutralization of Input During Web Page Generation"),
    "ssrf":               ("CWE-918", "Server-Side Request Forgery"),
    "idor":               ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
    "rce":                ("CWE-78",  "Improper Neutralization of Special Elements used in an OS Command"),
    "lfi":                ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory"),
    "ssti":               ("CWE-94",  "Improper Control of Generation of Code"),
    "open-redirect":      ("CWE-601", "URL Redirection to Untrusted Site"),
    "cors":               ("CWE-942", "Permissive Cross-domain Policy with Untrusted Domains"),
    "info-disclosure":    ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
    "auth-bypass":        ("CWE-287", "Improper Authentication"),
    "csrf":               ("CWE-352", "Cross-Site Request Forgery"),
    "subdomain-takeover": ("CWE-840", "Business Logic Errors"),
    "xxe":                ("CWE-611", "Improper Restriction of XML External Entity Reference"),
    "command-injection":  ("CWE-77",  "Improper Neutralization of Special Elements used in a Command"),
    "path-traversal":     ("CWE-22",  "Improper Limitation of a Pathname to a Restricted Directory"),
    "mass-assignment":    ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
}

OWASP_MAP = {
    "sqli":           "A03:2021 — Injection",
    "xss":            "A03:2021 — Injection",
    "ssrf":           "A10:2021 — Server-Side Request Forgery",
    "idor":           "A01:2021 — Broken Access Control",
    "rce":            "A03:2021 — Injection",
    "lfi":            "A01:2021 — Broken Access Control",
    "ssti":           "A03:2021 — Injection",
    "open-redirect":  "A01:2021 — Broken Access Control",
    "cors":           "A05:2021 — Security Misconfiguration",
    "info-disclosure":"A02:2021 — Cryptographic Failures",
    "auth-bypass":    "A07:2021 — Identification and Authentication Failures",
    "csrf":           "A01:2021 — Broken Access Control",
    "xxe":            "A05:2021 — Security Misconfiguration",
    "command-injection": "A03:2021 — Injection",
}

# Bugcrowd VRT mapping (simplified)
BUGCROWD_VRT = {
    "sqli":              ("server-side-injection", "sql-injection", "P1"),
    "xss":               ("cross-site-scripting-xss", "reflected-xss", "P3"),
    "xss-stored":        ("cross-site-scripting-xss", "stored-xss", "P2"),
    "ssrf":              ("server-side-request-forgery-ssrf", "", "P2"),
    "idor":              ("broken-access-control", "insecure-direct-object-reference", "P2"),
    "rce":               ("remote-code-execution", "", "P1"),
    "lfi":               ("local-file-inclusion", "", "P2"),
    "ssti":               ("server-side-template-injection", "", "P1"),
    "open-redirect":     ("unvalidated-redirects-and-forwards", "open-redirect", "P4"),
    "cors":              ("broken-access-control", "cors-misconfiguration", "P3"),
    "info-disclosure":   ("sensitive-data-exposure", "server-information-disclosure", "P5"),
    "auth-bypass":       ("broken-authentication", "authentication-bypass", "P2"),
    "csrf":               ("cross-site-request-forgery-csrf", "", "P4"),
    "subdomain-takeover":("dns-vulnerability", "subdomain-takeover", "P2"),
    "xxe":               ("xml-external-entity-injection-xxe", "", "P2"),
    "command-injection": ("server-side-injection", "os-command-injection", "P1"),
}

REMEDIATIONS = {
    "sqli": (
        "Use parameterized queries or prepared statements. "
        "Never interpolate user input into SQL strings. "
        "Example (Python): `cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))`"
    ),
    "xss": (
        "Encode all user-supplied data before rendering in HTML. "
        "Implement a strict Content Security Policy (CSP). "
        "Use framework-provided escaping functions (e.g., `{{ value | escape }}` in Jinja2)."
    ),
    "ssrf": (
        "Validate and whitelist allowed URL schemes and destinations. "
        "Block requests to private IP ranges (RFC 1918) and cloud metadata endpoints. "
        "Use a DNS resolver that validates the final IP after resolution."
    ),
    "idor": (
        "Enforce authorization on every object access: verify the requesting user "
        "owns or has permission to access the requested resource. "
        "Avoid using predictable IDs — use random UUIDs or opaque tokens."
    ),
    "cors": (
        "Do not reflect the request Origin header blindly. "
        "Maintain an explicit allowlist of trusted origins. "
        "Never combine `Access-Control-Allow-Credentials: true` with a wildcard or reflected origin."
    ),
    "open-redirect": (
        "Validate redirect destinations against a whitelist of allowed URLs/domains. "
        "If dynamic redirects are necessary, use an indirect reference map rather than "
        "accepting full URLs from users."
    ),
    "ssti": (
        "Never pass user input directly into template rendering functions. "
        "Use sandboxed template environments where available. "
        "Separate template logic from user-controlled data."
    ),
    "xxe": (
        "Disable XML external entity processing in your XML parser. "
        "In Java: `factory.setFeature('http://xml.org/sax/features/external-general-entities', false)`. "
        "Prefer JSON for data exchange where XML is not required."
    ),
    "command-injection": (
        "Avoid passing user input to shell commands. "
        "If shell execution is necessary, use language-native APIs with argument arrays "
        "(not string interpolation). Whitelist allowed input values."
    ),
    "subdomain-takeover": (
        "Remove or update dangling DNS CNAME records pointing to decommissioned services. "
        "Implement a process to audit DNS records when services are shut down."
    ),
}

def normalize_vuln_type(vt: str) -> str:
    if not vt: return "other"
    return vt.lower().replace(" ", "-").replace("_", "-")
