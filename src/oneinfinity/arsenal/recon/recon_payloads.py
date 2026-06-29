"""
Recon payloads — OSINT subdomain, endpoint, and fingerprinting probes.
Used by ContextMatcher for tech-stack-aware recon payload selection.
"""
from __future__ import annotations
from oneinfinity.arsenal.context_matcher import Payload

RECON_PAYLOADS = [
    # ── Subdomain wordlist probes ─────────────────────────────────────────────
    Payload("admin",          vuln_type="recon", tags=["subdomain","high-value"]),
    Payload("api",            vuln_type="recon", tags=["subdomain","api"]),
    Payload("dev",            vuln_type="recon", tags=["subdomain"]),
    Payload("staging",        vuln_type="recon", tags=["subdomain"]),
    Payload("test",           vuln_type="recon", tags=["subdomain"]),
    Payload("beta",           vuln_type="recon", tags=["subdomain"]),
    Payload("portal",         vuln_type="recon", tags=["subdomain","high-value"]),
    Payload("vpn",            vuln_type="recon", tags=["subdomain","infra"]),
    Payload("mail",           vuln_type="recon", tags=["subdomain","infra"]),
    Payload("jenkins",        vuln_type="recon", tags=["subdomain","cicd","high-value"]),
    Payload("ci",             vuln_type="recon", tags=["subdomain","cicd"]),
    Payload("jira",           vuln_type="recon", tags=["subdomain","internal"]),
    Payload("confluence",     vuln_type="recon", tags=["subdomain","internal"]),
    Payload("gitlab",         vuln_type="recon", tags=["subdomain","cicd","high-value"]),
    Payload("git",            vuln_type="recon", tags=["subdomain","cicd"]),
    Payload("internal",       vuln_type="recon", tags=["subdomain","internal"]),
    Payload("corp",           vuln_type="recon", tags=["subdomain","internal"]),
    Payload("dashboard",      vuln_type="recon", tags=["subdomain","high-value"]),
    Payload("monitoring",     vuln_type="recon", tags=["subdomain","infra"]),
    Payload("grafana",        vuln_type="recon", tags=["subdomain","monitoring"]),
    # ── Directory/path probes ─────────────────────────────────────────────────
    Payload("/.git/config",   vuln_type="recon", tags=["path","git","high-value"]),
    Payload("/.env",          vuln_type="recon", tags=["path","config","high-value"]),
    Payload("/robots.txt",    vuln_type="recon", tags=["path","disclosure"]),
    Payload("/sitemap.xml",   vuln_type="recon", tags=["path","disclosure"]),
    Payload("/.well-known/security.txt", vuln_type="recon", tags=["path","disclosure"]),
    Payload("/swagger.json",  vuln_type="recon", tags=["path","api-docs","high-value"]),
    Payload("/openapi.json",  vuln_type="recon", tags=["path","api-docs","high-value"]),
    Payload("/api/v1/",       vuln_type="recon", tags=["path","api"]),
    Payload("/graphql",       vuln_type="recon", tags=["path","api","graphql"]),
    Payload("/admin/",        vuln_type="recon", tags=["path","admin","high-value"]),
    Payload("/phpinfo.php",   vuln_type="recon", tech_stack=["php"], tags=["path","php"]),
    Payload("/wp-login.php",  vuln_type="recon", tech_stack=["php","wordpress"], tags=["path","cms"]),
    Payload("/actuator/health", vuln_type="recon", tech_stack=["java","spring"], tags=["path","spring"]),
    Payload("/actuator/env",  vuln_type="recon", tech_stack=["java","spring"], tags=["path","spring","high-value"]),
    # ── Technology fingerprint probes ─────────────────────────────────────────
    Payload("X-Powered-By",   vuln_type="recon", tags=["header","fingerprint"]),
    Payload("Server",         vuln_type="recon", tags=["header","fingerprint"]),
    Payload("X-AspNet-Version", vuln_type="recon", tech_stack=["asp"], tags=["header","fingerprint"]),
    Payload("X-Generator",    vuln_type="recon", tags=["header","fingerprint","cms"]),
    Payload("X-Debug-Token",  vuln_type="recon", tech_stack=["php","symfony"], tags=["header","debug"]),
]
