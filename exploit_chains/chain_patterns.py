"""Chain pattern registry — defines which vuln type combinations form attack chains."""
from typing import FrozenSet, Dict, Any

CHAIN_PATTERNS: Dict[str, Dict[str, Any]] = {
    "sqli_to_rce": {
        # Canonical vuln_type values from result_ingestion_engine parsers
        "trigger_types": frozenset({"sqli", "sqli_blind", "sqli_time", "sqli_error"}),
        "steps": ["sql_injection", "file_write", "command_execution"],
        "cvss_boost": 2.5,
        "severity": "critical",
        "confidence": 0.8,
    },
    "xss_to_account_takeover": {
        "trigger_types": frozenset({"xss", "stored_xss", "dom_xss"}),
        "steps": ["reflected_xss", "csrf_token_theft", "account_takeover"],
        "cvss_boost": 1.8,
        "severity": "high",
        "confidence": 0.7,
    },
    "ssrf_to_metadata": {
        "trigger_types": frozenset({"ssrf"}),
        "steps": ["ssrf", "cloud_metadata_access", "credential_exfiltration"],
        "cvss_boost": 3.0,
        "severity": "critical",
        "confidence": 0.85,
    },
    "idor_to_privilege_escalation": {
        "trigger_types": frozenset({"idor", "bac"}),
        "steps": ["idor", "admin_object_access", "privilege_escalation"],
        "cvss_boost": 2.0,
        "severity": "critical",
        "confidence": 0.75,
    },
    "open_redirect_to_oauth_hijack": {
        "trigger_types": frozenset({"open_redirect"}),
        "steps": ["open_redirect", "oauth_token_leakage", "account_takeover"],
        "cvss_boost": 1.5,
        "severity": "high",
        "confidence": 0.7,
    },
    "cors_to_credential_theft": {
        "trigger_types": frozenset({"cors"}),
        "steps": ["cors_misconfiguration", "cross_origin_request", "credential_exfiltration"],
        "cvss_boost": 1.5,
        "severity": "high",
        "confidence": 0.7,
    },
}
