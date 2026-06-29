"""
Adaptive Mutation Helper
========================
Dynamically mutates payloads when encountering WAF/defense signatures.
Uses WAF fingerprint from waf_detection_engine to select the most effective
bypass strategy for the detected vendor.
"""
import logging
import re
from typing import List, Optional
from oneinfinity.scan.payload_mutation_engine import PayloadMutationEngine

log = logging.getLogger("oneinfinity.adaptive_mutation")

# Module-level cached instance of the mutation engine
_MUTATION_ENGINE = None

# WAF vendor → preferred mutation strategy
_WAF_STRATEGY_MAP = {
    "cloudflare":    "waf_bypass_all",
    "modsecurity":   "waf_bypass_sqli",
    "akamai":        "waf_bypass_all",
    "aws_waf":       "waf_bypass_all",
    "sucuri":        "waf_bypass_sqli",
    "f5":            "waf_bypass_sqli",
    "imperva":       "waf_bypass_all",
    "wordfence":     "waf_bypass_xss",
    "barracuda":     "waf_bypass_sqli",
    None:            "waf_bypass_all",   # unknown WAF
}

# Response body patterns that indicate WAF block (beyond status code)
_WAF_BLOCK_PATTERNS = [
    re.compile(r'(blocked|forbidden|access denied|rejected|waf|security)', re.I),
    re.compile(r'(cf-ray|cf_clearance|__cf_bm)', re.I),
    re.compile(r'(request id|incident|reference #)', re.I),
]


def get_mutation_engine() -> PayloadMutationEngine:
    """Returns a cached instance of the PayloadMutationEngine."""
    global _MUTATION_ENGINE
    if _MUTATION_ENGINE is None:
        _MUTATION_ENGINE = PayloadMutationEngine()
    return _MUTATION_ENGINE


def is_waf_blocked(resp) -> bool:
    """Detect WAF block from status code OR response body patterns."""
    if resp is None:
        return False
    if getattr(resp, 'status_code', 0) in (403, 406, 429, 503):
        return True
    body = getattr(resp, 'text', '') or ''
    return any(p.search(body[:2000]) for p in _WAF_BLOCK_PATTERNS)


def get_waf_vendor(resp) -> Optional[str]:
    """Extract WAF vendor name from response headers."""
    if resp is None:
        return None
    headers = dict(getattr(resp, 'headers', {}))
    h_lower = {k.lower(): v.lower() for k, v in headers.items()}
    if 'cf-ray' in h_lower or 'cf-cache-status' in h_lower:
        return 'cloudflare'
    if 'x-akamai-edgescape' in h_lower or 'akamai' in str(h_lower):
        return 'akamai'
    if 'x-amzn-requestid' in h_lower or 'x-amzn-trace-id' in h_lower:
        return 'aws_waf'
    if 'x-sucuri-id' in h_lower or 'sucuri' in str(h_lower):
        return 'sucuri'
    if 'x-mod-security' in h_lower or 'modsec' in str(h_lower):
        return 'modsecurity'
    server = h_lower.get('server', '')
    if 'imperva' in server or 'incapsula' in server:
        return 'imperva'
    return None


def mutate_on_block(
    resp,
    original_payload: str,
    vuln_type: str,
    param_type: str,
    param_name: str,
) -> List[str]:
    """
    Check if response is blocked; return WAF-specific mutated payloads.

    Detects the WAF vendor from response headers and selects the optimal
    bypass strategy. Falls back to 'waf_bypass_all' for unknown vendors.
    """
    try:
        if not is_waf_blocked(resp):
            return []

        vendor = get_waf_vendor(resp)
        strategy = _WAF_STRATEGY_MAP.get(vendor, _WAF_STRATEGY_MAP[None])
        log.info(
            "Blocked by %s WAF (status %s) — applying strategy %s for %s payload",
            vendor or "unknown", getattr(resp, 'status_code', '?'), strategy, vuln_type,
        )

        engine = get_mutation_engine()

        # Use the targeted WAF bypass strategy
        waf_variants = engine.mutate_payload(original_payload, param_type, param_name, mutation_type=strategy)

        # Also apply general mutation as backup
        general = engine.mutate_payload(original_payload, param_type, param_name)

        # Merge, deduplicate, remove original
        combined = list(dict.fromkeys(
            p for p in (waf_variants + general) if p and p != original_payload
        ))
        return combined[:20]  # cap to avoid runaway expansion

    except Exception as e:
        log.error("Error during adaptive mutation: %s", e)
        return []


def select_best_payload(
    payload_candidates: List[str],
    resp_history: List,
    vuln_type: str,
) -> Optional[str]:
    """
    Select the best payload candidate based on response history.
    Prioritizes candidates that produced the least blocked/error responses.
    Returns None if all candidates are exhausted.
    """
    if not payload_candidates:
        return None
    blocked_statuses = {403, 406, 429, 503}
    # Score candidates: prefer those not yet tried or that got non-block responses
    tried = set(getattr(r, '_payload', '') for r in (resp_history or []))
    untried = [p for p in payload_candidates if p not in tried]
    return untried[0] if untried else payload_candidates[0]
