"""
Chain Suggestion Engine
========================
Real-time suggestions for completing partial attack chains.

Innovation:
1. **Partial Chain Detection** - Identifies chains 1 vuln away from completion
2. **Scanner Recommendation** - Suggests exact scanner to run next
3. **Priority Scoring** - Ranks suggestions by severity + confidence
4. **Adaptive Scanning** - Focuses effort on high-value chains
5. **Gap Analysis** - Shows what's missing from each chain

Enables intelligent, goal-oriented scanning instead of blind enumeration.
"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Set
from dataclasses import dataclass, field

log = logging.getLogger("oneinfinity.chain_suggestion")


# Import chain patterns
from oneinfinity.scan.unified_advanced_scanner import _ATTACK_CHAINS


@dataclass
class ChainSuggestion:
    """Suggestion for completing attack chain."""
    chain_name: str
    chain_severity: str
    missing_vuln_types: List[str]
    present_vuln_types: List[str]
    completion_percentage: float
    recommended_scanner: str
    confidence: float
    priority_score: float
    exploitation_impact: str


class ChainSuggestionEngine:
    """
    Suggests next tests to complete partial chains.
    """

    # Scanner mapping for vuln types
    SCANNER_MAP = {
        "sqli": "sqli_scanner",
        "xss": "xss_scanner",
        "ssrf": "ssrf_scanner",
        "xxe": "xxe_scanner",
        "idor": "multi_account_idor_engine",
        "race_condition": "race_condition_engine",
        "toctou_balance": "race_condition_engine",
        "vertical_escalation": "multi_account_idor_engine",
        "auth_bypass": "captcha_bypass_engine",
        "2fa_bypass": "captcha_bypass_engine",
        "captcha_bypass": "captcha_bypass_engine",
        "graphql_batch": "graphql_scan_engine",
        "jwt_none_alg": "jwt_vulnerability_scanner",
        "path_traversal": "path_traversal_scanner",
        "file_read": "path_traversal_scanner",
        "cors_misconfiguration": "cors_scanner",
        "subdomain_takeover": "subdomain_takeover_scanner",
        "phishing": "subdomain_takeover_scanner",
        "nosql_injection": "nosql_scanner",
        "ssti": "ssti_scanner",
        "deserialization": "deserialization_scanner",
        "ldap_injection": "ldap_scanner",
        "saml_attack": "saml_scanner",
        "prototype_pollution": "prototype_pollution_scanner",
        "grpc_reflection": "grpc_scanner",
        "request_smuggling": "smuggling_engine",
        "dom_clobbering": "client_side_attack_scanner",
        "service_worker_poison": "client_side_attack_scanner",
        "webrtc_leak": "client_side_attack_scanner",
        "css_injection": "client_side_attack_scanner",
        "pdf_ssrf": "advanced_attack_scanners",
        "unicode_normalization": "advanced_attack_scanners",
        "redis_injection": "advanced_attack_scanners",
        "no_rate_limiting": "advanced_attack_scanners",
        "cache_poisoning": "advanced_attack_scanners",
        "dns_rebinding": "dns_rebinding_scanner",
        "hpp": "hpp_scanner",
        "oauth_token_leak": "oauth_token_leak_scanner",
    }

    SEVERITY_SCORES = {
        "critical": 10.0,
        "high": 7.0,
        "medium": 4.0,
        "low": 2.0,
    }

    def __init__(self):
        self.chain_patterns = _ATTACK_CHAINS

    def suggest_next_tests(self, current_findings: List[Dict]) -> List[ChainSuggestion]:
        """
        Analyze current findings and suggest tests to complete chains.

        Args:
            current_findings: All findings discovered so far

        Returns:
            List of chain suggestions, sorted by priority
        """
        suggestions = []

        # Build set of present vuln types
        present_types = set()
        for finding in current_findings:
            vuln_type = finding.get('vuln_type', '').lower()
            present_types.add(vuln_type)

            # Also add normalized aliases
            from oneinfinity.scan.unified_advanced_scanner import _normalize_vuln_type
            normalized = _normalize_vuln_type(vuln_type)
            present_types.update(normalized)

        log.info(f"Analyzing {len(current_findings)} findings with {len(present_types)} vuln types")

        # Check each chain pattern
        for chain_pattern in self.chain_patterns:
            pattern_types = set(chain_pattern['pattern'])
            missing = pattern_types - present_types
            present = pattern_types & present_types

            # Calculate completion percentage
            completion = len(present) / len(pattern_types) if pattern_types else 0

            # Only suggest chains that are partially complete
            if 0 < len(missing) <= 2:  # 1-2 vulns away from completion
                # Determine best scanner for missing vulns
                recommended_scanner = self._get_scanner_for_vulns(list(missing))

                # Calculate priority score
                severity_score = self.SEVERITY_SCORES.get(chain_pattern['severity'], 2.0)
                completion_bonus = completion * 5.0  # Higher completion = higher priority
                confidence = 0.90 if len(missing) == 1 else 0.70

                priority_score = (severity_score + completion_bonus) * confidence

                suggestion = ChainSuggestion(
                    chain_name=chain_pattern['name'],
                    chain_severity=chain_pattern['severity'],
                    missing_vuln_types=list(missing),
                    present_vuln_types=list(present),
                    completion_percentage=completion * 100,
                    recommended_scanner=recommended_scanner,
                    confidence=confidence,
                    priority_score=priority_score,
                    exploitation_impact=chain_pattern.get('description', 'Chain exploitation'),
                )
                suggestions.append(suggestion)

        # Sort by priority score (highest first)
        suggestions.sort(key=lambda x: -x.priority_score)

        log.info(f"Generated {len(suggestions)} chain suggestions")

        return suggestions

    def _get_scanner_for_vulns(self, vuln_types: List[str]) -> str:
        """
        Get scanner name for vulnerability types.

        Returns:
            Scanner name or "unknown"
        """
        for vuln_type in vuln_types:
            scanner = self.SCANNER_MAP.get(vuln_type)
            if scanner:
                return scanner

        return "unknown_scanner"

    def format_suggestions(self, suggestions: List[ChainSuggestion]) -> str:
        """
        Format suggestions as human-readable text.

        Returns:
            Formatted suggestion report
        """
        if not suggestions:
            return "No chain suggestions - all chains either complete or require too many vulns"

        lines = ["=== Chain Completion Suggestions ===", ""]

        for i, sug in enumerate(suggestions[:10], 1):  # Top 10
            lines.append(f"{i}. {sug.chain_name} ({sug.chain_severity})")
            lines.append(f"   Completion: {sug.completion_percentage:.0f}%")
            lines.append(f"   Present: {', '.join(sug.present_vuln_types)}")
            lines.append(f"   Missing: {', '.join(sug.missing_vuln_types)}")
            lines.append(f"   Next: Run {sug.recommended_scanner}")
            lines.append(f"   Priority: {sug.priority_score:.1f}/15.0")
            lines.append(f"   Impact: {sug.exploitation_impact}")
            lines.append("")

        return "\n".join(lines)

    def get_priority_scanners(self, suggestions: List[ChainSuggestion]) -> List[str]:
        """
        Get prioritized list of scanners to run next.

        Returns:
            List of scanner names, deduplicated and ordered by priority
        """
        scanner_scores = {}

        for sug in suggestions:
            scanner = sug.recommended_scanner
            if scanner not in scanner_scores:
                scanner_scores[scanner] = 0
            scanner_scores[scanner] += sug.priority_score

        # Sort by cumulative priority score
        sorted_scanners = sorted(scanner_scores.items(), key=lambda x: -x[1])

        return [scanner for scanner, _ in sorted_scanners]


# ── Convenience Function ──────────────────────────────────────────────────────

def suggest_chain_completions(current_findings: List[Dict]) -> Dict[str, Any]:
    """Get chain completion suggestions."""
    engine = ChainSuggestionEngine()
    suggestions = engine.suggest_next_tests(current_findings)
    priority_scanners = engine.get_priority_scanners(suggestions)

    return {
        "suggestions": [
            {
                "chain_name": s.chain_name,
                "severity": s.chain_severity,
                "completion": s.completion_percentage,
                "missing": s.missing_vuln_types,
                "present": s.present_vuln_types,
                "next_scanner": s.recommended_scanner,
                "priority": s.priority_score,
            }
            for s in suggestions
        ],
        "priority_scanners": priority_scanners,
        "report": engine.format_suggestions(suggestions),
    }
