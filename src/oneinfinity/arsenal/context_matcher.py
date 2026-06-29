"""
Context-Aware Payload Matcher

Selects best payload from arsenal based on:
1. Target tech stack (PHP vs Node vs Python)
2. Detected WAF (Cloudflare vs Akamai vs AWS)
3. Blocked patterns (from failed attempts)
4. Historical success rate (learning from past scans)
5. Payload complexity (simple → complex escalation)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import logging

log = logging.getLogger(__name__)


@dataclass
class Payload:
    """Payload with metadata."""
    content: str
    vuln_type: str
    tech_stack: List[str] = field(default_factory=list)  # ["php", "mysql"]
    waf_bypasses: List[str] = field(default_factory=list)  # ["cloudflare", "akamai"]
    complexity: str = "simple"  # simple, medium, complex
    success_rate: float = 0.5  # Historical success (0-1)
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)


@dataclass
class TargetContext:
    """Context about target for payload selection."""
    vuln_type: str
    tech_stack: List[str] = field(default_factory=list)
    waf: Optional[str] = None
    blocked_patterns: Set[str] = field(default_factory=set)
    similar_targets: List[str] = field(default_factory=list)
    filters_detected: List[str] = field(default_factory=list)
    previous_attempts: int = 0


class ContextMatcher:
    """
    Context-aware payload selector.

    Uses multi-factor scoring to select optimal payload:
    - Tech stack compatibility (30% weight)
    - WAF bypass capability (25% weight)
    - Filter evasion (20% weight)
    - Historical success (15% weight)
    - Complexity match (10% weight)
    """

    WEIGHTS = {
        "tech_stack": 0.30,
        "waf": 0.25,
        "filter_evasion": 0.20,
        "historical": 0.15,
        "complexity": 0.10,
    }

    # Tech stack indicators in responses/headers
    TECH_INDICATORS = {
        "php": ["x-powered-by: php", ".php", "phpsessid", "php/"],
        "python": ["wsgi", "django", "flask", "fastapi", "python/"],
        "node": ["express", "x-powered-by: express", "node.js", "nodejs"],
        "java": ["jsessionid", "java/", "tomcat", "spring"],
        "asp": [".aspx", "asp.net", "x-aspnet-version"],
        "ruby": ["rack", "rails", "ruby/"],
    }

    # WAF signatures
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "akamai": ["akamai", "x-akamai"],
        "aws": ["x-amzn", "awselb", "aws-waf"],
        "imperva": ["incapsula", "visid_incap"],
        "f5": ["f5", "bigip"],
        "fortinet": ["fortigate", "fortiweb"],
    }

    def __init__(self):
        """Initialize context matcher."""
        self._payload_cache: Dict[str, List[Payload]] = {}
        self._success_history: Dict[Tuple[str, str], float] = {}  # (vuln_type, tech) → success_rate
        self._loaded_modules: set = set()  # track loaded module_paths for idempotency
    def select_best_payload(
        self,
        payloads: List[Payload],
        context: TargetContext,
    ) -> Optional[Payload]:
        """
        Select best payload for given context.

        Args:
            payloads: Candidate payloads
            context: Target context with tech stack, WAF, etc.

        Returns:
            Best scoring payload or None if no candidates
        """
        if not payloads:
            return None

        start = time.time()

        # Score all payloads
        scored = []
        for payload in payloads:
            score = self._calculate_score(payload, context)
            scored.append((score, payload))

        # Sort by score (highest first)
        scored.sort(key=lambda x: x[0], reverse=True)

        elapsed_ms = (time.time() - start) * 1000
        log.debug(f"Payload selection took {elapsed_ms:.1f}ms for {len(payloads)} candidates")

        return scored[0][1] if scored else None

    def _calculate_score(self, payload: Payload, context: TargetContext) -> float:
        """Calculate weighted score for payload."""
        tech_score = self._score_tech_stack_match(payload, context.tech_stack)
        waf_score = self._score_waf_compatibility(payload, context.waf)
        filter_score = self._score_filter_evasion(payload, context.blocked_patterns)
        history_score = self._score_historical_success(payload, context)
        complexity_score = self._score_complexity_match(payload, context.previous_attempts)

        total = (
            tech_score * self.WEIGHTS["tech_stack"] +
            waf_score * self.WEIGHTS["waf"] +
            filter_score * self.WEIGHTS["filter_evasion"] +
            history_score * self.WEIGHTS["historical"] +
            complexity_score * self.WEIGHTS["complexity"]
        )

        return total

    def _score_tech_stack_match(self, payload: Payload, target_stack: List[str]) -> float:
        """
        Score tech stack compatibility.

        Returns 0-1 score based on overlap between payload tech requirements
        and target tech stack.
        """
        if not payload.tech_stack or not target_stack:
            return 0.5  # Neutral if unknown

        # Normalize to lowercase
        payload_techs = set(t.lower() for t in payload.tech_stack)
        target_techs = set(t.lower() for t in target_stack)

        # Calculate overlap
        overlap = len(payload_techs & target_techs)
        total = len(payload_techs)

        if total == 0:
            return 0.5

        score = overlap / total

        # Bonus if exact match
        if payload_techs == target_techs:
            score = min(1.0, score + 0.2)

        return score

    def _score_waf_compatibility(self, payload: Payload, waf: Optional[str]) -> float:
        """
        Score WAF bypass capability.

        Returns higher score if payload has known bypasses for detected WAF.
        """
        if not waf:
            return 1.0  # No WAF, all payloads equally good

        waf_lower = waf.lower()

        # Check if payload explicitly supports this WAF
        if payload.waf_bypasses:
            for bypass in payload.waf_bypasses:
                if bypass.lower() == waf_lower:
                    return 1.0  # Perfect match
                if bypass.lower() in waf_lower or waf_lower in bypass.lower():
                    return 0.8  # Partial match

        # Check tags for WAF bypass hints
        if "waf-bypass" in payload.tags or "universal-bypass" in payload.tags:
            return 0.7

        # No specific WAF bypass capability
        return 0.3

    def _score_filter_evasion(
        self,
        payload: Payload,
        blocked_patterns: Set[str],
    ) -> float:
        """
        Score filter evasion capability.

        Returns higher score if payload doesn't contain blocked patterns.
        """
        if not blocked_patterns:
            return 1.0  # No known blocks

        payload_lower = payload.content.lower()

        # Count how many blocked patterns appear in payload
        matches = 0
        for pattern in blocked_patterns:
            if pattern.lower() in payload_lower:
                matches += 1

        # Score inversely proportional to matches
        if matches == 0:
            return 1.0

        # Heavy penalty for matching blocked patterns
        penalty = matches / len(blocked_patterns)
        score = max(0.0, 1.0 - penalty * 2)  # 2x penalty multiplier

        return score

    def _score_historical_success(
        self,
        payload: Payload,
        context: TargetContext,
    ) -> float:
        """
        Score based on historical success rate.

        Uses payload's success_rate field and checks history cache
        for similar targets.
        """
        # Start with payload's own success rate
        base_score = payload.success_rate

        # Check if we have history for this vuln type + tech combo
        if context.tech_stack:
            for tech in context.tech_stack:
                key = (context.vuln_type, tech.lower())
                if key in self._success_history:
                    history_rate = self._success_history[key]
                    # Blend with historical data (70% history, 30% base)
                    base_score = history_rate * 0.7 + base_score * 0.3
                    break

        return base_score

    def _score_complexity_match(
        self,
        payload: Payload,
        previous_attempts: int,
    ) -> float:
        """
        Score complexity appropriateness.

        Start with simple payloads, escalate to complex after failures.
        """
        complexity_levels = {"simple": 0, "medium": 1, "complex": 2}
        payload_level = complexity_levels.get(payload.complexity, 1)

        # Ideal complexity based on attempts
        if previous_attempts == 0:
            ideal_level = 0  # Start simple
        elif previous_attempts <= 2:
            ideal_level = 1  # Try medium
        else:
            ideal_level = 2  # Escalate to complex

        # Score based on how close to ideal
        distance = abs(payload_level - ideal_level)
        score = 1.0 - (distance * 0.3)  # 0.3 penalty per level difference

        return max(0.0, score)

    def adaptive_selection(
        self,
        payloads: List[Payload],
        context: TargetContext,
        feedback: Optional[Dict] = None,
    ) -> Optional[Payload]:
        """
        Adaptive payload selection with learning.

        Updates success history based on feedback and selects next payload.

        Args:
            payloads: Available payloads
            context: Target context
            feedback: Optional feedback from previous attempt
                     {"success": bool, "payload_id": str, "blocked_patterns": []}

        Returns:
            Next best payload
        """
        # Process feedback if provided
        if feedback:
            self._update_from_feedback(feedback, context)

        # Select best payload with updated knowledge
        return self.select_best_payload(payloads, context)

    def _update_from_feedback(self, feedback: Dict, context: TargetContext) -> None:
        """Update internal knowledge from feedback."""
        success = feedback.get("success", False)

        # Update blocked patterns
        if not success and "blocked_patterns" in feedback:
            for pattern in feedback["blocked_patterns"]:
                context.blocked_patterns.add(pattern)

        # Update success history
        if context.tech_stack:
            for tech in context.tech_stack:
                key = (context.vuln_type, tech.lower())
                current = self._success_history.get(key, 0.5)

                # Exponential moving average
                alpha = 0.3  # Learning rate
                new_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * current
                self._success_history[key] = new_rate

    def detect_tech_stack(self, headers: Dict[str, str], body: str) -> List[str]:
        """
        Detect tech stack from HTTP headers and body.

        Args:
            headers: HTTP response headers
            body: Response body

        Returns:
            List of detected technologies
        """
        detected = set()

        # Combine headers and body for analysis
        content = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        content += " " + body.lower()

        # Check each tech stack indicator
        for tech, indicators in self.TECH_INDICATORS.items():
            for indicator in indicators:
                if indicator.lower() in content:
                    detected.add(tech)
                    break

        return list(detected)

    def detect_waf(self, headers: Dict[str, str], status_code: int, body: str) -> Optional[str]:
        """
        Detect WAF from response characteristics.

        Args:
            headers: HTTP response headers
            status_code: HTTP status code
            body: Response body

        Returns:
            Detected WAF name or None
        """
        # Combine headers and body
        content = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        content += " " + body.lower()

        # Check WAF signatures
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content:
                    log.info(f"Detected WAF: {waf_name}")
                    return waf_name

        # Check for generic WAF behavior
        if status_code == 403:
            if any(keyword in content for keyword in ["blocked", "forbidden", "access denied"]):
                return "generic_waf"

        return None

    def get_stats(self) -> Dict:
        """Get matcher statistics."""
        return {
            "cached_payloads": len(self._payload_cache),
            "success_history_entries": len(self._success_history),
            "avg_success_rate": (
                sum(self._success_history.values()) / len(self._success_history)
                if self._success_history else 0.5
            ),
        }

    def select_best(self, payloads: "List[Payload]", context: "TargetContext") -> "Optional[Payload]":
        """Alias for select_best_payload for API compatibility."""
        return self.select_best_payload(payloads, context)

    def detect_waf_from_headers(self, headers: dict) -> "Optional[str]":
        """Detect WAF from request headers (e.g. custom headers passed to scan)."""
        if not headers:
            return None
        content = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in content:
                    return waf_name
        return None

    # ── Arsenal loading ───────────────────────────────────────────────────────

    def load_arsenal(self) -> None:
        """
        Load all payload libraries from arsenal subdirectories into the cache.
        Idempotent — tracks loaded module_paths so repeated calls never add duplicates.
        """
        _MODULES = [
            ("oneinfinity.arsenal.recon.recon_payloads",    "RECON_PAYLOADS"),
            ("oneinfinity.arsenal.bypass.bypass_payloads",  "BYPASS_PAYLOADS"),
            ("oneinfinity.arsenal.chains.chain_payloads",   "CHAIN_PAYLOADS"),
            ("oneinfinity.arsenal.privesc.privesc_payloads","PRIVESC_PAYLOADS"),
            ("oneinfinity.arsenal.shells.shell_payloads",   "SHELL_PAYLOADS"),
            ("oneinfinity.arsenal.web.web_payloads",        "WEB_PAYLOADS"),
        ]
        for module_path, attr in _MODULES:
            if module_path in self._loaded_modules:
                continue  # already loaded — guard on module path, not vuln_type category
            try:
                import importlib
                mod = importlib.import_module(module_path)
                payloads = getattr(mod, attr, [])
                for p in payloads:
                    self._payload_cache.setdefault(p.vuln_type, []).append(p)
                self._loaded_modules.add(module_path)  # mark as loaded
                log.debug("Arsenal loaded: %s (%d payloads)", module_path, len(payloads))
            except ImportError:
                log.warning("Arsenal module unavailable: %s", module_path)  # visible at default log level
            except Exception as exc:
                log.warning("Arsenal load error (%s): %s", module_path, exc)

    def get_payloads_for_type(self, vuln_type: str) -> "List[Payload]":
        """
        Return all arsenal payloads for the given vulnerability type.
        Lazily loads the arsenal on first call.
        """
        if not self._payload_cache:
            self.load_arsenal()
        return list(self._payload_cache.get(vuln_type, []))


# Singleton instance
_matcher_instance: Optional[ContextMatcher] = None


def get_context_matcher() -> ContextMatcher:
    """Get singleton ContextMatcher instance."""
    global _matcher_instance
    if _matcher_instance is None:
        _matcher_instance = ContextMatcher()
    return _matcher_instance
